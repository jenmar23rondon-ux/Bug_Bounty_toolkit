from __future__ import annotations

from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from dataclasses import dataclass
import math
from pathlib import Path
import re
from threading import Event, local
from urllib.parse import quote, urlsplit, urlunsplit

from .body import BodyDocument
from .comparison import AccessCase, exact, load_case, lookup, observations, parse_json
from ..core.http_client import HttpClient, RequestSpec
from ..core.rate_limiter import RateLimiter
from ..core.redaction import redact_url
from ..core.scope_validator import ScopeValidator
from ..reporting.evidence import write_evidence_json
from ..requests_engine.parameters import with_parameter
from ..utils.exceptions import ToolkitError


def parse_id_range(value: str, limit: int = 10000) -> list[int]:
    if not isinstance(value, str) or not value.strip() or len(value) > 8192:
        raise ValueError("Use a bounded ID range such as 1-100 or 1,2,5,10.")
    values = {}
    for token in value.split(","):
        match = re.fullmatch(r"\s*([0-9]{1,19})(?:-([0-9]{1,19}))?\s*", token)
        if not match:
            raise ValueError("ID lists must contain ascending nonnegative integer ranges.")
        start = int(match[1])
        end = int(match[2]) if match[2] else start
        if end < start or end >= 2**63 or end - start + 1 > limit:
            raise ValueError("ID range exceeds its bounds or item limit.")
        for identifier in range(start, end + 1):
            values[identifier] = None
            if len(values) > limit:
                raise ValueError("ID range exceeds its item limit.")
    return list(values)


def parse_filter_sizes(value: str | None) -> tuple[int, ...]:
    if value is None:
        return ()
    if not re.fullmatch(r"[0-9]+(?:,[0-9]+)*", value) or len(value) > 1024:
        raise ValueError("Filter sizes must be comma-separated byte counts.")
    return tuple(dict.fromkeys(int(item) for item in value.split(",")))


def identity_different(body: str, identity: dict | None) -> bool:
    if identity is None:
        return False
    try:
        value = lookup(parse_json(body), identity["pointer"])
    except ValueError:
        return False
    return isinstance(value, str) and bool(value) and not exact(value, identity["actor_value"])


def probe_verdict(response, case: AccessCase, filters: tuple[int, ...]) -> dict:
    facts = observations(response, case.checks)
    different = identity_different(response.body_text, case.identity_check)
    proof = facts["owner_resource_match"] and facts["owner_private_match"]
    candidate = response.status_code == 200 and not response.body_truncated and (proof or different)
    if response.body_truncated or 300 <= response.status_code < 400:
        verdict = "inconclusive"
    elif candidate:
        verdict = "candidate"
    elif response.status_code in {401, 403} or facts["application_success"] is False:
        verdict = "rejected_in_this_test"
    else:
        verdict = "inconclusive"
    filtered = response.body_size in filters
    return {
        "status": response.status_code,
        "size": response.body_size,
        "verdict": "filtered" if filtered else verdict,
        "noise_filtered": filtered,
        "candidate_before_filter": candidate,
        "different_identity": different,
        "private_proof_matched": proof,
        "confirmed": False,
        "write_effect_verified": False,
        "observations": facts,
    }


@dataclass(frozen=True)
class BatchOptions:
    id_range: str | None = None
    concurrency: int = 10
    delay: float = 0.0
    filter_sizes: tuple[int, ...] = ()
    body_idor: bool = False
    methods: tuple[str, ...] = ()
    allow_write: bool = False


@dataclass(frozen=True)
class Probe:
    request: RequestSpec
    identifier: str
    field: str | None = None


class AccessBatchTester:
    def __init__(self, scope: ScopeValidator, client: HttpClient, client_factory=None):
        self.scope, self.client, self.client_factory = scope, client, client_factory

    def validate(self, case_file: Path, options: BatchOptions, max_tests: int) -> tuple[AccessCase, list[Probe]]:
        if (
            type(options.concurrency) is not int
            or not 1 <= options.concurrency <= 100
            or not math.isfinite(options.delay)
            or options.delay < 0
        ):
            raise ValueError("Concurrency must be 1-100 and delay must be finite and nonnegative.")
        if type(max_tests) is not int or not 3 <= max_tests <= 10000:
            raise ValueError("A bounded batch budget of 3-10000 requests is required.")
        case = load_case(case_file, self.scope, body_mode=options.body_idor, allow_write=options.allow_write)
        values = parse_id_range(options.id_range, max_tests) if options.id_range is not None else None
        probes = []
        if options.body_idor:
            content_type = next(
                (value for key, value in case.cross.headers.items() if key.lower() == "content-type"), ""
            )
            document = BodyDocument.parse(case.cross.body, content_type)
            methods = options.methods or (case.owner.method,)
            if not set(methods) <= set(case.methods):
                raise ValueError("Requested methods must be explicitly approved in the case.")
            if (
                any(
                    method in {"PUT", "PATCH", "DELETE"} or (method == "POST" and case.owner.method != "POST")
                    for method in methods
                )
                and not options.allow_write
            ):
                raise ValueError("Write-method probes require --allow-write and case writes_authorized=true.")
            for field, value, body in document.variations(list(case.body_fields), values):
                for method in dict.fromkeys(methods):
                    probes.append(
                        Probe(
                            RequestSpec(method, case.cross.url, dict(case.cross.headers), body=body), str(value), field
                        )
                    )
                    if len(probes) + 2 > max_tests:
                        raise ValueError("The complete body plan exceeds the configured request budget.")
        else:
            if values is None or options.methods or options.allow_write:
                raise ValueError("URL batch mode requires --range; methods and writes are body-only options.")
            for value in values:
                url = case.cross.url
                if "query_parameter" in case.resource:
                    url = with_parameter(url, case.resource["query_parameter"], str(value))
                else:
                    parsed = urlsplit(url)
                    segments = parsed.path[1:].split("/")
                    segments[case.resource["path_segment"]] = quote(str(value), safe="")
                    url = urlunsplit((parsed.scheme, parsed.netloc, "/" + "/".join(segments), parsed.query, ""))
                probes.append(Probe(RequestSpec("GET", url, dict(case.cross.headers)), str(value)))
        if len(probes) + 2 > max_tests:
            raise ValueError("Range plus two account controls exceeds the configured request budget.")
        for probe in probes:
            self.scope.require(probe.request.prepared_url())
        return case, probes

    def run(self, case_file: Path, options: BatchOptions, evidence_dir: Path, max_tests: int):
        case, probes = self.validate(case_file, options, max_tests)
        result = {
            "type": "access-control",
            "mode": "body" if options.body_idor else "range",
            "classification": "inconclusive",
            "confirmed": False,
            "controls_valid": False,
            "steps": [],
            "results": [],
            "requests_attempted": 0,
            "planned_probes": len(probes),
            "request_budget": max_tests,
            "stop_reason": None,
            "concurrency": options.concurrency,
            "inverse_sent": False,
            "anonymous_sent": False,
        }
        stop = Event()
        limiter = RateLimiter(
            min(self.client.rate_limiter.requests_per_second, 1 / options.delay)
            if options.delay
            else self.client.rate_limiter.requests_per_second,
            cancel_event=stop,
        )
        limiter._last_request_at = self.client.rate_limiter._last_request_at
        self.client.rate_limiter = limiter
        for account, request in (("owner", case.owner), ("actor", case.actor)):
            result["requests_attempted"] += 1
            try:
                response = self.client.send(request)
            except (ToolkitError, ValueError):
                result["stop_reason"] = "transport_error"
                break
            facts = observations(response, case.checks)
            result["steps"].append({"step": account + "_control", **facts})
            other = "actor" if account == "owner" else "owner"
            if (
                response.status_code != 200
                or response.body_truncated
                or facts["application_success"] is not True
                or not facts[f"{account}_resource_match"]
                or not facts[f"{account}_private_match"]
                or facts[f"{other}_marker_seen"]
            ):
                result["stop_reason"] = "invalid_" + account + "_control"
                break
            if account == "actor":
                result["controls_valid"] = True
        if not result["controls_valid"]:
            return write_evidence_json(evidence_dir, result, prefix="access-batch"), result
        state = local()

        def worker(index):
            if stop.is_set():
                return index, None
            if not hasattr(state, "client"):
                state.client = (
                    self.client_factory(limiter)
                    if self.client_factory
                    else HttpClient(self.scope, self.client.timeout, limiter, self.client.max_response_bytes)
                )
            probe = probes[index]
            try:
                response = state.client.send(probe.request)
                row = probe_verdict(response, case, options.filter_sizes)
                if response.status_code in {401, 429} or response.body_truncated or 300 <= response.status_code < 400:
                    stop.set()
                    row["stop_reason"] = (
                        "rate_limited"
                        if response.status_code == 429
                        else "truncated_response"
                        if response.body_truncated
                        else "access_or_rate_limit"
                        if response.status_code == 401
                        else "redirect_not_followed"
                    )
            except (ToolkitError, ValueError):
                if stop.is_set():
                    return index, None
                stop.set()
                row = {
                    "status": None,
                    "size": 0,
                    "verdict": "error",
                    "confirmed": False,
                    "stop_reason": "transport_error",
                }
            return index, {
                "id": probe.identifier,
                "url": redact_url(probe.request.prepared_url()),
                "method": probe.request.method,
                "field": probe.field,
                **row,
            }

        collected = {}
        next_index = 0
        with ThreadPoolExecutor(max_workers=options.concurrency) as pool:
            pending = set()
            while next_index < len(probes) and len(pending) < options.concurrency:
                pending.add(pool.submit(worker, next_index))
                next_index += 1
            while pending:
                done, pending = wait(pending, return_when=FIRST_COMPLETED)
                for future in done:
                    index, row = future.result()
                    if row is not None:
                        collected[index] = row
                while not stop.is_set() and next_index < len(probes) and len(pending) < options.concurrency:
                    pending.add(pool.submit(worker, next_index))
                    next_index += 1
        result["results"] = [collected[index] for index in sorted(collected)]
        for row in result["results"]:
            result["steps"].append({"step": "cross_read", **row.get("observations", {})})
        result["requests_attempted"] += len(collected)
        result["not_completed"] = len(probes) - len(collected)
        result["stop_reason"] = next((row["stop_reason"] for row in result["results"] if "stop_reason" in row), None)
        if any(row["verdict"] == "candidate" for row in result["results"]):
            result["classification"] = "candidate"
        elif (
            result["results"]
            and not stop.is_set()
            and all(row["verdict"] == "rejected_in_this_test" for row in result["results"])
        ):
            result["classification"] = "rejected_in_this_test"
        return write_evidence_json(evidence_dir, result, prefix="access-batch"), result
