from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
import math
import re
from pathlib import Path
import threading
import time
from urllib.request import ProxyHandler, build_opener
from urllib.parse import quote, urlsplit, urlunsplit

from ..core.http_client import HttpClient, NoRedirects, RequestSpec
from ..core.scope_validator import ScopeValidator
from ..reporting.evidence import write_evidence_json
from ..requests_engine.parameters import with_parameter
from ..utils.exceptions import ToolkitError
from .comparison import AccessControlTester, AccessCase, MISSING, exact, lookup, observations, parse_json, read_local
from .guards import is_loopback_url


MAX_RANGE_IDS = 25
MAX_LOCAL_RANGE_IDS = 100
MAX_RANGE_REQUESTS = MAX_LOCAL_RANGE_IDS + 2
MAX_REQUESTS_PER_SECOND = 0.1
MAX_LOCAL_CONCURRENCY = 4
MIN_LOCAL_INTERVAL_SECONDS = 0.01


def parse_id_range(value: str, max_ids: int = MAX_RANGE_IDS) -> range:
    if not isinstance(value, str) or len(value) > 64:
        raise ValueError("Use one small numeric interval, for example 1-10.")
    match = re.fullmatch(r"\s*([1-9][0-9]{0,18})\s*-\s*([1-9][0-9]{0,18})\s*", value)
    if not match:
        raise ValueError("Use one ascending numeric interval, for example 1-10.")
    start, end = int(match[1]), int(match[2])
    if type(max_ids) is not int or not 1 <= max_ids <= MAX_LOCAL_RANGE_IDS:
        raise ValueError(f"The configurable range cap must be between 1 and {MAX_LOCAL_RANGE_IDS} IDs.")
    if end < start or end >= 2**63 or end - start + 1 > max_ids:
        raise ValueError(f"The interval must contain at most {max_ids} IDs.")
    return range(start, end + 1)


@dataclass(frozen=True)
class AccessRangeOptions:
    id_range: str
    max_tests: int
    max_range: int = MAX_RANGE_IDS
    concurrency: int = 1
    min_interval: float = 10.0
    allow_public_range: bool = False


class _ThreadSafeIntervalLimiter:
    def __init__(self, interval: float, cancel_event=None):
        self.requests_per_second = 1.0 / interval
        self._interval = interval
        self.cancel_event = cancel_event
        self._last_request_at = 0.0
        self._lock = threading.Lock()

    def wait(self, max_wait: float | None = None) -> None:
        with self._lock:
            if self.cancel_event is not None and self.cancel_event.is_set():
                raise ToolkitError("Request schedule cancelled.")
            delay = self._interval - (time.monotonic() - self._last_request_at)
            if delay > 0:
                if max_wait is not None and delay > max_wait:
                    if self.cancel_event is not None:
                        if self.cancel_event.wait(max_wait):
                            raise ToolkitError("Request schedule cancelled.")
                    else:
                        time.sleep(max_wait)
                    raise ToolkitError("Run time budget would expire before the next request slot.")
                if self.cancel_event is not None:
                    if self.cancel_event.wait(delay):
                        raise ToolkitError("Request schedule cancelled.")
                else:
                    time.sleep(delay)
            if self.cancel_event is not None and self.cancel_event.is_set():
                raise ToolkitError("Request schedule cancelled.")
            self._last_request_at = time.monotonic()


class AccessRangeTester:
    def __init__(self, scope: ScopeValidator, client: HttpClient):
        self.scope = scope
        self.client = client
        self._request_lock = threading.Lock()

    def validate(self, case_file: Path, options: AccessRangeOptions) -> tuple[AccessCase, list[RequestSpec]]:
        if (
            type(options.allow_public_range) is not bool
            or type(options.max_range) is not int
            or not 1 <= options.max_range <= MAX_LOCAL_RANGE_IDS
            or type(options.concurrency) is not int
            or not 1 <= options.concurrency <= MAX_LOCAL_CONCURRENCY
            or isinstance(options.min_interval, bool)
            or not isinstance(options.min_interval, (int, float))
            or not math.isfinite(options.min_interval)
            or options.min_interval <= 0
        ):
            raise ValueError("Range cap, concurrency or minimum interval is invalid.")
        ids = parse_id_range(options.id_range, options.max_range)
        if (
            type(options.max_tests) is not int
            or len(ids) + 2 > options.max_tests
            or options.max_tests > MAX_RANGE_REQUESTS
        ):
            raise ValueError(f"Budget must cover two controls and at most {MAX_LOCAL_RANGE_IDS} GET probes.")
        case = AccessControlTester(self.scope, self.client).validate(case_file, options.max_tests)
        data = parse_json(read_local(case_file, 131072))
        if data.get("identifier_enumeration_authorized") is not True:
            raise ValueError("Range checks require explicit identifier-enumeration authorization in the private case.")
        resource = data["resource"]
        requests = [self._request(case, resource, identifier) for identifier in ids]
        self.scope.require_all(request.prepared_url() for request in requests)
        local_lab = all(is_loopback_url(request.prepared_url()) for request in (case.owner, case.actor, *requests))
        if local_lab:
            if options.min_interval < MIN_LOCAL_INTERVAL_SECONDS:
                raise ValueError(f"Loopback interval must be at least {MIN_LOCAL_INTERVAL_SECONDS} seconds.")
        else:
            max_public_range = MAX_LOCAL_RANGE_IDS if options.allow_public_range else MAX_RANGE_IDS
            min_public_interval = 1.0 if options.allow_public_range else 10.0
            max_public_concurrency = MAX_LOCAL_CONCURRENCY if options.allow_public_range else 1
            if (
                options.max_range > max_public_range
                or options.concurrency > max_public_concurrency
                or options.min_interval < min_public_interval
            ):
                if options.allow_public_range:
                    raise ValueError(
                        "Relaxed public ranges allow at most 100 IDs, four workers, and require at least one second between starts."
                    )
                raise ValueError(
                    "Non-loopback ranges remain capped at 25 IDs, sequential, and at least ten seconds apart."
                )
            if options.max_tests > max_public_range + 2:
                raise ValueError(
                    f"Non-loopback range checks are capped at {max_public_range + 2} total requests including controls."
                )
        return case, requests

    @staticmethod
    def _request(case: AccessCase, resource: dict, identifier: int) -> RequestSpec:
        url = case.cross.prepared_url()
        if set(resource) == {"query_parameter"}:
            url = with_parameter(url, resource["query_parameter"], str(identifier))
        elif set(resource) == {"path_segment"}:
            parsed = urlsplit(url)
            segments = parsed.path[1:].split("/")
            index = resource["path_segment"]
            if type(index) is not int or index < 0 or index >= len(segments):
                raise ValueError("The declared resource path segment is invalid.")
            segments[index] = quote(str(identifier), safe="")
            url = urlunsplit((parsed.scheme, parsed.netloc, "/" + "/".join(segments), parsed.query, ""))
        else:
            raise ValueError("Range checks support one declared path segment or query parameter.")
        return RequestSpec("GET", url, dict(case.cross.headers))

    def run(self, case_file: Path, options: AccessRangeOptions, evidence_dir: Path):
        case, requests = self.validate(case_file, options)
        local_lab = all(is_loopback_url(request.prepared_url()) for request in (case.owner, case.actor, *requests))
        configured_rate = getattr(self.client.rate_limiter, "requests_per_second", MAX_REQUESTS_PER_SECOND)
        policy_interval = 1.0 / configured_rate if configured_rate > 0 else 10.0
        effective_interval = options.min_interval if local_lab else max(options.min_interval, policy_interval)
        if local_lab:
            self.client.opener = build_opener(ProxyHandler({}), NoRedirects())
        if options.concurrency == 1:
            self.client.rate_limiter.requests_per_second = 1.0 / effective_interval
        else:
            cancel_event = getattr(self.client.rate_limiter, "cancel_event", None)
            self.client.rate_limiter = _ThreadSafeIntervalLimiter(effective_interval, cancel_event)
        result = {
            "type": "access-control",
            "mode": "bounded-range",
            "classification": "inconclusive",
            "finding_state": "inconclusive",
            "confirmed": False,
            "confirmation_gap": None,
            "controls_valid": False,
            "steps": [],
            "results": [],
            "requests_attempted": 0,
            "request_budget": len(requests) + 2,
            "planned_probes": len(requests),
            "candidate_offset": None,
            "stop_reason": None,
            "inverse_sent": False,
            "anonymous_sent": False,
            "concurrency": options.concurrency,
            "minimum_interval_seconds": effective_interval,
            "max_range": options.max_range,
            "local_lab": local_lab,
            "concurrent_requests_not_evaluated": 0,
        }

        for account, request in (("owner", case.owner), ("actor", case.actor)):
            response = self._send(request, result)
            if response is None:
                return self._save(evidence_dir, result)
            facts = observations(response, case.checks)
            result["steps"].append({"step": account + "_control", **facts})
            other = "actor" if account == "owner" else "owner"
            valid = (
                response.status_code == 200
                and not response.body_truncated
                and facts["application_success"] is True
                and facts[f"{account}_resource_match"]
                and facts[f"{account}_private_match"]
                and not facts[f"{other}_marker_seen"]
            )
            if not valid:
                result["stop_reason"] = "invalid_" + account + "_control"
                return self._save(evidence_dir, result)
            if account == "actor":
                result["controls_valid"] = True

        stop = False
        with ThreadPoolExecutor(max_workers=options.concurrency) as executor:
            for start in range(0, len(requests), options.concurrency):
                window = list(enumerate(requests[start : start + options.concurrency], start))
                futures = [(offset, executor.submit(self._send, request, result)) for offset, request in window]
                for offset, future in futures:
                    response = future.result()
                    if stop:
                        result["results"].append(
                            {
                                "probe_offset": offset,
                                "status_code": response.status_code if response else None,
                                "duration_ms": response.duration_ms if response else None,
                                "classification": "sent_concurrently_not_evaluated",
                                "confirmed": False,
                            }
                        )
                        result["concurrent_requests_not_evaluated"] += 1
                        continue
                    if response is None:
                        result["stop_reason"] = "transport_error"
                        result["steps"].append({"step": "cross_read", "transport_error": True})
                        stop = True
                        continue
                    facts = observations(response, case.checks)
                    identity_differs = self._identity_differs(case, response.body_text)
                    owner_proof = facts["owner_resource_match"] and facts["owner_private_match"]
                    returned_resource = self._resource_value(case, response.body_text)
                    resource_is_not_actor = (
                        type(returned_resource) in {str, int}
                        and returned_resource != ""
                        and not exact(returned_resource, case.checks["actor_resource"])
                        and facts["application_success"] is True
                    )
                    candidate = not response.body_truncated and (
                        owner_proof or identity_differs or (response.status_code == 200 and resource_is_not_actor)
                    )
                    denied = response.status_code in {401, 403} or facts["application_success"] is False
                    row = {
                        "probe_offset": offset,
                        "status_code": response.status_code,
                        "duration_ms": response.duration_ms,
                        "body_size": response.body_size,
                        "body_truncated": response.body_truncated,
                        "application_success": facts["application_success"],
                        "owner_resource_match": facts["owner_resource_match"],
                        "owner_private_match": facts["owner_private_match"],
                        "identity_differs_from_actor": identity_differs,
                        "resource_differs_from_actor": resource_is_not_actor,
                        "classification": "candidate"
                        if candidate
                        else "rejected_in_this_test"
                        if denied
                        else "inconclusive",
                        "confirmed": False,
                    }
                    result["steps"].append(
                        {"step": "cross_read", **facts, "identity_differs_from_actor": identity_differs}
                    )
                    result["results"].append(row)
                    if candidate:
                        result["candidate_offset"] = offset
                        step_names = {str(step.get("step")) for step in result["steps"] if isinstance(step, dict)}
                        # Confirmed only with controls + cross evidence of A's resource via B's session.
                        if (
                            result["controls_valid"]
                            and owner_proof
                            and "owner_control" in step_names
                            and "actor_control" in step_names
                        ):
                            row["classification"] = "confirmed"
                            row["finding_state"] = "confirmed"
                            row["confirmed"] = True
                            result["classification"] = "confirmed"
                            result["finding_state"] = "confirmed"
                            result["confirmed"] = True
                            result["stop_reason"] = "private_evidence_observed"
                        else:
                            row["finding_state"] = "candidate"
                            row["confirmation_gap"] = "no_second_proof"
                            result["classification"] = "candidate"
                            result["finding_state"] = "candidate"
                            result["stop_reason"] = "candidate_observed_stop_early"
                        stop = True
                    elif response.status_code == 429 or response.body_truncated or 300 <= response.status_code < 400:
                        result["stop_reason"] = (
                            "rate_limited"
                            if response.status_code == 429
                            else "truncated_response"
                            if response.body_truncated
                            else "redirect_not_followed"
                        )
                        stop = True
                    elif response.status_code == 401:
                        result["stop_reason"] = "authentication_failure"
                        stop = True
                if stop:
                    break
        if result["classification"] not in {"candidate", "confirmed"} and result["stop_reason"] is None:
            completed = len(result["results"]) == len(requests)
            denied = all(row["classification"] == "rejected_in_this_test" for row in result["results"])
            result["classification"] = "rejected_in_this_test" if completed and denied else "inconclusive"
            result["finding_state"] = (
                "not_observed" if result["classification"] == "rejected_in_this_test" else "inconclusive"
            )
        controls_attempted = sum(step.get("step") in {"owner_control", "actor_control"} for step in result["steps"])
        result["not_completed"] = max(0, len(requests) - (result["requests_attempted"] - controls_attempted))
        return self._save(evidence_dir, result)

    def _send(self, request: RequestSpec, result: dict):
        with self._request_lock:
            result["requests_attempted"] += 1
        try:
            return self.client.send(request)
        except (ToolkitError, ValueError):
            return None

    @staticmethod
    def _response_json(body_text: str):
        try:
            return parse_json(body_text)
        except ValueError:
            return None

    @classmethod
    def _resource_value(cls, case: AccessCase, body_text: str):
        body = cls._response_json(body_text)
        if body is None:
            return MISSING
        return lookup(body, case.checks["resource_pointer"])

    @classmethod
    def _identity_differs(cls, case: AccessCase, body_text: str) -> bool:
        identity = case.identity_check
        if identity is None:
            return False
        body = cls._response_json(body_text)
        if body is None:
            return False
        observed = lookup(body, identity["pointer"])
        return isinstance(observed, str) and bool(observed) and observed != identity["actor_value"]

    @staticmethod
    def _save(evidence_dir: Path, result: dict):
        path = write_evidence_json(evidence_dir, result, prefix="access-range")
        return path, result
