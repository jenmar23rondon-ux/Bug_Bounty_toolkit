from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import json
import math
from pathlib import Path
import threading
from urllib.request import ProxyHandler, build_opener

from ..core.http_client import NoRedirects, RequestSpec
from ..core.scope_validator import ScopeValidator
from ..reporting.evidence import write_evidence_json
from ..utils.exceptions import ToolkitError
from .comparison import AccessCase, exact, load_case, lookup, observations, parse_json, read_local, replace_pointer
from .guards import is_loopback_url
from .range_checker import (
    AccessRangeOptions,
    MAX_LOCAL_CONCURRENCY,
    MAX_LOCAL_RANGE_IDS,
    MAX_RANGE_IDS,
    MAX_RANGE_REQUESTS,
    MAX_REQUESTS_PER_SECOND,
    MIN_LOCAL_INTERVAL_SECONDS,
    _ThreadSafeIntervalLimiter,
    parse_id_range,
)


class AccessWriteRangeTester:
    def __init__(self, scope: ScopeValidator, client, allow_public_writes: bool = False):
        if type(allow_public_writes) is not bool:
            raise ValueError("allow_public_writes must be a boolean.")
        self.scope = scope
        self.client = client
        self.allow_public_writes = allow_public_writes
        self._request_lock = threading.Lock()

    def validate(self, case_file: Path, options: AccessRangeOptions) -> tuple[AccessCase, list[RequestSpec]]:
        if (type(options.allow_public_range) is not bool or
                type(options.max_range) is not int or not 1 <= options.max_range <= MAX_LOCAL_RANGE_IDS or
                type(options.concurrency) is not int or not 1 <= options.concurrency <= MAX_LOCAL_CONCURRENCY or
                isinstance(options.min_interval, bool) or not isinstance(options.min_interval, (int, float)) or
                not math.isfinite(options.min_interval) or options.min_interval <= 0):
            raise ValueError("Write-range cap, concurrency or minimum interval is invalid.")
        ids = parse_id_range(options.id_range, options.max_range)
        if (type(options.max_tests) is not int or len(ids) + 2 > options.max_tests or
                options.max_tests > MAX_RANGE_REQUESTS):
            raise ValueError(f"Budget must cover two write controls and at most {MAX_LOCAL_RANGE_IDS} write probes.")

        case = load_case(case_file, self.scope, allow_lab_writes=True)
        if case.mode != "lab-write":
            raise ValueError("Write ranges require a JSON body resource pointer and disposable test resources.")
        if not self.allow_public_writes and not all(
                is_loopback_url(request.prepared_url()) for request in (case.owner, case.actor, case.cross)):
            raise ValueError("Automated write comparisons are restricted to localhost or loopback IPs.")
        data = parse_json(read_local(case_file, 131072))
        if data.get("identifier_enumeration_authorized") is not True:
            raise ValueError("Write ranges require explicit identifier-enumeration authorization in the private case.")

        actor_document = parse_json(case.actor.body.decode("utf-8") if isinstance(case.actor.body, bytes) else case.actor.body)
        pointer = case.resource["json_body_pointer"]
        actor_identifier = lookup(actor_document, pointer)
        identifier_is_numeric = type(actor_identifier) is int
        requests = []
        for identifier in ids:
            replacement = identifier if identifier_is_numeric else str(identifier)
            body = replace_pointer(actor_document, pointer, replacement)
            requests.append(RequestSpec(case.actor.method, case.actor.prepared_url(), dict(case.actor.headers),
                                        body=json.dumps(body, ensure_ascii=False, separators=(",", ":"))))
        self.scope.require_all(request.prepared_url() for request in requests)

        local_lab = all(is_loopback_url(request.prepared_url()) for request in (case.owner, case.actor, *requests))
        if local_lab:
            if options.min_interval < MIN_LOCAL_INTERVAL_SECONDS:
                raise ValueError(f"Loopback interval must be at least {MIN_LOCAL_INTERVAL_SECONDS} seconds.")
        else:
            max_range = MAX_LOCAL_RANGE_IDS if options.allow_public_range else MAX_RANGE_IDS
            max_concurrency = MAX_LOCAL_CONCURRENCY if options.allow_public_range else 1
            min_interval = 1.0 if options.allow_public_range else 10.0
            if options.max_range > max_range or options.concurrency > max_concurrency or options.min_interval < min_interval:
                raise ValueError("Public write ranges require --allow-public-range to exceed 25 IDs, use concurrency, or go below ten seconds.")
            if options.max_tests > max_range + 2:
                raise ValueError("Public write-range budget exceeds the configured range cap including two controls.")
        return case, requests

    def run(self, case_file: Path, options: AccessRangeOptions, evidence_dir: Path):
        case, requests = self.validate(case_file, options)
        local_lab = all(is_loopback_url(request.prepared_url()) for request in (case.owner, case.actor, *requests))
        configured_rate = getattr(self.client.rate_limiter, "requests_per_second", MAX_REQUESTS_PER_SECOND)
        policy_interval = 1.0 / configured_rate if configured_rate > 0 else 10.0
        effective_interval = options.min_interval if local_lab else max(options.min_interval, policy_interval)
        if local_lab and hasattr(self.client, "opener"):
            self.client.opener = build_opener(ProxyHandler({}), NoRedirects())
        if options.concurrency == 1:
            self.client.rate_limiter.requests_per_second = 1.0 / effective_interval
        else:
            cancel_event = getattr(self.client.rate_limiter, "cancel_event", None)
            self.client.rate_limiter = _ThreadSafeIntervalLimiter(effective_interval, cancel_event)

        result = {"type": "access-control", "mode": "bounded-write-range", "classification": "inconclusive",
                  "confirmed": False, "controls_valid": False, "steps": [], "results": [],
                  "requests_attempted": 0, "request_budget": len(requests) + 2,
                  "planned_probes": len(requests), "candidate_offset": None,
                  "stop_reason": None, "inverse_sent": False, "anonymous_sent": False,
                  "concurrency": options.concurrency, "minimum_interval_seconds": effective_interval,
                  "max_range": options.max_range, "local_lab": local_lab,
                  "concurrent_requests_not_evaluated": 0}

        for account, request in (("owner", case.owner), ("actor", case.actor)):
            response = self._send(request, result)
            if response is None:
                result["stop_reason"] = "transport_error"
                result["steps"].append({"step": account + "_control", "transport_error": True})
                return self._save(evidence_dir, result)
            facts = observations(response, case.checks)
            result["steps"].append({"step": account + "_control", **facts})
            valid = (200 <= response.status_code < 300 and not response.body_truncated and
                     facts["application_success"] is True and facts[f"{account}_resource_match"] and
                     facts[f"{account}_private_match"] and not facts[("actor" if account == "owner" else "owner") + "_marker_seen"])
            if not valid:
                result["stop_reason"] = "invalid_" + account + "_control"
                return self._save(evidence_dir, result)
            if account == "actor":
                result["controls_valid"] = True

        stop = False
        with ThreadPoolExecutor(max_workers=options.concurrency) as executor:
            for start in range(0, len(requests), options.concurrency):
                window = list(enumerate(requests[start:start + options.concurrency], start))
                futures = [(offset, executor.submit(self._send, request, result)) for offset, request in window]
                for offset, future in futures:
                    response = future.result()
                    if stop:
                        result["results"].append({"probe_offset": offset,
                                                  "status_code": response.status_code if response else None,
                                                  "duration_ms": response.duration_ms if response else None,
                                                  "classification": "sent_concurrently_not_evaluated",
                                                  "confirmed": False})
                        result["concurrent_requests_not_evaluated"] += 1
                        continue
                    if response is None:
                        result["steps"].append({"step": "cross_write", "transport_error": True})
                        result["results"].append({"probe_offset": offset, "status_code": None,
                                                  "classification": "inconclusive", "confirmed": False})
                        result["stop_reason"] = "transport_error"
                        stop = True
                        continue

                    facts = observations(response, case.checks)
                    identity_differs = self._identity_differs(case, response.body_text)
                    owner_proof = facts["owner_resource_match"] and facts["owner_private_match"]
                    returned_resource = self._resource_value(case, response.body_text)
                    resource_is_not_actor = (type(returned_resource) in {str, int} and returned_resource != "" and
                                             not exact(returned_resource, case.checks["actor_resource"]) and
                                             facts["application_success"] is True)
                    successful_write = 200 <= response.status_code < 300 and facts["application_success"] is True
                    candidate = (not response.body_truncated and successful_write and
                                 (owner_proof or identity_differs or resource_is_not_actor))
                    rejected = (response.status_code >= 400 or response.status_code in {401, 403} or
                                facts["application_success"] is False)
                    row = {"probe_offset": offset, "status_code": response.status_code,
                           "duration_ms": response.duration_ms, "body_size": response.body_size,
                           "body_truncated": response.body_truncated,
                           "application_success": facts["application_success"],
                           "owner_resource_match": facts["owner_resource_match"],
                           "owner_private_match": facts["owner_private_match"],
                           "identity_differs_from_actor": identity_differs,
                           "resource_differs_from_actor": resource_is_not_actor,
                           "classification": "candidate" if candidate else "rejected_in_this_test" if rejected else "inconclusive",
                           "confirmed": False}
                    result["steps"].append({"step": "cross_write", **facts,
                                            "identity_differs_from_actor": identity_differs})
                    result["results"].append(row)
                    if candidate:
                        result["candidate_offset"] = offset
                        result["classification"] = "candidate"
                        result["stop_reason"] = "candidate_observed_stop_early"
                        stop = True
                    elif response.status_code == 429:
                        result["stop_reason"] = "rate_limited"
                        stop = True
                    elif response.body_truncated:
                        result["stop_reason"] = "truncated_response"
                        stop = True
                    elif 300 <= response.status_code < 400:
                        result["stop_reason"] = "redirect_not_followed"
                        stop = True
                    elif rejected:
                        result["stop_reason"] = "write_probe_rejected"
                        stop = True
                if stop:
                    break
        if result["classification"] != "candidate" and result["stop_reason"] is None:
            completed = len(result["results"]) == len(requests)
            denied = all(row["classification"] == "rejected_in_this_test" for row in result["results"])
            result["classification"] = "rejected_in_this_test" if completed and denied else "inconclusive"
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
    def _identity_differs(case: AccessCase, body_text: str) -> bool:
        if case.identity_check is None:
            return False
        try:
            body = parse_json(body_text)
        except ValueError:
            return False
        observed = lookup(body, case.identity_check["pointer"])
        return isinstance(observed, str) and bool(observed) and observed != case.identity_check["actor_value"]

    @staticmethod
    def _resource_value(case: AccessCase, body_text: str):
        try:
            return lookup(parse_json(body_text), case.checks["resource_pointer"])
        except ValueError:
            return None

    @staticmethod
    def _save(evidence_dir: Path, result: dict):
        path = write_evidence_json(evidence_dir, result, prefix="access-write-range")
        return path, result
