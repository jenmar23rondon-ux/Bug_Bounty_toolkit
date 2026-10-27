from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from urllib.request import ProxyHandler, build_opener

from ..core.http_client import HttpClient, NoRedirects, RequestSpec, ResponseRecord
from ..core.scope_validator import ScopeValidator
from ..reporting.evidence import write_evidence_json
from ..utils.exceptions import ToolkitError
from .comparison import (
    AccessAccount,
    AccessCase,
    AccessControlTester,
    MISSING,
    account_observations,
    load_case,
    lookup,
    parse_json,
    replace_pointer,
)
from .guards import is_loopback_url


class AccessWriteLabTester(AccessControlTester):
    """Execute bounded, disposable JSON write comparisons with explicit cleanup options."""

    def __init__(self, scope: ScopeValidator, client: HttpClient, allow_public_writes: bool = False):
        super().__init__(scope, client)
        if type(allow_public_writes) is not bool:
            raise ValueError("allow_public_writes must be a boolean.")
        self.allow_public_writes = allow_public_writes

    @staticmethod
    def write_request_count(
        verify_persistence: bool = False, inverse_write: bool = False, cleanup: bool = False
    ) -> int:
        cleanup_requests = 2 * (1 + int(inverse_write)) if cleanup else 0
        return 3 + int(verify_persistence) + int(inverse_write) + cleanup_requests

    def validate(
        self,
        case_file: Path,
        max_tests: int = 3,
        verify_persistence: bool = False,
        inverse_write: bool = False,
        cleanup: bool = False,
    ) -> AccessCase:
        """Validate write-mode flags, disposable resources, scope and request budget."""
        if any(type(flag) is not bool for flag in (verify_persistence, inverse_write, cleanup)):
            raise ValueError("Write-lab mode flags must be booleans.")
        required = self.write_request_count(verify_persistence, inverse_write, cleanup)
        if type(max_tests) is not int or max_tests < required:
            raise ValueError(f"This write-lab mode requires a budget of at least {required} requests.")
        case = load_case(
            case_file,
            self.scope,
            allow_lab_writes=True,
            verify_persistence=verify_persistence,
            cleanup=cleanup,
            inverse_write=inverse_write,
        )
        if case.mode != "lab-write":
            raise ValueError("Use a declared JSON body resource pointer for lab write checks.")
        writes = [case.owner, case.actor, case.cross]
        if verify_persistence and case.persistence_request is not None:
            self.scope.require(case.persistence_request.prepared_url())
        if cleanup:
            assert case.cleanup_request is not None
            self.scope.require(case.cleanup_request.prepared_url())
            if inverse_write:
                assert case.cleanup_actor_request is not None
                self.scope.require(case.cleanup_actor_request.prepared_url())
        if not self.allow_public_writes and not all(is_loopback_url(request.prepared_url()) for request in writes):
            raise ValueError("Automated write comparisons are restricted to localhost or loopback IPs.")
        return case

    def run(
        self,
        case_file: Path,
        evidence_dir: Path,
        max_tests: int = 3,
        verify_persistence: bool = False,
        inverse_write: bool = False,
        cleanup: bool = False,
    ) -> tuple[Path, dict[str, Any]]:
        """Run write controls/crosses and save minimized result predicates."""
        case = self.validate(case_file, max_tests, verify_persistence, inverse_write, cleanup)
        required = self.write_request_count(verify_persistence, inverse_write, cleanup)
        if all(is_loopback_url(request.prepared_url()) for request in (case.owner, case.actor, case.cross)):
            self.client.opener = build_opener(ProxyHandler({}), NoRedirects())
        result: dict[str, Any] = {
            "type": "access-control",
            "mode": "lab-write",
            "classification": "inconclusive",
            "confirmed": False,
            "controls_valid": False,
            "requests_attempted": 0,
            "request_budget": required,
            "steps": [],
            "stop_reason": None,
            "inverse_sent": False,
            "persistence_verified": False,
            "cleanup_requested": cleanup,
            "cleanup_success": None,
            "write_effect_verified": False,
        }
        if cleanup:
            result["cleanup_status"] = "not_run"
            result["cleanup_verified"] = False
        accounts = case.accounts[:2]

        def send(label: str, request: RequestSpec) -> ResponseRecord | None:
            result["requests_attempted"] += 1
            try:
                return self.client.send(request)
            except (ToolkitError, ValueError):
                result["steps"].append({"step": label, "transport_error": True})
                result["stop_reason"] = "transport_error"
                return None

        def blocked(response: ResponseRecord) -> str | None:
            if response.status_code == 429:
                return "rate_limited"
            if response.body_truncated:
                return "truncated_response"
            if 300 <= response.status_code < 400:
                return "redirect_not_followed"
            return None

        def write_facts(response: ResponseRecord, target: AccessAccount) -> dict[str, Any]:
            return account_observations(response, case.checks, target.resource, target.marker)

        def write_verdict(response: ResponseRecord, target: AccessAccount) -> tuple[str, dict[str, Any]]:
            facts = write_facts(response, target)
            if blocked(response):
                verdict = "inconclusive"
            elif facts["resource_match"] and facts["private_match"]:
                verdict = "candidate"
            elif response.status_code in {401, 403} or facts["application_success"] is False:
                verdict = "rejected_in_this_test"
            else:
                verdict = "inconclusive"
            return verdict, facts

        controls_valid = True
        for account in accounts:
            label = account.name + "_control"
            response = send(label, account.request)
            if response is None:
                controls_valid = False
                break
            facts = write_facts(response, account)
            result["steps"].append({"step": label, **facts})
            if blocked(response):
                result["stop_reason"] = blocked(response)
                controls_valid = False
                break
            other = accounts[1] if account.name == "owner" else accounts[0]
            valid = (
                200 <= response.status_code < 300
                and facts["application_success"] is True
                and facts["resource_match"]
                and facts["private_match"]
                and other.marker not in response.body_text
            )
            if not valid:
                result["stop_reason"] = "invalid_" + label
                controls_valid = False
                break
        result["controls_valid"] = controls_valid
        if not controls_valid:
            path = write_evidence_json(evidence_dir, result, prefix="access-control")
            return path, result

        cross_request = case.cross
        if verify_persistence:
            assert case.cross.body is not None and case.persistence_body_pointer is not None
            cross_body = parse_json(
                case.cross.body.decode("utf-8") if isinstance(case.cross.body, bytes) else case.cross.body
            )
            cross_body = replace_pointer(cross_body, case.persistence_body_pointer, case.persistence_value)
            cross_request = RequestSpec(
                case.cross.method,
                case.cross.prepared_url(),
                dict(case.cross.headers),
                body=json.dumps(cross_body, ensure_ascii=False, separators=(",", ":")),
            )
        cross_attempted = True
        cross_response = send("cross_write", cross_request)
        if cross_response is None:
            result["classification"] = "inconclusive"
        else:
            cross_verdict, cross_facts = write_verdict(cross_response, accounts[0])
            result["steps"].append({"step": "cross_write", **cross_facts})
            result["cross_result"] = cross_verdict
            result["classification"] = cross_verdict
            result["stop_reason"] = blocked(cross_response)
            if cross_verdict == "candidate":
                result["stop_reason"] = result["stop_reason"] or "private_evidence_observed"

        if verify_persistence and cross_attempted and result["stop_reason"] != "rate_limited":
            assert case.persistence_body_pointer is not None and case.persistence_response_pointer is not None
            assert case.persistence_request is not None
            readback = case.persistence_request
            if readback is not None:
                response = send("verify_persistence", readback)
                if response is not None:
                    facts = write_facts(response, accounts[0])
                    result["steps"].append({"step": "verify_persistence", **facts})
                    owner_before = lookup(case.owner_body, case.persistence_body_pointer)
                    attempted_value = case.persistence_value
                    observed_body = self._response_json(response.body_text)
                    observed_value = lookup(observed_body, case.persistence_response_pointer)
                    verified = (
                        response.status_code == 200
                        and not response.body_truncated
                        and facts["application_success"] is True
                        and facts["resource_match"]
                        and facts["private_match"]
                        and owner_before is not MISSING
                        and attempted_value is not MISSING
                        and observed_value is not MISSING
                        and exact_json_value(observed_value, attempted_value)
                        and not exact_json_value(attempted_value, owner_before)
                    )
                    result["persistence_verified"] = bool(verified)
                    result["write_effect_verified"] = bool(verified)
                    result["persistence_result"] = (
                        "write_confirmed_persisted"
                        if verified
                        else "write_not_persisted"
                        if facts["resource_match"] and facts["private_match"]
                        else "inconclusive"
                    )
                    if verified:
                        result["classification"] = "write_confirmed_persisted"
                        result["finding_state"] = "confirmed"
                        result["confirmed"] = True
                    elif result["classification"] == "candidate":
                        result["classification"] = result["persistence_result"]
                    result["stop_reason"] = blocked(response) or result["stop_reason"]

        inverse_attempted = False
        if inverse_write and result["stop_reason"] not in {
            "rate_limited",
            "truncated_response",
            "redirect_not_followed",
            "transport_error",
        }:
            assert case.body_pointer is not None and case.owner_body is not None
            inverse_body = replace_pointer(case.owner_body, case.body_pointer, case.checks["actor_resource"])
            if verify_persistence:
                assert case.persistence_body_pointer is not None
                inverse_body = replace_pointer(inverse_body, case.persistence_body_pointer, case.persistence_value)
            inverse = RequestSpec(
                case.owner.method,
                case.actor.prepared_url(),
                dict(case.owner.headers),
                body=json.dumps(inverse_body, ensure_ascii=False, separators=(",", ":")),
            )
            self.scope.require(inverse.prepared_url())
            inverse_attempted = True
            inverse_response = send("inverse_write", inverse)
            result["inverse_sent"] = True
            if inverse_response is not None:
                verdict, facts = write_verdict(inverse_response, accounts[1])
                result["steps"].append({"step": "inverse_write", **facts})
                result["inverse_result"] = verdict
                result["bidirectional_write_candidate"] = (
                    result.get("cross_result") == "candidate" and verdict == "candidate"
                )
                result["stop_reason"] = blocked(inverse_response) or result["stop_reason"]
            else:
                result["inverse_result"] = "inconclusive"

        if cleanup and cross_attempted:
            cleanup_pairs = [(accounts[0], case.cleanup_request, case.cleanup_original_value)]
            if inverse_attempted:
                cleanup_pairs.append((accounts[1], case.cleanup_actor_request, case.cleanup_actor_original_value))
            cleanup_results: list[dict[str, Any]] = []
            for account, readback_request, original_value in cleanup_pairs:
                assert readback_request is not None
                if result["stop_reason"] == "rate_limited":
                    cleanup_results.append({"resource_owner": account.name, "classification": "cleanup_unconfirmed"})
                    continue
                self.scope.require(account.request.prepared_url())
                restore = send("cleanup_restore_" + account.name, account.request)
                restore_ok = False
                if restore is not None:
                    facts = write_facts(restore, account)
                    result["steps"].append({"step": "cleanup_restore_" + account.name, **facts})
                    restore_ok = (
                        200 <= restore.status_code < 300
                        and not restore.body_truncated
                        and facts["application_success"] is True
                        and facts["resource_match"]
                        and facts["private_match"]
                    )
                if restore is not None and restore.status_code == 429:
                    result["stop_reason"] = "rate_limited"
                    cleanup_results.append(
                        {
                            "resource_owner": account.name,
                            "restore_status_code": restore.status_code,
                            "classification": "cleanup_failed",
                        }
                    )
                    break
                self.scope.require(readback_request.prepared_url())
                cleanup_response = send("cleanup_verify_" + account.name, readback_request)
                cleanup_classification = "cleanup_unconfirmed"
                row: dict[str, Any] = {"resource_owner": account.name}
                if restore is not None:
                    row["restore_status_code"] = restore.status_code
                if cleanup_response is not None:
                    row["readback_status_code"] = cleanup_response.status_code
                    readback_facts = write_facts(cleanup_response, account)
                    result["steps"].append({"step": "cleanup_verify_" + account.name, **readback_facts})
                    observed = lookup(
                        self._response_json(cleanup_response.body_text), case.cleanup_response_pointer or ""
                    )
                    readback_valid = (
                        cleanup_response.status_code == 200
                        and not cleanup_response.body_truncated
                        and readback_facts["application_success"] is True
                        and readback_facts["resource_match"]
                        and readback_facts["private_match"]
                        and observed is not MISSING
                    )
                    if readback_valid and observed is not MISSING and not exact_json_value(observed, original_value):
                        cleanup_classification = "cleanup_failed"
                    elif restore_ok and readback_valid:
                        cleanup_classification = "cleanup_confirmed"
                    elif not restore_ok:
                        cleanup_classification = "cleanup_failed"
                    if blocked(cleanup_response) == "rate_limited":
                        result["stop_reason"] = "rate_limited"
                elif not restore_ok:
                    cleanup_classification = "cleanup_failed"
                row["classification"] = cleanup_classification
                cleanup_results.append(row)
                if result["stop_reason"] == "rate_limited":
                    break
            result["cleanup_results"] = cleanup_results
            classifications = [row["classification"] for row in cleanup_results]
            if "cleanup_failed" in classifications:
                result["cleanup_status"] = "cleanup_failed"
            elif "cleanup_unconfirmed" in classifications or len(classifications) != len(cleanup_pairs):
                result["cleanup_status"] = "cleanup_unconfirmed"
            elif classifications and all(value == "cleanup_confirmed" for value in classifications):
                result["cleanup_status"] = "cleanup_confirmed"
            result["cleanup_verified"] = result["cleanup_status"] == "cleanup_confirmed"
            result["cleanup_success"] = result["cleanup_verified"]
            result["cleanup_verification"] = "final GET compared the captured original value"

        path = write_evidence_json(evidence_dir, result, prefix="access-control")
        return path, result

    @staticmethod
    def _response_json(body_text: str) -> Any:
        try:
            return parse_json(body_text)
        except ValueError:
            return None


def exact_json_value(left: Any, right: Any) -> bool:
    return type(left) is type(right) and left == right
