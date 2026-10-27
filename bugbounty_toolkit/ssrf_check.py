"""SSRF heuristic checks with confirmation bar.

confirmed only when a lab loopback canary received the outbound request for a
payload. A URL-looking parameter, response difference, or reflection alone is
candidate / not_observed — never confirmed. Redirects are not followed.
"""

from __future__ import annotations

import hashlib
import html
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import unquote, urlsplit

from .core.checks import aggregate_finding_state, validate_rejection_reason
from .core.http_client import HttpClient, RequestSpec, ResponseRecord
from .core.redaction import redact_url
from .core.scope_validator import ScopeValidator
from .open_redirect import replace_query_parameter
from .reporting.evidence import write_evidence_json
from .utils.exceptions import ToolkitError


SSRF_PAYLOADS = (
    "http://127.0.0.1:80",
    "http://127.0.0.1:22",
    "http://127.0.0.1:8080",
    "http://169.254.169.254/latest/meta-data/",
    "http://[::1]",
)
STOP_STATUSES = {401, 403, 429}
# Marker a lab canary may echo; never proves SSRF by itself without canary_hits.
LAB_CANARY_MARKER = "bbtk_ssrf_canary"


@dataclass(frozen=True)
class SsrfOptions:
    url: str
    parameter: str
    headers: dict[str, str] = field(default_factory=dict)
    # Payloads for which the offline/synthetic lab canary recorded a hit.
    lab_canary_hits: frozenset[str] = field(default_factory=frozenset)


def _fingerprint(response: ResponseRecord) -> str:
    return hashlib.sha256(response.body_text.encode("utf-8", errors="replace")).hexdigest()


def _response_differs(baseline: ResponseRecord, response: ResponseRecord) -> bool:
    return response.status_code != baseline.status_code or (
        not baseline.body_truncated
        and not response.body_truncated
        and (response.body_size != baseline.body_size or _fingerprint(response) != _fingerprint(baseline))
    )


def _contains_payload(body: str, payload: str) -> bool:
    normalized = html.unescape(unquote(body)).replace("\\/", "/").lower()
    return payload.lower() in normalized


def _response_summary(response: ResponseRecord) -> dict[str, object]:
    return {
        "status_code": response.status_code,
        "duration_ms": response.duration_ms,
        "body_size": response.body_size,
        "body_fingerprint": _fingerprint(response),
        "body_truncated": response.body_truncated,
    }


def _access_stop(response: ResponseRecord) -> bool:
    return response.status_code in STOP_STATUSES


def assess_ssrf_finding(
    *,
    payload: str,
    response_differs: bool,
    payload_reflected: bool,
    canary_received: bool,
    body_truncated: bool = False,
    rejection_reason: str | None = None,
    transport_error: bool = False,
) -> dict[str, object]:
    """SSRF confirmation bar: canary hit → confirmed; else signal → candidate."""
    if rejection_reason is not None:
        validate_rejection_reason(rejection_reason)
        return {
            "classification": "error" if transport_error else "possible" if response_differs else "no_difference",
            "finding_state": "rejected",
            "confirmed": False,
            "canary_received": False,
            "confirmation_gap": None,
            "rejection_reason": rejection_reason,
        }
    if transport_error:
        return {
            "classification": "error",
            "finding_state": "inconclusive",
            "confirmed": False,
            "canary_received": False,
            "confirmation_gap": None,
            "rejection_reason": None,
        }
    if canary_received:
        return {
            "classification": "confirmed",
            "finding_state": "confirmed",
            "confirmed": True,
            "canary_received": True,
            "confirmation_gap": None,
            "rejection_reason": None,
        }
    if payload_reflected:
        classification = "reflected"
    elif response_differs:
        classification = "possible"
    elif body_truncated:
        classification = "inconclusive"
    else:
        classification = "no_difference"
    if classification in {"possible", "reflected"}:
        return {
            "classification": classification,
            "finding_state": "candidate",
            "confirmed": False,
            "canary_received": False,
            "confirmation_gap": "no_second_proof",
            "rejection_reason": None,
        }
    if classification == "inconclusive":
        return {
            "classification": classification,
            "finding_state": "inconclusive",
            "confirmed": False,
            "canary_received": False,
            "confirmation_gap": None,
            "rejection_reason": None,
        }
    return {
        "classification": classification,
        "finding_state": "not_observed",
        "confirmed": False,
        "canary_received": False,
        "confirmation_gap": None,
        "rejection_reason": None,
    }


class SsrfChecker:
    def __init__(self, scope: ScopeValidator, client: HttpClient):
        self.scope = scope
        self.client = client

    def validate(self, options: SsrfOptions) -> list[str]:
        parsed = urlsplit(options.url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ValueError("SSRF checks require an absolute HTTP(S) URL.")
        if not options.parameter.strip():
            raise ValueError("Parameter name cannot be empty.")
        self.scope.require(options.url)
        urls = [replace_query_parameter(options.url, options.parameter, payload) for payload in SSRF_PAYLOADS]
        for url in urls:
            self.scope.require(url)
        return urls

    def run(self, options: SsrfOptions, evidence_dir: Path) -> tuple[Path, dict[str, object]]:
        urls = self.validate(options)
        results: list[dict[str, object]] = []
        stop_reason: str | None = None
        baseline: ResponseRecord | None = None

        try:
            baseline = self.client.send(RequestSpec("GET", options.url, options.headers))
        except (ToolkitError, ValueError) as exc:
            stop_reason = "transport_error"
            baseline_result: dict[str, object] = {"classification": "error", "reason": type(exc).__name__}
        else:
            baseline_result = _response_summary(baseline)
            baseline_result["classification"] = "baseline"
            if _access_stop(baseline):
                stop_reason = "access_or_rate_limit"
            elif baseline.body_truncated:
                stop_reason = "truncated_response"

        if baseline is not None and stop_reason is None:
            for payload, request_url in zip(SSRF_PAYLOADS, urls):
                try:
                    response = self.client.send(RequestSpec("GET", request_url, options.headers))
                except (ToolkitError, ValueError) as exc:
                    assessment = assess_ssrf_finding(
                        payload=payload,
                        response_differs=False,
                        payload_reflected=False,
                        canary_received=False,
                        transport_error=True,
                    )
                    results.append(
                        {
                            "payload": payload,
                            "classification": "error",
                            "reason": type(exc).__name__,
                            "finding_state": assessment["finding_state"],
                            "confirmed": False,
                            "canary_received": False,
                            "confirmation_gap": assessment["confirmation_gap"],
                            "rejection_reason": assessment["rejection_reason"],
                        }
                    )
                    stop_reason = "transport_error"
                    break

                differs = _response_differs(baseline, response)
                reflected = _contains_payload(response.body_text, payload) and not _contains_payload(
                    baseline.body_text, payload
                )
                canary_received = payload in options.lab_canary_hits
                assessment = assess_ssrf_finding(
                    payload=payload,
                    response_differs=differs,
                    payload_reflected=reflected,
                    canary_received=canary_received,
                    body_truncated=response.body_truncated,
                )
                results.append(
                    {
                        "payload": payload,
                        "status_code": response.status_code,
                        "duration_ms": response.duration_ms,
                        "timing_delta_ms": response.duration_ms - baseline.duration_ms,
                        "body_size": response.body_size,
                        "body_fingerprint": _fingerprint(response),
                        "body_truncated": response.body_truncated,
                        "response_differs": differs,
                        "payload_reflected": reflected,
                        "classification": assessment["classification"],
                        "finding_state": assessment["finding_state"],
                        "confirmed": assessment["confirmed"],
                        "canary_received": canary_received,
                        "confirmation_gap": assessment["confirmation_gap"],
                        "rejection_reason": assessment["rejection_reason"],
                    }
                )
                if _access_stop(response):
                    stop_reason = "access_or_rate_limit"
                    break
                if response.body_truncated:
                    stop_reason = "truncated_response"
                    break

        overall = aggregate_finding_state(
            [str(row.get("finding_state") or "") for row in results], stop_reason=stop_reason
        )
        # Preserve legacy top-level labels for callers that expect possible/not_observed.
        legacy = (
            "confirmed"
            if overall == "confirmed"
            else "possible"
            if overall == "candidate"
            else "inconclusive"
            if overall == "inconclusive"
            else "not_observed"
        )
        evidence: dict[str, object] = {
            "type": "ssrf",
            "url": redact_url(options.url),
            "parameter": options.parameter,
            "requests_attempted": 1 + len(results),
            "baseline": baseline_result,
            "results": results,
            "classification": legacy,
            "finding_state": overall,
            "confirmed": overall == "confirmed",
            "stop_reason": stop_reason,
            "note": (
                "URL-looking parameters, response differences and reflections are candidates only. "
                "confirmed requires a lab loopback canary hit for the payload. "
                "Bodies and credentials are omitted; redirects are not followed."
            ),
        }
        path = write_evidence_json(evidence_dir, evidence, prefix="ssrf")
        return path, evidence
