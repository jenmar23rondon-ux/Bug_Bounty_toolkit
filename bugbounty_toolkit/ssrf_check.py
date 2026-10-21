from __future__ import annotations

import hashlib
import html
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import unquote, urlsplit

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


@dataclass(frozen=True)
class SsrfOptions:
    url: str
    parameter: str
    headers: dict[str, str] = field(default_factory=dict)


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
                    results.append(
                        {
                            "payload": payload,
                            "classification": "error",
                            "reason": type(exc).__name__,
                            "confirmed": False,
                        }
                    )
                    stop_reason = "transport_error"
                    break

                differs = _response_differs(baseline, response)
                reflected = _contains_payload(response.body_text, payload) and not _contains_payload(
                    baseline.body_text, payload
                )
                classification = (
                    "reflected"
                    if reflected
                    else "possible"
                    if differs
                    else "inconclusive"
                    if response.body_truncated
                    else "no_difference"
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
                        "classification": classification,
                        "confirmed": False,
                    }
                )
                if _access_stop(response):
                    stop_reason = "access_or_rate_limit"
                    break
                if response.body_truncated:
                    stop_reason = "truncated_response"
                    break

        has_signal = any(row.get("classification") in {"possible", "reflected"} for row in results)
        has_inconclusive = stop_reason is not None or any(
            row.get("classification") == "inconclusive" for row in results
        )
        evidence: dict[str, object] = {
            "type": "ssrf",
            "url": redact_url(options.url),
            "parameter": options.parameter,
            "requests_attempted": 1 + len(results),
            "baseline": baseline_result,
            "results": results,
            "classification": "possible" if has_signal else "inconclusive" if has_inconclusive else "not_observed",
            "confirmed": False,
            "stop_reason": stop_reason,
            "note": (
                "Heuristic only: response differences and reflections are not SSRF confirmation. "
                "Timing deltas are contextual only, response bodies and request credentials are omitted, "
                "and redirects are not followed. Confirm only with an explicitly authorized OOB method."
            ),
        }
        path = write_evidence_json(evidence_dir, evidence, prefix="ssrf")
        return path, evidence
