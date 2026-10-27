"""Open-redirect checks with confirmation bar.

confirmed only if the supplied parameter controls Location AND the destination
leaves the request host. Redirects are never followed. Without a controlled
external Location the result stays candidate.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import parse_qsl, urljoin, urlsplit, urlunsplit

from .core.checks import aggregate_finding_state, validate_rejection_reason
from .core.http_client import HttpClient, RequestSpec
from .core.redaction import redact_url
from .core.scope_validator import ScopeValidator
from .reporting.evidence import write_evidence_json
from .utils.exceptions import ToolkitError


REDIRECT_PAYLOADS = (
    "https://evil.com",
    "//evil.com",
    "/\\evil.com",
    "https:evil.com",
    "//evil.com/%2f..",
)
REDIRECT_STATUSES = {301, 302, 303, 307, 308}


def replace_query_parameter(url: str, parameter: str, value: str) -> str:
    parsed = urlsplit(url)
    pairs = parse_qsl(parsed.query, keep_blank_values=True)
    matches = sum(key == parameter for key, _ in pairs)
    if matches == 0:
        raise ValueError(f"Query parameter {parameter!r} is not present in the URL.")
    if matches != 1:
        raise ValueError(f"Query parameter {parameter!r} must appear exactly once.")
    query = [(key, value if key == parameter else current) for key, current in pairs]
    from urllib.parse import urlencode

    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, urlencode(query), ""))


def resolved_location(base_url: str, location: str) -> str:
    value = location.strip().replace("\\", "/")
    parts = urlsplit(value)
    if parts.scheme.lower() in {"http", "https"} and not parts.netloc and parts.path:
        value = f"{parts.scheme}://{parts.path.lstrip('/')}"
    return urljoin(base_url, value)


def _host(url: str) -> str:
    return (urlsplit(url).hostname or "").lower().rstrip(".")


def location_leaves_host(base_url: str, location: str) -> bool:
    base_host = _host(base_url)
    dest_host = _host(resolved_location(base_url, location))
    return bool(dest_host) and dest_host != base_host


def payload_controls_location(payload: str, location: str, base_url: str) -> bool:
    """True when the Location target reflects the injected external payload host."""
    dest = urlsplit(resolved_location(base_url, location))
    dest_host = (dest.hostname or "").lower().rstrip(".")
    payload_host = _host(payload if "://" in payload or payload.startswith("//") else f"https:{payload}")
    if not payload_host:
        # Protocol-relative / slash-trick payloads targeting evil.com
        if "evil.com" in payload.lower() and (dest_host == "evil.com" or dest_host.endswith(".evil.com")):
            return True
        return False
    return dest_host == payload_host or dest_host.endswith(f".{payload_host}")


def classify_redirect(base_url: str, location: str | None, status_code: int | None = None) -> str:
    if not location or (status_code is not None and status_code not in REDIRECT_STATUSES):
        return "NO VULNERABLE"
    target = urlsplit(resolved_location(base_url, location))
    host = (target.hostname or "").lower().rstrip(".")
    if host == "evil.com" or host.endswith(".evil.com"):
        return "VULNERABLE"
    return "NO VULNERABLE"


def assess_open_redirect(
    *,
    base_url: str,
    payload: str,
    location: str | None,
    status_code: int | None,
    rejection_reason: str | None = None,
    transport_error: bool = False,
) -> dict[str, object]:
    """Apply open-redirect confirmation bar."""
    if rejection_reason is not None:
        validate_rejection_reason(rejection_reason)
        return {
            "classification": "error" if transport_error else classify_redirect(base_url, location, status_code),
            "finding_state": "rejected",
            "confirmed": False,
            "param_controls_location": False,
            "destination_leaves_host": False,
            "confirmation_gap": None,
            "rejection_reason": rejection_reason,
        }
    if transport_error or status_code in {401, 403, 429}:
        return {
            "classification": "error" if transport_error else classify_redirect(base_url, location, status_code),
            "finding_state": "inconclusive",
            "confirmed": False,
            "param_controls_location": False,
            "destination_leaves_host": False,
            "confirmation_gap": None,
            "rejection_reason": None,
        }
    classification = classify_redirect(base_url, location, status_code)
    if not location or status_code not in REDIRECT_STATUSES:
        return {
            "classification": classification,
            "finding_state": "not_observed",
            "confirmed": False,
            "param_controls_location": False,
            "destination_leaves_host": False,
            "confirmation_gap": None,
            "rejection_reason": None,
        }
    controlled = payload_controls_location(payload, location, base_url)
    leaves = location_leaves_host(base_url, location)
    if controlled and leaves:
        return {
            "classification": classification,
            "finding_state": "confirmed",
            "confirmed": True,
            "param_controls_location": True,
            "destination_leaves_host": True,
            "confirmation_gap": None,
            "rejection_reason": None,
        }
    if leaves or controlled or classification == "VULNERABLE":
        return {
            "classification": classification,
            "finding_state": "candidate",
            "confirmed": False,
            "param_controls_location": controlled,
            "destination_leaves_host": leaves,
            "confirmation_gap": "no_second_proof",
            "rejection_reason": None,
        }
    return {
        "classification": classification,
        "finding_state": "not_observed",
        "confirmed": False,
        "param_controls_location": False,
        "destination_leaves_host": False,
        "confirmation_gap": None,
        "rejection_reason": None,
    }


@dataclass(frozen=True)
class OpenRedirectOptions:
    url: str
    parameter: str
    headers: dict[str, str] = field(default_factory=dict)


class OpenRedirectTester:
    def __init__(self, scope: ScopeValidator, client: HttpClient):
        self.scope = scope
        self.client = client

    def validate(self, options: OpenRedirectOptions) -> list[str]:
        parsed = urlsplit(options.url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ValueError("Open-redirect checks require an absolute HTTP(S) URL.")
        if not options.parameter.strip():
            raise ValueError("Parameter name cannot be empty.")
        self.scope.require(options.url)
        return [replace_query_parameter(options.url, options.parameter, payload) for payload in REDIRECT_PAYLOADS]

    def run(self, options: OpenRedirectOptions, evidence_dir: Path) -> tuple[Path, list[dict[str, object]]]:
        urls = self.validate(options)
        results: list[dict[str, object]] = []
        stop_reason = None
        for payload, request_url in zip(REDIRECT_PAYLOADS, urls):
            try:
                response = self.client.send(RequestSpec("GET", request_url, options.headers))
            except (ToolkitError, ValueError) as exc:
                assessment = assess_open_redirect(
                    base_url=options.url,
                    payload=payload,
                    location=None,
                    status_code=None,
                    transport_error=True,
                )
                results.append(
                    {
                        "payload": payload,
                        "classification": "error",
                        "reason": type(exc).__name__,
                        "finding_state": assessment["finding_state"],
                        "confirmed": False,
                        "param_controls_location": False,
                        "destination_leaves_host": False,
                        "confirmation_gap": assessment["confirmation_gap"],
                        "rejection_reason": assessment["rejection_reason"],
                    }
                )
                stop_reason = "transport_error"
                break
            location = response.headers.get("location")
            assessment = assess_open_redirect(
                base_url=options.url,
                payload=payload,
                location=location,
                status_code=response.status_code,
            )
            results.append(
                {
                    "payload": payload,
                    "status_code": response.status_code,
                    "location": redact_url(resolved_location(options.url, location)) if location else None,
                    "classification": assessment["classification"],
                    "finding_state": assessment["finding_state"],
                    "confirmed": assessment["confirmed"],
                    "param_controls_location": assessment["param_controls_location"],
                    "destination_leaves_host": assessment["destination_leaves_host"],
                    "confirmation_gap": assessment["confirmation_gap"],
                    "rejection_reason": assessment["rejection_reason"],
                    "duration_ms": response.duration_ms,
                }
            )
            if response.status_code in {401, 403, 429}:
                stop_reason = "access_or_rate_limit"
                break
        overall = aggregate_finding_state(
            [str(row.get("finding_state") or "") for row in results], stop_reason=stop_reason
        )
        path = write_evidence_json(
            evidence_dir,
            {
                "type": "open-redirect",
                "url": redact_url(options.url),
                "parameter": options.parameter,
                "requests_attempted": len(results),
                "stop_reason": stop_reason,
                "results": results,
                "classification": overall,
                "finding_state": overall,
                "confirmed": overall == "confirmed",
                "note": (
                    "Redirects are not followed. confirmed requires parameter-controlled Location "
                    "leaving the host; otherwise candidate. Evidence omits credentials and bodies."
                ),
            },
            prefix="open-redirect",
        )
        return path, results
