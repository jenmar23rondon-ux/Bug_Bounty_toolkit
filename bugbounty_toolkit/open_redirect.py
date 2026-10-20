from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import parse_qsl, urljoin, urlsplit, urlunsplit

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


def classify_redirect(base_url: str, location: str | None, status_code: int | None = None) -> str:
    if not location or (status_code is not None and status_code not in REDIRECT_STATUSES):
        return "NO VULNERABLE"
    target = urlsplit(resolved_location(base_url, location))
    host = (target.hostname or "").lower().rstrip(".")
    if host == "evil.com" or host.endswith(".evil.com"):
        return "VULNERABLE"
    return "NO VULNERABLE"


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
                results.append({"payload": payload, "classification": "error",
                                "reason": type(exc).__name__, "confirmed": False})
                stop_reason = "transport_error"
                break
            location = response.headers.get("location")
            classification = classify_redirect(options.url, location, response.status_code)
            results.append({
                "payload": payload,
                "status_code": response.status_code,
                "location": redact_url(resolved_location(options.url, location)) if location else None,
                "classification": classification,
                "confirmed": classification == "VULNERABLE",
                "duration_ms": response.duration_ms,
            })
            if response.status_code in {401, 403, 429}:
                stop_reason = "access_or_rate_limit"
                break
        path = write_evidence_json(evidence_dir, {
            "type": "open-redirect", "url": redact_url(options.url), "parameter": options.parameter,
            "requests_attempted": len(results), "stop_reason": stop_reason, "results": results,
            "note": "Redirects are not followed. Evidence omits request credentials and response bodies.",
        }, prefix="open-redirect")
        return path, results
