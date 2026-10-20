from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit

from .core.http_client import HttpClient, RequestSpec
from .core.redaction import redact_url
from .core.scope_validator import ScopeValidator
from .reporting.evidence import write_evidence_json
from .utils.exceptions import ToolkitError


def origins_for_target(url: str) -> list[str]:
    host = urlsplit(url).hostname
    if not host:
        raise ValueError("URL must include a hostname.")
    return list(dict.fromkeys((
        "https://evil.com",
        "null",
        f"https://evil.{host}",
        f"https://{host}.evil.com",
    )))


def classify_cors(origin: str, allow_origin: str | None, allow_credentials: str | None) -> str:
    if allow_origin is None or allow_origin.strip() == "*":
        return "SEGURO"
    if allow_origin.strip() != origin:
        return "SEGURO"
    return "VULNERABLE" if (allow_credentials or "").strip().lower() == "true" else "DÉBIL"


@dataclass(frozen=True)
class CorsOptions:
    url: str
    headers: dict[str, str] = field(default_factory=dict)


class CorsChecker:
    def __init__(self, scope: ScopeValidator, client: HttpClient):
        self.scope = scope
        self.client = client

    def validate(self, options: CorsOptions) -> list[str]:
        parsed = urlsplit(options.url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ValueError("CORS checks require an absolute HTTP(S) URL.")
        self.scope.require(options.url)
        return origins_for_target(options.url)

    def run(self, options: CorsOptions, evidence_dir: Path) -> tuple[Path, list[dict[str, object]]]:
        origins = self.validate(options)
        results: list[dict[str, object]] = []
        stop_reason = None
        for origin in origins:
            headers = {key: value for key, value in options.headers.items() if key.lower() != "origin"}
            headers["Origin"] = origin
            try:
                response = self.client.send(RequestSpec("GET", options.url, headers))
            except (ToolkitError, ValueError) as exc:
                results.append({"origin": origin, "classification": "error",
                                "reason": type(exc).__name__, "confirmed": False})
                stop_reason = "transport_error"
                break
            allow_origin = response.headers.get("access-control-allow-origin")
            allow_credentials = response.headers.get("access-control-allow-credentials")
            classification = classify_cors(origin, allow_origin, allow_credentials)
            results.append({
                "origin": origin,
                "status_code": response.status_code,
                "access_control_allow_origin": allow_origin,
                "access_control_allow_credentials": allow_credentials,
                "classification": classification,
                "confirmed": classification == "VULNERABLE",
                "duration_ms": response.duration_ms,
            })
            if response.status_code in {401, 403, 429}:
                stop_reason = "access_or_rate_limit"
                break
        evidence = {"type": "cors", "url": redact_url(options.url), "requests_attempted": len(results),
                   "stop_reason": stop_reason, "results": results,
                   "note": "Only Origin and CORS response headers are recorded; request credentials and response bodies are omitted."}
        path = write_evidence_json(evidence_dir, evidence, prefix="cors")
        return path, results
