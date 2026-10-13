from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from ..core.http_client import HttpClient, RequestSpec
from ..core.scope_validator import ScopeValidator
from ..core.target import load_routes
from ..core.redaction import redact_text, redact_url
from ..utils.exceptions import ToolkitError
from ..reporting.evidence import write_evidence_json
from ..requests_engine.parameters import load_parameter_names
from .reflection_detector import detect_reflection
from .result_validator import classify_reflection
from .test_cases import new_marker, payloads_for_marker


@dataclass(frozen=True)
class XssOptions:
    routes_file: Path
    parameters_file: Path
    base_url: str | None = None
    max_tests: int = 100
    headers: dict[str, str] = field(default_factory=dict)


class XssParameterTester:
    def __init__(self, scope: ScopeValidator, client: HttpClient):
        self.scope = scope
        self.client = client

    def run(self, options: XssOptions, evidence_dir: Path) -> tuple[Path, list[dict[str, object]]]:
        routes, parameters = self.validate(options)

        results: list[dict[str, object]] = []
        test_count = 0
        for route in routes:
            for parameter in parameters:
                marker = new_marker()
                for payload in payloads_for_marker(marker):
                    if test_count >= options.max_tests:
                        path = write_evidence_json(evidence_dir, {"type": "xss", "results": results}, prefix="xss")
                        return path, results
                    test_count += 1
                    spec = RequestSpec(method="GET", url=with_parameter(route, parameter, payload), headers=options.headers)
                    try:
                        response = self.client.send(spec)
                    except ToolkitError as exc:
                        results.append({"route": redact_url(route), "method": "GET", "parameter": parameter,
                                        "payload": payload, "classification": "error", "confirmed": False, "reason": str(exc)})
                        continue
                    reflection = detect_reflection(response.body_text, marker=marker, payload=payload)
                    validation = classify_reflection(reflection, response.headers.get("content-type", ""))
                    results.append(
                        {
                            "route": redact_url(route),
                            "method": "GET",
                            "parameter": parameter,
                            "payload": payload,
                            "status_code": response.status_code,
                            "duration_ms": response.duration_ms,
                            "classification": validation["classification"],
                            "confirmed": validation["confirmed"],
                            "reason": validation["reason"],
                            "reflected": reflection.reflected,
                            "reflected_unescaped": reflection.reflected_unescaped,
                            "reflection_context": redact_text(reflection.context),
                            "body_truncated": response.body_truncated,
                            "exchange": response.to_dict(),
                        }
                    )
        path = write_evidence_json(evidence_dir, {"type": "xss", "results": results}, prefix="xss")
        return path, results

    def validate(self, options: XssOptions) -> tuple[list[str], list[str]]:
        if options.max_tests <= 0:
            raise ValueError("Max tests must be positive.")
        routes = load_routes(options.routes_file, base_url=options.base_url)
        parameters = load_parameter_names(options.parameters_file)
        if not routes or not parameters:
            raise ValueError("Routes and parameters must contain at least one usable entry.")
        self.scope.require_all(routes)
        return routes, parameters


def with_parameter(url: str, name: str, value: str) -> str:
    parsed = urlparse(url)
    query = [(key, current) for key, current in parse_qsl(parsed.query, keep_blank_values=True) if key != name]
    query.append((name, value))
    return urlunparse((parsed.scheme, parsed.netloc, parsed.path or "/", "", urlencode(query), parsed.fragment))
