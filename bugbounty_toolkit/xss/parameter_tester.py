from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from ..core.http_client import HttpClient, RequestSpec
from ..core.scope_validator import ScopeValidator
from ..core.target import load_routes
from ..core.redaction import redact_text, redact_url
from ..utils.exceptions import ToolkitError
from ..reporting.evidence import write_evidence_json
from ..requests_engine.parameters import load_parameter_names, with_parameter
from ..analysis.html_context import analyze_html
from .reflection_detector import detect_reflection
from .result_validator import classify_reflection
from .test_cases import new_marker, payload_cases_for_marker
from .playwright_confirm import PlaywrightExecutionChecker, require_playwright_installed


@dataclass(frozen=True)
class XssOptions:
    routes_file: Path
    parameters_file: Path
    base_url: str | None = None
    max_tests: int = 100
    headers: dict[str, str] = field(default_factory=dict)
    html_parser: str = "html.parser"
    confirm_exec: bool = False


class XssParameterTester:
    def __init__(self, scope: ScopeValidator, client: HttpClient):
        self.scope = scope
        self.client = client

    def run(self, options: XssOptions, evidence_dir: Path) -> tuple[Path, list[dict[str, object]]]:
        routes, parameters = self.validate(options)
        if options.confirm_exec:
            require_playwright_installed()
        checker = (
            PlaywrightExecutionChecker(
                self.scope,
                timeout_ms=int(self.client.timeout * 1000),
                rate_limiter=self.client.rate_limiter,
                execution_budget=self.client.execution_budget,
            )
            if options.confirm_exec
            else None
        )

        results: list[dict[str, object]] = []
        test_count = 0
        try:
            for route in routes:
                for parameter in parameters:
                    marker = new_marker()
                    for payload_case in payload_cases_for_marker(marker, include_context=options.confirm_exec):
                        payload = payload_case.payload
                        if test_count >= options.max_tests:
                            path = write_evidence_json(evidence_dir, {"type": "xss", "results": results}, prefix="xss")
                            return path, results
                        test_count += 1
                        spec = RequestSpec(
                            method="GET", url=with_parameter(route, parameter, payload), headers=options.headers
                        )
                        try:
                            response = self.client.send(spec)
                        except ToolkitError as exc:
                            results.append(
                                {
                                    "route": redact_url(route),
                                    "method": "GET",
                                    "parameter": parameter,
                                    "payload": payload,
                                    "payload_context": payload_case.context,
                                    "classification": "error",
                                    "confirmed": False,
                                    "transport_error": True,
                                    "reason": str(exc),
                                }
                            )
                            path = write_evidence_json(
                                evidence_dir,
                                {"type": "xss", "results": results, "stop_reason": "transport_error"},
                                prefix="xss",
                            )
                            return path, results
                        reflection = detect_reflection(response.body_text, marker=marker, payload=payload)
                        validation = classify_reflection(reflection, response.headers.get("content-type", ""))
                        context = {"status": "not_html", "contexts": [], "confirmed": False}
                        media_type = response.headers.get("content-type", "").split(";", 1)[0].strip().lower()
                        if media_type in {"text/html", "application/xhtml+xml"}:
                            try:
                                context = {
                                    "status": "analyzed",
                                    **analyze_html(response.body_text, marker, options.html_parser),
                                }
                            except ValueError:
                                context = {
                                    "status": "unavailable",
                                    "contexts": [],
                                    "confirmed": False,
                                    "note": "Install the xss extra and selected parser for HTML context analysis.",
                                }
                        result = {
                            "route": redact_url(route),
                            "method": "GET",
                            "parameter": parameter,
                            "payload": payload,
                            "payload_context": payload_case.context,
                            "status_code": response.status_code,
                            "duration_ms": response.duration_ms,
                            "classification": validation["classification"],
                            "confirmed": validation["confirmed"],
                            "reason": validation["reason"],
                            "reflected": reflection.reflected,
                            "reflected_unescaped": reflection.reflected_unescaped,
                            "reflection_context": redact_text(reflection.context),
                            "reflection_contexts": context.get("contexts", []),
                            "body_truncated": response.body_truncated,
                            "content_type": media_type,
                            "context_analysis": context,
                            "browser_execution_observed": False,
                            "exchange": response.to_dict(),
                        }
                        stop_reason = None
                        if response.status_code in {401, 403, 429}:
                            result.update(
                                classification="error",
                                confirmed=False,
                                reason="Authentication/access failure or rate limit; batch stopped.",
                            )
                            stop_reason = "access_or_rate_limit"
                        elif response.body_truncated:
                            result.update(
                                classification="error",
                                confirmed=False,
                                reason="Response truncated; context validation incomplete.",
                            )
                            stop_reason = "truncated_response"
                        elif options.confirm_exec:
                            if not reflection.reflected:
                                result.update(
                                    classification="not_reflected",
                                    confirmed=False,
                                    reason="The unique marker was not reflected in the response.",
                                )
                            elif validation["classification"] == "possible":
                                try:
                                    execution = checker.confirm(spec.prepared_url(), marker, options.headers)
                                except ToolkitError as exc:
                                    result.update(
                                        classification="error",
                                        confirmed=False,
                                        reason=str(exc),
                                        browser_execution_observed=False,
                                    )
                                    results.append(result)
                                    path = write_evidence_json(
                                        evidence_dir,
                                        {
                                            "type": "xss",
                                            "results": results,
                                            "stop_reason": "run_budget_or_browser_error",
                                        },
                                        prefix="xss",
                                    )
                                    return path, results
                                result["browser_execution_observed"] = execution["classification"] == "confirmed"
                                result["execution"] = execution
                                result["dom_sinks"] = execution.get("dom_sinks", [])
                                result["classification"] = execution["classification"]
                                result["confirmed"] = execution["classification"] == "confirmed"
                                result["reason"] = (
                                    "Harmless marker execution was observed in a headless browser."
                                    if result["confirmed"]
                                    else "The marker was reflected but did not execute in the headless browser."
                                )
                        results.append(result)
                        if stop_reason:
                            path = write_evidence_json(
                                evidence_dir,
                                {"type": "xss", "results": results, "stop_reason": stop_reason},
                                prefix="xss",
                            )
                            return path, results
            path = write_evidence_json(evidence_dir, {"type": "xss", "results": results}, prefix="xss")
            return path, results
        finally:
            if checker:
                checker.close()

    def validate(self, options: XssOptions) -> tuple[list[str], list[str]]:
        if options.max_tests <= 0:
            raise ValueError("Max tests must be positive.")
        if options.html_parser not in {"html.parser", "lxml", "html5lib"}:
            raise ValueError("Unsupported HTML parser.")
        routes = load_routes(options.routes_file, base_url=options.base_url)
        parameters = load_parameter_names(options.parameters_file)
        if not routes or not parameters:
            raise ValueError("Routes and parameters must contain at least one usable entry.")
        self.scope.require_all(routes)
        return routes, parameters
