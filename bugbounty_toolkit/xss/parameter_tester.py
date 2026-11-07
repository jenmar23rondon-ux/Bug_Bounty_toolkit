from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from ..core.http_client import HttpClient
from ..core.scope_validator import ScopeValidator
from ..core.target import load_routes
from ..core.redaction import redact_text, redact_url
from ..utils.exceptions import ToolkitError
from ..reporting.evidence import write_evidence_json
from ..requests_engine.injection_surface import (
    InjectionSurface,
    bind_parameters,
    build_injection_request,
    seal_parameter_location,
    validate_surface,
)
from ..requests_engine.parameters import load_parameter_names
from ..analysis.html_context import analyze_html
from .reflection_detector import detect_reflection
from .result_validator import classify_reflection
from .test_cases import new_marker, payload_cases_for_marker
from .playwright_confirm import PlaywrightExecutionChecker, require_playwright_installed
from .dom_inscope import run_dom
from .dom_local import require_literal_loopback, run_dom_local
from .context_classifier import classify_reflected_context
from .stored_local import StoredLocalOptions, run_stored_local
from .capture_review import review_captures


@dataclass(frozen=True)
class XssOptions:
    routes_file: Path
    parameters_file: Path
    base_url: str | None = None
    max_tests: int = 100
    headers: dict[str, str] = field(default_factory=dict)
    html_parser: str = "html.parser"
    confirm_exec: bool = False
    dom_local: bool = False
    # In-scope DOM probes. ``--dom-local`` sets this and keeps loopback_only.
    dom: bool = False
    # Opt-in Phase-3 evidence-quality features (additive; default off).
    enrich_context: bool = True
    stored_local: bool = False
    stored_write_url: str | None = None
    stored_render_url: str | None = None
    stored_parameter: str = "content"
    capture_review_file: Path | None = None
    method: str = "GET"
    content_type: str | None = None
    header_inject: tuple[str, ...] = ()
    body_template: str | None = None


class XssParameterTester:
    def __init__(self, scope: ScopeValidator, client: HttpClient):
        self.scope = scope
        self.client = client

    def run(self, options: XssOptions, evidence_dir: Path) -> tuple[Path, list[dict[str, object]]]:
        if options.capture_review_file is not None:
            import json

            self.validate(options)
            exchanges = json.loads(options.capture_review_file.read_text(encoding="utf-8"))
            if isinstance(exchanges, dict):
                exchanges = exchanges.get("exchanges", exchanges.get("items", []))
            reviews = review_captures(exchanges)
            path = write_evidence_json(
                evidence_dir,
                {
                    "type": "xss_capture_review",
                    "results": reviews,
                    "finding_confirmed": False,
                    "requests_issued": 0,
                    "note": "Offline capture review only; no new HTTP requests were issued.",
                },
                prefix="xss-capture-review",
            )
            return path, reviews
        if options.stored_local:
            self.validate(options)
            require_playwright_installed()
            local_checker = PlaywrightExecutionChecker(
                self.scope,
                timeout_ms=int(self.client.timeout * 1000),
                rate_limiter=self.client.rate_limiter,
                execution_budget=self.client.execution_budget,
            )
            try:
                return run_stored_local(
                    StoredLocalOptions(
                        write_url=options.stored_write_url,
                        render_url=options.stored_render_url,
                        parameter=options.stored_parameter,
                        max_tests=options.max_tests,
                        headers=options.headers,
                    ),
                    self.client,
                    local_checker,
                    evidence_dir,
                )
            finally:
                local_checker.close()
        routes, parameters = self.validate(options)
        if options.dom:
            require_playwright_installed()
            scoped_checker = PlaywrightExecutionChecker(
                self.scope,
                timeout_ms=int(self.client.timeout * 1000),
                rate_limiter=self.client.rate_limiter,
                execution_budget=self.client.execution_budget,
            )
            try:
                return run_dom(
                    routes,
                    parameters,
                    scoped_checker,
                    evidence_dir,
                    max_tests=options.max_tests,
                    headers=options.headers,
                    loopback_only=options.dom_local,
                )
            finally:
                scoped_checker.close()
        if options.dom_local:
            require_playwright_installed()
            local_checker = PlaywrightExecutionChecker(
                self.scope,
                timeout_ms=int(self.client.timeout * 1000),
                rate_limiter=self.client.rate_limiter,
                execution_budget=self.client.execution_budget,
            )
            try:
                return run_dom_local(
                    routes,
                    parameters,
                    local_checker,
                    evidence_dir,
                    max_tests=options.max_tests,
                    headers=options.headers,
                )
            finally:
                local_checker.close()
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
        surface = _surface(options)
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
                        spec = build_injection_request(route, parameter, payload, options.headers, surface)
                        try:
                            response = self.client.send(spec)
                        except ToolkitError as exc:
                            error_result: dict[str, object] = {
                                "route": redact_url(route),
                                "method": spec.method,
                                "parameter": parameter,
                                "payload": payload,
                                "payload_context": payload_case.context,
                                "classification": "error",
                                "confirmed": False,
                                "transport_error": True,
                                "reason": str(exc),
                            }
                            seal_parameter_location(error_result, surface.location)
                            results.append(error_result)
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
                            "method": spec.method,
                            "parameter": parameter,
                            "parameter_location": surface.location,
                            "payload": payload,
                            "payload_context": payload_case.context,
                            "status_code": response.status_code,
                            "duration_ms": response.duration_ms,
                            "classification": validation["classification"],
                            "finding_state": validation.get(
                                "finding_state",
                                "candidate" if validation["classification"] == "possible" else "not_observed",
                            ),
                            "confirmed": validation["confirmed"],
                            "confirmation_gap": validation.get("confirmation_gap"),
                            "rejection_reason": validation.get("rejection_reason"),
                            "finding_confirmed": False,
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
                        if options.enrich_context:
                            # Additive deep context analysis; never overrides confirmed=False.
                            deep = classify_reflected_context(
                                response.body_text,
                                marker,
                                payload,
                                media_type,
                                truncated=response.body_truncated,
                            )
                            result["reflected_assessment"] = deep.to_dict()
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
                                    execution = checker.confirm(spec.prepared_url(), marker, dict(spec.headers))
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
                                    seal_parameter_location(result, surface.location)
                                    return path, results
                                result["browser_execution_observed"] = execution["classification"] == "confirmed"
                                result["execution"] = execution
                                result["dom_sinks"] = execution.get("dom_sinks", [])
                                result["classification"] = execution["classification"]
                                result["confirmed"] = execution["classification"] == "confirmed"
                                result["finding_state"] = (
                                    "confirmed" if result["confirmed"] else result.get("finding_state", "candidate")
                                )
                                result["confirmation_gap"] = None if result["confirmed"] else "no_second_proof"
                                result["reason"] = (
                                    "Harmless marker execution was observed in a headless browser."
                                    if result["confirmed"]
                                    else "The marker was reflected but did not execute in the headless browser."
                                )
                        seal_parameter_location(result, surface.location)
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
        _surface(options)
        if options.stored_local and options.dom:
            raise ValueError("dom and stored_local are mutually exclusive.")
        if options.stored_local and options.dom_local:
            raise ValueError("dom_local and stored_local are mutually exclusive.")
        if options.stored_local:
            if not options.stored_write_url or not options.stored_render_url:
                raise ValueError("stored_local requires write and render loopback URLs.")
            require_literal_loopback(options.stored_write_url)
            require_literal_loopback(options.stored_render_url)
            return [], []
        if options.capture_review_file is not None:
            if not options.capture_review_file.is_file():
                raise ValueError("capture_review_file must be an existing JSON file.")
            return [], []
        routes = load_routes(options.routes_file, base_url=options.base_url)
        parameters = load_parameter_names(options.parameters_file)
        if not routes or not parameters:
            raise ValueError("Routes and parameters must contain at least one usable entry.")
        self.scope.require_all(routes)
        if options.dom_local:
            for route in routes:
                require_literal_loopback(route)
        surface = _surface(options)
        if (options.dom or options.dom_local) and surface.location != "query":
            raise ValueError("DOM probes stay on query and hash sources.")
        if options.confirm_exec and surface.location not in {"query", "header"}:
            raise ValueError("Browser confirmation does not replay a POST body.")
        bind_parameters(surface, parameters)
        return routes, parameters


def _surface(options: XssOptions) -> InjectionSurface:
    return validate_surface(options.method, options.content_type, options.header_inject, options.body_template)
