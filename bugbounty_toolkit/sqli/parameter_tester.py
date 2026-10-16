from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
import re
from urllib.parse import parse_qsl, urlsplit

from ..core.http_client import HttpClient, RequestSpec
from ..core.redaction import redact_url
from ..core.scope_validator import ScopeValidator
from ..core.target import load_routes
from ..reporting.evidence import write_evidence_json
from ..requests_engine.parameters import load_parameter_names, with_parameter
from ..utils.exceptions import ToolkitError


SQL_ERRORS = {
    "mysql": re.compile(r"you have an error in your sql syntax|warning.*mysqli?[_(:]|mysql.*syntax", re.I),
    "postgresql": re.compile(r"postgresql.*error|psycopg\w*\.errors\.|unterminated quoted string|syntax error at or near", re.I),
    "sqlite": re.compile(r"sqlite3?\.(?:OperationalError|DatabaseError)|SQLite/JDBCDriver|unrecognized token:", re.I),
    "mssql": re.compile(r"unclosed quotation mark|SQL Server.*(?:Driver|error)|System\.Data\.SqlClient\.SqlException", re.I),
    "oracle": re.compile(r"\bORA-(?:00933|00936|01756|00907)\b", re.I),
}


def error_families(body: str) -> set[str]:
    return {name for name, pattern in SQL_ERRORS.items() if pattern.search(body)}


@dataclass(frozen=True)
class SqliOptions:
    routes_file: Path
    parameters_file: Path
    base_url: str | None = None
    max_tests: int = 100
    headers: dict[str, str] = field(default_factory=dict)


class SqliParameterTester:
    def __init__(self, scope: ScopeValidator, client: HttpClient):
        self.scope = scope
        self.client = client

    def validate(self, options: SqliOptions) -> tuple[list[str], list[str]]:
        if options.max_tests < 3:
            raise ValueError("SQLi probing requires a budget of at least three requests (baseline plus two quotes).")
        routes = load_routes(options.routes_file, base_url=options.base_url)
        parameters = load_parameter_names(options.parameters_file)
        if not routes or not parameters:
            raise ValueError("Routes and parameters must contain usable entries.")
        self.scope.require_all(routes)
        return routes, parameters

    def run(self, options: SqliOptions, evidence_dir: Path) -> tuple[Path, list[dict]]:
        routes, parameters = self.validate(options)
        results = []
        stop_reason = None
        sent = 0
        for route in routes:
            for parameter in parameters:
                if sent + 3 > options.max_tests:
                    stop_reason = "request_budget"
                    break
                original = dict(parse_qsl(urlsplit(route).query, keep_blank_values=True)).get(parameter, "")
                baseline_errors = set()
                for stage, suffix in (("baseline", ""), ("single_quote", "'"), ("double_quote", '"')):
                    spec = RequestSpec("GET", with_parameter(route, parameter, original + suffix), options.headers)
                    sent += 1
                    try:
                        response = self.client.send(spec)
                    except ToolkitError:
                        results.append({"route": redact_url(route), "parameter": parameter, "stage": stage,
                                        "classification": "error", "confirmed": False, "reason": "transport_error"})
                        stop_reason = "transport_error"
                        break
                    errors = error_families(response.body_text)
                    if stage == "baseline":
                        baseline_errors = errors
                    new_errors = sorted(errors - baseline_errors) if stage != "baseline" else []
                    classification = "baseline" if stage == "baseline" else "possible" if new_errors else "not_reproducible"
                    blocked = response.status_code in {401, 403, 429}
                    if blocked or response.body_truncated:
                        classification = "error"
                        stop_reason = "access_or_rate_limit" if blocked else "truncated_response"
                    results.append({"route": redact_url(route), "parameter": parameter, "stage": stage,
                                    "status_code": response.status_code, "duration_ms": response.duration_ms,
                                    "new_error_families": new_errors, "classification": classification,
                                    "confirmed": False, "exchange": response.to_dict()})
                    if stop_reason:
                        break
                if stop_reason:
                    break
            if stop_reason:
                break
        path = write_evidence_json(evidence_dir, {"type": "sqli", "requests_attempted": sent, "stop_reason": stop_reason,
                                                "results": results, "note": "Error probes are indicators, not proof of SQL injection; no extraction or delay payloads are used."}, prefix="sqli")
        return path, results
