from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
import hashlib
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
    "mysql": re.compile(r"you have an error in your sql syntax|\bsql syntax\b|warning.*mysqli?[_(:]|mysql.*(?:syntax|error)", re.I),
    "postgresql": re.compile(r"postgres(?:ql)?.*(?:error|syntax)|psycopg\w*\.errors\.|\bpg_[a-z_]+\b|unterminated quoted string|syntax error at or near", re.I),
    "sqlite": re.compile(r"sqlite(?:3)?(?:\.|\s|/)|SQLite/JDBCDriver|unrecognized token:", re.I),
    "mssql": re.compile(r"unclosed quotation mark|SQL Server.*(?:Driver|error)|System\.Data\.SqlClient\.SqlException", re.I),
    "oracle": re.compile(r"\bORA-\d{5}\b", re.I),
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
    deep: bool = False


class SqliParameterTester:
    def __init__(self, scope: ScopeValidator, client: HttpClient):
        self.scope = scope
        self.client = client

    def validate(self, options: SqliOptions) -> tuple[list[str], list[str]]:
        minimum = 8 if options.deep else 3
        if options.max_tests < minimum:
            detail = "baseline, two quote probes, three time probes and two boolean probes" if options.deep else "baseline plus two quotes"
            raise ValueError(f"SQLi probing requires a budget of at least {minimum} requests ({detail}).")
        routes = load_routes(options.routes_file, base_url=options.base_url)
        parameters = load_parameter_names(options.parameters_file)
        if not routes or not parameters:
            raise ValueError("Routes and parameters must contain usable entries.")
        self.scope.require_all(routes)
        return routes, parameters

    def run(self, options: SqliOptions, evidence_dir: Path) -> tuple[Path, list[dict[str, object]]]:
        routes, parameters = self.validate(options)
        results: list[dict[str, object]] = []
        stop_reason = None
        sent = 0
        group_size = 8 if options.deep else 3
        for route in routes:
            for parameter in parameters:
                if sent + group_size > options.max_tests:
                    stop_reason = "request_budget"
                    break
                original = dict(parse_qsl(urlsplit(route).query, keep_blank_values=True)).get(parameter, "")
                baseline_errors: set[str] = set()
                baseline_duration: int | None = None
                boolean_records: list[dict[str, object]] = []
                probes: list[tuple[str, str, str]] = [
                    ("baseline", original, "error"),
                    ("single_quote", original + "'", "error"),
                    ("double_quote", original + '"', "error"),
                ]
                if options.deep:
                    probes.extend([
                        ("time_mysql", original + "' AND SLEEP(3)-- ", "time"),
                        ("time_postgresql", original + "'; SELECT pg_sleep(3);--", "time"),
                        ("time_mssql", original + "'; WAITFOR DELAY '0:0:3'--", "time"),
                        ("boolean_true", original + "' AND 1=1-- ", "boolean"),
                        ("boolean_false", original + "' AND 1=2-- ", "boolean"),
                    ])
                for stage, value, probe_kind in probes:
                    spec = RequestSpec("GET", with_parameter(route, parameter, value), options.headers)
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
                        baseline_duration = response.duration_ms
                    new_errors = sorted(errors - baseline_errors) if stage != "baseline" else []
                    classification = "baseline" if stage == "baseline" else "possible" if new_errors else "not_reproducible"
                    body_hash = hashlib.sha256(response.body_text.encode("utf-8", errors="replace")).hexdigest()
                    time_candidate = (probe_kind == "time" and baseline_duration is not None
                                      and baseline_duration < 2500 and response.duration_ms >= 2500)
                    if probe_kind == "time":
                        classification = "possible" if time_candidate or new_errors else "not_reproducible"
                    elif probe_kind == "boolean":
                        boolean_records.append({"body_size": response.body_size, "body_sha256": body_hash})
                        classification = "possible" if new_errors else "not_reproducible"
                    blocked = response.status_code in {401, 403, 429}
                    if blocked or response.body_truncated:
                        classification = "error"
                        stop_reason = "access_or_rate_limit" if blocked else "truncated_response"
                    results.append({"route": redact_url(route), "parameter": parameter, "stage": stage,
                                    "status_code": response.status_code, "duration_ms": response.duration_ms,
                                    "new_error_families": new_errors, "classification": classification,
                                    "confirmed": False, "time_candidate": time_candidate,
                                    "body_size": response.body_size, "body_sha256": body_hash,
                                    "baseline_duration_ms": baseline_duration if probe_kind == "time" else None,
                                    "exchange": response.to_dict()})
                    if stop_reason:
                        break
                    if probe_kind == "boolean" and len(boolean_records) == 2:
                        differs = boolean_records[0] != boolean_records[1]
                        for row in results[-2:]:
                            row["boolean_pair_differs"] = differs
                            row["classification"] = "possible" if differs or row["new_error_families"] else "not_reproducible"
                if stop_reason:
                    break
            if stop_reason:
                break
        path = write_evidence_json(evidence_dir, {"type": "sqli", "requests_attempted": sent, "stop_reason": stop_reason,
                                                "results": results, "note": "SQL error, timing and boolean differences are candidates only; no extraction or data retrieval is performed."}, prefix="sqli")
        return path, results
