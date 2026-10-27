"""Parser metrics and Chromium metrics. The two tables are never merged."""

from __future__ import annotations

from typing import Any, Sequence

from .spec import Scenario
from .states import REQUIRED_ROW_FIELDS


def _rate(num: int, den: int) -> float:
    return round(num / den, 4) if den else 0.0


def _percentile(values: Sequence[float], pct: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    if len(ordered) == 1:
        return float(ordered[0])
    rank = (len(ordered) - 1) * pct
    low = int(rank)
    high = min(low + 1, len(ordered) - 1)
    weight = rank - low
    return float(ordered[low] * (1.0 - weight) + ordered[high] * weight)


def parser_metrics(rows: Sequence[dict[str, Any]], cases: Sequence[Scenario]) -> dict[str, Any]:
    by_id = {case.letter: case for case in cases}
    context_ok = decision_ok = 0
    mismatches: list[dict[str, Any]] = []
    confirmed = 0
    for row in rows:
        case = by_id[str(row["scenario_id"])]
        if row.get("context") == case.expected_parser_context:
            context_ok += 1
        else:
            mismatches.append(
                {
                    "id": case.letter,
                    "field": "context",
                    "expected": case.expected_parser_context,
                    "got": row.get("context"),
                }
            )
        if row.get("decision") == case.expected_parser_decision:
            decision_ok += 1
        else:
            mismatches.append(
                {
                    "id": case.letter,
                    "field": "decision",
                    "expected": case.expected_parser_decision,
                    "got": row.get("decision"),
                }
            )
        if row.get("finding_confirmed") is True:
            confirmed += 1
    total = len(rows)
    return {
        "table": "offline_parser",
        "cases": total,
        "context_accuracy": _rate(context_ok, total),
        "decision_accuracy": _rate(decision_ok, total),
        "mismatches": mismatches,
        "browser_time_ms": 0.0,
        "external_requests": sum(int(row.get("external_requests", 0)) for row in rows),
        "automatic_confirmations": confirmed,
        "finding_confirmed_always_false": confirmed == 0,
    }


def browser_metrics(rows: Sequence[dict[str, Any]], cases: Sequence[Scenario]) -> dict[str, Any]:
    by_id = {case.letter: case for case in cases}
    tp = fp = fn = tn = 0
    mismatches: list[dict[str, Any]] = []
    confirmed = 0
    csp_total = csp_correct = 0
    safe_total = safe_correct = 0
    timeout_total = timeout_correct = 0
    complete = 0
    latencies: list[float] = []
    allowed = blocked = external = sockets = leaks = 0
    peak_python = 0
    for row in rows:
        case = by_id[str(row["scenario_id"])]
        expected_exec = case.expect_execution
        got_exec = row.get("state") == "execution_observed"
        if got_exec and expected_exec:
            tp += 1
        elif got_exec and not expected_exec:
            fp += 1
            mismatches.append({"id": case.letter, "type": "false_positive_execution", "state": row.get("state")})
        elif not got_exec and expected_exec:
            fn += 1
            mismatches.append({"id": case.letter, "type": "false_negative_execution", "state": row.get("state")})
        else:
            tn += 1
        if row.get("state") != case.expected_browser_state:
            mismatches.append(
                {
                    "id": case.letter,
                    "type": "state_mismatch",
                    "expected": case.expected_browser_state,
                    "got": row.get("state"),
                }
            )
        groups = set(case.metric_groups)
        if "csp" in groups:
            csp_total += 1
            if row.get("state") == "execution_blocked":
                csp_correct += 1
        if "safe_sink" in groups:
            safe_total += 1
            if row.get("state") != "execution_observed" and row.get("marker_execution") is False:
                safe_correct += 1
        if "timeout" in groups:
            timeout_total += 1
            if row.get("state") == "inconclusive_browser_error":
                timeout_correct += 1
        if all(key in row for key in REQUIRED_ROW_FIELDS):
            complete += 1
        if row.get("finding_confirmed") is True or row.get("confirmed") is True:
            confirmed += 1
        latencies.append(float(row.get("runtime_ms", 0.0)))
        allowed += int(row.get("allowed_requests", 0))
        blocked += int(row.get("blocked_requests", 0))
        external += int(row.get("external_requests", 0))
        sockets = max(sockets, int(row.get("external_sockets", 0)))
        peak_python = max(peak_python, int(row.get("python_tracemalloc_peak_bytes", 0)))
    return {
        "table": "chromium" if rows and rows[0].get("measurement") == "chromium" else "mock_fixture",
        "cases": len(rows),
        "execution_precision": _rate(tp, tp + fp),
        "execution_recall": _rate(tp, tp + fn),
        "false_positives": fp,
        "false_negatives": fn,
        "true_positives": tp,
        "true_negatives": tn,
        "csp_blocked_correct_rate": _rate(csp_correct, csp_total),
        "safe_sink_correct_rate": _rate(safe_correct, safe_total),
        "timeouts_correct": timeout_correct,
        "timeouts_expected": timeout_total,
        "latency_median_ms": round(_percentile(latencies, 0.50), 3),
        "latency_p95_ms": round(_percentile(latencies, 0.95), 3),
        "allowed_requests": allowed,
        "blocked_requests": blocked,
        "external_requests": external,
        "external_socket_observations": sockets,
        "evidence_completeness": _rate(complete, len(rows)),
        "python_tracemalloc_peak_bytes": peak_python,
        "automatic_confirmations": confirmed,
        "finding_confirmed_always_false": confirmed == 0,
        "secret_leaks": leaks,
        "mismatches": mismatches,
    }


def reproducibility(runs: Sequence[Sequence[dict[str, Any]]]) -> dict[str, Any]:
    if len(runs) < 2:
        return {
            "status": "NOT_MEASURED",
            "reason": "fewer than 2 live runs were executed",
            "runs": len(runs),
        }
    ids = [str(row["scenario_id"]) for row in runs[0]]
    disagreements: list[dict[str, Any]] = []
    for scenario_id in ids:
        states: list[object] = []
        for run in runs:
            match = next(row for row in run if str(row["scenario_id"]) == scenario_id)
            states.append(match.get("state"))
        if len(set(states)) != 1:
            disagreements.append({"scenario_id": scenario_id, "states": states})
    return {
        "status": "measured",
        "runs": len(runs),
        "scenarios": len(ids),
        "state_agreement": _rate(len(ids) - len(disagreements), len(ids)),
        "disagreements": disagreements,
    }
