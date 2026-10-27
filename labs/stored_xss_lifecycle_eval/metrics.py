"""Score lifecycle observations against outcomes declared before the run."""

from __future__ import annotations

from typing import Mapping

PERSIST_FIELDS = (
    "write_status",
    "persisted",
    "truncated",
    "marker_in_write_body",
    "actor_writer",
    "actor_viewer",
)
RENDER_FIELDS = (
    "view_status",
    "content_type",
    "render_context",
    "marker_in_html",
    "executable_img",
    "sanitize_path",
    "csp_restrictive",
    "interaction_required",
)
CONTROL_FIELDS = ("browser_error",)


def case_mismatches(expected: Mapping[str, object], observed: Mapping[str, object]) -> list[dict[str, object]]:
    mismatches: list[dict[str, object]] = []
    for field in PERSIST_FIELDS + RENDER_FIELDS + CONTROL_FIELDS:
        if field not in expected:
            continue
        if expected[field] != observed.get(field):
            mismatches.append({"field": field, "expected": expected[field], "got": observed.get(field)})
    if expected.get("pipeline_confirms_finding") is not False:
        mismatches.append(
            {"field": "pipeline_confirms_finding", "expected": False, "got": expected.get("pipeline_confirms_finding")}
        )
    if expected.get("finding_confirmed") is not False:
        mismatches.append({"field": "finding_confirmed", "expected": False, "got": expected.get("finding_confirmed")})
    if observed.get("pipeline_finding_confirmed") is True or observed.get("pipeline_confirmed") is True:
        mismatches.append(
            {
                "field": "pipeline_finding_confirmed",
                "expected": False,
                "got": True,
            }
        )
    return mismatches


def rate(numerator: int, denominator: int) -> float:
    if denominator == 0:
        return 0.0
    return round(numerator / denominator, 4)


def summarize_cases(cases: list[dict[str, object]]) -> dict[str, object]:
    persist_ok = render_ok = control_ok = cleanup_ok = 0
    inconclusive = 0
    browser_errors = 0
    write_success_confirmed = 0
    marker_only_execution_claims = 0
    status_disagreements = 0
    execution_claims = 0
    for case in cases:
        mismatches = case.get("mismatches")
        mismatch_fields = set()
        if isinstance(mismatches, list):
            for item in mismatches:
                if isinstance(item, dict) and isinstance(item.get("field"), str):
                    mismatch_fields.add(item["field"])
        if not mismatch_fields.intersection(PERSIST_FIELDS):
            persist_ok += 1
        if not mismatch_fields.intersection(RENDER_FIELDS):
            render_ok += 1
        if "browser_error" not in mismatch_fields:
            control_ok += 1
        if case.get("cleanup_ok") is True:
            cleanup_ok += 1
        classification = case.get("pipeline_classification")
        if classification in {"inconclusive", "inconclusive_browser_error", "error"}:
            inconclusive += 1
        if case.get("browser_error") is True:
            browser_errors += 1
        write_status = case.get("write_status")
        confirmed = case.get("pipeline_finding_confirmed") is True or case.get("pipeline_confirmed") is True
        if isinstance(write_status, int) and 200 <= write_status < 300 and confirmed:
            write_success_confirmed += 1
        claim = case.get("pipeline_execution_claim") is True
        execution = case.get("execution_observed")
        if claim:
            execution_claims += 1
        if case.get("marker_in_html") is True and claim and execution is not True:
            marker_only_execution_claims += 1
        if case.get("status_disagreement") is True:
            status_disagreements += 1
    total = len(cases)
    return {
        "cases": total,
        "persistence_correctness": rate(persist_ok, total),
        "render_recall": rate(render_ok, total),
        "control_accuracy": rate(control_ok, total),
        "cleanup_success_rate": rate(cleanup_ok, total),
        "pipeline_inconclusive_rate": rate(inconclusive, total),
        "browser_errors": browser_errors,
        "browser_error_rate": rate(browser_errors, total),
        "write_success_confirmed": write_success_confirmed,
        "marker_only_execution_claims": marker_only_execution_claims,
        "pipeline_execution_claims": execution_claims,
        "status_disagreements": status_disagreements,
        "exec_precision": "NOT_MEASURED",
        "exec_false_positive_rate": "NOT_MEASURED",
        "exec_false_negative_rate": "NOT_MEASURED",
        "counts": {
            "persistence_correct": persist_ok,
            "render_correct": render_ok,
            "control_correct": control_ok,
            "cleanup_correct": cleanup_ok,
            "pipeline_inconclusive": inconclusive,
        },
    }
