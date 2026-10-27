"""Score matrix and naive-baseline predictions against frozen scenario labels."""

from __future__ import annotations

from typing import Any, Mapping

from bugbounty_toolkit.analysis.authorization_control_matrix import CONTROL_TYPES, OBSERVATION_FIELDS


def _sessions_match(expected: Mapping[str, Any], predicted: Mapping[str, Any]) -> bool:
    sessions = predicted.get("sessions") if isinstance(predicted.get("sessions"), dict) else {}
    for ref, state in expected.get("session_states", {}).items():
        row = sessions.get(ref) if isinstance(sessions, dict) else None
        if not isinstance(row, dict) or row.get("state") != state:
            return False
    return True


def _invalid_pairs(expected: Mapping[str, Any], predicted: Mapping[str, Any]) -> tuple[int, int]:
    sessions = predicted.get("sessions") if isinstance(predicted.get("sessions"), dict) else {}
    total = correct = 0
    for ref, state in expected.get("session_states", {}).items():
        if state != "invalid":
            continue
        total += 1
        row = sessions.get(ref) if isinstance(sessions, dict) else None
        if isinstance(row, dict) and row.get("state") == "invalid":
            correct += 1
    return correct, total


def scenario_pass(expected: Mapping[str, Any], predicted: Mapping[str, Any]) -> bool:
    reasons = set(predicted.get("reason_codes") or [])
    rules = set(predicted.get("rules_fired") or [])
    raw_cells = predicted.get("cells")
    cells: Mapping[str, Any] = raw_cells if isinstance(raw_cells, dict) else {}
    raw_continuity = predicted.get("session_continuity")
    continuity: Mapping[str, Any] = raw_continuity if isinstance(raw_continuity, dict) else {}
    if predicted.get("disposition") != expected["disposition"]:
        return False
    if bool(predicted.get("denial_consistent")) != bool(expected["denial_consistent"]):
        return False
    if predicted.get("negative_finding") is not False or predicted.get("finding_confirmed") is not False:
        return False
    if predicted.get("access_claim") is not False:
        return False
    if bool(continuity.get("identity_changed")) != bool(expected["identity_changed"]):
        return False
    if bool(continuity.get("expiry_proven")) != bool(expected["expiry_proven"]):
        return False
    if any(code not in reasons for code in expected.get("reason_codes_include") or []):
        return False
    if any(code in reasons for code in expected.get("reason_codes_exclude") or []):
        return False
    if any(rule not in rules for rule in expected.get("rules_include") or []):
        return False
    if not _sessions_match(expected, predicted):
        return False
    for name in expected.get("cells_present") or []:
        cell = cells.get(name) if isinstance(cells, dict) else None
        if not isinstance(cell, dict) or not cell.get("present"):
            return False
    return True


def _ratio(numerator: int, denominator: int) -> float | None:
    if denominator == 0:
        return None
    return round(numerator / denominator, 4)


def summarize(rows: list[dict[str, Any]]) -> dict[str, Any]:
    """Aggregate the brief's metrics. Ratios are null when the denominator is zero."""
    session_hit = session_total = 0
    inconclusive_hit = inconclusive_total = 0
    false_denial = false_denial_base = 0
    unsupported_claims = 0
    missing_hit = missing_total = 0
    invalid_hit = invalid_total = 0
    provenance_obs = provenance_good = 0
    covered: set[str] = set()
    finding_true = 0
    for row in rows:
        expected = row["expected"]
        predicted = row["predicted"]
        if expected.get("session_states"):
            session_total += 1
            if _sessions_match(expected, predicted):
                session_hit += 1
        if expected["disposition"] in {"inconclusive", "blocked"}:
            inconclusive_total += 1
            if (
                predicted.get("disposition") == expected["disposition"]
                and predicted.get("negative_finding") is False
                and bool(predicted.get("denial_consistent")) == bool(expected["denial_consistent"])
            ):
                inconclusive_hit += 1
        if expected["denial_consistent"] is False:
            false_denial_base += 1
            if predicted.get("denial_consistent") is True or predicted.get("negative_finding") is True:
                false_denial += 1
        if predicted.get("access_claim") is True:
            unsupported_claims += 1
        missing = list(expected.get("missing_reasons") or [])
        if missing:
            missing_total += 1
            reasons = set(predicted.get("reason_codes") or [])
            if (
                all(code in reasons for code in missing)
                and predicted.get("disposition") == "blocked"
                and predicted.get("denial_consistent") is False
                and predicted.get("negative_finding") is False
            ):
                missing_hit += 1
        hit, total = _invalid_pairs(expected, predicted)
        invalid_hit += hit
        invalid_total += total
        cells = predicted.get("cells") if isinstance(predicted.get("cells"), dict) else {}
        for name in expected.get("cells_present") or []:
            cell = cells.get(name) if isinstance(cells, dict) else None
            if isinstance(cell, dict) and cell.get("present"):
                covered.add(str(name))
        if predicted.get("finding_confirmed") is True:
            finding_true += 1
        for observation in predicted.get("observations") or []:
            if not isinstance(observation, dict):
                continue
            provenance_obs += 1
            if all(observation.get(field) is not None for field in OBSERVATION_FIELDS):
                provenance_good += 1
    return {
        "session_control_accuracy": _ratio(session_hit, session_total),
        "access_control_coverage": _ratio(len(covered), len(CONTROL_TYPES)),
        "correct_inconclusive_rate": _ratio(inconclusive_hit, inconclusive_total),
        "false_denial_inference_rate": _ratio(false_denial, false_denial_base),
        "unsupported_access_claims": unsupported_claims,
        "missing_control_recall": _ratio(missing_hit, missing_total),
        "invalid_session_inference_rate": _ratio(invalid_hit, invalid_total),
        "provenance_completeness": _ratio(provenance_good, provenance_obs),
        "cells_covered": sorted(covered),
        "finding_confirmed_true_count": finding_true,
        "scenarios": len(rows),
    }
