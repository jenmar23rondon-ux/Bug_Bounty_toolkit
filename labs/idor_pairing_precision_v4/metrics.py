"""Metric helpers for the pairing-precision lab. No I/O and no network."""

from __future__ import annotations

from typing import Any


def ratio(num: float, den: float) -> float | None:
    if not den:
        return None
    return round(num / den, 4)


def f1(precision: float | None, recall: float | None) -> float | None:
    if precision is None or recall is None or precision + recall == 0:
        return None
    return round(2 * precision * recall / (precision + recall), 4)


def classification_counts(rows: list[dict[str, Any]]) -> dict[str, Any]:
    """Score pairing_decision against expect_pairing_decision."""
    tp = fp = fn = tn = 0
    abstentions = 0
    cross_kind_collisions = 0
    cross_program_contamination = 0
    cross_origin_contamination = 0
    provenance_hits = 0
    for row in rows:
        predicted = bool(row["pairing_decision"])
        expected = bool(row["expect_pairing_decision"])
        if predicted and expected:
            tp += 1
        elif predicted and not expected:
            fp += 1
        elif not predicted and expected:
            fn += 1
        else:
            tn += 1
        if row["compatibility"] in {"insufficient_evidence", "conflicting_evidence"}:
            abstentions += 1
        tags = set(row.get("tags") or [])
        if row["compatibility"] == "compatible" and "cross_kind" in tags:
            cross_kind_collisions += 1
        if row["compatibility"] == "compatible" and "cross_program" in tags:
            cross_program_contamination += 1
        if row["compatibility"] == "compatible" and "mixed_origin" in tags:
            cross_origin_contamination += 1
        if row.get("owner_evidence_ref") and row.get("actor_evidence_ref"):
            provenance_hits += 1
    precision = ratio(tp, tp + fp)
    recall = ratio(tp, tp + fn)
    return {
        "cases": len(rows),
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "tn": tn,
        "precision": precision,
        "recall": recall,
        "f1": f1(precision, recall),
        "false_pairs": fp,
        "missed_valid_pairs": fn,
        "abstentions": abstentions,
        "cross_kind_collisions": cross_kind_collisions,
        "cross_program_contamination": cross_program_contamination,
        "cross_origin_contamination": cross_origin_contamination,
        "provenance_completeness": ratio(provenance_hits, len(rows)),
        "finding_confirmed": False,
    }
