"""Aggregate metrics for resource-kind-lineage-v1 evaluation."""

from __future__ import annotations

from typing import Any


def ratio(num: int, den: int) -> float | None:
    return round(num / den, 4) if den else None


def summarize(rows: list[dict[str, Any]]) -> dict[str, Any]:
    n = len(rows)
    kind_ok = sum(1 for r in rows if r["kind_accuracy"])
    preserve = sum(1 for r in rows if r["kind_preserved"])
    collisions = sum(r["cross_kind_collisions"] for r in rows)
    false_ns = sum(r["false_namespace_unions"] for r in rows)
    ownership = sum(1 for r in rows if r["ownership_claim"])
    abstain = sum(1 for r in rows if r["correct_abstention"])
    tech = sum(r["technical_errors"] for r in rows)
    handoff_ok = sum(1 for r in rows if r["handoff_coherent"])
    return {
        "scenarios": n,
        "kind_accuracy": ratio(kind_ok, n),
        "kind_preservation_rate": ratio(preserve, n),
        "cross_kind_collisions": collisions,
        "false_namespace_unions": false_ns,
        "ownership_claims": ownership,
        "correct_abstentions": abstain,
        "technical_errors": tech,
        "handoff_coherence_rate": ratio(handoff_ok, n),
        "precision_at_1_before": None,  # filled by evaluate from IRB baseline
        "precision_at_1_after": None,
        "by_family": {
            tag: {
                "scenarios": sum(1 for r in rows if r["tag"] == tag),
                "kind_accuracy": ratio(
                    sum(1 for r in rows if r["tag"] == tag and r["kind_accuracy"]),
                    sum(1 for r in rows if r["tag"] == tag),
                ),
            }
            for tag in sorted({r["tag"] for r in rows})
        },
        "rows": rows,
    }
