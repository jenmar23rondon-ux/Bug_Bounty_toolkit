"""Pure metric functions for irb-1.0 (no bbtk imports; unit-tested independently)."""

from __future__ import annotations

import math
from collections.abc import Iterable, Mapping, Sequence
from typing import Any

Z95 = 1.959963984540054


def ratio(num: float, den: float) -> float | None:
    return round(num / den, 4) if den else None


def wilson(successes: int, n: int, z: float = Z95) -> list[float] | None:
    """95% Wilson score interval; None when n == 0."""
    if n <= 0:
        return None
    p = successes / n
    denom = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / denom
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / denom
    return [round(max(0.0, centre - half), 4), round(min(1.0, centre + half), 4)]


def precision_at_k(relevance: Sequence[int], k: int) -> float:
    top = list(relevance[:k])
    return sum(top) / k if k > 0 else 0.0


def reciprocal_rank(relevance: Sequence[int]) -> float:
    for i, rel in enumerate(relevance, start=1):
        if rel:
            return 1.0 / i
    return 0.0


def ndcg_at_k(relevance: Sequence[int], k: int) -> float:
    dcg = sum(rel / math.log2(i + 2) for i, rel in enumerate(relevance[:k]))
    ideal = sorted(relevance, reverse=True)[:k]
    idcg = sum(rel / math.log2(i + 2) for i, rel in enumerate(ideal))
    return dcg / idcg if idcg > 0 else 0.0


def relevance_vector(ranked_types: Sequence[str], targets: Iterable[str]) -> list[int]:
    wanted = {t.lower() for t in targets}
    return [1 if str(t).lower() in wanted else 0 for t in ranked_types]


def pairing_counts(predicted: Iterable[str], ideal: Iterable[str], forbidden: Iterable[str]) -> dict[str, int]:
    """Ideal types are alternatives naming one target: at most one TP per scenario."""
    pred = {p.lower() for p in predicted}
    ide = {p.lower() for p in ideal}
    forb = {p.lower() for p in forbidden}
    tp = 1 if pred & ide else 0
    return {
        "tp": tp,
        "fn": (1 - tp) if ide else 0,
        "fp": len(pred - ide),
        "forbidden_hits": len(pred & forb),
    }


OUTCOME_PRIORITY = ("integrity_block", "duplicate", "stop", "reviewable", "abstain")
ABSTAIN_LIKE = frozenset({"abstain", "stop"})


def scenario_outcome(active_statuses: Iterable[str], *, technical: bool, no_input: bool) -> str:
    """Collapse planner candidate statuses into one predicted scenario outcome."""
    mapped = set()
    for st in active_statuses:
        mapped.add(
            {
                "integrity_blocked": "integrity_block",
                "duplicate": "duplicate",
                "stop_recommended": "stop",
                "blocked": "stop",
                "open": "reviewable",
                "ready_for_manual_review": "reviewable",
                "abstain": "abstain",
            }.get(st, "abstain")
        )
    for o in OUTCOME_PRIORITY:
        if o in mapped:
            return o
    if technical or no_input:
        return "technical_error"
    return "abstain"


def summarize(rows: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    """Aggregate per-scenario score rows (output of ``evaluate.score``)."""
    n = len(rows)
    out_ok = sum(1 for r in rows if r["outcome_correct"])
    lenient = sum(1 for r in rows if r["outcome_correct_lenient"])
    ideal_rev = [r for r in rows if r["ideal_reviewable"]]
    not_rev = [r for r in rows if not r["ideal_reviewable"]]
    false_rev = sum(1 for r in not_rev if r["predicted_reviewable"])
    missed = sum(1 for r in ideal_rev if not r["predicted_reviewable"])
    abst = [r for r in rows if r["ideal_outcome"] in ABSTAIN_LIKE]
    abst_ok = sum(1 for r in abst if r["predicted_outcome"] in ABSTAIN_LIKE)
    ranked = [r for r in rows if r["ranking"] is not None]
    pair_tp = sum(r["pairing"]["tp"] for r in rows)
    pair_fp = sum(r["pairing"]["fp"] for r in rows)
    pair_fn = sum(r["pairing"]["fn"] for r in rows)
    mc = [r for r in rows if r["missing_control"] is not None]
    mc_hit = sum(r["missing_control"]["hit"] for r in mc)
    mc_tot = sum(r["missing_control"]["expected"] for r in mc)
    step_ok = sum(1 for r in rows if r["next_step_correct"])
    refs_ok = sum(r["refs"]["valid"] for r in rows)
    refs_tot = sum(r["refs"]["total"] for r in rows)

    def mean(key: str) -> float | None:
        vals = [r["ranking"][key] for r in ranked if key in r["ranking"] and r["ranking"][key] is not None]
        return round(sum(vals) / len(vals), 4) if vals else None

    return {
        "scenarios": n,
        "outcome_accuracy": ratio(out_ok, n),
        "outcome_accuracy_ci95": wilson(out_ok, n),
        "outcome_accuracy_lenient": ratio(lenient, n),
        "ranking_scenarios": len(ranked),
        "object_recall": ratio(sum(1 for r in ranked if r["ranking"]["recall"]), len(ranked)),
        "precision_at_1": mean("p@1"),
        "precision_at_1_ci95": wilson(sum(1 for r in ranked if r["ranking"]["p@1"] == 1.0), len(ranked)),
        "precision_at_1_strict_resource_type": mean("strict_p@1"),
        "object_recall_strict_resource_type": ratio(
            sum(1 for r in ranked if r["ranking"]["strict_recall"]), len(ranked)
        ),
        "precision_at_1_exported_kind": mean("kind_p@1"),
        "object_recall_exported_kind": ratio(sum(1 for r in ranked if r["ranking"].get("kind_recall")), len(ranked)),
        "precision_at_3": mean("p@3"),
        "precision_at_5": mean("p@5"),
        "mrr": mean("rr"),
        "ndcg_at_5": mean("ndcg@5"),
        "wrong_object_top1": sum(1 for r in ranked if r["ranking"]["recall"] and r["ranking"]["p@1"] == 0.0),
        "pairing_precision": ratio(pair_tp, pair_tp + pair_fp),
        "pairing_recall": ratio(pair_tp, pair_tp + pair_fn),
        "forbidden_pairs_proposed": sum(r["pairing"]["forbidden_hits"] for r in rows),
        "eligibility_correct": ratio(sum(1 for r in rows if r["eligibility_correct"]), n),
        "false_reviewable_cases": false_rev,
        "false_reviewable_rate": ratio(false_rev, len(not_rev)),
        "false_reviewable_rate_ci95": wilson(false_rev, len(not_rev)),
        # Post-planner view (added after the first FINAL run; labels unchanged): a case is only
        # counted as falsely reviewable if the planner also leaves it in a reviewable state.
        "false_reviewable_after_planner": sum(
            1 for r in not_rev if r["predicted_reviewable"] and r["predicted_outcome"] == "reviewable"
        ),
        "missed_eligible_cases": missed,
        "missed_eligible_rate": ratio(missed, len(ideal_rev)),
        "technical_errors_predicted": sum(1 for r in rows if r["predicted_outcome"] == "technical_error"),
        "pipeline_exceptions": sum(1 for r in rows if r["exception"]),
        "correct_abstentions": abst_ok,
        "abstention_recall": ratio(abst_ok, len(abst)),
        "missing_control_recall": ratio(mc_hit, mc_tot),
        "next_step_precision_at_1": ratio(step_ok, n),
        "next_step_precision_at_1_ci95": wilson(step_ok, n),
        "redundant_proposals": sum(r["redundant_proposals"] for r in rows),
        "synthetic_manual_steps": sum(r["manual_steps"] for r in rows),
        "reference_correct_rate": ratio(refs_ok, refs_tot),
        "secret_leaks": sum(r["leaks"] for r in rows),
        "auto_confirmations": sum(r["confirmed"] for r in rows),
        "network_attempts": sum(r["network_attempts"] for r in rows),
        "info_loss_events": sum(len(r["info_loss"]) for r in rows),
    }


def by_family(rows: Sequence[Mapping[str, Any]]) -> dict[str, dict[str, Any]]:
    fams: dict[str, list[Mapping[str, Any]]] = {}
    for r in rows:
        fams.setdefault(str(r["family"]), []).append(r)
    return {f: summarize(v) for f, v in sorted(fams.items())}
