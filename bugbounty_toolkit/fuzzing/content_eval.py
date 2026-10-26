"""Offline metrics for content-aware vs filename wordlist ranking."""

from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
from typing import Any, Mapping, Sequence

from .content_ranking import collect_profiles, rank_content_aware
from .context_planner import CaptureContext, recommend_for_context
from .wordlist_manager import WordlistCollection


@dataclass(frozen=True)
class RankingMetrics:
    precision_at_1: float
    precision_at_3: float
    mrr: float
    ndcg_at_3: float
    irrelevant_top3: int
    forbidden_hits: int
    recommended: int


def _dcg(relevances: Sequence[float]) -> float:
    total = 0.0
    for index, value in enumerate(relevances, start=1):
        total += (2**value - 1) / (__import__("math").log2(index + 1))
    return total


def score_ranked_paths(
    ranked: Sequence[str],
    relevant: set[str],
    forbidden: set[str],
    *,
    k: int = 3,
) -> RankingMetrics:
    top = list(ranked[:k])
    hits = [1.0 if path in relevant else 0.0 for path in top]
    p1 = hits[0] if hits else 0.0
    p3 = sum(hits) / max(len(top), 1) if top else 0.0
    mrr = 0.0
    for index, path in enumerate(ranked, start=1):
        if path in relevant:
            mrr = 1.0 / index
            break
    ideal = sorted(hits, reverse=True)
    dcg = _dcg(hits)
    idcg = _dcg(ideal) or 1.0
    ndcg = dcg / idcg if ideal and any(ideal) else 0.0
    return RankingMetrics(
        precision_at_1=p1,
        precision_at_3=p3,
        mrr=mrr,
        ndcg_at_3=ndcg,
        irrelevant_top3=sum(1 for path in top if path not in relevant),
        forbidden_hits=sum(1 for path in ranked if path in forbidden),
        recommended=len(ranked),
    )


def _context_from_scenario(scenario: Mapping[str, Any]) -> CaptureContext:
    paths = tuple(scenario["paths"])
    prefixes = tuple(
        sorted({"/".join(path.rstrip("/").split("/")[: i + 1]) or "/" for path in paths for i in range(3)})
    )
    return CaptureContext(
        hosts=("127.0.0.1:8191",),
        schemes=("http",),
        route_prefixes=prefixes,
        observed_paths=paths,
        parameters=tuple(scenario.get("params", [])),
        technologies=tuple(scenario.get("technologies", [])),
        content_types=("application/json",),
        methods=("GET",),
        categories_needed=tuple(scenario["categories"]),
        entry_count=len(paths),
        capture_import={"format": "synthetic", "accepted": len(paths), "rejected": 0},
    )


def evaluate_scenario(
    collection: WordlistCollection,
    scenario: Mapping[str, Any],
    *,
    mode: str,
) -> dict[str, Any]:
    """Run one scenario under filename or content ranking and return per-category metrics."""
    context = _context_from_scenario(scenario)
    forbidden = {str((collection.path / rel).resolve(strict=False)) for rel in scenario.get("forbidden", [])}
    per_category: dict[str, Any] = {}
    aggregate = RankingMetrics(0.0, 0.0, 0.0, 0.0, 0, 0, 0)
    categories = list(scenario["categories"])
    if mode == "filename":
        recommendations, _ = recommend_for_context([collection], context, ranking="filename")
        by_cat: dict[str, list[str]] = {}
        for item in recommendations:
            by_cat.setdefault(item.category, []).append(str(Path(item.path).resolve(strict=False)))
    else:
        profiles, _ = collect_profiles([collection])
        by_cat = {}
        for category in categories:
            ranked, _ = rank_content_aware(profiles, category, context)
            by_cat[category] = [str(Path(item.path).resolve(strict=False)) for item in ranked]
    for category in categories:
        relevant_rel = scenario["relevant"].get(category, [])
        relevant = {str((collection.path / rel).resolve(strict=False)) for rel in relevant_rel}
        metrics = score_ranked_paths(by_cat.get(category, []), relevant, forbidden)
        per_category[category] = metrics.__dict__
        aggregate = RankingMetrics(
            precision_at_1=aggregate.precision_at_1 + metrics.precision_at_1,
            precision_at_3=aggregate.precision_at_3 + metrics.precision_at_3,
            mrr=aggregate.mrr + metrics.mrr,
            ndcg_at_3=aggregate.ndcg_at_3 + metrics.ndcg_at_3,
            irrelevant_top3=aggregate.irrelevant_top3 + metrics.irrelevant_top3,
            forbidden_hits=aggregate.forbidden_hits + metrics.forbidden_hits,
            recommended=aggregate.recommended + metrics.recommended,
        )
    n = max(len(categories), 1)
    return {
        "mode": mode,
        "per_category": per_category,
        "mean": {
            "precision_at_1": aggregate.precision_at_1 / n,
            "precision_at_3": aggregate.precision_at_3 / n,
            "mrr": aggregate.mrr / n,
            "ndcg_at_3": aggregate.ndcg_at_3 / n,
            "irrelevant_top3": aggregate.irrelevant_top3,
            "forbidden_hits": aggregate.forbidden_hits,
            "recommended": aggregate.recommended,
        },
    }


def load_ground_truth(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict) or "scenarios" not in payload:
        raise ValueError(f"Malformed ground truth: {path}")
    return payload


def evaluate_set(
    collection: WordlistCollection,
    ground_truth: Mapping[str, Any],
    *,
    mode: str,
) -> dict[str, Any]:
    rows = {
        name: evaluate_scenario(collection, scenario, mode=mode) for name, scenario in ground_truth["scenarios"].items()
    }
    means = [row["mean"] for row in rows.values()]
    n = max(len(means), 1)
    return {
        "set": ground_truth.get("set"),
        "mode": mode,
        "scenarios": rows,
        "overall": {
            "precision_at_1": sum(item["precision_at_1"] for item in means) / n,
            "precision_at_3": sum(item["precision_at_3"] for item in means) / n,
            "mrr": sum(item["mrr"] for item in means) / n,
            "ndcg_at_3": sum(item["ndcg_at_3"] for item in means) / n,
            "forbidden_hits": sum(item["forbidden_hits"] for item in means),
            "irrelevant_top3": sum(item["irrelevant_top3"] for item in means),
        },
    }


__all__ = [
    "RankingMetrics",
    "evaluate_scenario",
    "evaluate_set",
    "load_ground_truth",
    "score_ranked_paths",
]
