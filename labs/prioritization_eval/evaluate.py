"""Before/after metrics for advisory review ordering.

The queue is the synthetic set in ``cases.py``. It is not the frozen DEV,
FINAL, or STRESS corpus and it is not used to change those labels.

The severity arm sorts every row by the tool's severity label and never
abstains. The existing arm is ``prioritize_hypotheses`` on the hypothesis
rows only; external findings and ledger candidates are outside that command.
The after arm is ``prioritize_review``.

Review-time proxy (unitless, lower is better): 30 per false confirmation,
25 per gold abstention placed in the ranked list, 15 per gold row dropped,
8 per inverted gold pair, 5 per abstention with the wrong reason, 2 per
incomplete explanation, and 1 per correctly handled row.
"""

from __future__ import annotations

import math
from typing import Any, Mapping

from bugbounty_toolkit.analysis.prioritization import prioritize_hypotheses
from bugbounty_toolkit.analysis.review_prioritization import FACTORS, prioritize_review
from bugbounty_toolkit.analysis.skill_router import load_hypotheses_result

from .cases import GOLD_ABSTAIN, GOLD_RANK, PROGRAM, build_queue, severity_of

PHRASES = (
    "Origin:",
    "Location:",
    "Evidence strength:",
    "Session/actor:",
    "Corroboration:",
    "Vulnerability class:",
    "Contradictions:",
)


def _ratio(numerator: int, denominator: int) -> float | None:
    if denominator == 0:
        return None
    return round(numerator / denominator, 4)


def _dcg(relevances: list[int]) -> float:
    return sum(relevance / math.log2(index + 2) for index, relevance in enumerate(relevances))


def ndcg_at(predicted: list[str], gold: tuple[str, ...] | list[str], k: int) -> float | None:
    gains = {item: len(gold) - index for index, item in enumerate(gold)}
    ideal = _dcg(sorted(gains.values(), reverse=True)[:k])
    if ideal == 0:
        return None
    actual = _dcg([gains.get(item, 0) for item in predicted[:k]])
    return round(actual / ideal, 4)


def precision_at(predicted: list[str], gold: tuple[str, ...] | list[str], k: int) -> float | None:
    if k == 0:
        return None
    return round(len(set(predicted[:k]) & set(list(gold)[:k])) / k, 4)


def _complete(row: Mapping[str, Any]) -> bool:
    factors = row.get("factors")
    explanation = row.get("explanation")
    if not isinstance(factors, dict) or not isinstance(explanation, str):
        return False
    if set(FACTORS) - set(factors):
        return False
    return all(phrase in explanation for phrase in PHRASES)


def _confirmed(row: Mapping[str, Any]) -> bool:
    if row.get("access_confirmed") is True or row.get("finding_confirmed") is True:
        return True
    count = row.get("vulnerabilities_confirmed")
    if isinstance(count, int) and count != 0:
        return True
    return row.get("decision") == "confirmed" or row.get("status") == "confirmed"


def review_cost(
    *,
    predicted_ranked: list[str],
    predicted_abstain: dict[str, str],
    complete: dict[str, bool],
    false_confirmations: int,
) -> int:
    cost = 30 * false_confirmations
    ranked = set(predicted_ranked)
    for item, reason in GOLD_ABSTAIN.items():
        if item in ranked:
            cost += 25
        elif item not in predicted_abstain:
            cost += 15
        elif predicted_abstain[item] != reason:
            cost += 5
        else:
            cost += 1
    for item in GOLD_RANK:
        cost += 1 if item in ranked else 15
    order = {item: index for index, item in enumerate(predicted_ranked)}
    present = [item for item in GOLD_RANK if item in order]
    for left_index, left in enumerate(present):
        for right in present[left_index + 1 :]:
            if order[left] > order[right]:
                cost += 8
    cost += 2 * sum(1 for item, done in complete.items() if item in (*GOLD_RANK, *GOLD_ABSTAIN) and not done)
    return cost


def _metrics(
    predicted_ranked: list[str], predicted_abstain: dict[str, str], complete: dict[str, bool], false_confirmations: int
) -> dict[str, Any]:
    abstain_gold = set(GOLD_ABSTAIN)
    abstain_pred = set(predicted_abstain)
    reason_hits = sum(1 for item, reason in GOLD_ABSTAIN.items() if predicted_abstain.get(item) == reason)
    relevant = [item for item in complete if item in (*GOLD_RANK, *GOLD_ABSTAIN)]
    return {
        "precision_at_1": precision_at(predicted_ranked, GOLD_RANK, 1),
        "precision_at_3": precision_at(predicted_ranked, GOLD_RANK, 3),
        "precision_at_5": precision_at(predicted_ranked, GOLD_RANK, 5),
        "ndcg_at_5": ndcg_at(predicted_ranked, GOLD_RANK, 5),
        "ndcg_at_10": ndcg_at(predicted_ranked, GOLD_RANK, 10),
        "abstention_precision": _ratio(len(abstain_pred & abstain_gold), len(abstain_pred)),
        "abstention_recall": _ratio(len(abstain_pred & abstain_gold), len(abstain_gold)),
        "abstention_reason_accuracy": _ratio(reason_hits, len(GOLD_ABSTAIN)),
        "wrong_confident_rank_count": sum(1 for item in predicted_ranked if item in abstain_gold),
        "false_confirmations": false_confirmations,
        "explanation_completeness": _ratio(sum(1 for item in relevant if complete.get(item)), len(relevant)),
        "review_time_proxy": review_cost(
            predicted_ranked=predicted_ranked,
            predicted_abstain=predicted_abstain,
            complete=complete,
            false_confirmations=false_confirmations,
        ),
        "ranked": predicted_ranked,
        "abstained": predicted_abstain,
    }


def _severity_arm(queue: Mapping[str, Any]) -> dict[str, Any]:
    weights = severity_of(dict(queue))
    order = sorted(weights, key=lambda item: (-weights[item], item))
    return _metrics(order, {}, {item: False for item in order}, 0)


def _existing_arm(queue: Mapping[str, Any]) -> dict[str, Any]:
    hypotheses = queue["hypotheses"]
    _data, pairs = load_hypotheses_result(hypotheses)
    report = prioritize_hypotheses(_data, pairs, PROGRAM, 100)
    group_to_review = {group_id: review_id for review_id, group_id in queue["group_ids"].items()}
    order: list[str] = []
    items = report.get("items")
    if isinstance(items, list):
        for item in items:
            if isinstance(item, dict) and isinstance(item.get("group_id"), str):
                review_id = group_to_review.get(item["group_id"])
                if review_id is not None:
                    order.append(review_id)
    false_confirmations = 0
    if report.get("access_confirmed") is True:
        false_confirmations += 1
    count = report.get("vulnerabilities_confirmed")
    if isinstance(count, int) and count != 0:
        false_confirmations += 1
    return _metrics(order, {}, {item: False for item in order}, false_confirmations)


def _after_arm(queue: Mapping[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    report = prioritize_review(
        PROGRAM,
        list(queue["scope"]),
        100,
        external=list(queue["external"]),
        hypotheses=queue["hypotheses"],
        ledger=queue["ledger"],
        requests_per_second=1,
        dry_run=True,
    )
    ranked_rows = report["ranked"] if isinstance(report.get("ranked"), list) else []
    abstained_rows = report["abstained"] if isinstance(report.get("abstained"), list) else []
    order = [str(row["item_id"]) for row in ranked_rows if isinstance(row, dict)]
    reasons = {
        str(row["item_id"]): str(row["reason"])
        for row in abstained_rows
        if isinstance(row, dict) and isinstance(row.get("reason"), str)
    }
    complete = {str(row["item_id"]): _complete(row) for row in [*ranked_rows, *abstained_rows] if isinstance(row, dict)}
    false_confirmations = sum(1 for row in [*ranked_rows, *abstained_rows] if isinstance(row, dict) and _confirmed(row))
    if report.get("access_confirmed") is True or report.get("confirmations_created") not in {0, None}:
        false_confirmations += 1
    count = report.get("vulnerabilities_confirmed")
    if isinstance(count, int) and count != 0:
        false_confirmations += 1
    if report.get("network_requests_sent") not in {0, None}:
        false_confirmations += 1
    return _metrics(order, reasons, complete, false_confirmations), report


def _missing_scope() -> dict[str, Any]:
    queue = build_queue()
    report = prioritize_review(
        PROGRAM,
        [],
        100,
        external=list(queue["external"][:1]),
        requests_per_second=1,
        dry_run=True,
    )
    abstained = report["abstained"] if isinstance(report.get("abstained"), list) else []
    ranked = report["ranked"] if isinstance(report.get("ranked"), list) else []
    return {
        "ranked_count": len(ranked),
        "abstained_count": len(abstained),
        "reasons": sorted({str(row.get("reason")) for row in abstained if isinstance(row, dict)}),
        "false_confirmations": sum(1 for row in abstained if isinstance(row, dict) and _confirmed(row)),
        "network_requests_sent": report.get("network_requests_sent"),
    }


def evaluate() -> dict[str, Any]:
    """Score the severity sort, the existing hypothesis prioritizer, and the new engine."""
    queue = build_queue()
    after, report = _after_arm(queue)
    return {
        "type": "review-prioritization-eval",
        "cases": len(GOLD_RANK) + len(GOLD_ABSTAIN),
        "gold_ranked": len(GOLD_RANK),
        "gold_abstained": len(GOLD_ABSTAIN),
        "frozen_benchmarks_used_for_tuning": False,
        "network_requests_sent": report.get("network_requests_sent"),
        "vulnerabilities_confirmed": report.get("vulnerabilities_confirmed"),
        "access_confirmed": report.get("access_confirmed"),
        "confirmation_claims_ignored": report.get("confirmation_claims_ignored"),
        "before_severity": _severity_arm(queue),
        "before_existing_prioritizer": _existing_arm(queue),
        "after": after,
        "missing_scope": _missing_scope(),
    }


def _public(metrics: Mapping[str, Any]) -> dict[str, Any]:
    hidden = {"ranked", "abstained"}
    return {key: value for key, value in metrics.items() if key not in hidden}


def main() -> None:
    import json

    report = evaluate()
    printable = {
        "cases": report["cases"],
        "before_severity": _public(report["before_severity"]),
        "before_existing_prioritizer": _public(report["before_existing_prioritizer"]),
        "after": _public(report["after"]),
        "missing_scope": report["missing_scope"],
        "after_ranked": report["after"]["ranked"],
        "after_abstained": report["after"]["abstained"],
    }
    print(json.dumps(printable, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
