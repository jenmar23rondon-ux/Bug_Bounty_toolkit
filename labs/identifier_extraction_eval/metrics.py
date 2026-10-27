"""Precision / recall / F1 helpers for the identifier-extraction lab."""

from __future__ import annotations

from typing import Any


def _key(item: dict[str, Any]) -> tuple[Any, ...]:
    return (
        item.get("value"),
        item.get("value_type"),
        item.get("id_format"),
        item.get("source"),
        item.get("locator"),
    )


def score(expected: list[dict[str, Any]], predicted: list[dict[str, Any]]) -> dict[str, float]:
    """Compute precision, recall and F1 against locator-aware ground truth."""
    truth = {_key(item) for item in expected}
    preds = {_key(item) for item in predicted}
    true_positive = len(truth & preds)
    precision = true_positive / len(preds) if preds else 1.0
    recall = true_positive / len(truth) if truth else 1.0
    if precision + recall == 0:
        f1 = 0.0
    else:
        f1 = 2 * precision * recall / (precision + recall)
    return {
        "true_positive": float(true_positive),
        "predicted": float(len(preds)),
        "expected": float(len(truth)),
        "precision": precision,
        "recall": recall,
        "f1": f1,
    }


def aggregate(rows: list[dict[str, float]]) -> dict[str, float]:
    """Micro-average precision / recall / F1 across cases."""
    tp = sum(row["true_positive"] for row in rows)
    pred = sum(row["predicted"] for row in rows)
    exp = sum(row["expected"] for row in rows)
    precision = tp / pred if pred else 1.0
    recall = tp / exp if exp else 1.0
    f1 = 0.0 if precision + recall == 0 else 2 * precision * recall / (precision + recall)
    return {"precision": precision, "recall": recall, "f1": f1, "true_positive": tp, "predicted": pred, "expected": exp}
