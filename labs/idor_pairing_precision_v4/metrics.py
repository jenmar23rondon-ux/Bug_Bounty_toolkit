"""Metric helpers for the pairing-precision v4 lab. No I/O."""

from __future__ import annotations


def ratio(num: int, den: int) -> float | None:
    if den == 0:
        return None
    return round(num / den, 4)


def f1(precision: float | None, recall: float | None) -> float | None:
    if precision is None or recall is None or precision + recall == 0:
        return None
    return round(2 * precision * recall / (precision + recall), 4)


def admission_counts(rows: list[dict[str, object]]) -> dict[str, int]:
    tp = fp = fn = 0
    for row in rows:
        admitted = bool(row["admitted"])
        valid = bool(row["valid_pair"])
        if admitted and valid:
            tp += 1
        elif admitted and not valid:
            fp += 1
        elif valid and not admitted:
            fn += 1
    return {"tp": tp, "fp": fp, "fn": fn}
