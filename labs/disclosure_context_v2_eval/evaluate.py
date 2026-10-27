"""Evaluate disclosure context quality v2 on frozen synthetic corpora.

Offline only. The detector is not allowed to open sockets. Metrics are computed
from hand-labeled dispositions. Prior information-disclosure FINAL labels are
re-scored and never rewritten.

    python -m labs.disclosure_context_v2_eval.evaluate [--split dev|final|stress|prior|all]
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import socket
import sys
import time
import tracemalloc
from typing import Any

from bugbounty_toolkit.analysis.disclosure_context import assess_context, provenance_complete
from bugbounty_toolkit.analysis.information_disclosure import assess_disclosure

LAB = Path(__file__).resolve().parent
V1_CANDIDATE = frozenset({"ready_for_manual_review", "access_control_validation_required"})
PRIOR_LAB = LAB.parent / "information_disclosure_eval"


class _NoNetwork:
    def __init__(self) -> None:
        self.attempts = 0
        self._original = socket.socket

    def __enter__(self) -> _NoNetwork:
        guard = self

        class _Blocked(socket.socket):
            def __init__(self, *args: Any, **kwargs: Any) -> None:
                guard.attempts += 1
                raise OSError("network disabled in disclosure context lab")

        socket.socket = _Blocked  # type: ignore[misc]
        return self

    def __exit__(self, *exc: object) -> None:
        socket.socket = self._original  # type: ignore[misc]


def load_split(split: str) -> list[dict[str, Any]]:
    data = json.loads((LAB / split / "cases.json").read_text(encoding="utf-8"))
    cases = data["cases"]
    if not isinstance(cases, list):
        raise ValueError("cases must be a list")
    return [case for case in cases if isinstance(case, dict)]


def split_is_frozen(split: str) -> bool:
    if split == "dev":
        return True
    path = LAB / split / "FROZEN.sha256"
    if not path.is_file():
        return False
    expected = path.read_text(encoding="utf-8").split()[0]
    digest = hashlib.sha256((LAB / split / "cases.json").read_bytes()).hexdigest()
    return digest == expected


def _rates(tp: int, fp: int, fn: int) -> dict[str, Any]:
    precision = tp / (tp + fp) if tp + fp else 1.0
    recall = tp / (tp + fn) if tp + fn else 1.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {
        "precision": round(precision, 3),
        "recall": round(recall, 3),
        "f1": round(f1, 3),
        "tp": tp,
        "fp": fp,
        "fn": fn,
    }


def evaluate(cases: list[dict[str, Any]]) -> dict[str, Any]:
    review_tp = review_fp = review_fn = 0
    high_tp = high_fp = high_fn = 0
    mismatch_tp = mismatch_fp = mismatch_fn = 0
    inconclusive_expected = inconclusive_correct = 0
    hard_promoted = provenance = leaks = confirmed = 0
    v1_fp = v2_fp = 0
    mismatches: list[dict[str, Any]] = []
    tracemalloc.start()
    started = time.perf_counter()
    with _NoNetwork() as net:
        outputs = [(case, assess_context(case).to_dict()) for case in cases]
    elapsed = time.perf_counter() - started
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    for case, out in outputs:
        expected = str(case["expected_disposition"])
        got = str(out["disposition"])
        if expected == "reviewable" and got == "reviewable":
            review_tp += 1
        elif got == "reviewable":
            review_fp += 1
        elif expected == "reviewable":
            review_fn += 1
        expect_high = bool(case["expected_high_confidence"])
        got_high = bool(out["high_confidence"])
        if expect_high and got_high:
            high_tp += 1
        elif got_high:
            high_fp += 1
        elif expect_high:
            high_fn += 1
        expect_mismatch = bool(case["expected_audience_mismatch"])
        got_mismatch = bool(out["audience_mismatch"])
        if expect_mismatch and got_mismatch:
            mismatch_tp += 1
        elif got_mismatch:
            mismatch_fp += 1
        elif expect_mismatch:
            mismatch_fn += 1
        if expected == "inconclusive":
            inconclusive_expected += 1
            inconclusive_correct += got == "inconclusive"
        if case.get("hard_negative") and (got_high or got == "reviewable"):
            hard_promoted += 1
        if provenance_complete(out["exposure"]):
            provenance += 1
        if out["v1_state"] in V1_CANDIDATE and expected != "reviewable":
            v1_fp += 1
        if got == "reviewable" and expected != "reviewable":
            v2_fp += 1
        blob = json.dumps(out, sort_keys=True)
        leaks += sum(1 for canary in case.get("canaries", []) if canary and canary in blob)
        confirmed += out["finding_confirmed"] is not False
        origin = str(out["exposure"]["content_origin"])
        human = bool(out["exposure"]["human_verification_required"])
        if (
            got != expected
            or got_high != expect_high
            or got_mismatch != expect_mismatch
            or origin != case["expected_content_origin"]
            or human != bool(case["expected_human_verification_required"])
        ):
            mismatches.append(
                {
                    "id": case["id"],
                    "expected_disposition": expected,
                    "got_disposition": got,
                    "expected_high_confidence": expect_high,
                    "got_high_confidence": got_high,
                    "expected_origin": case["expected_content_origin"],
                    "got_origin": origin,
                }
            )
    n = len(cases)
    reduction = round((v1_fp - v2_fp) / v1_fp, 3) if v1_fp else None
    return {
        "cases": n,
        "reviewable": _rates(review_tp, review_fp, review_fn),
        "high_confidence": _rates(high_tp, high_fp, high_fn),
        "audience_mismatch": _rates(mismatch_tp, mismatch_fp, mismatch_fn),
        "correct_inconclusive": inconclusive_correct,
        "expected_inconclusive": inconclusive_expected,
        "correct_inconclusive_rate": round(inconclusive_correct / inconclusive_expected, 3)
        if inconclusive_expected
        else 1.0,
        "provenance_complete": provenance,
        "provenance_complete_rate": round(provenance / n, 3) if n else 1.0,
        "hard_negative_promoted": hard_promoted,
        "baseline_v1_false_candidates": v1_fp,
        "v2_false_reviewable": v2_fp,
        "false_positive_reduction": reduction,
        "secret_leaks": leaks,
        "finding_confirmed_true": confirmed,
        "external_requests": net.attempts,
        "network_attempts": net.attempts,
        "peak_memory_kib": round(peak / 1024, 1),
        "elapsed_ms": round(elapsed * 1000, 2),
        "mismatches": mismatches,
    }


def prior_final_regression() -> dict[str, Any]:
    """Re-score the historical 18 FINAL disclosure cases without editing labels."""
    frozen_path = PRIOR_LAB / "final" / "FROZEN.sha256"
    cases_path = PRIOR_LAB / "final" / "cases.json"
    expected_hash = frozen_path.read_text(encoding="utf-8").split()[0]
    actual_hash = hashlib.sha256(cases_path.read_bytes()).hexdigest()
    payload = json.loads(cases_path.read_text(encoding="utf-8"))
    cases = [case for case in payload["cases"] if isinstance(case, dict)]
    rows: list[dict[str, Any]] = []
    leaks = confirmed = 0
    with _NoNetwork() as net:
        for case in cases:
            v1 = assess_disclosure(case)
            v2 = assess_context(case).to_dict()
            blob = json.dumps(v2, sort_keys=True)
            leaks += sum(1 for canary in case.get("canaries", []) if canary and canary in blob)
            confirmed += v2["finding_confirmed"] is not False or v1.finding_confirmed is not False
            rows.append(
                {
                    "id": case["id"],
                    "label": case["expected_state"],
                    "v1_state": v1.state,
                    "v1_matches_label": v1.state == case["expected_state"],
                    "v2_disposition": v2["disposition"],
                    "v2_high_confidence": v2["high_confidence"],
                    "v2_origin": v2["exposure"]["content_origin"],
                }
            )
    matched = sum(1 for row in rows if row["v1_matches_label"])
    f16 = next(row for row in rows if row["id"] == "F16")
    return {
        "cases": len(cases),
        "labels_frozen_sha256_ok": actual_hash == expected_hash,
        "labels_modified": False,
        "v1_state_matches": matched,
        "v1_state_accuracy": round(matched / len(cases), 3) if cases else 0.0,
        "v1_mismatches": [row["id"] for row in rows if not row["v1_matches_label"]],
        "f16_label": f16["label"],
        "f16_v1_state": f16["v1_state"],
        "f16_v2_disposition": f16["v2_disposition"],
        "f16_v2_high_confidence": f16["v2_high_confidence"],
        "f16_v2_origin": f16["v2_origin"],
        "secret_leaks": leaks,
        "finding_confirmed_true": confirmed,
        "external_requests": net.attempts,
        "dispositions": rows,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--split", choices=("dev", "final", "stress", "prior", "all"), default="all")
    args = parser.parse_args(argv)
    report: dict[str, Any] = {}
    splits = ("dev", "final", "stress") if args.split == "all" else (() if args.split == "prior" else (args.split,))
    ok = True
    for split in splits:
        frozen = split_is_frozen(split)
        report[f"{split}_frozen_sha256_ok"] = frozen
        if split != "dev" and not frozen:
            report[split] = {"metrics": "NOT_MEASURED", "reason": "FINAL/STRESS hash manifest mismatch or missing"}
            ok = False
            continue
        report[split] = evaluate(load_split(split))
        metrics = report[split]
        ok = (
            ok
            and metrics["secret_leaks"] == 0
            and metrics["external_requests"] == 0
            and metrics["finding_confirmed_true"] == 0
        )
        ok = ok and metrics["hard_negative_promoted"] == 0 and not metrics["mismatches"]
    if args.split in {"prior", "all"}:
        report["prior_final_18"] = prior_final_regression()
        prior = report["prior_final_18"]
        ok = ok and prior["labels_frozen_sha256_ok"] and prior["f16_label"] == "indicator_detected"
        ok = (
            ok
            and prior["secret_leaks"] == 0
            and prior["external_requests"] == 0
            and prior["finding_confirmed_true"] == 0
        )
        ok = ok and prior["v1_mismatches"] == ["F16"] and prior["f16_v1_state"] == "ready_for_manual_review"
        ok = ok and prior["f16_v2_disposition"] == "inconclusive" and prior["f16_v2_high_confidence"] is False
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
