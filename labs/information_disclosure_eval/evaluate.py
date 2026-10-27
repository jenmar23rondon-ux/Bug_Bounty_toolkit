"""Evaluate the information-disclosure detector on frozen synthetic corpora.

Offline only. Reports per-category precision/recall/F1, false positives, correct
abstentions, % incomplete, secret leaks (must be 0), peak memory, time and external
requests (always 0: the detector has no network code path).

    python -m labs.information_disclosure_eval.evaluate [--split dev|final|all]
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

from bugbounty_toolkit.analysis.information_disclosure import CATEGORIES, assess_disclosure

LAB = Path(__file__).resolve().parent
ABSTAIN_STATES = frozenset({"insufficient_context", "invalid_evidence"})


def load_split(split: str) -> list[dict[str, Any]]:
    data = json.loads((LAB / split / "cases.json").read_text(encoding="utf-8"))
    cases: list[dict[str, Any]] = data["cases"]
    return cases


def final_is_frozen() -> bool:
    expected = (LAB / "final" / "FROZEN.sha256").read_text(encoding="utf-8").split()[0]
    return hashlib.sha256((LAB / "final" / "cases.json").read_bytes()).hexdigest() == expected


class _NoNetwork:
    """Count (and refuse) any socket creation while the detector runs."""

    def __init__(self) -> None:
        self.attempts = 0
        self._original = socket.socket

    def __enter__(self) -> _NoNetwork:
        guard = self

        class _Blocked(socket.socket):
            def __init__(self, *args: Any, **kwargs: Any) -> None:
                guard.attempts += 1
                raise OSError("network disabled in information disclosure lab")

        socket.socket = _Blocked  # type: ignore[misc]
        return self

    def __exit__(self, *exc: object) -> None:
        socket.socket = self._original  # type: ignore[misc]


def evaluate(cases: list[dict[str, Any]]) -> dict[str, Any]:
    tp = {c: 0 for c in CATEGORIES}
    fp = {c: 0 for c in CATEGORIES}
    fn = {c: 0 for c in CATEGORIES}
    state_correct = 0
    abstain_expected = abstain_correct = incomplete = leaks = confirmed = 0
    mismatches: list[dict[str, Any]] = []
    tracemalloc.start()
    started = time.perf_counter()
    with _NoNetwork() as net:
        outputs = [(case, assess_disclosure(case).to_dict()) for case in cases]
    elapsed = time.perf_counter() - started
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    for case, out in outputs:
        expected = set(case["expected_categories"])
        got = set(out["categories"])
        for category in CATEGORIES:
            if category in got and category in expected:
                tp[category] += 1
            elif category in got:
                fp[category] += 1
            elif category in expected:
                fn[category] += 1
        if out["state"] == case["expected_state"]:
            state_correct += 1
        else:
            mismatches.append({"id": case["id"], "expected": case["expected_state"], "got": out["state"]})
        if case["expected_state"] in ABSTAIN_STATES:
            abstain_expected += 1
            abstain_correct += out["state"] == case["expected_state"]
        incomplete += bool(out["incomplete"]) or out["state"] in ABSTAIN_STATES
        serialized = json.dumps(out)
        leaks += sum(1 for canary in case.get("canaries", []) if canary and canary in serialized)
        confirmed += out["finding_confirmed"] is not False
    per_category = {}
    for category in CATEGORIES:
        p = tp[category] / (tp[category] + fp[category]) if tp[category] + fp[category] else 1.0
        r = tp[category] / (tp[category] + fn[category]) if tp[category] + fn[category] else 1.0
        f1 = 2 * p * r / (p + r) if p + r else 0.0
        per_category[category] = {
            "precision": round(p, 3),
            "recall": round(r, 3),
            "f1": round(f1, 3),
            "tp": tp[category],
            "fp": fp[category],
            "fn": fn[category],
        }
    n = len(cases)
    return {
        "cases": n,
        "state_accuracy": round(state_correct / n, 3) if n else 0.0,
        "per_category": per_category,
        "false_positives": sum(fp.values()),
        "correct_abstentions": abstain_correct,
        "expected_abstentions": abstain_expected,
        "pct_incomplete": round(100 * incomplete / n, 1) if n else 0.0,
        "secret_leaks": leaks,
        "finding_confirmed_true": confirmed,
        "peak_memory_kib": round(peak / 1024, 1),
        "elapsed_ms": round(elapsed * 1000, 2),
        "external_requests": net.attempts,
        "state_mismatches": mismatches,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--split", choices=("dev", "final", "all"), default="all")
    args = parser.parse_args(argv)
    splits = ("dev", "final") if args.split == "all" else (args.split,)
    report: dict[str, Any] = {"final_frozen_sha256_ok": final_is_frozen()}
    for split in splits:
        report[split] = evaluate(load_split(split))
    print(json.dumps(report, indent=2, sort_keys=True))
    ok = report["final_frozen_sha256_ok"] and all(
        report[s]["secret_leaks"] == 0
        and report[s]["external_requests"] == 0
        and report[s]["finding_confirmed_true"] == 0
        for s in splits
    )
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
