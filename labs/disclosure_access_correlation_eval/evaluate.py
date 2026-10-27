"""Evaluate disclosure-access correlation on synthetic corpora.

Offline only. Metrics: correlation precision/recall, false exposures, missed
correlations, contradictions, integrity blockers, ref loss, secret leaks (=0).

    python -m labs.disclosure_access_correlation_eval.evaluate [--split dev|final|all]
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import socket
import time
import tracemalloc
from typing import Any

from bugbounty_toolkit.analysis.disclosure_access_correlation import (
    STATES,
    correlate_disclosure_access,
)

LAB = Path(__file__).resolve().parent

POSITIVE = frozenset({"ready_for_manual_review", "correlation_candidate"})
NEGATIVE_EXPOSURE = frozenset(
    {
        "public_resource",
        "shared_resource",
        "denied_correctly",
        "reflected_or_example",
        "fake_or_invalid_credential_shape",
    }
)


def load_split(split: str) -> list[dict[str, Any]]:
    data = json.loads((LAB / split / "cases.json").read_text(encoding="utf-8"))
    cases: list[dict[str, Any]] = data["cases"]
    return cases


def final_is_frozen() -> bool:
    expected = (LAB / "final" / "FROZEN.sha256").read_text(encoding="utf-8").split()[0]
    return hashlib.sha256((LAB / "final" / "cases.json").read_bytes()).hexdigest() == expected


class _NoNetwork:
    def __init__(self) -> None:
        self.attempts = 0
        self._original = socket.socket

    def __enter__(self) -> _NoNetwork:
        guard = self

        class _Blocked(socket.socket):
            def __init__(self, *args: Any, **kwargs: Any) -> None:
                guard.attempts += 1
                raise OSError("network disabled in disclosure-access correlation lab")

        socket.socket = _Blocked  # type: ignore[misc]
        return self

    def __exit__(self, *exc: object) -> None:
        socket.socket = self._original  # type: ignore[misc]


def evaluate(cases: list[dict[str, Any]]) -> dict[str, Any]:
    tp = fp = fn = tn = 0
    state_correct = 0
    false_exposures = 0
    missed = 0
    contradictions = 0
    integrity_blockers = 0
    ref_loss = 0
    leaks = 0
    confirmed = 0
    mismatches: list[dict[str, Any]] = []
    tracemalloc.start()
    started = time.perf_counter()
    with _NoNetwork() as net:
        outputs = [(case, correlate_disclosure_access(case).to_dict()) for case in cases]
    elapsed = time.perf_counter() - started
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    for case, out in outputs:
        expected = case["expected_state"]
        got = out["state"]
        if got == expected:
            state_correct += 1
        else:
            mismatches.append({"id": case["id"], "expected": expected, "got": got})
        exp_pos = expected in POSITIVE
        got_pos = got in POSITIVE
        if exp_pos and got_pos:
            tp += 1
        elif got_pos and not exp_pos:
            fp += 1
            false_exposures += 1
        elif exp_pos and not got_pos:
            fn += 1
            missed += 1
        else:
            tn += 1
        contradictions += len(out.get("contradictions") or [])
        integrity_blockers += len(out.get("integrity_blockers") or [])
        ref_loss += sum(1 for b in out.get("integrity_blockers") or [] if b.endswith(":ref_loss"))
        serialized = json.dumps(out)
        leaks += sum(1 for canary in case.get("canaries", []) if canary and canary in serialized)
        confirmed += out.get("finding_confirmed") is not False
        assert got in STATES

    precision = tp / (tp + fp) if tp + fp else 1.0
    recall = tp / (tp + fn) if tp + fn else 1.0
    n = len(cases)
    return {
        "cases": n,
        "state_accuracy": round(state_correct / n, 3) if n else 0.0,
        "correlation_precision": round(precision, 3),
        "correlation_recall": round(recall, 3),
        "false_exposures": false_exposures,
        "missed_correlations": missed,
        "contradictions": contradictions,
        "integrity_blockers": integrity_blockers,
        "ref_loss": ref_loss,
        "secret_leaks": leaks,
        "finding_confirmed_true": confirmed,
        "peak_memory_kib": round(peak / 1024, 1),
        "elapsed_ms": round(elapsed * 1000, 1),
        "external_requests": net.attempts,
        "mismatches": mismatches,
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "tn": tn,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--split", choices=("dev", "final", "all"), default="all")
    args = parser.parse_args(argv)
    splits = ["dev", "final"] if args.split == "all" else [args.split]
    if "final" in splits and not final_is_frozen():
        print("FINAL corpus hash mismatch — refusing to report success")
        return 2
    overall_ok = True
    for split in splits:
        metrics = evaluate(load_split(split))
        print(f"=== {split.upper()} ===")
        print(json.dumps(metrics, indent=2))
        if metrics["secret_leaks"] or metrics["finding_confirmed_true"] or metrics["external_requests"]:
            overall_ok = False
        if metrics["false_exposures"]:
            overall_ok = False
    return 0 if overall_ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
