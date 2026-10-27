"""Score DOM observability v3 against the DOM local v2 baseline.

Offline only. Sockets are blocked. The evaluator refuses a thawed FINAL corpus.

    python -m labs.dom_observability_v3_eval.evaluate --split dev|final|all
"""

from __future__ import annotations

import argparse
import hashlib
import json
import socket
import sys
import time
import tracemalloc
from pathlib import Path
from typing import Any

from bugbounty_toolkit.xss.dom_observability import assert_observation_integrity, classify_case

LAB = Path(__file__).resolve().parent
_LEAK_NEEDLES = (
    "set-cookie",
    "authorization:",
    "bearer ",
    "bbtk-canary",
    "ghp_",
    "akia",
    "sk-",
    "password=",
    "document.cookie",
)


def load_split(split: str) -> list[dict[str, Any]]:
    data = json.loads((LAB / split / "cases.json").read_text(encoding="utf-8"))
    cases = data["cases"]
    if not isinstance(cases, list):
        raise ValueError("cases.json is missing a cases list.")
    return cases


def final_manifest_hash() -> str:
    return (LAB / "final" / "MANIFEST.sha256").read_text(encoding="utf-8").split()[0]


def final_is_frozen() -> bool:
    actual = hashlib.sha256((LAB / "final" / "cases.json").read_bytes()).hexdigest()
    return actual == final_manifest_hash()


class _NoNetwork:
    def __init__(self) -> None:
        self.attempts = 0
        self._original = socket.socket

    def __enter__(self) -> _NoNetwork:
        guard = self

        class _Blocked(socket.socket):
            def __init__(self, *args: Any, **kwargs: Any) -> None:
                guard.attempts += 1
                raise OSError("network disabled in dom observability v3 lab")

        socket.socket = _Blocked  # type: ignore[misc]
        return self

    def __exit__(self, *exc: object) -> None:
        socket.socket = self._original  # type: ignore[misc]


def _assert_corpus_safe(cases: list[dict[str, Any]]) -> None:
    blob = json.dumps(cases)
    lowered = blob.lower()
    for needle in ("http://", "https://", "document.cookie", "burpcollaborator", "ngrok"):
        if needle in lowered:
            raise ValueError(f"Corpus contains a forbidden token: {needle}")
    for needle in _LEAK_NEEDLES:
        if needle in lowered:
            raise ValueError(f"Corpus contains a secret-like token: {needle}")


def _matches(case: dict[str, Any], record: dict[str, Any]) -> bool:
    evidence = record["execution_evidence"]
    return bool(
        record["outcome"] == case["expected_outcome"]
        and record["source_observed"] == case["expected_source_observed"]
        and evidence["executed"] == case["expected_executed"]
        and record["dom_state"] == case["expected_dom_state"]
        and record["finding_confirmed"] is False
        and evidence["claimed_from_innerhtml_alone"] is False
    )


def _score(cases: list[dict[str, Any]], generation: str) -> dict[str, Any]:
    outcome_ok = source_ok = exec_ok = state_ok = 0
    missed_total = missed_ok = 0
    negative_total = negative_ok = 0
    inner_total = inner_ok = 0
    false_source = 0
    legacy_url_claims = 0
    available_unread = 0
    confirmed = 0
    leaks = 0
    mismatches: list[dict[str, Any]] = []
    external = 0
    for case in cases:
        record = classify_case(case, generation=generation)
        assert_observation_integrity(record)
        evidence = record["execution_evidence"]
        external += int(record["external_requests"])
        if record["outcome"] == case["expected_outcome"]:
            outcome_ok += 1
        else:
            mismatches.append({"id": case["case_id"], "field": "outcome", "got": record["outcome"]})
        if record["source_observed"] == case["expected_source_observed"]:
            source_ok += 1
        if evidence["executed"] == case["expected_executed"]:
            exec_ok += 1
        if record["dom_state"] == case["expected_dom_state"]:
            state_ok += 1
        else:
            mismatches.append({"id": case["case_id"], "field": "dom_state", "got": record["dom_state"]})
        if case["previously_missed"]:
            missed_total += 1
            if _matches(case, record):
                missed_ok += 1
        if case["negative"]:
            negative_total += 1
            if evidence["executed"] is False:
                negative_ok += 1
        if case["innerhtml_without_execution"]:
            inner_total += 1
            if evidence["executed"] is False and evidence["claimed_from_innerhtml_alone"] is False:
                inner_ok += 1
        if record["source_observed"] and not case["source_was_read"]:
            false_source += 1
        if record.get("source_available") and not case["source_was_read"]:
            available_unread += 1
        legacy = record.get("legacy_v2")
        if isinstance(legacy, dict) and legacy.get("source_marker_present") and not case["source_was_read"]:
            legacy_url_claims += 1
        if record.get("finding_confirmed"):
            confirmed += 1
        blob = json.dumps(record).lower()
        if any(needle in blob for needle in _LEAK_NEEDLES):
            leaks += 1
    total = len(cases)

    def rate(num: int, den: int) -> float:
        return round(num / den, 4) if den else 0.0

    return {
        "cases": total,
        "outcome_accuracy": rate(outcome_ok, total),
        "source_read_accuracy": rate(source_ok, total),
        "execution_accuracy": rate(exec_ok, total),
        "dom_state_accuracy": rate(state_ok, total),
        "missed_case_coverage": rate(missed_ok, missed_total),
        "missed_cases": missed_total,
        "negative_retention": rate(negative_ok, negative_total),
        "no_exec_from_innerhtml_alone": rate(inner_ok, inner_total),
        "false_source_reads": false_source,
        "legacy_url_source_claims": legacy_url_claims,
        "source_available_without_read": available_unread,
        "external_requests": external,
        "automatic_confirmations": confirmed,
        "secret_leaks": leaks,
        "finding_confirmed_always_false": confirmed == 0,
        "mismatches": mismatches,
    }


def evaluate(cases: list[dict[str, Any]]) -> dict[str, Any]:
    _assert_corpus_safe(cases)
    tracemalloc.start()
    started = time.perf_counter()
    with _NoNetwork() as guard:
        v2 = _score(cases, "v2")
        v3 = _score(cases, "v3")
    elapsed = time.perf_counter() - started
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    return {
        "v2": v2,
        "v3": v3,
        "external_requests": guard.attempts,
        "network_attempts": guard.attempts,
        "secret_leaks": v2["secret_leaks"] + v3["secret_leaks"],
        "automatic_confirmations": v2["automatic_confirmations"] + v3["automatic_confirmations"],
        "elapsed_seconds": round(elapsed, 6),
        "latency_ms_per_case": round((elapsed / len(cases)) * 1000, 4) if cases else 0.0,
        "memory_peak_bytes": peak,
        "finding_confirmed_always_false": v2["finding_confirmed_always_false"] and v3["finding_confirmed_always_false"],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--split", choices=("dev", "final", "all"), default="all")
    args = parser.parse_args(argv)
    splits = ["dev", "final"] if args.split == "all" else [args.split]
    if "final" in splits and not final_is_frozen():
        print("FINAL corpus hash mismatch — refusing to evaluate a thawed FINAL.", file=sys.stderr)
        return 2
    report: dict[str, Any] = {
        "lab": "dom_observability_v3",
        "version": "0.2.2",
        "final_frozen": True,
        "final_sha256": final_manifest_hash(),
        "splits": {},
    }
    for split in splits:
        report["splits"][split] = evaluate(load_split(split))
    print(json.dumps(report, indent=2, sort_keys=True))
    bad = any(
        report["splits"][split]["secret_leaks"]
        or report["splits"][split]["automatic_confirmations"]
        or report["splits"][split]["external_requests"]
        or report["splits"][split]["v3"]["false_source_reads"]
        or report["splits"][split]["v3"]["mismatches"]
        for split in report["splits"]
    )
    return 1 if bad else 0


if __name__ == "__main__":
    raise SystemExit(main())
