"""Evaluate XSS evidence-quality v2 classifiers on frozen synthetic corpora.

Offline only. No browser, no network. DOM/stored scenarios are scored from
synthetic observation dictionaries (the same shape produced by
``PlaywrightExecutionChecker`` / ``run_dom_local`` / ``run_stored_local``).

    python -m labs.xss_evidence_v2_eval.evaluate [--split dev|final|all]
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

from bugbounty_toolkit.xss.context_classifier import classify_reflected_context
from bugbounty_toolkit.xss.evidence_record import (
    DomObservation,
    assess_dom_result,
    assert_minimized,
    build_browser_evidence,
    classify_dom_state,
)

LAB = Path(__file__).resolve().parent
ABSTAIN_DECISIONS = frozenset(
    {
        "abstain_truncated",
        "abstain_malformed",
        "abstain_insufficient_context",
        "inconclusive",
        "inconclusive_browser_error",
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
                raise OSError("network disabled in xss evidence v2 lab")

        socket.socket = _Blocked  # type: ignore[misc]
        return self

    def __exit__(self, *exc: object) -> None:
        socket.socket = self._original  # type: ignore[misc]


def _first_sink(value: object) -> str | None:
    if isinstance(value, list) and value and isinstance(value[0], str):
        return value[0]
    return None


def _run_case(case: dict[str, Any]) -> dict[str, Any]:
    kind = case["kind"]
    if kind == "reflected":
        assessment = classify_reflected_context(
            case["body"],
            case["marker"],
            case["payload"],
            case.get("content_type", "text/html"),
            truncated=bool(case.get("truncated")),
        )
        out = assessment.to_dict()
        out["kind"] = "reflected"
        # Candidate-like decisions with live break-out count as detections.
        out["detection"] = assessment.decision in {"candidate", "needs_browser_confirmation"} and not assessment.escaped
        out["abstained"] = assessment.decision in ABSTAIN_DECISIONS
        out["finding_confirmed"] = False
        return out
    obs = case["observation"]
    mapped: dict[str, object]
    if obs.get("browser_failed") or obs.get("classification") == "error":
        state = classify_dom_state(DomObservation(browser_failed=True))
        mapped = {"classification": "error"}
    else:
        mapped = {
            "source_marker_present": obs.get("source_marker_present"),
            "dom_sinks": obs.get("dom_sinks", []),
            "browser_execution_observed": bool(obs.get("marker_observed") or obs.get("alert_observed")),
            "sanitized": obs.get("sanitized"),
            "csp_blocked": obs.get("csp_blocked"),
            "interaction_required": obs.get("interaction_required"),
            "classification": obs.get("classification", "ok"),
        }
        state = str(assess_dom_result(mapped, csp_header=case.get("csp"))["dom_state"])
    evidence = build_browser_evidence(
        case_id=case["id"],
        context=kind,
        execution_result=state,
        observed_source="query" if mapped.get("source_marker_present") else None,
        observed_sink=_first_sink(mapped.get("dom_sinks")),
        csp_header=case.get("csp"),
        technical_errors=obs.get("console_errors", []),
        capture_refs=[case["id"]],
        capture_bytes={"observation": json.dumps(mapped, sort_keys=True)},
    )
    assert_minimized(evidence.to_dict())
    return {
        "kind": kind,
        "dom_state": state,
        "detection": state == "execution_observed",
        "abstained": state in ABSTAIN_DECISIONS,
        "finding_confirmed": False,
        "evidence": evidence.to_dict(),
    }


def evaluate(cases: list[dict[str, Any]]) -> dict[str, Any]:
    tp = fp = fn = tn = 0
    context_correct = context_total = 0
    source_sink_correct = source_sink_total = 0
    abstain_expected = abstain_correct = 0
    exec_pred = exec_true = exec_tp = 0
    confirmed = leaks = 0
    mismatches: list[dict[str, Any]] = []
    tracemalloc.start()
    started = time.perf_counter()
    with _NoNetwork() as net:
        outputs = [(case, _run_case(case)) for case in cases]
    elapsed = time.perf_counter() - started
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    for case, out in outputs:
        expected_det = bool(case["expected_detection"])
        got_det = bool(out["detection"])
        if got_det and expected_det:
            tp += 1
        elif got_det and not expected_det:
            fp += 1
            mismatches.append({"id": case["id"], "type": "false_positive", "out": out})
        elif not got_det and expected_det:
            fn += 1
            mismatches.append({"id": case["id"], "type": "false_negative", "out": out})
        else:
            tn += 1

        if case.get("expected_abstention"):
            abstain_expected += 1
            if out.get("abstained"):
                abstain_correct += 1

        if case["kind"] == "reflected":
            context_total += 1
            if out.get("context") == case.get("expected_context") and out.get("decision") == case.get(
                "expected_decision"
            ):
                context_correct += 1
            else:
                mismatches.append(
                    {
                        "id": case["id"],
                        "type": "context_mismatch",
                        "expected": (case.get("expected_context"), case.get("expected_decision")),
                        "got": (out.get("context"), out.get("decision")),
                    }
                )
            if case.get("expect_prompt_injection_ignored") and not out.get("prompt_injection_ignored"):
                mismatches.append({"id": case["id"], "type": "prompt_injection_not_ignored"})
        else:
            source_sink_total += 1
            if out.get("dom_state") == case.get("expected_dom_state"):
                source_sink_correct += 1
            else:
                mismatches.append(
                    {
                        "id": case["id"],
                        "type": "dom_state_mismatch",
                        "expected": case.get("expected_dom_state"),
                        "got": out.get("dom_state"),
                    }
                )
            if case.get("expected_dom_state") == "execution_observed":
                exec_true += 1
            if out.get("dom_state") == "execution_observed":
                exec_pred += 1
                if case.get("expected_dom_state") == "execution_observed":
                    exec_tp += 1

        if out.get("finding_confirmed"):
            confirmed += 1
        # Leak check: evidence must not contain private fields.
        blob = json.dumps(out)
        for needle in ("set-cookie", "localStorage", "sessionStorage", "Authorization:"):
            if needle.lower() in blob.lower():
                leaks += 1

    def _rate(num: int, den: int) -> float:
        return round(num / den, 4) if den else 0.0

    detection_recall = _rate(tp, tp + fn)
    candidate_precision = _rate(tp, tp + fp)
    observed_exec_precision = _rate(exec_tp, exec_pred)
    return {
        "cases": len(cases),
        "detection_recall": detection_recall,
        "candidate_precision": candidate_precision,
        "observed_execution_precision": observed_exec_precision,
        "false_positive_rate": _rate(fp, fp + tn),
        "false_negative_rate": _rate(fn, fn + tp),
        "context_classification_accuracy": _rate(context_correct, context_total),
        "source_to_sink_recall": _rate(source_sink_correct, source_sink_total),
        "correct_abstention_rate": _rate(abstain_correct, abstain_expected),
        "counts": {"tp": tp, "fp": fp, "fn": fn, "tn": tn},
        "browser_time_seconds": 0.0,
        "request_count": net.attempts,
        "memory_peak_bytes": peak,
        "elapsed_seconds": round(elapsed, 6),
        "automatic_confirmations": confirmed,
        "secret_leaks": leaks,
        "mismatches": mismatches,
        "finding_confirmed_always_false": confirmed == 0,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--split", choices=("dev", "final", "all"), default="all")
    args = parser.parse_args(argv)
    if not final_is_frozen():
        print("FINAL corpus hash mismatch — refusing to evaluate a thawed FINAL.", file=sys.stderr)
        return 2
    splits = ["dev", "final"] if args.split == "all" else [args.split]
    report: dict[str, Any] = {"version": "xss-evidence-v2", "final_frozen": True, "splits": {}}
    for split in splits:
        report["splits"][split] = evaluate(load_split(split))
    print(json.dumps(report, indent=2, sort_keys=True))
    # Non-zero only on secret leaks or auto-confirmations.
    bad = any(
        report["splits"][s]["secret_leaks"] or report["splits"][s]["automatic_confirmations"] for s in report["splits"]
    )
    return 1 if bad else 0


if __name__ == "__main__":
    raise SystemExit(main())
