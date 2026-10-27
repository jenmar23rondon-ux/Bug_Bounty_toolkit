"""Evaluate security-research pipelines on the v2 offline corpora.

Categories: IDOR, reflected XSS, DOM XSS, information disclosure,
IDOR↔disclosure correlation, capture→dossier. Offline/synthetic only.

    python -m labs.security_research_eval_v2.evaluate [--split dev|final|stress|all]
"""

from __future__ import annotations

import argparse
import hashlib
import json
import socket
import tempfile
import time
import tracemalloc
from pathlib import Path
from typing import Any

from bugbounty_toolkit.analysis.disclosure_access_correlation import (
    correlate_disclosure_access,
)
from bugbounty_toolkit.analysis.information_disclosure import assess_disclosure
from bugbounty_toolkit.analysis.resource_kind_lineage import correlate_resources
from bugbounty_toolkit.reporting.dossier_verifier import verify_research_dossier
from bugbounty_toolkit.xss.context_classifier import classify_reflected_context
from bugbounty_toolkit.xss.evidence_record import DomObservation, classify_dom_state

LAB = Path(__file__).resolve().parent

CATEGORIES = (
    "idor",
    "reflected_xss",
    "dom_xss",
    "information_disclosure",
    "idor_disclosure_correlation",
    "capture_to_dossier",
)


def load_split(split: str) -> list[dict[str, Any]]:
    data = json.loads((LAB / split / "cases.json").read_text(encoding="utf-8"))
    cases: list[dict[str, Any]] = data["cases"]
    return cases


def final_is_frozen() -> bool:
    expected = (LAB / "final" / "FROZEN.sha256").read_text(encoding="utf-8").split()[0]
    return hashlib.sha256((LAB / "final" / "cases.json").read_bytes()).hexdigest() == expected


def stress_is_frozen() -> bool:
    expected = (LAB / "stress" / "FROZEN.sha256").read_text(encoding="utf-8").split()[0]
    return hashlib.sha256((LAB / "stress" / "cases.json").read_bytes()).hexdigest() == expected


class _NoNetwork:
    def __init__(self) -> None:
        self.attempts = 0
        self._original = socket.socket

    def __enter__(self) -> _NoNetwork:
        guard = self

        class _Blocked(socket.socket):
            def __init__(self, *args: Any, **kwargs: Any) -> None:
                guard.attempts += 1
                raise OSError("network disabled in security_research_eval_v2")

        socket.socket = _Blocked  # type: ignore[misc]
        return self

    def __exit__(self, *exc: object) -> None:
        socket.socket = self._original  # type: ignore[misc]


def _run_case(case: dict[str, Any]) -> dict[str, Any]:
    category = case["category"]
    if category == "information_disclosure":
        payload = dict(case)
        payload.setdefault("request", {})
        payload.setdefault("url", f"https://lab.invalid/{case['id']}")
        out = assess_disclosure(payload).to_dict()
        out["match"] = out.get("state") == case["expected_state"] and set(out.get("categories") or []) == set(
            case.get("expected_categories") or []
        )
        out["predicted"] = out.get("state")
        out["finding_confirmed"] = bool(out.get("finding_confirmed"))
        return out
    if category == "reflected_xss":
        assessment = classify_reflected_context(
            case["body"],
            case["marker"],
            case["payload"],
            case.get("content_type", "text/html"),
        )
        out = assessment.to_dict()
        out["match"] = (
            assessment.decision == case["expected_decision"] and assessment.context == case["expected_context"]
        )
        out["predicted"] = assessment.decision
        out["finding_confirmed"] = False
        return out
    if category == "dom_xss":
        obs = case["observation"]
        state = classify_dom_state(
            DomObservation(
                source_observed=bool(obs.get("source_observed", False)),
                sinks=tuple(obs.get("sinks") or ()),
                marker_executed=bool(obs.get("marker_executed", False)),
                sanitized=bool(obs.get("sanitized", False)),
                csp_blocked=bool(obs.get("csp_blocked", False)),
            )
        )
        return {
            "state": state,
            "predicted": state,
            "match": state == case["expected_state"],
            "finding_confirmed": False,
        }
    if category == "idor":
        relation = correlate_resources(case["owner"], case["actor"])
        signal = bool(relation.get("idor_review_signal"))
        return {
            "idor_review_signal": signal,
            "predicted": signal,
            "match": signal == bool(case["expected_idor_review_signal"]),
            "finding_confirmed": False,
            "confirmed": bool(relation.get("confirmed")),
        }
    if category == "idor_disclosure_correlation":
        result = correlate_disclosure_access(case).to_dict()
        result["match"] = result.get("state") == case["expected_state"]
        result["predicted"] = result.get("state")
        result["finding_confirmed"] = bool(result.get("finding_confirmed"))
        return result
    if category == "capture_to_dossier":
        with tempfile.TemporaryDirectory(prefix="srev2-") as tmp:
            prog = Path(tmp) / "prog"
            (prog / "evidence").mkdir(parents=True)
            body = json.dumps(case["evidence_content"], sort_keys=True).encode()
            digest = hashlib.sha256(body).hexdigest()
            (prog / "evidence" / f"{case['id']}.json").write_bytes(body)
            ledger = json.loads(json.dumps(case["ledger"]))
            ledger["evidence"][0]["sha256"] = digest
            result = verify_research_dossier(case["package"], ledger, program_dir=prog)
            result["match"] = result.get("validation_result") == case["expected_validation_result"]
            result["predicted"] = result.get("validation_result")
            result["finding_confirmed"] = bool(result.get("finding_confirmed"))
            return result
    raise ValueError(f"unknown category: {category}")


def _empty_cat() -> dict[str, Any]:
    return {
        "cases": 0,
        "correct": 0,
        "accuracy": 1.0,
        "mismatches": [],
    }


def evaluate(cases: list[dict[str, Any]]) -> dict[str, Any]:
    by_cat: dict[str, dict[str, Any]] = {c: _empty_cat() for c in CATEGORIES}
    leaks = 0
    confirmed = 0
    tracemalloc.start()
    started = time.perf_counter()
    with _NoNetwork() as net:
        outputs: list[tuple[dict[str, Any], dict[str, Any]]] = []
        for case in cases:
            outputs.append((case, _run_case(case)))
    elapsed = time.perf_counter() - started
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    for case, out in outputs:
        cat = case["category"]
        bucket = by_cat[cat]
        bucket["cases"] += 1
        if out.get("match"):
            bucket["correct"] += 1
        else:
            bucket["mismatches"].append(
                {
                    "id": case["id"],
                    "expected": case.get("expected_state")
                    or case.get("expected_decision")
                    or case.get("expected_idor_review_signal")
                    or case.get("expected_validation_result"),
                    "got": out.get("predicted"),
                }
            )
        serialized = json.dumps(out, default=str)
        leaks += sum(1 for canary in case.get("canaries", []) if canary and canary in serialized)
        if out.get("finding_confirmed") or out.get("confirmed"):
            confirmed += 1

    for bucket in by_cat.values():
        n = bucket["cases"]
        bucket["accuracy"] = round(bucket["correct"] / n, 3) if n else 1.0

    total = len(cases)
    correct = sum(b["correct"] for b in by_cat.values())
    return {
        "cases": total,
        "overall_accuracy": round(correct / total, 3) if total else 0.0,
        "by_category": by_cat,
        "secret_leaks": leaks,
        "finding_confirmed_true": confirmed,
        "peak_memory_kib": round(peak / 1024, 1),
        "elapsed_ms": round(elapsed * 1000, 1),
        "external_requests": net.attempts,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--split", choices=("dev", "final", "stress", "all"), default="all")
    args = parser.parse_args(argv)
    splits = ["dev", "final", "stress"] if args.split == "all" else [args.split]
    if "final" in splits and not final_is_frozen():
        print("FINAL corpus hash mismatch — refusing to report success")
        return 2
    if "stress" in splits and not stress_is_frozen():
        print("STRESS corpus hash mismatch — refusing to report success")
        return 2
    overall_ok = True
    for split in splits:
        metrics = evaluate(load_split(split))
        print(f"=== {split.upper()} ===")
        print(json.dumps(metrics, indent=2))
        if (
            metrics["secret_leaks"]
            or metrics["finding_confirmed_true"]
            or metrics["external_requests"]
            or metrics["overall_accuracy"] < 1.0
        ):
            overall_ok = False
    return 0 if overall_ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
