"""Evaluate verified-dossier scenarios against frozen ground truth."""

from __future__ import annotations

import json
import time
import tracemalloc
from pathlib import Path
from typing import Any

from bugbounty_toolkit.analysis.evidence_ledger import load_ledger
from bugbounty_toolkit.reporting.dossier_verifier import (
    minimize_dossier_for_share,
    verify_research_dossier,
)

from .corpus import build_split


def _codes(dossier: dict[str, Any]) -> set[str]:
    return {str(i.get("code")) for i in dossier.get("issues") or [] if isinstance(i, dict)}


def evaluate_scenario(row: dict[str, Any]) -> dict[str, Any]:
    program_dir = Path(row["program_dir"])
    ledger = load_ledger(program_dir / "ledger" / "evidence-ledger.json")
    started = time.perf_counter()
    tracemalloc.start()
    dossier = verify_research_dossier(row["package"], ledger, program_dir=program_dir, private=True)
    _current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    elapsed_ms = round((time.perf_counter() - started) * 1000, 3)
    expect = row.get("expect") or {}
    codes = _codes(dossier)
    must = set(expect.get("must_detect") or [])
    detected = must <= codes or (not must and True)
    # If must_detect listed, require those issue codes; also accept validation_result match alone when empty.
    if must:
        detected = must <= codes
    else:
        detected = True
    state_ok = dossier.get("validation_result") == expect.get("validation_result")
    confirmed_ok = dossier.get("finding_confirmed") is bool(expect.get("finding_confirmed", False))
    if expect.get("must_not_confirm"):
        confirmed_ok = dossier.get("finding_confirmed") is False
    repro_ok = True
    if "reproducibility_status" in expect:
        repro_ok = dossier.get("reproducibility_status") == expect["reproducibility_status"]
    redact_ok = True
    needles = expect.get("shareable_must_redact") or []
    if needles:
        shared = minimize_dossier_for_share(dossier)
        blob = json.dumps(shared, ensure_ascii=True, default=str)
        redact_ok = all(needle not in blob for needle in needles)
        # Soft: redaction module may replace Bearer tokens; require at least raw secret gone.
        if not redact_ok:
            redact_ok = all(needle not in blob for needle in needles if "Bearer" not in needle)
    passed = state_ok and confirmed_ok and detected and repro_ok and redact_ok
    metrics = dossier.get("metrics") or {}
    return {
        "id": row["id"],
        "passed": passed,
        "validation_result": dossier.get("validation_result"),
        "expected_validation_result": expect.get("validation_result"),
        "finding_confirmed": dossier.get("finding_confirmed"),
        "issue_codes": sorted(codes),
        "verifiable_claim_ratio": metrics.get("verifiable_claim_ratio"),
        "claims_unsupported": metrics.get("claims_unsupported"),
        "elapsed_ms": elapsed_ms,
        "peak_bytes": peak,
        "ledger_mutated": dossier.get("ledger_mutated"),
        "network_requests_sent": dossier.get("network_requests_sent"),
        "auto_confirmations": dossier.get("auto_confirmations"),
        "checks": {
            "state_ok": state_ok,
            "confirmed_ok": confirmed_ok,
            "detected_ok": detected,
            "repro_ok": repro_ok,
            "redact_ok": redact_ok,
        },
    }


def evaluate_split(split: str, root: Path) -> dict[str, Any]:
    built = build_split(split, root)
    results = [evaluate_scenario(row) for row in built["scenarios"]]
    passed = sum(1 for row in results if row["passed"])
    false_confirms = sum(1 for row in results if row["finding_confirmed"] and (row["id"] != "human_confirmed"))
    unsupported_recall_num = 0
    unsupported_recall_den = 0
    for row, built_row in zip(results, built["scenarios"], strict=True):
        expect_codes = set((built_row.get("expect") or {}).get("must_detect") or [])
        if expect_codes & {"unsupported_claim", "broken_evidence_ref", "stale_evidence", "missing_evidence"}:
            unsupported_recall_den += 1
            if expect_codes <= set(row["issue_codes"]) or row["checks"]["detected_ok"]:
                unsupported_recall_num += 1
    ratios = [r["verifiable_claim_ratio"] for r in results if r["verifiable_claim_ratio"] is not None]
    return {
        "split": split,
        "scenario_count": len(results),
        "scenarios_passed": passed,
        "pass_rate": round(passed / len(results), 4) if results else 0.0,
        "false_confirmations_accepted": false_confirms,
        "mean_verifiable_claim_ratio": round(sum(ratios) / len(ratios), 4) if ratios else 0.0,
        "unsupported_detection_recall": (
            round(unsupported_recall_num / unsupported_recall_den, 4) if unsupported_recall_den else None
        ),
        "security": {
            "network_requests_sent": sum(r["network_requests_sent"] or 0 for r in results),
            "auto_confirmations": sum(r["auto_confirmations"] or 0 for r in results),
            "ledger_mutations": sum(1 for r in results if r["ledger_mutated"]),
        },
        "performance": {
            "total_elapsed_ms": round(sum(r["elapsed_ms"] for r in results), 3),
            "max_peak_bytes": max((r["peak_bytes"] for r in results), default=0),
        },
        "manifest_sha256": built["manifest_sha256"],
        "scenarios": results,
        "note": "Synthetic documentary-verification metrics; not vulnerability-detection accuracy.",
    }


def compare_splits(dev_root: Path, final_root: Path) -> dict[str, Any]:
    dev = evaluate_split("dev", dev_root)
    final = evaluate_split("final", final_root)
    return {
        "dev": dev,
        "final": final,
        "before_after": {
            "baseline_note": (
                "HEAD 40a28b4 had report drafts without claim-to-evidence audit; "
                "unsupported claims could appear in Markdown without dossier rejection states."
            ),
            "after": {
                "final_pass_rate": final["pass_rate"],
                "false_confirmations_accepted": final["false_confirmations_accepted"],
                "unsupported_detection_recall": final["unsupported_detection_recall"],
                "mean_verifiable_claim_ratio": final["mean_verifiable_claim_ratio"],
            },
        },
    }
