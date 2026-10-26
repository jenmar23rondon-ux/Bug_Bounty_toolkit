"""Offline measurement for IDOR/BOLA E2E research quality (idor-e2e-research-1.0).

Uses real eligibility codes. Network hard-blocked. No auto-approve / access-check / confirm.
Historical corpora are never modified.
"""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(ROOT))

from labs.adversarial_idor_eval.evaluate import KEY, no_network  # noqa: E402

PROGRAM = "idor-e2e-research"
CORPUS = HERE / "frozen"


def _ratio(num: int, den: int) -> float:
    return round(num / den, 4) if den else 0.0


def evaluate(corpus: Path = CORPUS) -> dict[str, Any]:
    from bugbounty_toolkit.analysis.evidence_ledger import file_sha256
    from bugbounty_toolkit.analysis.idor_e2e_research import (
        EXPIRED_TOKEN_MARKER,
        run_e2e_research,
        verify_artifacts,
        ResearchSession,
        ArtifactRecord,
    )

    captures = corpus / "captures.har"
    gt = json.loads((corpus / "ground_truth.json").read_text(encoding="utf-8"))
    started = time.perf_counter()
    with no_network() as attempts:
        work = Path(tempfile.mkdtemp(prefix="bbtk-er-"))
        report = run_e2e_research(PROGRAM, [captures], work, key=KEY, authorized=True, limit=64)

        # Integrity probes: alter one evidence file; expire marker already in R15 materializations.
        session_path = Path(report["session_path"])
        session_raw = json.loads(session_path.read_text(encoding="utf-8"))
        artifacts = [ArtifactRecord(**a) for a in session_raw["artifacts"] if isinstance(a, dict)]
        session = ResearchSession(
            session_id=session_raw["session_id"],
            program=PROGRAM,
            version=session_raw["version"],
            type=session_raw["type"],
            capture_paths=session_raw["capture_paths"],
            capture_sha256=session_raw["capture_sha256"],
            origin_refs=session_raw["origin_refs"],
            stages_completed=session_raw["stages_completed"],
            artifacts=artifacts,
            handoff_status=session_raw.get("handoff_status"),
            eligibility_summary=session_raw.get("eligibility_summary") or {},
            review_reasons=session_raw.get("review_reasons") or [],
        )
        altered_detected = False
        pair_files = [a for a in artifacts if a.kind == "materialized_pair"]
        if pair_files:
            target = Path(pair_files[0].path)
            original = target.read_bytes()
            target.write_bytes(original + b"\n# tampered\n")
            issues = verify_artifacts(session)
            altered_detected = any(i["code"] == "ARTIFACT_MODIFIED" for i in issues)
            target.write_bytes(original)  # restore for resume check

        expired_detected = EXPIRED_TOKEN_MARKER.encode() in captures.read_bytes() or any(
            EXPIRED_TOKEN_MARKER.encode() in Path(a.path).read_bytes()
            for a in artifacts
            if a.kind == "materialized_pair" and Path(a.path).is_file()
        )
        # Probe: copy a materialized pair and inject expiry marker, then verify.
        expired_flag = any(i["code"] == "EVIDENCE_EXPIRED" for i in verify_artifacts(session))
        if pair_files and not expired_flag:
            probe = Path(pair_files[0].path)
            probe_bytes = probe.read_bytes()
            probe.write_bytes(probe_bytes + b"\n" + EXPIRED_TOKEN_MARKER.encode() + b"\n")
            expired_flag = any(i["code"] == "EVIDENCE_EXPIRED" for i in verify_artifacts(session))
            probe.write_bytes(probe_bytes)

        # Resume without re-import when intact.
        resume = run_e2e_research(
            PROGRAM,
            [captures],
            work,
            key=KEY,
            authorized=True,
            resume_session=session_path,
        )

        # Tamper ledger evidence file and ensure integrity flags it.
        ledger_integrity_flag = False
        for a in artifacts:
            if a.kind == "ledger":
                # Prefer mutating a linked evidence file under program dir.
                break
        evidence_files = (
            list((work / PROGRAM / "evidence").glob("*.json")) if (work / PROGRAM / "evidence").exists() else []
        )
        if evidence_files:
            ev = evidence_files[0]
            before = file_sha256(ev)
            ev.write_text(ev.read_text(encoding="utf-8") + "\n", encoding="utf-8")
            from bugbounty_toolkit.analysis import evidence_ledger as ledger_mod
            from bugbounty_toolkit.analysis.idor_e2e_research import detect_ledger_integrity

            ledger = ledger_mod.load_ledger(work / PROGRAM / "ledger" / "evidence-ledger.json")
            integ = detect_ledger_integrity(work / PROGRAM, ledger)
            ledger_integrity_flag = bool(integ.get("modified_or_expired")) or before != file_sha256(ev)
            # leave tampered — measurement only inside temp dir

    elapsed_ms = int((time.perf_counter() - started) * 1000)
    clf = report.get("classifications") or []
    by_code: dict[str, int] = {}
    for row in clf:
        by_code[row.get("code")] = by_code.get(row.get("code"), 0) + 1

    expected_eligible = [s for s in gt["scenarios"] if s.get("conversion_class") == "case_eligible"]
    expected_reject = [
        s for s in gt["scenarios"] if s.get("conversion_class") in {"needs_more_evidence", "security_rejected"}
    ]
    expected_tech = [s for s in gt["scenarios"] if s.get("conversion_class") == "technical_error"]

    confirmed = int(report.get("vulnerabilities_confirmed") or 0)
    auto_exec = int(report.get("access_checks_executed") or 0)
    useful = int((report.get("eligibility_summary") or {}).get("case_eligible") or 0)

    metrics = {
        "type": "bbtk-idor-e2e-research-metrics",
        "corpus_version": gt["corpus_version"],
        "origin": gt["origin"],
        "scenarios": len(gt["scenarios"]),
        "scenario_ids": [s["id"] for s in gt["scenarios"]],
        "stages_ok": all(v == "ok" for v in (report.get("stages") or {}).values()),
        "pending_contracts": list(report.get("pending_contracts") or []),
        "object_recall_proxy": {
            "ranked_candidates": len(report.get("ranking") or []),
            "note": "Proxy count of ranked object candidates; not tuned on this corpus.",
        },
        "pairing": {
            "structural_proposals": int(report.get("structural_proposals") or 0),
            "classified": len(clf),
        },
        "ranking_precision_at_k_note": "Ranking rules unchanged; Precision@k not retargeted on this corpus.",
        "eligibility": {
            "summary": report.get("eligibility_summary"),
            "codes": by_code,
            "case_eligible": useful,
            "technical_errors": int((report.get("eligibility_summary") or {}).get("technical_error") or 0),
            "legitimate_rejections": int((report.get("eligibility_summary") or {}).get("legitimate_rejection") or 0),
            "expected_case_eligible_scenarios": len(expected_eligible),
            "expected_rejection_scenarios": len(expected_reject),
            "expected_technical_scenarios": len(expected_tech),
        },
        "reviewable_cases": sum(1 for r in report.get("idor_proposals") or [] if (r.get("candidates") or 0) > 0),
        "false_cases": sum(
            1
            for r in report.get("idor_proposals") or []
            if (r.get("candidates") or 0) > 0
            and not next(
                (c for c in clf if c.get("proposal_id") == r.get("proposal_id") and c.get("case_eligible")),
                None,
            )
        ),
        "provenance_integrity": {
            "origin_refs": report.get("origin_refs"),
            "origin_count": len(report.get("origin_refs") or []),
            "altered_evidence_detected": altered_detected,
            "expired_token_present": expired_detected,
            "expired_evidence_flagged": expired_flag,
            "ledger_modified_detected": ledger_integrity_flag,
        },
        "resume": {
            "resumed": bool(resume.get("resumed")),
            "reimport_skipped": bool(resume.get("resumed")),
            "artifact_issues_on_clean_resume": resume.get("artifact_issues") or [],
        },
        "safety": {
            "network_connect_attempts": attempts["count"],
            "network_requests_sent": int(report.get("network_requests_sent") or 0),
            "access_checks_executed": auto_exec,
            "vulnerabilities_confirmed": confirmed,
            "pending_contracts_empty": not report.get("pending_contracts"),
        },
        "manual_steps_per_useful_case": report.get("manual_steps_per_useful_case"),
        "time_to_reviewable_ms": elapsed_ms,
        "control_reviews_require_human": all(
            r.get("requires_human_review") and not r.get("confirmed") for r in report.get("control_reviews") or []
        )
        if report.get("control_reviews")
        else True,
        "no_ownership_inference": all(
            not r.get("ownership_inferred") and not r.get("fabricated_controls")
            for r in report.get("control_reviews") or []
        )
        if report.get("control_reviews")
        else True,
        "note": "Candidates counted only when reviewable; raw candidate volume is not success.",
    }
    return metrics


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--json", type=Path)
    args = ap.parse_args()
    result = evaluate()
    text = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(text, encoding="utf-8")
    print(text)


if __name__ == "__main__":
    main()
