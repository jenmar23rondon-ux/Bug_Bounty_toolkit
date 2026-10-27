"""Evaluate the local AI evidence assistant against a deterministic baseline.

Mock mode (CI): loopback ``MockLocalAIServer`` with fixed profiles — never real GPU
scores. Live mode (opt-in): Ollama/LM Studio only when models are already installed.

    python -m labs.local_ai_evidence_assistant_eval.evaluate [--split dev|final|all]
"""

from __future__ import annotations

import argparse
import hashlib
import json
from dataclasses import replace
from pathlib import Path
from typing import Any

from bugbounty_toolkit import ai_mock_server as mocks
from bugbounty_toolkit.analysis.ai_backend import AISelection
from bugbounty_toolkit.analysis.ai_providers import PROVIDER_REGISTRY
from bugbounty_toolkit.analysis.local_ai_evidence_assistant import (
    assist_evidence,
)
from bugbounty_toolkit.analysis.multi_review import build_evidence_bundle

LAB = Path(__file__).resolve().parent


def load_split(split: str) -> list[dict[str, Any]]:
    data = json.loads((LAB / split / "cases.json").read_text(encoding="utf-8"))
    cases: list[dict[str, Any]] = data["cases"]
    return cases


def final_is_frozen() -> bool:
    expected = (LAB / "final" / "FROZEN.sha256").read_text(encoding="utf-8").split()[0]
    return hashlib.sha256((LAB / "final" / "cases.json").read_bytes()).hexdigest() == expected


def _spec(port: int) -> Any:
    return replace(PROVIDER_REGISTRY["ollama"], port=port, allowed_ports=(port,))


def _faithful(bundle: dict[str, Any]) -> mocks.Reply:
    """Mirror deterministic assist closely — no advisory improvement."""
    fields = {row["field"]: row["value"] for row in bundle.get("observations") or [] if isinstance(row, dict)}
    private = fields.get("private_evidence_observed")
    controls = fields.get("controls_valid")
    cross = fields.get("cross_read_observed")
    pending: list[str] = []
    missing: list[str] = []
    if controls is False:
        pending.append("Re-capture owner/actor sessions after validating session controls.")
        missing.append("valid_evidence")
    if private is None:
        pending.append("Is private-resource content actually present in the owner capture?")
        missing.append("owner_baseline_read")
    if cross is None:
        pending.append("Was a distinct second-actor cross-read captured under declared auth context?")
        missing.append("second_session")
    if private is True and controls is True:
        summary = "Private marker observed under valid controls; ready for human review, not confirmation."
        if cross is True:
            missing.append("cross_actor_denied")
            pending.append("Confirm the second actor was not legitimately shared/public.")
    elif private is False and cross is True:
        summary = "Cross-read without private marker: not observed as disclosure."
    else:
        summary = "Evidence package is incomplete or inconclusive for automated triage."
    if not missing:
        missing.append("integrity_check")
    content = {
        "summary": summary,
        "explanation": "Mock faithful profile.",
        "pending_questions": pending,
        "contradictions": [],
        "draft_notes": "Advisory only.",
        "missing_data_suggestions": missing,
        "limitations": ["Simulated profile; not a real model score."],
    }
    return {"content": content}


def _enricher(bundle: dict[str, Any]) -> mocks.Reply:
    content = {
        "summary": "Private marker with valid controls; suggest additional negative control.",
        "explanation": "Mock enricher adds a mapped missing-control suggestion.",
        "pending_questions": ["Is a negative_control anonymous denial recorded?"],
        "contradictions": [],
        "draft_notes": "Human should verify negative_control before review.",
        "missing_data_suggestions": ["negative_control", "execution_proof"],
        "limitations": ["Simulated enricher profile."],
    }
    return {"content": content}


def _inventor(bundle: dict[str, Any]) -> mocks.Reply:
    content = {
        "summary": "Invented reference present.",
        "explanation": "See ev-fake-999 which does not exist.",
        "pending_questions": ["What does ev-fake-999 show?"],
        "contradictions": [],
        "draft_notes": "finding confirmed true",  # also unsafe language
        "missing_data_suggestions": ["ownership"],
        "limitations": ["Inventor profile."],
    }
    return {"content": content}


PROFILES = {
    "faithful": _faithful,
    "enricher": _enricher,
    "inventor": _inventor,
}


def evaluate(cases: list[dict[str, Any]]) -> dict[str, Any]:
    primary_ok = 0
    confirmed = 0
    leaks = 0
    invented_caught = 0
    improved = 0
    expected_improved = 0
    mismatches: list[dict[str, Any]] = []

    for case in cases:
        evidence = case["evidence"]
        # Deterministic-only path always available.
        det_only = assist_evidence(evidence, dry_run=True)
        if det_only["finding_confirmed"] or det_only["ledger_mutated"] or det_only["requests_executed"]:
            confirmed += 1
        if det_only["primary"] != "deterministic":
            mismatches.append({"id": case["id"], "reason": "primary_not_deterministic_dry_run"})
        else:
            primary_ok += 1

        profile = case.get("profile", "faithful")
        behavior = PROFILES.get(profile, _faithful)
        with mocks.MockLocalAIServer(behavior, models=("mock-assist",)) as server:
            selection = AISelection(
                provider="ollama",
                model="mock-assist",
                timeout=30.0,
                spec=_spec(server.port),
            )
            out = assist_evidence(evidence, selection=selection)
        blob = json.dumps(out, default=str)
        leaks += sum(1 for c in case.get("canaries") or [] if c and c in blob)
        if out.get("finding_confirmed") or out.get("ledger_mutated") or out.get("cloud_api_used"):
            confirmed += 1
        if out.get("primary") != case.get("expected_primary", "deterministic"):
            mismatches.append({"id": case["id"], "reason": "primary_mismatch", "got": out.get("primary")})
        else:
            primary_ok += 1
        if case.get("expected_ai_improved_advisory"):
            expected_improved += 1
            if out.get("ai_improved_advisory"):
                improved += 1
            else:
                mismatches.append({"id": case["id"], "reason": "expected_improvement_missing"})
        elif out.get("ai_improved_advisory") and profile == "faithful":
            mismatches.append({"id": case["id"], "reason": "unexpected_improvement"})
        if profile == "inventor" and out.get("evidence_invented"):
            invented_caught += 1
        elif profile == "inventor":
            # Unsafe language alone also rejects
            status = (out.get("ai") or {}).get("status")
            if status == "rejected":
                invented_caught += 1
            else:
                mismatches.append({"id": case["id"], "reason": "inventor_not_rejected", "status": status})

        # Bundle builds without raising.
        build_evidence_bundle(evidence)

    n = len(cases)
    return {
        "cases": n,
        "primary_deterministic_rate": round(primary_ok / (2 * n), 3) if n else 0.0,
        "ai_improved_advisory_count": improved,
        "expected_improved": expected_improved,
        "inventor_caught": invented_caught,
        "secret_leaks": leaks,
        "finding_confirmed_true": confirmed,
        "mismatches": mismatches,
        "note": "Mock profiles measure the harness; they are not real Qwen/DeepSeek scores. "
        "If AI does not improve advisory quality, deterministic remains primary.",
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--split", choices=("dev", "final", "all"), default="all")
    args = parser.parse_args(argv)
    splits = ["dev", "final"] if args.split == "all" else [args.split]
    if "final" in splits and not final_is_frozen():
        print("FINAL corpus hash mismatch — refusing to report success")
        return 2
    ok = True
    for split in splits:
        metrics = evaluate(load_split(split))
        print(f"=== {split.upper()} ===")
        print(json.dumps(metrics, indent=2))
        if metrics["secret_leaks"] or metrics["finding_confirmed_true"] or metrics["mismatches"]:
            ok = False
        if metrics["primary_deterministic_rate"] < 1.0:
            ok = False
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
