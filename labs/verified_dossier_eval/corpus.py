"""Synthetic DEV/FINAL corpora for claim-to-evidence dossier verification.

Ground truth is authored here independently of verifier outputs. Scenarios use
only local synthetic files; no network and no real program data.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from bugbounty_toolkit.analysis.evidence_ledger import new_ledger

SCHEMA = "bbtk-evidence-ledger/1"
NOW = "2026-10-26T15:00:00Z"
FP = "fp-dossier-lab-v1"


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _write(path: Path, payload: dict[str, Any] | str) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(payload, str):
        path.write_text(payload, encoding="utf-8")
    else:
        path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return _sha(path)


def _surface(sid: str = "s-orders") -> dict[str, Any]:
    return {
        "surface_id": sid,
        "kind": "endpoint",
        "ref": "/api/orders/{id}",
        "status": "investigated",
        "fingerprint": FP,
    }


def _ev(eid: str, rel: str, digest: str) -> dict[str, Any]:
    return {
        "evidence_id": eid,
        "path": rel,
        "sha256": digest,
        "surface_fingerprint": FP,
        "provenance": {"tool": "synthetic-lab", "captured_at": NOW},
    }


def _cand(
    cid: str,
    refs: list[str],
    *,
    state: str = "candidate",
    category: str = "idor",
    **extra: Any,
) -> dict[str, Any]:
    row: dict[str, Any] = {
        "candidate_id": cid,
        "surface_id": "s-orders",
        "category": category,
        "title": cid,
        "state": state,
        "evidence_refs": refs,
        "raised_by": "analyst",
    }
    row.update(extra)
    return row


def _program(root: Path, name: str) -> Path:
    path = root / name
    (path / "evidence").mkdir(parents=True, exist_ok=True)
    (path / "ledger").mkdir(parents=True, exist_ok=True)
    return path


def scenario_complete_idor(root: Path) -> dict[str, Any]:
    prog = _program(root, "complete_idor")
    digest = _write(
        prog / "evidence" / "control.json",
        {
            "type": "access-control",
            "classification": "candidate",
            "confirmed": False,
            "steps": [
                {"step": "owner_control", "status_code": 200, "application_success": True, "owner_private_match": True},
                {"step": "cross_read", "status_code": 200, "application_success": True, "owner_private_match": True},
                {"step": "public_negative_control", "status_code": 403, "application_success": False},
            ],
        },
    )
    ledger = new_ledger("complete_idor")
    ledger["surfaces"] = [_surface()]
    ledger["evidence"] = [_ev("e-complete", "evidence/control.json", digest)]
    ledger["candidates"] = [_cand("c-complete", ["e-complete"], state="requires_validation", blockers=["human replay"])]
    _write(prog / "ledger" / "evidence-ledger.json", ledger)
    package = {
        "candidate_id": "c-complete",
        "declared_ledger_state": "requires_validation",
        "expected_behavior": "Cross-account read of private order must be denied.",
        "expected_behavior_source": "lab_spec",
        "observed_behavior": "Actor session retrieved owner private marker.",
        "observed_behavior_refs": ["e-complete"],
        "control_evidence_refs": ["e-complete"],
        "negative_controls": ["public_negative_control"],
        "deterministic_result": {"classification": "candidate"},
        "claims": [
            {
                "claim_id": "cl-state",
                "kind": "ledger_state",
                "text": "requires_validation",
                "evidence_refs": ["e-complete"],
            },
            {
                "claim_id": "cl-obs",
                "kind": "observed_behavior",
                "text": "private marker seen",
                "evidence_refs": ["e-complete"],
            },
            {
                "claim_id": "cl-ctrl",
                "kind": "control_result",
                "text": "owner control valid",
                "evidence_refs": ["e-complete"],
            },
            {
                "claim_id": "cl-exp",
                "kind": "expected_behavior",
                "text": "deny cross-account private read",
                "source": "lab_spec",
                "evidence_refs": [],
            },
        ],
    }
    return {
        "id": "complete_idor",
        "program_dir": str(prog),
        "package": package,
        "expect": {
            "validation_result": "human_validation_required",
            "finding_confirmed": False,
            "must_detect": [],
            "must_not_confirm": True,
        },
    }


def scenario_denied(root: Path) -> dict[str, Any]:
    prog = _program(root, "denied")
    digest = _write(
        prog / "evidence" / "denied.json",
        {"type": "access-control", "classification": "rejected_in_this_test", "confirmed": False, "steps": []},
    )
    ledger = new_ledger("denied")
    ledger["surfaces"] = [_surface()]
    ledger["evidence"] = [_ev("e-denied", "evidence/denied.json", digest)]
    ledger["candidates"] = [
        _cand(
            "c-denied",
            ["e-denied"],
            state="rejected",
            rejection={"reason": "expected_behavior", "detail": "cross read denied with 403"},
            review={"reviewer": "bob", "method": "human_manual", "basis": "403 denial", "reviewed_at": NOW},
        )
    ]
    _write(prog / "ledger" / "evidence-ledger.json", ledger)
    package = {
        "candidate_id": "c-denied",
        "declared_ledger_state": "rejected",
        "expected_behavior": "Unauthorized read denied.",
        "expected_behavior_source": "lab_spec",
        "observed_behavior": "HTTP 403 and application_success false.",
        "observed_behavior_refs": ["e-denied"],
        "deterministic_result": {"classification": "rejected_in_this_test"},
        "claims": [
            {"claim_id": "cl-state", "kind": "ledger_state", "text": "rejected", "evidence_refs": ["e-denied"]},
            {"claim_id": "cl-obs", "kind": "observed_behavior", "text": "denied", "evidence_refs": ["e-denied"]},
        ],
    }
    return {
        "id": "denied",
        "program_dir": str(prog),
        "package": package,
        "expect": {"validation_result": "complete_for_review", "finding_confirmed": False, "must_detect": []},
    }


def scenario_public(root: Path) -> dict[str, Any]:
    prog = _program(root, "public")
    digest = _write(
        prog / "evidence" / "public.json",
        {"type": "access-control", "classification": "public_endpoint", "resource_private": False},
    )
    ledger = new_ledger("public")
    ledger["surfaces"] = [_surface()]
    ledger["evidence"] = [_ev("e-pub", "evidence/public.json", digest)]
    ledger["candidates"] = [
        _cand(
            "c-pub",
            ["e-pub"],
            state="rejected",
            rejection={"reason": "expected_behavior", "detail": "public resource"},
            review={"reviewer": "bob", "method": "human_manual", "basis": "public", "reviewed_at": NOW},
        )
    ]
    _write(prog / "ledger" / "evidence-ledger.json", ledger)
    package = {
        "candidate_id": "c-pub",
        "declared_ledger_state": "rejected",
        "expected_behavior": "Public catalog readable.",
        "expected_behavior_source": "program_policy",
        "observed_behavior": "Same body for owner and actor.",
        "observed_behavior_refs": ["e-pub"],
        "claims": [
            {"claim_id": "cl-state", "kind": "ledger_state", "text": "rejected", "evidence_refs": ["e-pub"]},
            {"claim_id": "cl-obs", "kind": "observed_behavior", "text": "public", "evidence_refs": ["e-pub"]},
        ],
    }
    return {
        "id": "public",
        "program_dir": str(prog),
        "package": package,
        "expect": {"validation_result": "complete_for_review", "finding_confirmed": False},
    }


def scenario_shared(root: Path) -> dict[str, Any]:
    prog = _program(root, "shared")
    digest = _write(
        prog / "evidence" / "shared.json",
        {"type": "access-control", "classification": "rejected_in_this_test", "shared_resource": True},
    )
    ledger = new_ledger("shared")
    ledger["surfaces"] = [_surface()]
    ledger["evidence"] = [_ev("e-share", "evidence/shared.json", digest)]
    ledger["candidates"] = [
        _cand(
            "c-share",
            ["e-share"],
            state="rejected",
            rejection={"reason": "expected_behavior", "detail": "legitimately shared"},
            review={"reviewer": "cara", "method": "human_manual", "basis": "ACL share", "reviewed_at": NOW},
        )
    ]
    _write(prog / "ledger" / "evidence-ledger.json", ledger)
    package = {
        "candidate_id": "c-share",
        "declared_ledger_state": "rejected",
        "expected_behavior": "Shared ACL grants read.",
        "expected_behavior_source": "explicit_declaration",
        "observed_behavior": "Share grant present.",
        "observed_behavior_refs": ["e-share"],
        "claims": [
            {"claim_id": "cl-state", "kind": "ledger_state", "text": "rejected", "evidence_refs": ["e-share"]},
            {"claim_id": "cl-obs", "kind": "observed_behavior", "text": "shared ok", "evidence_refs": ["e-share"]},
        ],
    }
    return {
        "id": "shared",
        "program_dir": str(prog),
        "package": package,
        "expect": {"validation_result": "complete_for_review", "finding_confirmed": False},
    }


def scenario_fp_http200(root: Path) -> dict[str, Any]:
    prog = _program(root, "fp_http200")
    digest = _write(
        prog / "evidence" / "fp.json",
        {"type": "access-control", "classification": "inconclusive", "status_code": 200},
    )
    ledger = new_ledger("fp_http200")
    ledger["surfaces"] = [_surface()]
    ledger["evidence"] = [_ev("e-fp", "evidence/fp.json", digest)]
    ledger["candidates"] = [_cand("c-fp", ["e-fp"])]
    _write(prog / "ledger" / "evidence-ledger.json", ledger)
    package = {
        "candidate_id": "c-fp",
        "declared_ledger_state": "candidate",
        "http_200_as_unauthorized": True,
        "expected_behavior": "Private resource denied to other users.",
        "expected_behavior_source": "lab_spec",
        "observed_behavior": "HTTP 200 without private marker proof.",
        "observed_behavior_refs": ["e-fp"],
        "claims": [
            {
                "claim_id": "cl-class",
                "kind": "classification",
                "text": "HTTP 200 proves unauthorized IDOR access",
                "evidence_refs": ["e-fp"],
            }
        ],
    }
    return {
        "id": "fp_http200",
        "program_dir": str(prog),
        "package": package,
        "expect": {
            "validation_result": "unsupported_claim",
            "finding_confirmed": False,
            "must_detect": ["unsupported_claim"],
        },
    }


def scenario_altered(root: Path) -> dict[str, Any]:
    prog = _program(root, "altered")
    path = prog / "evidence" / "alt.json"
    digest = _write(path, {"type": "access-control", "classification": "candidate", "v": 1})
    ledger = new_ledger("altered")
    ledger["surfaces"] = [_surface()]
    ledger["evidence"] = [_ev("e-alt", "evidence/alt.json", digest)]
    ledger["candidates"] = [_cand("c-alt", ["e-alt"])]
    _write(prog / "ledger" / "evidence-ledger.json", ledger)
    # Alter after recording.
    path.write_text(json.dumps({"type": "access-control", "classification": "candidate", "v": 2}), encoding="utf-8")
    package = {
        "candidate_id": "c-alt",
        "declared_ledger_state": "candidate",
        "observed_behavior": "candidate signal",
        "observed_behavior_refs": ["e-alt"],
        "claims": [
            {"claim_id": "cl-obs", "kind": "observed_behavior", "text": "seen", "evidence_refs": ["e-alt"]},
        ],
    }
    return {
        "id": "altered",
        "program_dir": str(prog),
        "package": package,
        "expect": {
            "validation_result": "stale_evidence",
            "finding_confirmed": False,
            "must_detect": ["stale_evidence"],
        },
    }


def scenario_missing_ref(root: Path) -> dict[str, Any]:
    prog = _program(root, "missing_ref")
    digest = _write(prog / "evidence" / "ok.json", {"type": "access-control", "classification": "candidate"})
    ledger = new_ledger("missing_ref")
    ledger["surfaces"] = [_surface()]
    ledger["evidence"] = [_ev("e-ok", "evidence/ok.json", digest)]
    ledger["candidates"] = [_cand("c-miss", ["e-ok"])]
    _write(prog / "ledger" / "evidence-ledger.json", ledger)
    package = {
        "candidate_id": "c-miss",
        "claims": [
            {"claim_id": "cl-ghost", "kind": "evidence_reference", "text": "ghost", "evidence_refs": ["e-ghost"]},
        ],
    }
    return {
        "id": "missing_ref",
        "program_dir": str(prog),
        "package": package,
        "expect": {
            "validation_result": "missing_evidence",
            "finding_confirmed": False,
            "must_detect": ["broken_evidence_ref"],
        },
    }


def scenario_stale_confirmed(root: Path) -> dict[str, Any]:
    """Evidence file removed after a would-be confirmation package."""
    prog = _program(root, "stale")
    path = prog / "evidence" / "gone.json"
    digest = _write(path, {"type": "access-control", "classification": "candidate"})
    ledger = new_ledger("stale")
    ledger["surfaces"] = [_surface()]
    ledger["evidence"] = [_ev("e-gone", "evidence/gone.json", digest)]
    ledger["candidates"] = [_cand("c-stale", ["e-gone"], state="requires_validation", blockers=["replay"])]
    _write(prog / "ledger" / "evidence-ledger.json", ledger)
    path.unlink()
    package = {
        "candidate_id": "c-stale",
        "declared_ledger_state": "requires_validation",
        "claims": [
            {"claim_id": "cl-obs", "kind": "observed_behavior", "text": "was there", "evidence_refs": ["e-gone"]},
        ],
    }
    return {
        "id": "stale",
        "program_dir": str(prog),
        "package": package,
        "expect": {
            "validation_result": "missing_evidence",
            "finding_confirmed": False,
            "must_detect": ["missing_evidence"],
        },
    }


def scenario_invented_impact(root: Path) -> dict[str, Any]:
    prog = _program(root, "invented_impact")
    digest = _write(prog / "evidence" / "x.json", {"type": "access-control", "classification": "candidate"})
    ledger = new_ledger("invented_impact")
    ledger["surfaces"] = [_surface()]
    ledger["evidence"] = [_ev("e-x", "evidence/x.json", digest)]
    ledger["candidates"] = [_cand("c-imp", ["e-x"])]
    _write(prog / "ledger" / "evidence-ledger.json", ledger)
    package = {
        "candidate_id": "c-imp",
        "impact_invented": True,
        "claims": [
            {
                "claim_id": "cl-imp",
                "kind": "impact",
                "text": "Critical because /api/orders endpoint exposes all tenants",
                "evidence_refs": [],
            }
        ],
    }
    return {
        "id": "invented_impact",
        "program_dir": str(prog),
        "package": package,
        "expect": {
            "validation_result": "unsupported_claim",
            "finding_confirmed": False,
            "must_detect": ["unsupported_claim"],
        },
    }


def scenario_missing_ownership(root: Path) -> dict[str, Any]:
    prog = _program(root, "missing_ownership")
    digest = _write(prog / "evidence" / "o.json", {"type": "access-control", "classification": "candidate"})
    ledger = new_ledger("missing_ownership")
    ledger["surfaces"] = [_surface()]
    ledger["evidence"] = [_ev("e-o", "evidence/o.json", digest)]
    ledger["candidates"] = [_cand("c-own", ["e-o"])]
    _write(prog / "ledger" / "evidence-ledger.json", ledger)
    package = {
        "candidate_id": "c-own",
        "claims": [
            {"claim_id": "cl-own", "kind": "ownership", "text": "user A owns order 5", "evidence_refs": []},
        ],
    }
    return {
        "id": "missing_ownership",
        "program_dir": str(prog),
        "package": package,
        "expect": {
            "validation_result": "unsupported_claim",
            "finding_confirmed": False,
            "must_detect": ["unsupported_claim"],
        },
    }


def scenario_ai_unverified(root: Path) -> dict[str, Any]:
    prog = _program(root, "ai_unverified")
    digest = _write(prog / "evidence" / "ai.json", {"type": "access-control", "classification": "candidate"})
    ledger = new_ledger("ai_unverified")
    ledger["surfaces"] = [_surface()]
    ledger["evidence"] = [_ev("e-ai", "evidence/ai.json", digest)]
    ledger["candidates"] = [_cand("c-ai", ["e-ai"])]
    _write(prog / "ledger" / "evidence-ledger.json", ledger)
    package = {
        "candidate_id": "c-ai",
        "ai_confirmation": True,
        "treat_ai_as_confirmed": True,
        "claims": [
            {
                "claim_id": "cl-ai",
                "kind": "ai_conclusion",
                "text": "Model confirmed IDOR",
                "evidence_refs": ["e-ai"],
            },
            {
                "claim_id": "cl-conf",
                "kind": "confirmation",
                "text": "confirmed by llm",
                "evidence_refs": ["e-ai"],
            },
        ],
    }
    return {
        "id": "ai_unverified",
        "program_dir": str(prog),
        "package": package,
        "expect": {
            "validation_result": "unsupported_claim",
            "finding_confirmed": False,
            "must_detect": ["unsupported_claim", "human_validation_required"],
            "must_not_confirm": True,
        },
    }


def scenario_rejected_as_confirmed(root: Path) -> dict[str, Any]:
    prog = _program(root, "rejected_as_confirmed")
    digest = _write(prog / "evidence" / "r.json", {"type": "access-control", "classification": "rejected_in_this_test"})
    ledger = new_ledger("rejected_as_confirmed")
    ledger["surfaces"] = [_surface()]
    ledger["evidence"] = [_ev("e-r", "evidence/r.json", digest)]
    ledger["candidates"] = [
        _cand(
            "c-rej",
            ["e-r"],
            state="rejected",
            rejection={"reason": "false_positive", "detail": "no private match"},
            review={"reviewer": "bob", "method": "human_manual", "basis": "fp", "reviewed_at": NOW},
        )
    ]
    _write(prog / "ledger" / "evidence-ledger.json", ledger)
    package = {
        "candidate_id": "c-rej",
        "declared_ledger_state": "confirmed",
        "present_rejected_as_confirmed": True,
        "claims": [
            {"claim_id": "cl-state", "kind": "ledger_state", "text": "confirmed", "evidence_refs": ["e-r"]},
            {"claim_id": "cl-conf", "kind": "confirmation", "text": "confirmed", "evidence_refs": ["e-r"]},
        ],
    }
    return {
        "id": "rejected_as_confirmed",
        "program_dir": str(prog),
        "package": package,
        "expect": {
            "validation_result": "contradictory_evidence",
            "finding_confirmed": False,
            "must_detect": ["ledger_state_mismatch"],
            "must_not_confirm": True,
        },
    }


def scenario_invented_steps(root: Path) -> dict[str, Any]:
    prog = _program(root, "invented_steps")
    digest = _write(prog / "evidence" / "s.json", {"type": "access-control", "classification": "candidate"})
    ledger = new_ledger("invented_steps")
    ledger["surfaces"] = [_surface()]
    ledger["evidence"] = [_ev("e-s", "evidence/s.json", digest)]
    ledger["candidates"] = [_cand("c-steps", ["e-s"])]
    _write(prog / "ledger" / "evidence-ledger.json", ledger)
    package = {
        "candidate_id": "c-steps",
        "invented_reproduction": True,
        "claims": [
            {
                "claim_id": "cl-step",
                "kind": "reproduction_step",
                "text": "Send crafted payload=../etc/passwd",
                "evidence_refs": [],
                "invented": True,
            }
        ],
    }
    return {
        "id": "invented_steps",
        "program_dir": str(prog),
        "package": package,
        "expect": {
            "validation_result": "unsupported_claim",
            "finding_confirmed": False,
            "must_detect": ["unsupported_claim"],
            "reproducibility_status": "steps_invented",
        },
    }


def scenario_duplicate_report(root: Path) -> dict[str, Any]:
    """Two packages for same candidate; verifier is per-package (no merge)."""
    prog = _program(root, "duplicate_report")
    digest = _write(prog / "evidence" / "d.json", {"type": "access-control", "classification": "candidate"})
    ledger = new_ledger("duplicate_report")
    ledger["surfaces"] = [_surface()]
    ledger["evidence"] = [_ev("e-d", "evidence/d.json", digest)]
    ledger["candidates"] = [_cand("c-dup", ["e-d"])]
    _write(prog / "ledger" / "evidence-ledger.json", ledger)
    package = {
        "candidate_id": "c-dup",
        "declared_ledger_state": "candidate",
        "claims": [
            {"claim_id": "cl-state", "kind": "ledger_state", "text": "candidate", "evidence_refs": ["e-d"]},
            {"claim_id": "cl-obs", "kind": "observed_behavior", "text": "dup draft", "evidence_refs": ["e-d"]},
        ],
    }
    return {
        "id": "duplicate_report",
        "program_dir": str(prog),
        "package": package,
        "expect": {"validation_result": "human_validation_required", "finding_confirmed": False},
    }


def scenario_sensitive_observations(root: Path) -> dict[str, Any]:
    prog = _program(root, "sensitive")
    digest = _write(
        prog / "evidence" / "sec.json",
        {"type": "access-control", "classification": "candidate", "token": "secret-token-value"},
    )
    ledger = new_ledger("sensitive")
    ledger["surfaces"] = [_surface()]
    ledger["evidence"] = [_ev("e-sec", "evidence/sec.json", digest)]
    ledger["candidates"] = [_cand("c-sec", ["e-sec"])]
    _write(prog / "ledger" / "evidence-ledger.json", ledger)
    package = {
        "candidate_id": "c-sec",
        "observed_behavior": "Authorization: Bearer super-secret-token-xyz",
        "observed_behavior_refs": ["e-sec"],
        "claims": [
            {
                "claim_id": "cl-obs",
                "kind": "observed_behavior",
                "text": "Authorization: Bearer super-secret-token-xyz",
                "evidence_refs": ["e-sec"],
            }
        ],
    }
    return {
        "id": "sensitive",
        "program_dir": str(prog),
        "package": package,
        "expect": {
            "validation_result": "human_validation_required",
            "finding_confirmed": False,
            "shareable_must_redact": ["super-secret-token-xyz", "Bearer super-secret"],
        },
    }


def scenario_contradictory_json(root: Path) -> dict[str, Any]:
    prog = _program(root, "contradictory")
    digest = _write(
        prog / "evidence" / "c.json",
        {"type": "access-control", "classification": "rejected_in_this_test"},
    )
    ledger = new_ledger("contradictory")
    ledger["surfaces"] = [_surface()]
    ledger["evidence"] = [_ev("e-c", "evidence/c.json", digest)]
    ledger["candidates"] = [_cand("c-con", ["e-c"])]
    _write(prog / "ledger" / "evidence-ledger.json", ledger)
    package = {
        "candidate_id": "c-con",
        "contradictory_json": True,
        "deterministic_result": {"classification": "rejected_in_this_test"},
        "reported_classification": "candidate",
        "classification_matches_deterministic": False,
        "claims": [
            {
                "claim_id": "cl-class",
                "kind": "classification",
                "text": "candidate",
                "evidence_refs": ["e-c"],
            }
        ],
    }
    return {
        "id": "contradictory",
        "program_dir": str(prog),
        "package": package,
        "expect": {
            "validation_result": "contradictory_evidence",
            "finding_confirmed": False,
            "must_detect": ["contradictory_evidence"],
        },
    }


def scenario_insufficient(root: Path) -> dict[str, Any]:
    prog = _program(root, "insufficient")
    digest = _write(
        prog / "evidence" / "i.json",
        {"type": "access-control", "classification": "inconclusive"},
    )
    ledger = new_ledger("insufficient")
    ledger["surfaces"] = [_surface()]
    ledger["evidence"] = [_ev("e-i", "evidence/i.json", digest)]
    ledger["candidates"] = [_cand("c-ins", ["e-i"], state="requires_validation", blockers=["ownership proof"])]
    _write(prog / "ledger" / "evidence-ledger.json", ledger)
    package = {
        "candidate_id": "c-ins",
        "declared_ledger_state": "requires_validation",
        "expected_behavior": "Private order denied.",
        "expected_behavior_source": "lab_spec",
        "observed_behavior": "Inconclusive without ownership.",
        "observed_behavior_refs": ["e-i"],
        "claims": [
            {"claim_id": "cl-state", "kind": "ledger_state", "text": "requires_validation", "evidence_refs": ["e-i"]},
            {"claim_id": "cl-obs", "kind": "observed_behavior", "text": "inconclusive", "evidence_refs": ["e-i"]},
            {"claim_id": "cl-own", "kind": "ownership", "text": "assumed ownership", "evidence_refs": []},
        ],
    }
    return {
        "id": "insufficient",
        "program_dir": str(prog),
        "package": package,
        "expect": {
            "validation_result": "unsupported_claim",
            "finding_confirmed": False,
            "must_detect": ["unsupported_claim"],
            "must_not_confirm": True,
        },
    }


def scenario_human_confirmed_lab(root: Path) -> dict[str, Any]:
    prog = _program(root, "human_confirmed")
    digest = _write(
        prog / "evidence" / "h.json",
        {
            "type": "access-control",
            "classification": "candidate",
            "steps": [
                {"step": "owner_control", "application_success": True},
                {"step": "cross_read", "owner_private_match": True, "application_success": True},
            ],
        },
    )
    ledger = new_ledger("human_confirmed")
    ledger["surfaces"] = [_surface()]
    ledger["evidence"] = [_ev("e-h", "evidence/h.json", digest)]
    ledger["candidates"] = [
        _cand(
            "c-human",
            ["e-h"],
            state="confirmed",
            review={
                "reviewer": "erin",
                "method": "human_lab_reproduction",
                "basis": "Replayed cross-read; private marker observed under actor session",
                "reviewed_at": NOW,
            },
        )
    ]
    _write(prog / "ledger" / "evidence-ledger.json", ledger)
    package = {
        "candidate_id": "c-human",
        "declared_ledger_state": "confirmed",
        "expected_behavior": "Cross-account private read denied.",
        "expected_behavior_source": "lab_spec",
        "observed_behavior": "Private marker returned to actor.",
        "observed_behavior_refs": ["e-h"],
        "control_evidence_refs": ["e-h"],
        "claims": [
            {"claim_id": "cl-state", "kind": "ledger_state", "text": "confirmed", "evidence_refs": ["e-h"]},
            {"claim_id": "cl-obs", "kind": "observed_behavior", "text": "marker", "evidence_refs": ["e-h"]},
            {"claim_id": "cl-conf", "kind": "confirmation", "text": "human lab reproduction", "evidence_refs": ["e-h"]},
            {
                "claim_id": "cl-step",
                "kind": "reproduction_step",
                "text": "Replay recorded cross_read from evidence/h.json",
                "evidence_refs": ["e-h"],
            },
            {
                "claim_id": "cl-exp",
                "kind": "expected_behavior",
                "text": "deny",
                "source": "lab_spec",
                "evidence_refs": [],
            },
        ],
    }
    return {
        "id": "human_confirmed",
        "program_dir": str(prog),
        "package": package,
        "expect": {
            "validation_result": "complete_for_review",
            "finding_confirmed": True,
            "reproducibility_status": "reproducible_with_recorded_evidence",
        },
    }


def scenario_invalid_provenance(root: Path) -> dict[str, Any]:
    prog = _program(root, "invalid_prov")
    digest = _write(prog / "evidence" / "p.json", {"type": "access-control", "classification": "candidate"})
    ledger = new_ledger("invalid_prov")
    ledger["surfaces"] = [_surface()]
    ledger["evidence"] = [
        {
            "evidence_id": "e-p",
            "path": "evidence/p.json",
            "sha256": digest,
            "surface_fingerprint": FP,
            "provenance": {"tool": "", "captured_at": ""},
        }
    ]
    ledger["candidates"] = [_cand("c-p", ["e-p"])]
    _write(prog / "ledger" / "evidence-ledger.json", ledger)
    package = {
        "candidate_id": "c-p",
        "claims": [
            {"claim_id": "cl-obs", "kind": "observed_behavior", "text": "x", "evidence_refs": ["e-p"]},
        ],
    }
    return {
        "id": "invalid_prov",
        "program_dir": str(prog),
        "package": package,
        "expect": {
            "validation_result": "invalid_provenance",
            "finding_confirmed": False,
            "must_detect": ["invalid_provenance"],
        },
    }


DEV_BUILDERS = (
    scenario_complete_idor,
    scenario_denied,
    scenario_fp_http200,
    scenario_missing_ref,
    scenario_invented_impact,
    scenario_ai_unverified,
    scenario_invented_steps,
    scenario_insufficient,
)

FINAL_BUILDERS = (
    scenario_complete_idor,
    scenario_denied,
    scenario_public,
    scenario_shared,
    scenario_fp_http200,
    scenario_altered,
    scenario_missing_ref,
    scenario_stale_confirmed,
    scenario_invented_impact,
    scenario_missing_ownership,
    scenario_ai_unverified,
    scenario_rejected_as_confirmed,
    scenario_invented_steps,
    scenario_duplicate_report,
    scenario_sensitive_observations,
    scenario_contradictory_json,
    scenario_insufficient,
    scenario_human_confirmed_lab,
    scenario_invalid_provenance,
)


def build_split(split: str, root: Path) -> dict[str, Any]:
    builders = DEV_BUILDERS if split == "dev" else FINAL_BUILDERS
    scenarios = [builder(root / "programs") for builder in builders]
    ground = {
        "split": split,
        "schema_version": "bbtk-verified-dossier-eval/1",
        "scenarios": [
            {
                "id": row["id"],
                "expect": row["expect"],
                "package_candidate_id": row["package"]["candidate_id"],
            }
            for row in scenarios
        ],
    }
    split_dir = root
    split_dir.mkdir(parents=True, exist_ok=True)
    gt_path = split_dir / "ground_truth.json"
    _write(gt_path, ground)
    # Persist scenario packages for the runner (paths relative to split root).
    index = []
    for row in scenarios:
        pkg_path = split_dir / "packages" / f"{row['id']}.json"
        _write(
            pkg_path,
            {
                "id": row["id"],
                "program_dir": row["program_dir"],
                "package": row["package"],
                "expect": row["expect"],
            },
        )
        index.append({"id": row["id"], "package": str(pkg_path)})
    _write(split_dir / "index.json", {"scenarios": index})
    # Manifest over frozen ground truth + index (programs change digests when altered scenarios mutate files).
    manifest_files = sorted([p for p in split_dir.rglob("*") if p.is_file() and p.name != "MANIFEST.sha256"])
    lines = []
    for path in manifest_files:
        rel = path.relative_to(split_dir).as_posix()
        # Skip mutable evidence under altered/stale after build — include package+ground only for freeze.
        if "/programs/" in rel and ("/altered/" in rel or "/stale/" in rel):
            continue
        lines.append(f"{_sha(path)}  {rel}")
    manifest = "\n".join(lines) + "\n"
    (split_dir / "MANIFEST.sha256").write_text(manifest, encoding="utf-8")
    return {
        "split": split,
        "scenario_count": len(scenarios),
        "ground_truth": str(gt_path),
        "manifest_sha256": hashlib.sha256(manifest.encode("utf-8")).hexdigest(),
        "scenarios": scenarios,
    }
