"""Build DEV and FINAL synthetic program trees for the evidence-gap planner.

Every scenario is a self-contained program directory under a temporary records
root: ledger + local evidence JSON files (``bbtk-control-annotation/1``) that
encode only the control facts the planner is allowed to trust. No network
traffic and no live captures are produced.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

ANNOTATION = "bbtk-control-annotation/1"
NOW = "2026-10-26T12:00:00Z"
FINGERPRINT = "fp-v1"


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _write_json(path: Path, payload: dict[str, Any]) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    return _sha(path)


def _surface(sid: str = "s-orders", status: str = "investigated", **extra: Any) -> dict[str, Any]:
    row = {
        "surface_id": sid,
        "kind": "endpoint",
        "ref": "/api/orders/{id}",
        "status": status,
        "fingerprint": FINGERPRINT,
    }
    row.update(extra)
    return row


def _evidence(eid: str, rel: str, digest: str, **prov: Any) -> dict[str, Any]:
    return {
        "evidence_id": eid,
        "path": rel,
        "sha256": digest,
        "surface_fingerprint": FINGERPRINT,
        "provenance": {"tool": "synthetic-lab", "captured_at": NOW, **prov},
    }


def _candidate(
    cid: str,
    refs: list[str],
    *,
    state: str = "candidate",
    category: str = "idor",
    surface: str = "s-orders",
    **extra: Any,
) -> dict[str, Any]:
    row: dict[str, Any] = {
        "candidate_id": cid,
        "surface_id": surface,
        "category": category,
        "title": cid,
        "state": state,
        "evidence_refs": refs,
        "raised_by": "analyst",
    }
    row.update(extra)
    return row


def _control(
    role: str | None = None,
    *,
    provides: list[str] | None = None,
    distinct_accounts: str | None = None,
    ownership: str | None = None,
    capture_complete: bool | None = None,
    content_denial: bool | None = None,
    resource_visibility: str | None = None,
    contradicts_hypothesis: bool | None = None,
    expires_at: str | None = None,
    eligibility_code: str | None = None,
    has_owner_response: bool | None = None,
    has_actor_response: bool | None = None,
) -> dict[str, Any]:
    payload: dict[str, Any] = {"annotation_version": ANNOTATION}
    if role is not None:
        payload["role"] = role
    if provides is not None:
        payload["provides"] = provides
    if distinct_accounts is not None:
        payload["distinct_accounts"] = distinct_accounts
    if ownership is not None:
        payload["ownership"] = ownership
    if capture_complete is not None:
        payload["capture_complete"] = capture_complete
    if content_denial is not None:
        payload["content_denial"] = content_denial
    if resource_visibility is not None:
        payload["resource_visibility"] = resource_visibility
    if contradicts_hypothesis is not None:
        payload["contradicts_hypothesis"] = contradicts_hypothesis
    if expires_at is not None:
        payload["expires_at"] = expires_at
    body: dict[str, Any] = {"control": payload, "body": "synthetic"}
    if eligibility_code is not None:
        body["classification"] = {
            "code": eligibility_code,
            "has_owner_response": bool(has_owner_response),
            "has_actor_response": bool(has_actor_response),
        }
    return body


def _ledger(
    program: str, surfaces: list[dict[str, Any]], evidence: list[dict[str, Any]], candidates: list[dict[str, Any]]
) -> dict[str, Any]:
    return {
        "schema_version": "bbtk-evidence-ledger/1",
        "program": program,
        "updated_at": NOW,
        "surfaces": surfaces,
        "evidence": evidence,
        "candidates": candidates,
    }


def _full_controls(program_dir: Path) -> tuple[list[dict[str, Any]], list[str]]:
    """Owner + actor + distinct + ownership + negative control (non-contradicting)."""
    refs: list[str] = []
    evidence: list[dict[str, Any]] = []
    pieces = [
        ("e-owner", "evidence/owner.json", _control("owner_response", ownership="attested")),
        ("e-actor", "evidence/actor.json", _control("actor_response", distinct_accounts="attested")),
        ("e-neg", "evidence/neg.json", _control("negative_control", contradicts_hypothesis=False)),
    ]
    for eid, rel, payload in pieces:
        digest = _write_json(program_dir / rel, payload)
        evidence.append(_evidence(eid, rel, digest))
        refs.append(eid)
    return evidence, refs


# Each builder returns (ledger, ground_truth). Ground truth drives metrics.
ScenarioBuilder = Any


def _scenario_1(root: Path, name: str) -> tuple[dict[str, Any], dict[str, Any]]:
    """IDOR with all required controls present → request human review."""
    program = name.replace("_", "-")
    program_dir = root / program
    evidence, refs = _full_controls(program_dir)
    ledger = _ledger(
        program,
        [_surface()],
        evidence,
        [_candidate("c-ready", refs, state="requires_validation", blockers=["awaiting_independent_review"])],
    )
    return ledger, {
        "scenario": name,
        "expected_top_step": "request_human_review",
        "missing_controls": [],
        "present_controls": ["owner_response", "actor_response", "distinct_accounts", "ownership", "negative_control"],
        "allowed_steps": ["request_human_review"],
        "forbidden_steps": ["identify_missing_owner_response", "identify_missing_actor_response"],
        "manual_steps_baseline": 8,
        "manual_steps_planner": 1,
        "abstain": False,
        "blocked": False,
        "stop": False,
    }


def _scenario_2(root: Path, name: str) -> tuple[dict[str, Any], dict[str, Any]]:
    """Owner response missing."""
    program = name.replace("_", "-")
    program_dir = root / program
    digest = _write_json(
        program_dir / "evidence/actor.json",
        _control("actor_response", distinct_accounts="attested", ownership="attested"),
    )
    dig2 = _write_json(program_dir / "evidence/neg.json", _control("negative_control"))
    evidence = [
        _evidence("e-actor", "evidence/actor.json", digest),
        _evidence("e-neg", "evidence/neg.json", dig2),
    ]
    ledger = _ledger(program, [_surface()], evidence, [_candidate("c-no-owner", ["e-actor", "e-neg"])])
    return ledger, {
        "scenario": name,
        "expected_top_step": "identify_missing_owner_response",
        "missing_controls": ["owner_response"],
        "present_controls": ["actor_response", "distinct_accounts", "ownership", "negative_control"],
        "allowed_steps": ["identify_missing_owner_response"],
        "forbidden_steps": ["request_human_review", "identify_missing_actor_response"],
        "manual_steps_baseline": 6,
        "manual_steps_planner": 2,
        "abstain": False,
        "blocked": False,
        "stop": False,
    }


def _scenario_3(root: Path, name: str) -> tuple[dict[str, Any], dict[str, Any]]:
    """Two cookies, no distinct-accounts attestation."""
    program = name.replace("_", "-")
    program_dir = root / program
    dig1 = _write_json(program_dir / "evidence/owner.json", _control("owner_response", ownership="attested"))
    dig2 = _write_json(program_dir / "evidence/actor.json", _control("actor_response"))
    dig3 = _write_json(program_dir / "evidence/neg.json", _control("negative_control"))
    evidence = [
        _evidence("e-owner", "evidence/owner.json", dig1),
        _evidence("e-actor", "evidence/actor.json", dig2),
        _evidence("e-neg", "evidence/neg.json", dig3),
    ]
    ledger = _ledger(program, [_surface()], evidence, [_candidate("c-cookies", ["e-owner", "e-actor", "e-neg"])])
    return ledger, {
        "scenario": name,
        "expected_top_step": "attest_distinct_accounts",
        "missing_controls": ["distinct_accounts"],
        "present_controls": ["owner_response", "actor_response", "ownership", "negative_control"],
        "allowed_steps": ["attest_distinct_accounts"],
        "forbidden_steps": ["request_human_review"],
        "manual_steps_baseline": 5,
        "manual_steps_planner": 1,
        "abstain": False,
        "blocked": False,
        "stop": False,
    }


def _scenario_4(root: Path, name: str) -> tuple[dict[str, Any], dict[str, Any]]:
    """HTTP 200 with content denial."""
    program = name.replace("_", "-")
    program_dir = root / program
    dig = _write_json(
        program_dir / "evidence/actor.json",
        _control("actor_response", content_denial=True, distinct_accounts="attested"),
    )
    dig2 = _write_json(program_dir / "evidence/owner.json", _control("owner_response", ownership="attested"))
    evidence = [
        _evidence("e-actor", "evidence/actor.json", dig),
        _evidence("e-owner", "evidence/owner.json", dig2),
    ]
    ledger = _ledger(program, [_surface()], evidence, [_candidate("c-denial", ["e-owner", "e-actor"])])
    return ledger, {
        "scenario": name,
        "expected_top_step": "review_content_denial",
        "missing_controls": [],
        "present_controls": ["owner_response", "actor_response", "distinct_accounts", "ownership"],
        "allowed_steps": ["review_content_denial"],
        "forbidden_steps": ["request_human_review"],
        "manual_steps_baseline": 4,
        "manual_steps_planner": 1,
        "abstain": False,
        "blocked": False,
        "stop": True,
    }


def _scenario_5(root: Path, name: str) -> tuple[dict[str, Any], dict[str, Any]]:
    """Public resource."""
    program = name.replace("_", "-")
    program_dir = root / program
    dig = _write_json(
        program_dir / "evidence/owner.json",
        _control("owner_response", resource_visibility="public", ownership="attested"),
    )
    evidence = [_evidence("e-owner", "evidence/owner.json", dig)]
    ledger = _ledger(program, [_surface()], evidence, [_candidate("c-public", ["e-owner"])])
    return ledger, {
        "scenario": name,
        "expected_top_step": "review_legitimate_access",
        "missing_controls": [],
        "present_controls": ["owner_response", "ownership"],
        "allowed_steps": ["review_legitimate_access"],
        "forbidden_steps": ["request_human_review"],
        "manual_steps_baseline": 3,
        "manual_steps_planner": 1,
        "abstain": False,
        "blocked": False,
        "stop": True,
    }


def _scenario_6(root: Path, name: str) -> tuple[dict[str, Any], dict[str, Any]]:
    """Legitimately shared resource."""
    program = name.replace("_", "-")
    program_dir = root / program
    dig = _write_json(
        program_dir / "evidence/owner.json",
        _control("owner_response", resource_visibility="shared", ownership="attested"),
    )
    evidence = [_evidence("e-owner", "evidence/owner.json", dig)]
    ledger = _ledger(program, [_surface()], evidence, [_candidate("c-shared", ["e-owner"])])
    return ledger, {
        "scenario": name,
        "expected_top_step": "review_legitimate_access",
        "missing_controls": [],
        "present_controls": ["owner_response", "ownership"],
        "allowed_steps": ["review_legitimate_access"],
        "forbidden_steps": ["request_human_review"],
        "manual_steps_baseline": 3,
        "manual_steps_planner": 1,
        "abstain": False,
        "blocked": False,
        "stop": True,
    }


def _scenario_7(root: Path, name: str) -> tuple[dict[str, Any], dict[str, Any]]:
    """Multiple HTTP differences (eligibility code)."""
    program = name.replace("_", "-")
    program_dir = root / program
    dig = _write_json(
        program_dir / "evidence/pair.json",
        _control(
            eligibility_code="REJECT_MULTI_RESOURCE_DIFF",
            has_owner_response=True,
            has_actor_response=True,
        ),
    )
    evidence = [_evidence("e-pair", "evidence/pair.json", dig)]
    ledger = _ledger(program, [_surface()], evidence, [_candidate("c-multi", ["e-pair"])])
    return ledger, {
        "scenario": name,
        "expected_top_step": "review_multiple_differences",
        "missing_controls": ["distinct_accounts", "ownership", "negative_control"],
        "present_controls": ["owner_response", "actor_response"],
        "allowed_steps": ["review_multiple_differences"],
        "forbidden_steps": ["request_human_review"],
        "manual_steps_baseline": 5,
        "manual_steps_planner": 1,
        "abstain": False,
        "blocked": False,
        "stop": False,
    }


def _scenario_8(root: Path, name: str) -> tuple[dict[str, Any], dict[str, Any]]:
    """Non-GET incompatible with read generator."""
    program = name.replace("_", "-")
    program_dir = root / program
    dig = _write_json(
        program_dir / "evidence/pair.json",
        _control(eligibility_code="REJECT_NON_GET", has_owner_response=True, has_actor_response=True),
    )
    evidence = [_evidence("e-pair", "evidence/pair.json", dig)]
    ledger = _ledger(program, [_surface()], evidence, [_candidate("c-post", ["e-pair"])])
    return ledger, {
        "scenario": name,
        "expected_top_step": "stop_incompatible_method",
        "missing_controls": [],
        "present_controls": ["owner_response", "actor_response"],
        "allowed_steps": ["stop_incompatible_method"],
        "forbidden_steps": ["request_human_review", "identify_missing_owner_response"],
        "manual_steps_baseline": 4,
        "manual_steps_planner": 1,
        "abstain": False,
        "blocked": False,
        "stop": True,
    }


def _scenario_9(root: Path, name: str) -> tuple[dict[str, Any], dict[str, Any]]:
    """Tampered evidence (digest mismatch)."""
    program = name.replace("_", "-")
    program_dir = root / program
    dig = _write_json(program_dir / "evidence/owner.json", _control("owner_response"))
    # Record a wrong digest so validation marks it tampered.
    evidence = [_evidence("e-owner", "evidence/owner.json", "0" * 64)]
    ledger = _ledger(program, [_surface()], evidence, [_candidate("c-tamper", ["e-owner"])])
    assert dig  # written for realism
    return ledger, {
        "scenario": name,
        "expected_top_step": "verify_evidence_digest",
        "missing_controls": [],
        "present_controls": [],
        "allowed_steps": ["verify_evidence_digest"],
        "forbidden_steps": ["request_human_review"],
        "manual_steps_baseline": 3,
        "manual_steps_planner": 1,
        "abstain": False,
        "blocked": False,
        "stop": False,
        "integrity": True,
    }


def _scenario_10(root: Path, name: str) -> tuple[dict[str, Any], dict[str, Any]]:
    """Expired evidence annotation."""
    program = name.replace("_", "-")
    program_dir = root / program
    dig = _write_json(
        program_dir / "evidence/owner.json",
        _control("owner_response", ownership="attested", expires_at="2020-01-01T00:00:00Z"),
    )
    evidence = [_evidence("e-owner", "evidence/owner.json", dig)]
    ledger = _ledger(program, [_surface()], evidence, [_candidate("c-stale", ["e-owner"])])
    return ledger, {
        "scenario": name,
        "expected_top_step": "review_stale_evidence",
        "missing_controls": [],
        "present_controls": [],
        "allowed_steps": ["review_stale_evidence"],
        "forbidden_steps": ["request_human_review"],
        "manual_steps_baseline": 3,
        "manual_steps_planner": 1,
        "abstain": False,
        "blocked": False,
        "stop": False,
        "integrity": True,
    }


def _scenario_11(root: Path, name: str) -> tuple[dict[str, Any], dict[str, Any]]:
    """Broken evidence reference."""
    program = name.replace("_", "-")
    program_dir = root / program
    dig = _write_json(program_dir / "evidence/owner.json", _control("owner_response"))
    evidence = [_evidence("e-owner", "evidence/owner.json", dig)]
    ledger = _ledger(program, [_surface()], evidence, [_candidate("c-broken", ["e-owner", "e-missing"])])
    return ledger, {
        "scenario": name,
        "expected_top_step": "repair_broken_reference",
        "missing_controls": [],
        "present_controls": ["owner_response"],
        "allowed_steps": ["repair_broken_reference"],
        "forbidden_steps": ["request_human_review"],
        "manual_steps_baseline": 3,
        "manual_steps_planner": 1,
        "abstain": False,
        "blocked": False,
        "stop": False,
        "integrity": True,
    }


def _scenario_12(root: Path, name: str) -> tuple[dict[str, Any], dict[str, Any]]:
    """Duplicate candidates sharing a dedup key."""
    program = name.replace("_", "-")
    program_dir = root / program
    dig = _write_json(program_dir / "evidence/owner.json", _control("owner_response", ownership="attested"))
    evidence = [_evidence("e-owner", "evidence/owner.json", dig)]
    ledger = _ledger(
        program,
        [_surface()],
        evidence,
        [
            _candidate("c-dup-a", ["e-owner"], dedup_key="orders|idor"),
            _candidate("c-dup-b", ["e-owner"], dedup_key="orders|idor"),
        ],
    )
    return ledger, {
        "scenario": name,
        "expected_top_step": "review_duplicate",
        "missing_controls": [],
        "present_controls": [],
        "allowed_steps": ["review_duplicate"],
        "forbidden_steps": ["request_human_review"],
        "manual_steps_baseline": 4,
        "manual_steps_planner": 1,
        "abstain": False,
        "blocked": False,
        "stop": False,
        "duplicate": True,
    }


def _scenario_13(root: Path, name: str) -> tuple[dict[str, Any], dict[str, Any]]:
    """Negative control contradicts the hypothesis."""
    program = name.replace("_", "-")
    program_dir = root / program
    dig = _write_json(
        program_dir / "evidence/neg.json",
        _control("negative_control", contradicts_hypothesis=True),
    )
    dig2 = _write_json(program_dir / "evidence/owner.json", _control("owner_response", ownership="attested"))
    dig3 = _write_json(
        program_dir / "evidence/actor.json",
        _control("actor_response", distinct_accounts="attested"),
    )
    evidence = [
        _evidence("e-neg", "evidence/neg.json", dig),
        _evidence("e-owner", "evidence/owner.json", dig2),
        _evidence("e-actor", "evidence/actor.json", dig3),
    ]
    ledger = _ledger(program, [_surface()], evidence, [_candidate("c-contra", ["e-owner", "e-actor", "e-neg"])])
    return ledger, {
        "scenario": name,
        "expected_top_step": "stop_contradicted_hypothesis",
        "missing_controls": [],
        "present_controls": ["owner_response", "actor_response", "distinct_accounts", "ownership", "negative_control"],
        "allowed_steps": ["stop_contradicted_hypothesis"],
        "forbidden_steps": ["request_human_review"],
        "manual_steps_baseline": 4,
        "manual_steps_planner": 1,
        "abstain": False,
        "blocked": False,
        "stop": True,
    }


def _scenario_14(root: Path, name: str) -> tuple[dict[str, Any], dict[str, Any]]:
    """Eligible, pending human review (same as 1 but state=candidate with all controls)."""
    return _scenario_1(root, name)


def _scenario_15(root: Path, name: str) -> tuple[dict[str, Any], dict[str, Any]]:
    """Partial capture."""
    program = name.replace("_", "-")
    program_dir = root / program
    dig = _write_json(
        program_dir / "evidence/owner.json",
        _control("owner_response", ownership="attested", capture_complete=False),
    )
    dig2 = _write_json(
        program_dir / "evidence/actor.json",
        _control("actor_response", distinct_accounts="attested"),
    )
    evidence = [
        _evidence("e-owner", "evidence/owner.json", dig),
        _evidence("e-actor", "evidence/actor.json", dig2),
    ]
    ledger = _ledger(program, [_surface()], evidence, [_candidate("c-partial", ["e-owner", "e-actor"])])
    return ledger, {
        "scenario": name,
        "expected_top_step": "complete_partial_capture",
        "missing_controls": ["negative_control"],
        "present_controls": ["owner_response", "actor_response", "distinct_accounts", "ownership"],
        "allowed_steps": ["complete_partial_capture"],
        "forbidden_steps": ["request_human_review"],
        "manual_steps_baseline": 4,
        "manual_steps_planner": 2,
        "abstain": False,
        "blocked": False,
        "stop": False,
    }


def _scenario_16(root: Path, name: str) -> tuple[dict[str, Any], dict[str, Any]]:
    """Origin difference."""
    program = name.replace("_", "-")
    program_dir = root / program
    dig = _write_json(
        program_dir / "evidence/pair.json",
        _control(
            eligibility_code="REJECT_ORIGIN_MISMATCH_SIDES",
            has_owner_response=True,
            has_actor_response=True,
        ),
    )
    evidence = [_evidence("e-pair", "evidence/pair.json", dig)]
    ledger = _ledger(program, [_surface()], evidence, [_candidate("c-origin", ["e-pair"])])
    return ledger, {
        "scenario": name,
        "expected_top_step": "review_origin_difference",
        "missing_controls": ["distinct_accounts", "ownership", "negative_control"],
        "present_controls": ["owner_response", "actor_response"],
        "allowed_steps": ["review_origin_difference"],
        "forbidden_steps": ["request_human_review"],
        "manual_steps_baseline": 4,
        "manual_steps_planner": 1,
        "abstain": False,
        "blocked": False,
        "stop": False,
    }


def _scenario_17(root: Path, name: str) -> tuple[dict[str, Any], dict[str, Any]]:
    """Two candidates; second can reuse the first's negative control."""
    program = name.replace("_", "-")
    program_dir = root / program
    dig_neg = _write_json(program_dir / "evidence/neg.json", _control("negative_control"))
    dig_o = _write_json(program_dir / "evidence/owner.json", _control("owner_response", ownership="attested"))
    dig_a = _write_json(
        program_dir / "evidence/actor.json",
        _control("actor_response", distinct_accounts="attested"),
    )
    dig_o2 = _write_json(program_dir / "evidence/owner2.json", _control("owner_response", ownership="attested"))
    dig_a2 = _write_json(
        program_dir / "evidence/actor2.json",
        _control("actor_response", distinct_accounts="attested"),
    )
    evidence = [
        _evidence("e-neg", "evidence/neg.json", dig_neg),
        _evidence("e-owner", "evidence/owner.json", dig_o),
        _evidence("e-actor", "evidence/actor.json", dig_a),
        _evidence("e-owner2", "evidence/owner2.json", dig_o2),
        _evidence("e-actor2", "evidence/actor2.json", dig_a2),
    ]
    ledger = _ledger(
        program,
        [_surface()],
        evidence,
        [
            _candidate("c-first", ["e-owner", "e-actor", "e-neg"], dedup_key="a|idor"),
            _candidate("c-second", ["e-owner2", "e-actor2"], dedup_key="b|idor"),
        ],
    )
    return ledger, {
        "scenario": name,
        "expected_top_step": "reuse_existing_control",
        "missing_controls": [],
        "present_controls": ["owner_response", "actor_response", "distinct_accounts", "ownership"],
        "allowed_steps": ["reuse_existing_control"],
        "forbidden_steps": ["identify_missing_negative_control"],
        "manual_steps_baseline": 6,
        "manual_steps_planner": 1,
        "abstain": False,
        "blocked": False,
        "stop": False,
        "target_candidate": "c-second",
    }


def _scenario_18(root: Path, name: str) -> tuple[dict[str, Any], dict[str, Any]]:
    """Out of scope surface — candidate must be rejected for ledger validity."""
    program = name.replace("_", "-")
    program_dir = root / program
    dig = _write_json(program_dir / "evidence/owner.json", _control("owner_response"))
    evidence = [_evidence("e-owner", "evidence/owner.json", dig)]
    ledger = _ledger(
        program,
        [_surface(status="out_of_scope", reason="out of program scope")],
        evidence,
        [
            _candidate(
                "c-oos",
                ["e-owner"],
                state="rejected",
                rejection={"reason": "out_of_scope", "detail": "surface out of program scope"},
            )
        ],
    )
    # Also include an active sibling on a blocked surface to exercise the planner path.
    ledger["surfaces"].append(
        _surface(sid="s-blocked", status="blocked", blocker="missing_authorization_token", fingerprint=FINGERPRINT)
    )
    dig2 = _write_json(program_dir / "evidence/actor.json", _control("actor_response"))
    ledger["evidence"].append(_evidence("e-actor", "evidence/actor.json", dig2))
    ledger["candidates"].append(_candidate("c-blocked", ["e-actor"], surface="s-blocked"))
    return ledger, {
        "scenario": name,
        "expected_top_step": "blocked_missing_authorization",
        "missing_controls": [],
        "present_controls": [],
        "allowed_steps": ["blocked_missing_authorization"],
        "forbidden_steps": ["request_human_review", "identify_missing_owner_response"],
        "manual_steps_baseline": 2,
        "manual_steps_planner": 0,
        "abstain": False,
        "blocked": True,
        "stop": True,
        "target_candidate": "c-blocked",
    }


def _scenario_19(root: Path, name: str) -> tuple[dict[str, Any], dict[str, Any]]:
    """Blocked by missing authorization (pending/blocked surface)."""
    program = name.replace("_", "-")
    program_dir = root / program
    dig = _write_json(program_dir / "evidence/owner.json", _control("owner_response"))
    evidence = [_evidence("e-owner", "evidence/owner.json", dig)]
    ledger = _ledger(
        program,
        [_surface(status="blocked", blocker="awaiting_write_permission")],
        evidence,
        [_candidate("c-auth", ["e-owner"])],
    )
    return ledger, {
        "scenario": name,
        "expected_top_step": "blocked_missing_authorization",
        "missing_controls": [],
        "present_controls": [],
        "allowed_steps": ["blocked_missing_authorization"],
        "forbidden_steps": ["request_human_review"],
        "manual_steps_baseline": 2,
        "manual_steps_planner": 0,
        "abstain": False,
        "blocked": True,
        "stop": True,
    }


def _scenario_20(root: Path, name: str) -> tuple[dict[str, Any], dict[str, Any]]:
    """No structured annotation → abstain."""
    program = name.replace("_", "-")
    program_dir = root / program
    dig = _write_json(program_dir / "evidence/raw.json", {"body": "opaque capture without control annotation"})
    evidence = [_evidence("e-raw", "evidence/raw.json", dig)]
    ledger = _ledger(program, [_surface()], evidence, [_candidate("c-opaque", ["e-raw"])])
    return ledger, {
        "scenario": name,
        "expected_top_step": "abstain_insufficient_information",
        "missing_controls": [],
        "present_controls": [],
        "allowed_steps": ["abstain_insufficient_information"],
        "forbidden_steps": ["request_human_review", "identify_missing_owner_response"],
        "manual_steps_baseline": 5,
        "manual_steps_planner": 0,
        "abstain": True,
        "blocked": False,
        "stop": True,
    }


BUILDERS: list[tuple[str, Any]] = [
    ("01_ready_controls", _scenario_1),
    ("02_missing_owner", _scenario_2),
    ("03_cookies_not_accounts", _scenario_3),
    ("04_content_denial", _scenario_4),
    ("05_public_resource", _scenario_5),
    ("06_shared_resource", _scenario_6),
    ("07_multi_diff", _scenario_7),
    ("08_non_get", _scenario_8),
    ("09_tampered_evidence", _scenario_9),
    ("10_expired_evidence", _scenario_10),
    ("11_broken_reference", _scenario_11),
    ("12_duplicate_candidate", _scenario_12),
    ("13_contradicted", _scenario_13),
    ("14_eligible_pending_review", _scenario_14),
    ("15_partial_capture", _scenario_15),
    ("16_origin_difference", _scenario_16),
    ("17_reuse_negative_control", _scenario_17),
    ("18_out_of_scope_blocked", _scenario_18),
    ("19_blocked_authorization", _scenario_19),
    ("20_insufficient_info", _scenario_20),
]


def build_split(split: str, root: Path) -> dict[str, Any]:
    """Materialize one split (dev|final) under ``root`` and return the manifest."""
    if split not in {"dev", "final"}:
        raise ValueError("split must be 'dev' or 'final'")
    # Slight remapping of names so FINAL is not byte-identical to DEV (frozen eval).
    suffix = "-final" if split == "final" else "-dev"
    scenarios: list[dict[str, Any]] = []
    for name, builder in BUILDERS:
        scenario_name = name + suffix
        ledger, truth = builder(root, scenario_name)
        program = ledger["program"]
        program_dir = root / program
        program_dir.mkdir(parents=True, exist_ok=True)
        (program_dir / "ledger").mkdir(exist_ok=True)
        path = program_dir / "ledger" / "evidence-ledger.json"
        path.write_text(json.dumps(ledger, sort_keys=True, indent=2) + "\n", encoding="utf-8")
        truth["program"] = program
        truth["ledger_sha256"] = _sha(path)
        scenarios.append(truth)
    manifest = {
        "split": split,
        "schema_version": "bbtk-evidence-gap-lab/1",
        "frozen": split == "final",
        "scenario_count": len(scenarios),
        "scenarios": scenarios,
        "network_requests_sent": 0,
    }
    (root / "manifest.json").write_text(json.dumps(manifest, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    return manifest
