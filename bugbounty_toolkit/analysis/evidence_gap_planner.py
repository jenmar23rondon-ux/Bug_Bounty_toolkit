"""Evidence-gap guided next-step planner (offline, deterministic, opt-in).

Given a program's existing Evidence Ledger, the evidence files it references and
the program's Investigation Memory, this module answers *what evidence is
missing for each open candidate* and *which human review step would resolve the
most uncertainty with the least redundant work*.

It is deliberately **not** a scanner, an agent or a generic re-ranker:

* It only reads. The ledger is validated with
  :func:`analysis.evidence_ledger.validate_ledger` (digests, references,
  fingerprints) and is never written; Investigation Memory is opened read-only.
* Every recommendation is an instruction for a human. ``execution_allowed`` and
  ``finding_confirmed`` are always ``False``; no HTTP requests, payloads, ID
  ranges or scan commands are produced, and steps that need new captures only
  describe the missing evidence.
* Ownership, privacy, distinct accounts and authorization are never inferred
  from paths, HTTP 200, different cookies or response similarity. They count as
  satisfied only when an evidence file carries an explicit, digest-verified
  control annotation (``bbtk-control-annotation/1``) or an IDOR E2E pair
  classification code. Anything else is ``unknown`` / ``requires_validation``.
* No AI provider is consulted. Ranking weights are fixed and documented in
  :data:`STEP_CATALOG` and :func:`_score`.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
from pathlib import Path
from typing import Any, Mapping

from ..core.records import ProgramPaths
from .blocker_dependency_graph import (
    build_blocker_dependency_graph,
    ledger_candidate_records,
    ledger_evidence_records,
)
from .evidence_ledger import MAX_LEDGER_BYTES, effective_eligibility, load_ledger, validate_ledger
from .handoff_case_eligibility import (
    CODE_NEEDS_SECOND_SESSION,
    CODE_REJECT_MULTI_RESOURCE_DIFF,
    CODE_REJECT_NON_GET,
    CODE_REJECT_ORIGIN_MISMATCH_SIDES,
    CODE_REJECT_SAME_SESSION,
    CODE_REJECT_SESSION_ONLY,
    CODE_TECH_INCOMPLETE_CAPTURE,
    CODE_TECH_ORIGIN_OVERRIDE,
)

PLAN_SCHEMA_VERSION = "bbtk-evidence-gap-plan/1"
ANNOTATION_VERSION = "bbtk-control-annotation/1"
MAX_ANNOTATED_EVIDENCE_BYTES = 2 * 1024 * 1024
ACTIVE_STATES = frozenset({"candidate", "requires_validation"})
IDOR_CATEGORIES = frozenset({"idor", "bola", "access_control", "bfla"})

# Controls a read-only IDOR/BOLA case needs before human review is meaningful.
REQUIRED_CONTROLS = ("owner_response", "actor_response", "distinct_accounts", "ownership", "negative_control")
GAP_KINDS = (
    "missing_evidence",
    "missing_control",
    "invalid_evidence",
    "stale_evidence",
    "unresolved_authorization",
    "insufficient_capture",
    "contradictory_observation",
    "duplicate_candidate",
    "blocked_by_scope",
    "session_control",
    "access_proof",
    "human_review_required",
    "ready_for_manual_review",
)

# step_type -> (class base score, information gain, estimated manual steps, gap kind, stop?)
# Base scores: integrity blockers first (evidence that cannot be trusted must be
# fixed before anything else is read), then stop/terminal decisions (they avoid
# all remaining work), then reuse of existing controls, then missing controls,
# then human review. Information gain: 3 high, 2 medium, 1 low.
STEP_CATALOG: dict[str, tuple[int, int, int, str, bool]] = {
    "blocked_out_of_scope": (95, 1, 0, "blocked_by_scope", True),
    "blocked_missing_authorization": (94, 1, 0, "blocked_by_scope", True),
    "review_duplicate": (92, 2, 1, "duplicate_candidate", True),
    "verify_evidence_digest": (90, 3, 1, "invalid_evidence", False),
    "repair_broken_reference": (90, 3, 1, "invalid_evidence", False),
    "review_stale_evidence": (88, 2, 1, "stale_evidence", False),
    "verify_evidence_program": (89, 2, 1, "invalid_evidence", False),
    "review_shared_capture_integrity": (87, 2, 1, "invalid_evidence", False),
    "review_shared_capture_contradiction": (85, 2, 1, "contradictory_observation", True),
    "restore_owner_control": (82, 3, 1, "session_control", False),
    "review_access_proof": (81, 3, 1, "access_proof", False),
    "stop_contradicted_hypothesis": (86, 3, 1, "contradictory_observation", True),
    "stop_incompatible_method": (85, 2, 1, "contradictory_observation", True),
    "review_content_denial": (84, 3, 1, "contradictory_observation", True),
    "review_legitimate_access": (83, 3, 1, "contradictory_observation", True),
    "review_multiple_differences": (80, 3, 1, "contradictory_observation", False),
    "review_origin_difference": (80, 3, 1, "contradictory_observation", False),
    "complete_partial_capture": (78, 2, 2, "insufficient_capture", False),
    "reuse_existing_control": (74, 3, 1, "missing_control", False),
    "identify_missing_owner_response": (66, 3, 2, "missing_control", False),
    "identify_missing_actor_response": (66, 3, 2, "missing_control", False),
    "attest_distinct_accounts": (64, 3, 1, "unresolved_authorization", False),
    "attest_ownership": (62, 3, 1, "missing_control", False),
    "identify_missing_negative_control": (60, 2, 2, "missing_control", False),
    "request_human_review": (55, 3, 1, "ready_for_manual_review", False),
    "abstain_insufficient_information": (10, 0, 0, "human_review_required", True),
}

_GUIDANCE = {
    "blocked_out_of_scope": "Surface is out of scope; keep the candidate stopped. No step is authorized.",
    "blocked_missing_authorization": "Surface is blocked by missing permission; keep it blocked until the "
    "program grants it. Nothing is authorized by this plan.",
    "review_duplicate": "Candidate shares a dedup key with another; review and reject one as duplicate.",
    "verify_evidence_digest": "Evidence changed after it was recorded; do not rely on it. Re-verify the digest "
    "with `bbtk ledger validate` and re-register only if a human confirms its origin.",
    "repair_broken_reference": "Candidate references evidence that is not recorded; repair the reference.",
    "review_stale_evidence": "Evidence was captured against a different code/surface fingerprint or expired; "
    "identify which control must be re-captured under existing authorization.",
    "verify_evidence_program": "Evidence is annotated for a different program; it cannot support this "
    "program's candidate. Re-register it only if a human confirms it belongs here.",
    "review_shared_capture_integrity": "Another candidate built from the same captured objects has altered, "
    "missing, unrecorded or expired evidence; resolve that integrity blocker before reviewing this one.",
    "review_shared_capture_contradiction": "A stored control on another candidate built from the same "
    "captured objects contradicts the hypothesis; review it before treating this candidate as reviewable.",
    "restore_owner_control": "The owner's own positive control was denied or redirected to login; actor "
    "results that depend on it are inconclusive. One 401 is not proof of session expiry: re-capture the "
    "owner control under existing authorization before reading the actor side.",
    "review_access_proof": "The actor response only echoes the requested identifier (or is otherwise "
    "ambiguous); it does not show the resource. An identifier match alone never proves access.",
    "stop_contradicted_hypothesis": "A stored negative control contradicts the hypothesis; review it and "
    "consider rejecting the candidate.",
    "stop_incompatible_method": "Capture is not a read (GET) request; the read-IDOR case generator cannot be "
    "used. Review manually or stop.",
    "review_content_denial": "Response status is 200 but the stored body is a denial; review the body before "
    "treating it as access.",
    "review_legitimate_access": "Resource is documented as public or legitimately shared; review and likely stop.",
    "review_multiple_differences": "Saved captures differ in more than the resource identifier; review the "
    "differences before any comparison is meaningful.",
    "review_origin_difference": "Saved captures come from different origins; review the origin difference.",
    "complete_partial_capture": "A stored capture is incomplete; record what part is missing.",
    "reuse_existing_control": "A suitable control already exists in the ledger; compare it instead of "
    "collecting a new one.",
    "identify_missing_owner_response": "The owner's response is missing; it is required evidence.",
    "identify_missing_actor_response": "The second user's response is missing; it is required evidence.",
    "attest_distinct_accounts": "Different cookies do not prove different accounts; a human must attest that "
    "the two sessions belong to distinct accounts.",
    "attest_ownership": "Ownership of the object by the first account is not attested.",
    "identify_missing_negative_control": "No negative control (expected denial) is stored for this case.",
    "request_human_review": "All required controls are present and verified; request independent human review.",
    "abstain_insufficient_information": "Not enough structured evidence to recommend a specific step.",
}


def _score(step_type: str, reused_refs: int) -> int:
    """Deterministic utility score: base + 5*gain + 3*min(reused,3) - 4*manual_steps."""
    base, gain, manual, _kind, _stop = STEP_CATALOG[step_type]
    return base + 5 * gain + 3 * min(reused_refs, 3) - 4 * manual


def _priority(score: int) -> str:
    return "high" if score >= 95 else "medium" if score >= 70 else "low"


def step_id_for(step_type: str, requirement: str, evidence_refs: list[str]) -> str:
    """Stable identifier: equivalent steps get the same id across regenerations and candidates."""
    raw = json.dumps([step_type, requirement, sorted(evidence_refs)], separators=(",", ":"))
    return "step-" + hashlib.sha256(raw.encode()).hexdigest()[:16]


def _read_annotation(path: Path) -> dict[str, Any] | None:
    """Read the structured control facts from a digest-verified JSON evidence file (never raw content)."""
    try:
        if path.stat().st_size > MAX_ANNOTATED_EVIDENCE_BYTES:
            return None
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, UnicodeDecodeError):
        return None
    if not isinstance(data, dict):
        return None
    facts: dict[str, Any] = {}
    control = data.get("control")
    if isinstance(control, dict) and control.get("annotation_version") == ANNOTATION_VERSION:
        facts.update(control)
    # IDOR E2E / handoff pair classification output (PairClassification.as_dict()).
    classification = data.get("classification")
    if isinstance(classification, dict) and isinstance(classification.get("code"), str):
        facts.setdefault("eligibility_code", classification["code"])
        facts.setdefault("role", "capture_pair")
        if classification.get("has_owner_response") is True:
            facts.setdefault("provides", []).append("owner_response")
        if classification.get("has_actor_response") is True:
            facts.setdefault("provides", []).append("actor_response")
    proposal = data.get("proposal")
    if isinstance(proposal, dict):
        objects = sorted(
            str((proposal.get(side) or {}).get("object_ref"))
            for side in ("owner", "actor")
            if isinstance(proposal.get(side), dict) and isinstance(proposal[side].get("object_ref"), str)
        )
        if objects:
            facts["object_refs"] = objects
    return facts or None


def _memory_status(paths: ProgramPaths) -> dict[str, str]:
    if not paths.db_path.is_file():
        return {}
    try:
        conn = sqlite3.connect(f"file:{paths.db_path}?mode=ro", uri=True)
    except sqlite3.Error:
        return {}
    try:
        rows = conn.execute("select investigation_id, status from investigation_memory").fetchall()
    except sqlite3.Error:
        rows = []
    finally:
        conn.close()
    return {str(r[0]): str(r[1]) for r in rows}


def _step(
    candidate_id: str,
    step_type: str,
    requirement: str,
    refs: list[str],
    *,
    prerequisites: list[str] | None = None,
    blocking: list[str] | None = None,
    reused: int = 0,
    reason_code: str | None = None,
) -> dict[str, Any]:
    _base, gain, manual, kind, stop = STEP_CATALOG[step_type]
    score = _score(step_type, reused)
    return {
        "candidate_id": candidate_id,
        "step_id": step_id_for(step_type, requirement, refs),
        "step_type": step_type,
        "gap_kind": kind,
        "priority": _priority(score),
        "score": score,
        "reason_code": reason_code or step_type.upper(),
        "evidence_refs": sorted(refs),
        "missing_requirement": requirement,
        "expected_information_gain": {3: "high", 2: "medium", 1: "low", 0: "none"}[gain],
        "estimated_manual_steps": manual,
        "prerequisites": sorted(prerequisites or []),
        "blocking_conditions": sorted(blocking or []),
        "terminal": stop,
        "guidance": _GUIDANCE[step_type],
        "requires_human_review": True,
        "execution_allowed": False,
        "finding_confirmed": False,
        "also_applies_to": [],
    }


def _analyze_candidate(
    cand: Mapping[str, Any],
    surface: Mapping[str, Any] | None,
    evidence_state: Mapping[str, str],
    facts_by_ref: Mapping[str, dict[str, Any]],
    duplicate_of: str | None,
    shared_controls: Mapping[str, list[str]],
    now: str | None,
    memory: Mapping[str, str],
    evidence_rows: Mapping[str, Mapping[str, Any]],
) -> dict[str, Any]:
    cid = str(cand.get("candidate_id"))
    refs = sorted(r for r in cand.get("evidence_refs") or [] if isinstance(r, str))
    gaps: list[dict[str, Any]] = []
    steps: list[dict[str, Any]] = []
    status = "open"

    def gap(kind: str, detail: str, gap_refs: list[str] | None = None) -> None:
        gaps.append({"kind": kind, "detail": detail, "evidence_refs": sorted(gap_refs or [])})

    surface_status = str((surface or {}).get("status") or "unknown")
    if surface_status == "out_of_scope":
        gap("blocked_by_scope", "surface out of scope")
        steps.append(_step(cid, "blocked_out_of_scope", "scope", [], blocking=["surface_out_of_scope"]))
        return {"candidate_id": cid, "status": "blocked", "gaps": gaps, "steps": steps, "controls": {}}
    if surface_status == "blocked":
        gap("blocked_by_scope", "surface blocked: missing authorization")
        steps.append(_step(cid, "blocked_missing_authorization", "authorization", [], blocking=["surface_blocked"]))
        return {"candidate_id": cid, "status": "blocked", "gaps": gaps, "steps": steps, "controls": {}}
    if duplicate_of:
        gap("duplicate_candidate", f"same dedup key as {duplicate_of}")
        steps.append(_step(cid, "review_duplicate", f"duplicate_of:{duplicate_of}", []))
        return {"candidate_id": cid, "status": "duplicate", "gaps": gaps, "steps": steps, "controls": {}}

    usable: list[str] = []
    for ref in refs:
        state = evidence_state.get(ref, "broken")
        if state == "broken":
            gap("invalid_evidence", "reference not recorded in ledger", [ref])
            steps.append(_step(cid, "repair_broken_reference", f"evidence:{ref}", [ref]))
            continue
        if state == "tampered":
            gap("invalid_evidence", "digest mismatch or missing file", [ref])
            steps.append(_step(cid, "verify_evidence_digest", f"evidence:{ref}", [ref]))
            continue
        if state == "out_of_program":
            gap("invalid_evidence", "evidence annotated for another program", [ref])
            steps.append(_step(cid, "verify_evidence_program", f"evidence:{ref}", [ref]))
            continue
        facts = facts_by_ref.get(ref) or {}
        expires = facts.get("expires_at")
        if state == "stale" or (isinstance(expires, str) and now is not None and expires <= now):
            gap("stale_evidence", "evidence invalidated by change or expired", [ref])
            steps.append(_step(cid, "review_stale_evidence", f"evidence:{ref}", [ref]))
            continue
        usable.append(ref)
        inv = (evidence_rows.get(ref, {}).get("provenance") or {}).get("investigation_id")
        if isinstance(inv, str) and memory.get(inv) == "closed":
            facts.setdefault("memory_closed_investigation", inv)

    controls: dict[str, str] = {c: "unknown" for c in REQUIRED_CONTROLS}
    control_refs: dict[str, list[str]] = {c: [] for c in REQUIRED_CONTROLS}
    terminal: list[dict[str, Any]] = []
    review: list[dict[str, Any]] = []
    eligibility: str | None = None

    def provide(control: str, ref: str) -> None:
        controls[control] = "present"
        control_refs[control].append(ref)

    for ref in usable:
        facts = facts_by_ref.get(ref) or {}
        role = facts.get("role")
        for item in facts.get("provides") or []:
            if item in controls:
                provide(str(item), ref)
        if role == "owner_response":
            provide("owner_response", ref)
        elif role == "actor_response":
            provide("actor_response", ref)
        elif role == "negative_control":
            provide("negative_control", ref)
            if facts.get("contradicts_hypothesis") is True:
                gap("contradictory_observation", "negative control contradicts hypothesis", [ref])
                terminal.append(_step(cid, "stop_contradicted_hypothesis", f"control:{ref}", [ref]))
        if facts.get("distinct_accounts") == "attested":
            provide("distinct_accounts", ref)
        if facts.get("ownership") == "attested":
            provide("ownership", ref)
        if facts.get("capture_complete") is False:
            gap("insufficient_capture", "capture marked incomplete", [ref])
            review.append(_step(cid, "complete_partial_capture", f"capture:{ref}", [ref]))
        if facts.get("content_denial") is True:
            gap("contradictory_observation", "HTTP 200 with denial in body", [ref])
            terminal.append(_step(cid, "review_content_denial", f"response:{ref}", [ref]))
        if facts.get("owner_control") == "broken":
            gap("session_control", "owner positive control denied/redirected; dependent results inconclusive", [ref])
            review.append(_step(cid, "restore_owner_control", f"session:{ref}", [ref]))
        if facts.get("actor_access_proof") == "id_echo_without_resource":
            gap("access_proof", "actor response echoes the identifier without the resource", [ref])
            review.append(_step(cid, "review_access_proof", f"proof:{ref}", [ref]))
        visibility = facts.get("resource_visibility")
        if visibility in {"public", "shared"}:
            gap("contradictory_observation", f"resource documented as {visibility}", [ref])
            terminal.append(_step(cid, "review_legitimate_access", f"visibility:{ref}", [ref]))
        code = facts.get("eligibility_code")
        if isinstance(code, str):
            eligibility = code
            if code == CODE_REJECT_NON_GET:
                gap("contradictory_observation", "non-GET capture incompatible with read generator", [ref])
                terminal.append(_step(cid, "stop_incompatible_method", f"method:{ref}", [ref], reason_code=code))
            elif code == CODE_REJECT_MULTI_RESOURCE_DIFF:
                gap("contradictory_observation", "captures differ in more than one place", [ref])
                review.append(_step(cid, "review_multiple_differences", f"diff:{ref}", [ref], reason_code=code))
            elif code in {CODE_REJECT_ORIGIN_MISMATCH_SIDES, CODE_TECH_ORIGIN_OVERRIDE}:
                gap("contradictory_observation", "origin differs between captures", [ref])
                review.append(_step(cid, "review_origin_difference", f"origin:{ref}", [ref], reason_code=code))
            elif code == CODE_TECH_INCOMPLETE_CAPTURE:
                gap("insufficient_capture", "pair classification reports incomplete capture", [ref])
                review.append(_step(cid, "complete_partial_capture", f"capture:{ref}", [ref], reason_code=code))
            elif code in {CODE_REJECT_SESSION_ONLY, CODE_REJECT_SAME_SESSION, CODE_NEEDS_SECOND_SESSION}:
                controls["distinct_accounts"] = "requires_validation"

    is_idor = str(cand.get("category", "")).lower() in IDOR_CATEGORIES
    has_structured = any(facts_by_ref.get(r) for r in usable)
    integrity_steps = list(steps)
    memory_refs = sorted(
        r for r in usable if (facts_by_ref.get(r) or {}).get("memory_closed_investigation") is not None
    )

    if terminal:
        status = "stop_recommended"
        steps = integrity_steps + terminal + review
    elif integrity_steps:
        # idor-evidence-correctness-v3: any altered, removed, unrecorded, expired or
        # out-of-program *required* evidence blocks advancement, even if other refs are usable.
        status = "integrity_blocked"
        if not usable:
            gap("missing_evidence", "no usable evidence after integrity checks")
        else:
            gap("missing_evidence", "required evidence failed integrity checks; resolve before review")
    elif not usable or not is_idor or not has_structured:
        status = "abstain"
        gap("human_review_required", "insufficient structured evidence for a specific recommendation")
        steps = integrity_steps + [
            _step(cid, "abstain_insufficient_information", "structured_evidence", usable, reused=0)
        ]
    else:
        missing: list[dict[str, Any]] = []
        for control in REQUIRED_CONTROLS:
            if controls[control] == "present":
                continue
            shared = [r for r in shared_controls.get(control, []) if r not in refs]
            if control == "negative_control" and shared:
                missing.append(_step(cid, "reuse_existing_control", f"control:{control}", shared, reused=len(shared)))
                gap("missing_control", f"{control} not linked; existing control available", shared)
                continue
            gap(
                "unresolved_authorization" if control == "distinct_accounts" else "missing_control",
                f"{control}: {controls[control]}",
            )
            step_type = {
                "owner_response": "identify_missing_owner_response",
                "actor_response": "identify_missing_actor_response",
                "distinct_accounts": "attest_distinct_accounts",
                "ownership": "attest_ownership",
                "negative_control": "identify_missing_negative_control",
            }[control]
            missing.append(_step(cid, step_type, f"control:{control}", [], prerequisites=[]))
        steps = integrity_steps + review + missing
        if not missing and not review and not integrity_steps:
            status = "ready_for_manual_review"
            gap("ready_for_manual_review", "all required controls present and verified")
            all_refs = sorted({r for v in control_refs.values() for r in v})
            steps.append(_step(cid, "request_human_review", "independent_review", all_refs, reused=len(all_refs)))
        elif cand.get("state") == "requires_validation":
            gap("human_review_required", "requires_validation blockers recorded in ledger")
    return {
        "candidate_id": cid,
        "status": status,
        "eligibility_code": eligibility,
        "controls": controls,
        "gaps": gaps,
        "steps": steps,
        "reused_evidence": sorted({r for v in control_refs.values() for r in v}),
        "memory_reused": memory_refs,
        "ledger_blockers_count": len(cand.get("blockers") or []),
    }


# Source status -> (gap kind, step) applied to siblings sharing captured objects.
_PROPAGATED: dict[str, tuple[str, str]] = {
    "integrity_blocked": ("invalid_evidence", "review_shared_capture_integrity"),
    "stop_recommended": ("contradictory_observation", "review_shared_capture_contradiction"),
    "duplicate": ("duplicate_candidate", "review_duplicate"),
}


def _blocker_evidence_ids(blockers: list[str]) -> list[str]:
    """Ledger evidence ids named by overlay blocker labels. Labels themselves are not refs."""
    refs: list[str] = []
    for item in blockers:
        if ":" not in item:
            continue
        prefix, ref = item.split(":", 1)
        if prefix in {"invalid", "stale", "shared_object", "ambiguous_objects"} and ref:
            refs.append(ref)
    return sorted(set(refs))


def _propagate_integrity_blocks(
    candidates: list[dict[str, Any]],
    results: list[dict[str, Any]],
    facts_by_ref: Mapping[str, dict[str, Any]],
    overlay: Mapping[str, Any],
    known_ids: set[str] | None = None,
) -> None:
    """Apply candidate-scoped blocks. Ledger history is not modified.

    Contradiction and duplicate blockers still propagate only across verifiably shared
    objects. Integrity blockers follow the dependency graph: a sibling stays
    ``open`` when its registered objects are disjoint and it does not depend on the
    bad artifact. Unknown object identity stays fail-closed (whole-surface).
    """
    by_id = {str(c.get("candidate_id")): c for c in candidates}
    overlay_by = {str(row.get("candidate_id")): row for row in overlay.get("candidates") or []}

    def objects(cand: Mapping[str, Any]) -> set[str]:
        return {
            o
            for r in cand.get("evidence_refs") or []
            for o in (facts_by_ref.get(str(r)) or {}).get("object_refs") or []
        }

    tainted: list[tuple[str, str, set[str], str]] = []
    for res in results:
        if res.get("status") in {"stop_recommended", "duplicate"}:
            cand = by_id.get(str(res.get("candidate_id"))) or {}
            tainted.append(
                (str(res.get("candidate_id")), str(cand.get("surface_id")), objects(cand), str(res["status"]))
            )
    for res in results:
        if res.get("status") not in {"open", "ready_for_manual_review"}:
            continue
        cid = str(res.get("candidate_id"))
        cand = by_id.get(cid) or {}
        mine = objects(cand)
        for src, surface, objs, src_status in tainted:
            if src == cid or surface != str(cand.get("surface_id")):
                continue
            if objs and not (objs & mine):
                continue
            gap_kind, step_type = _PROPAGATED[src_status]
            res["status"] = src_status
            res.setdefault("gaps", []).append(
                {
                    "kind": gap_kind,
                    "detail": f"shares captured objects with {src_status} candidate {src}",
                    "evidence_refs": [],
                }
            )
            res["steps"] = [
                _step(cid, step_type, f"candidate:{src}", []),
                *[st for st in res.get("steps") or [] if st.get("step_type") != "request_human_review"],
            ]
            break
        if res.get("status") not in {"open", "ready_for_manual_review"}:
            continue
        row = overlay_by.get(cid) or {}
        state = str(row.get("effective_state") or "")
        if state not in {
            "blocked_invalid_evidence",
            "blocked_stale_evidence",
            "requires_manual_independence_review",
        }:
            continue
        if state == "blocked_stale_evidence":
            gap_kind, step_type = "stale_evidence", "review_stale_evidence"
        else:
            gap_kind, step_type = "invalid_evidence", "review_shared_capture_integrity"
        res["status"] = "integrity_blocked"
        cited = _blocker_evidence_ids(list(row.get("blockers") or []))
        if known_ids is not None:
            cited = [ref for ref in cited if ref in known_ids]
        res.setdefault("gaps", []).append(
            {
                "kind": gap_kind,
                "detail": str(row.get("decision_reason") or "blocked by the dependency graph"),
                "evidence_refs": cited,
            }
        )
        res["steps"] = [
            _step(cid, step_type, f"dependency:{cid}", cited),
            *[st for st in res.get("steps") or [] if st.get("step_type") != "request_human_review"],
        ]


def build_plan(paths: ProgramPaths, *, ledger_file: Path | None = None, now: str | None = None) -> dict[str, Any]:
    """Return the versioned next-step plan for one program. Read-only; no network; no AI."""
    ledger_path = ledger_file or (paths.program_dir / "ledger" / "evidence-ledger.json")
    base: dict[str, Any] = {
        "schema_version": PLAN_SCHEMA_VERSION,
        "program": paths.program,
        "mode": "dry_run",
        "deterministic": True,
        "ai_used": False,
        "network_requests_sent": 0,
        "executions": 0,
        "auto_confirmations": 0,
        "ledger_modified": False,
    }
    if not ledger_path.is_file():
        return {**base, "status": "no_ledger", "candidates": [], "plan": []}
    if ledger_path.stat().st_size > MAX_LEDGER_BYTES:
        return {**base, "status": "ledger_too_large", "candidates": [], "plan": []}
    ledger = load_ledger(ledger_path)
    validation = validate_ledger(ledger, program_dir=paths.program_dir)
    issues = [i for i in validation.get("issues", []) if isinstance(i, dict)]
    tampered = {
        str(i["ref"])
        for i in issues
        if i.get("code")
        in {"evidence_digest_mismatch", "evidence_missing", "evidence_path_unsafe", "evidence_too_large"}
    }
    duplicates = {str(i["ref"]) for i in issues if i.get("code") == "duplicate_candidate"}
    stale = set(validation.get("summary", {}).get("stale_evidence") or []) - tampered
    evidence_rows = {str(e.get("evidence_id")): e for e in ledger.get("evidence") or [] if isinstance(e, dict)}
    evidence_state: dict[str, str] = {}
    facts_by_ref: dict[str, dict[str, Any]] = {}
    for eid, row in evidence_rows.items():
        if eid in tampered:
            evidence_state[eid] = "tampered"
            continue
        evidence_state[eid] = "stale" if eid in stale else "ok"
        facts = _read_annotation(paths.program_dir / str(row.get("path")))
        if facts:
            facts_by_ref[eid] = facts
            claimed = facts.get("program")
            if isinstance(claimed, str) and claimed != str(ledger.get("program") or paths.program):
                evidence_state[eid] = "out_of_program"
    # Fingerprint staleness is reported per candidate as a warning; mark referenced evidence stale.
    for issue in issues:
        if issue.get("code") == "evidence_invalidated_by_change":
            msg = str(issue.get("message", ""))
            for eid in evidence_rows:
                if f"Evidence {eid} " in msg and evidence_state.get(eid) == "ok":
                    evidence_state[eid] = "stale"
    surfaces = {str(s.get("surface_id")): s for s in ledger.get("surfaces") or [] if isinstance(s, dict)}
    candidates = sorted(
        (c for c in ledger.get("candidates") or [] if isinstance(c, dict)), key=lambda c: str(c.get("candidate_id"))
    )
    first_by_key: dict[str, str] = {}
    duplicate_map: dict[str, str] = {}
    for cand in candidates:
        if cand.get("state") == "rejected":
            continue
        key = str(cand.get("dedup_key") or f"{cand.get('surface_id')}|{str(cand.get('category', '')).lower()}")
        cid = str(cand.get("candidate_id"))
        if key in first_by_key and cid in duplicates:
            duplicate_map[cid] = first_by_key[key]
        else:
            first_by_key.setdefault(key, cid)
    # Existing, verified negative controls per surface that related candidates may reuse.
    shared: dict[str, dict[str, list[str]]] = {}
    for cand in candidates:
        for ref in cand.get("evidence_refs") or []:
            facts = facts_by_ref.get(str(ref)) or {}
            if evidence_state.get(str(ref)) == "ok" and facts.get("role") == "negative_control":
                if facts.get("contradicts_hypothesis") is not True:
                    bucket = shared.setdefault(str(cand.get("surface_id")), {})
                    bucket.setdefault("negative_control", []).append(str(ref))
    memory = _memory_status(paths)
    results: list[dict[str, Any]] = []
    for cand in candidates:
        if cand.get("state") not in ACTIVE_STATES:
            results.append(
                {"candidate_id": str(cand.get("candidate_id")), "status": f"closed_{cand.get('state')}", "steps": []}
            )
            continue
        sid = str(cand.get("surface_id"))
        results.append(
            _analyze_candidate(
                cand,
                surfaces.get(sid),
                evidence_state,
                facts_by_ref,
                duplicate_map.get(str(cand.get("candidate_id"))),
                {k: sorted(set(v)) for k, v in shared.get(sid, {}).items()},
                now,
                memory,
                evidence_rows,
            )
        )
    overlay = build_blocker_dependency_graph(
        ledger_candidate_records(candidates),
        ledger_evidence_records(evidence_rows, evidence_state, facts_by_ref, now=now),
    )
    _propagate_integrity_blocks(candidates, results, facts_by_ref, overlay, set(evidence_rows))
    # Global plan: dedupe equivalent steps across related candidates, rank deterministically.
    plan: dict[str, dict[str, Any]] = {}
    for res in results:
        for step in res["steps"]:
            existing = plan.get(step["step_id"])
            if existing is None:
                plan[step["step_id"]] = dict(step)
            elif step["candidate_id"] not in existing["also_applies_to"]:
                existing["also_applies_to"].append(step["candidate_id"])
                existing["also_applies_to"].sort()
    ranked = sorted(plan.values(), key=lambda s: (-int(s["score"]), s["candidate_id"], s["step_id"]))
    for rank, step in enumerate(ranked, start=1):
        step["rank"] = rank
    for res in results:
        res["steps"] = [s["step_id"] for s in res["steps"]]
    effective = effective_eligibility(ledger, results)
    eff_by_id = {row["candidate_id"]: row for row in effective}
    for res in results:
        row = eff_by_id.get(str(res.get("candidate_id")))
        if row is not None:
            res["effective"] = {
                k: row[k] for k in ("ledger_state", "effective_state", "effective_reviewable", "blockers")
            }
    return {
        **base,
        "status": "ok",
        "ledger_valid": bool(validation.get("valid")),
        "ledger_issue_count": len(issues),
        "candidates": results,
        "effective_eligibility": effective,
        "blocker_dependency_graph": overlay,
        "plan": ranked,
    }


def dumps_plan(plan: Mapping[str, Any]) -> str:
    """Minimized, deterministic JSON serialization."""
    return json.dumps(plan, sort_keys=True, separators=(",", ":"))


PLAN_SCHEMA: dict[str, Any] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "title": "bbtk evidence-gap next-step plan",
    "type": "object",
    "required": ["schema_version", "program", "status", "candidates", "plan", "network_requests_sent"],
    "properties": {
        "schema_version": {"const": PLAN_SCHEMA_VERSION},
        "network_requests_sent": {"const": 0},
        "executions": {"const": 0},
        "auto_confirmations": {"const": 0},
        "ai_used": {"const": False},
        "plan": {
            "type": "array",
            "items": {
                "type": "object",
                "required": [
                    "candidate_id",
                    "step_id",
                    "step_type",
                    "priority",
                    "reason_code",
                    "evidence_refs",
                    "missing_requirement",
                    "expected_information_gain",
                    "estimated_manual_steps",
                    "prerequisites",
                    "blocking_conditions",
                    "requires_human_review",
                    "execution_allowed",
                    "finding_confirmed",
                ],
                "properties": {
                    "step_type": {"enum": sorted(STEP_CATALOG)},
                    "requires_human_review": {"const": True},
                    "execution_allowed": {"const": False},
                    "finding_confirmed": {"const": False},
                },
            },
        },
    },
}


def validate_plan(plan: Mapping[str, Any]) -> list[str]:
    """Zero-dependency contract check; returns a list of problems (empty when valid)."""
    problems: list[str] = []
    for key in PLAN_SCHEMA["required"]:
        if key not in plan:
            problems.append(f"missing:{key}")
    if plan.get("schema_version") != PLAN_SCHEMA_VERSION:
        problems.append("schema_version")
    for key in ("network_requests_sent", "executions", "auto_confirmations"):
        if plan.get(key, 0) != 0:
            problems.append(f"nonzero:{key}")
    required = PLAN_SCHEMA["properties"]["plan"]["items"]["required"]
    for i, step in enumerate(plan.get("plan") or []):
        for key in required:
            if key not in step:
                problems.append(f"plan[{i}].missing:{key}")
        if step.get("step_type") not in STEP_CATALOG:
            problems.append(f"plan[{i}].step_type")
        if step.get("execution_allowed") is not False or step.get("finding_confirmed") is not False:
            problems.append(f"plan[{i}].unsafe_flags")
        if step.get("requires_human_review") is not True:
            problems.append(f"plan[{i}].human_review")
    return problems
