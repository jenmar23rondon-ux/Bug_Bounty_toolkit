"""Blocker dependency graph for IDOR false-negative recovery.

Read-only overlay computed at evaluation time. It answers which artifact is
invalid or stale, which candidates depend on it, which objects are verifiably
associated, and which valid evidence does not depend on the bad artifact.

Historical Evidence Ledger states are never rewritten. ``finding_confirmed`` is
always false. Nothing here sends HTTP or turns uncertainty into a vulnerability.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

SCHEMA_VERSION = "bbtk-blocker-dependency-graph/1"

EFFECTIVE_STATES = (
    "reviewable",
    "blocked_invalid_evidence",
    "blocked_stale_evidence",
    "blocked_missing_control",
    "inconclusive",
    "safely_independent",
    "requires_manual_independence_review",
)

_INVALID = frozenset({"invalid", "missing", "out_of_program"})
_REVIEWABLE_STATES = frozenset({"reviewable", "safely_independent"})


def _as_str_list(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, str)]


def _integrity(row: Mapping[str, Any] | None) -> str:
    if row is None:
        return "missing"
    state = str(row.get("integrity") or "missing")
    if state in {"ok", "invalid", "stale", "missing", "out_of_program"}:
        return state
    return "invalid"


def closure(refs: Sequence[str], evidence: Mapping[str, Mapping[str, Any]]) -> list[str]:
    """Transitive evidence-id closure through ``depends_on``. Order-independent."""
    seen: set[str] = set()
    stack = [ref for ref in refs if isinstance(ref, str)]
    while stack:
        ref = stack.pop()
        if ref in seen:
            continue
        seen.add(ref)
        row = evidence.get(ref)
        for dep in _as_str_list((row or {}).get("depends_on")):
            if dep not in seen:
                stack.append(dep)
    return sorted(seen)


def _object_set(refs: Sequence[str], evidence: Mapping[str, Mapping[str, Any]]) -> set[str] | None:
    """Known object identities, or None when any cited artifact was never snapshotted."""
    found: set[str] = set()
    for ref in refs:
        row = evidence.get(ref)
        if row is None or "object_refs" not in row or row.get("object_refs") is None:
            return None
        namespace = row.get("namespace")
        prefix = f"{namespace}:" if isinstance(namespace, str) and namespace else ""
        for item in _as_str_list(row.get("object_refs")):
            found.add(prefix + item)
    return found


def _depends_on_bad(ref: str, evidence: Mapping[str, Mapping[str, Any]], seen: set[str] | None = None) -> bool:
    if seen is None:
        seen = set()
    if ref in seen:
        return False
    seen.add(ref)
    row = evidence.get(ref)
    if _integrity(row) != "ok":
        return True
    return any(_depends_on_bad(dep, evidence, seen) for dep in _as_str_list((row or {}).get("depends_on")))


def _sibling_association(
    candidate: Mapping[str, Any],
    own_closure: Sequence[str],
    evidence: Mapping[str, Mapping[str, Any]],
    candidates: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    """How this candidate relates to bad artifacts cited by same-surface siblings."""
    surface = str(candidate.get("surface_id") or "")
    own = set(own_closure)
    bad_refs: list[str] = []
    for other in candidates:
        if str(other.get("candidate_id")) == str(candidate.get("candidate_id")):
            continue
        if str(other.get("surface_id") or "") != surface:
            continue
        other_closure = closure(_as_str_list(other.get("evidence_refs")), evidence)
        for ref in other_closure:
            if ref in own:
                continue
            if _integrity(evidence.get(ref)) != "ok":
                bad_refs.append(ref)
    if not bad_refs:
        return {"kind": "none", "refs": [], "basis": "no_same_surface_bad_artifact"}
    mine = _object_set(own_closure, evidence)
    associated_invalid: list[str] = []
    associated_stale: list[str] = []
    ambiguous: list[str] = []
    disjoint: list[str] = []
    for ref in sorted(set(bad_refs)):
        theirs = _object_set([ref], evidence)
        state = _integrity(evidence.get(ref))
        # An empty object set on the bad artifact is unscoped: it does not prove
        # disjointness, so the surface stays fail-closed. A nonempty disjoint set does.
        if theirs is None or not theirs or mine is None:
            ambiguous.append(ref)
            continue
        if mine & theirs:
            if state == "stale":
                associated_stale.append(ref)
            else:
                associated_invalid.append(ref)
        else:
            disjoint.append(ref)
    if associated_invalid:
        return {
            "kind": "associated_invalid",
            "refs": associated_invalid,
            "basis": "verifiably_associated_objects",
        }
    if associated_stale:
        return {"kind": "associated_stale", "refs": associated_stale, "basis": "verifiably_associated_objects"}
    if ambiguous:
        return {"kind": "ambiguous", "refs": ambiguous, "basis": "object_association_unknown"}
    return {"kind": "proven_independent", "refs": disjoint, "basis": "disjoint_registered_objects"}


def _annotate_one(
    candidate: Mapping[str, Any],
    evidence: Mapping[str, Mapping[str, Any]],
    candidates: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    refs = _as_str_list(candidate.get("evidence_refs"))
    dependent = closure(refs, evidence)
    integrity = {ref: _integrity(evidence.get(ref)) for ref in dependent}
    invalid = [ref for ref, state in integrity.items() if state in _INVALID]
    stale = [ref for ref, state in integrity.items() if state == "stale"]
    independent = [ref for ref in dependent if not _depends_on_bad(ref, evidence)]
    association = _sibling_association(candidate, dependent, evidence, candidates)
    missing = _as_str_list(candidate.get("missing_mandatory_controls"))
    blockers: list[str] = []
    basis = "own_evidence"
    if invalid or association["kind"] == "associated_invalid":
        state = "blocked_invalid_evidence"
        blockers = [f"invalid:{ref}" for ref in invalid]
        blockers += [
            f"shared_object:{ref}"
            for ref in association.get("refs") or []
            if association["kind"] == "associated_invalid"
        ]
        basis = (
            association["basis"]
            if association["kind"] == "associated_invalid" and not invalid
            else "depends_on_invalid_artifact"
        )
        reason = "invalid, missing or out-of-program evidence is in this candidate's dependency closure"
        if association["kind"] == "associated_invalid" and not invalid:
            reason = "registered object identities intersect an invalid sibling artifact"
    elif stale or association["kind"] == "associated_stale":
        state = "blocked_stale_evidence"
        blockers = [f"stale:{ref}" for ref in stale]
        blockers += [
            f"shared_object:{ref}" for ref in association.get("refs") or [] if association["kind"] == "associated_stale"
        ]
        basis = (
            association["basis"]
            if association["kind"] == "associated_stale" and not stale
            else "depends_on_stale_artifact"
        )
        reason = "stale evidence is in this candidate's dependency closure"
        if association["kind"] == "associated_stale" and not stale:
            reason = "registered object identities intersect a stale sibling artifact"
    elif association["kind"] == "ambiguous":
        state = "requires_manual_independence_review"
        blockers = [f"ambiguous_objects:{ref}" for ref in association.get("refs") or []]
        basis = "object_association_unknown"
        reason = "a same-surface artifact is bad and its object identities were not registered, so independence is not proven"
    elif missing:
        state = "blocked_missing_control"
        blockers = [f"missing_control:{name}" for name in missing]
        basis = "mandatory_control_absent"
        reason = "a mandatory control is absent; the candidate is not reviewable"
    elif candidate.get("conflict") is True:
        state = "inconclusive"
        blockers = ["conflict"]
        basis = "conflicting_valid_observations"
        reason = "two otherwise valid observations conflict; uncertainty stays unresolved"
    elif _is_semantic_duplicate(candidate, candidates, evidence):
        state = "inconclusive"
        blockers = ["semantic_duplicate"]
        basis = "semantic_duplicate"
        reason = f"semantic duplicate of {candidate.get('semantic_duplicate_of')}"
    elif association["kind"] == "proven_independent":
        state = "safely_independent"
        basis = "disjoint_registered_objects"
        if str(candidate.get("bundle_id") or ""):
            basis = "disjoint_registered_objects"
        reason = "valid evidence does not depend on the bad artifact and object identities are disjoint"
    else:
        shared_bundle = _intact_shared_bundle(candidate, candidates, evidence)
        if shared_bundle:
            state = "reviewable"
            basis = "shared_provenance_intact"
            reason = "shared provenance is intact across candidates"
        else:
            state = "reviewable"
            basis = "no_blocker"
            reason = "no integrity, staleness, control or association blocker applies"
    return {
        "candidate_id": str(candidate.get("candidate_id")),
        "original_state": str(candidate.get("original_state") or ""),
        "effective_state": state,
        "reviewable": state in _REVIEWABLE_STATES,
        "blockers": sorted(set(blockers)),
        "dependent_refs": dependent,
        "independent_refs": independent,
        "independence_basis": basis,
        "evidence_integrity": integrity,
        "decision_reason": reason,
        "finding_confirmed": False,
    }


def _is_semantic_duplicate(
    candidate: Mapping[str, Any],
    candidates: Sequence[Mapping[str, Any]],
    evidence: Mapping[str, Mapping[str, Any]],
) -> bool:
    target_id = candidate.get("semantic_duplicate_of")
    if not isinstance(target_id, str):
        return False
    target = next((row for row in candidates if str(row.get("candidate_id")) == target_id), None)
    if target is None or str(target.get("surface_id") or "") != str(candidate.get("surface_id") or ""):
        return False
    mine = _object_set(_as_str_list(candidate.get("evidence_refs")), evidence)
    theirs = _object_set(_as_str_list(target.get("evidence_refs")), evidence)
    if mine is not None and theirs is not None:
        return mine == theirs
    return sorted(_as_str_list(candidate.get("evidence_refs"))) == sorted(_as_str_list(target.get("evidence_refs")))


def _intact_shared_bundle(
    candidate: Mapping[str, Any],
    candidates: Sequence[Mapping[str, Any]],
    evidence: Mapping[str, Mapping[str, Any]],
) -> bool:
    """True when a sibling shares a bundle id and every artifact in that bundle is ok."""
    own_bundles = {
        str(evidence[ref].get("bundle_id"))
        for ref in _as_str_list(candidate.get("evidence_refs"))
        if ref in evidence and isinstance(evidence[ref].get("bundle_id"), str)
    }
    if not own_bundles:
        return False
    surface = str(candidate.get("surface_id") or "")
    for other in candidates:
        if str(other.get("candidate_id")) == str(candidate.get("candidate_id")):
            continue
        if str(other.get("surface_id") or "") != surface:
            continue
        other_bundles = {
            str(evidence[ref].get("bundle_id"))
            for ref in _as_str_list(other.get("evidence_refs"))
            if ref in evidence and isinstance(evidence[ref].get("bundle_id"), str)
        }
        shared = own_bundles & other_bundles
        if not shared:
            continue
        for row in evidence.values():
            if str(row.get("bundle_id") or "") in shared and _integrity(row) != "ok":
                return False
        return True
    return False


def _whole_surface_blocks(
    rows: Sequence[Mapping[str, Any]],
    candidates: Sequence[Mapping[str, Any]],
    evidence: Mapping[str, Mapping[str, Any]],
) -> list[str]:
    by_surface: dict[str, list[Mapping[str, Any]]] = {}
    for row in rows:
        cand = next(c for c in candidates if str(c.get("candidate_id")) == row["candidate_id"])
        by_surface.setdefault(str(cand.get("surface_id") or ""), []).append(row)
    whole: list[str] = []
    for surface, group in by_surface.items():
        if any(row["effective_state"] == "requires_manual_independence_review" for row in group):
            whole.append(surface)
            continue
        if len(group) < 2:
            continue
        closures = []
        for row in group:
            cand = next(c for c in candidates if str(c.get("candidate_id")) == row["candidate_id"])
            closures.append(set(closure(_as_str_list(cand.get("evidence_refs")), evidence)))
        bad = {ref for refs in closures for ref in refs if _integrity(evidence.get(ref)) != "ok"}
        if bad and all(refs & bad for refs in closures):
            whole.append(surface)
    return sorted(surface for surface in whole if surface)


def build_blocker_dependency_graph(
    candidates: Sequence[Mapping[str, Any]],
    evidence: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    """Return the overlay. Input order does not affect the result. Inputs are not mutated."""
    evidence_by_id = {str(row.get("evidence_id")): dict(row) for row in evidence if isinstance(row, Mapping)}
    cand_rows = [dict(row) for row in candidates if isinstance(row, Mapping)]
    annotated = [_annotate_one(cand, evidence_by_id, cand_rows) for cand in cand_rows]
    annotated.sort(key=lambda row: row["candidate_id"])
    artifacts = []
    for eid in sorted(evidence_by_id):
        row = evidence_by_id[eid]
        artifacts.append(
            {
                "evidence_id": eid,
                "integrity": _integrity(row),
                "object_refs_known": row.get("object_refs") is not None,
                "depends_on": sorted(_as_str_list(row.get("depends_on"))),
                "dependent_candidates": [item["candidate_id"] for item in annotated if eid in item["dependent_refs"]],
            }
        )
    return {
        "schema_version": SCHEMA_VERSION,
        "finding_confirmed": False,
        "ledger_modified": False,
        "network_requests_sent": 0,
        "external_requests": 0,
        "auto_confirmations": 0,
        "effective_states": list(EFFECTIVE_STATES),
        "artifacts": artifacts,
        "whole_surface_blocks": _whole_surface_blocks(annotated, cand_rows, evidence_by_id),
        "candidates": annotated,
    }


def ledger_evidence_records(
    evidence_rows: Mapping[str, Mapping[str, Any]],
    evidence_state: Mapping[str, str],
    facts_by_ref: Mapping[str, Mapping[str, Any]],
    *,
    now: str | None = None,
) -> list[dict[str, Any]]:
    """Project ledger rows into graph evidence without reading tampered file bytes."""
    records: list[dict[str, Any]] = []
    for eid in sorted(evidence_rows):
        row = evidence_rows[eid]
        state = evidence_state.get(eid, "broken")
        if state == "ok":
            integrity = "ok"
        elif state == "stale":
            integrity = "stale"
        elif state == "out_of_program":
            integrity = "out_of_program"
        else:
            integrity = "invalid"
        prov = row.get("provenance") if isinstance(row.get("provenance"), Mapping) else {}
        facts = facts_by_ref.get(eid) or {}
        expires = facts.get("expires_at")
        if integrity == "ok" and isinstance(expires, str) and now is not None and expires <= now:
            integrity = "stale"
        readable = eid in facts_by_ref or integrity in {"ok", "stale", "out_of_program"}
        if readable:
            if "object_refs" in facts:
                objects: list[str] | None = _as_str_list(facts.get("object_refs"))
            elif "registered_object_refs" in prov:
                objects = _as_str_list(prov.get("registered_object_refs"))
            else:
                objects = []
        elif "registered_object_refs" in prov:
            objects = _as_str_list(prov.get("registered_object_refs"))
        else:
            objects = None
        depends = set(_as_str_list(prov.get("depends_on"))) | set(_as_str_list(facts.get("depends_on")))
        record: dict[str, Any] = {
            "evidence_id": eid,
            "integrity": integrity,
            "object_refs": objects,
            "depends_on": sorted(depends),
        }
        bundle = prov.get("bundle_id")
        if isinstance(bundle, str):
            record["bundle_id"] = bundle
        records.append(record)
    return records


def ledger_candidate_records(candidates: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    return [
        {
            "candidate_id": str(cand.get("candidate_id")),
            "surface_id": str(cand.get("surface_id") or ""),
            "evidence_refs": _as_str_list(cand.get("evidence_refs")),
            "original_state": str(cand.get("state") or ""),
        }
        for cand in candidates
        if isinstance(cand, Mapping)
    ]
