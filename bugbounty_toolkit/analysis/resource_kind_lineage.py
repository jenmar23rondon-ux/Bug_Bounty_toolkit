"""Resource-kind lineage coherence checks (resource-kind-lineage-v1).

Read-only validation that the inferred resource kind of every object reference is preserved, without
silent renames, from the object graph (capture facts) through ranking candidates to Object Handoff
proposals. Kinds are keyed identifiers (``kind:<known noun>`` or ``kind-<hmac>``); they are a
structural inference only and never an ownership, privacy or authorization claim.
"""

from __future__ import annotations

from collections import defaultdict
from typing import Any

from .object_relationships import KIND_LINEAGE_VERSION, kind_status

__all__ = ["graph_object_kinds", "check_kind_coherence", "correlate_resources"]


def graph_object_kinds(graph: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """object_ref -> {kind_refs, bases, status} aggregated from every graph fact (capture provenance)."""
    kinds: dict[str, set[str]] = defaultdict(set)
    bases: dict[str, set[str]] = defaultdict(set)
    objects = {node["id"] for node in graph.get("nodes") or [] if node.get("type") == "Object"}
    for observation in graph.get("observations") or []:
        for fact in observation.get("references") or []:
            ref = fact.get("object_ref")
            if not isinstance(ref, str):
                continue
            if isinstance(fact.get("kind_ref"), str):
                kinds[ref].add(fact["kind_ref"])
                if isinstance(fact.get("kind_basis"), str):
                    bases[ref].add(fact["kind_basis"])
    return {
        ref: {
            "kind_refs": sorted(kinds[ref]),
            "bases": sorted(bases[ref]),
            "status": kind_status(kinds[ref], bases[ref]),
        }
        for ref in sorted(objects)
    }


def check_kind_coherence(
    graph: dict[str, Any], candidates: dict[str, Any] | None = None, handoff: dict[str, Any] | None = None
) -> dict[str, Any]:
    """Return lineage violations between graph, ranking and handoff (empty list = coherent).

    Violation codes:
      * ``ranking_kind_mismatch`` — candidate kind id differs from the graph facts' single kind.
      * ``ranking_kind_invented`` — candidate claims a kind the graph has no evidence for.
      * ``ranking_ambiguity_hidden`` — graph is ambiguous but ranking reports one kind.
      * ``handoff_kind_not_in_graph`` — a proposal side's object never carried the proposal kind.
      * ``handoff_cross_kind_pair`` — owner and actor objects carry different single kinds.
      * ``handoff_ambiguous_side`` — a proposal pairs an object whose graph kind is ambiguous.
      * ``ownership_claim`` — any stage asserts ownership other than unknown.
    """
    lineage = graph_object_kinds(graph)
    violations: list[dict[str, str]] = []

    def add(code: str, ref: str, stage: str) -> None:
        violations.append({"code": code, "object_ref": ref, "stage": stage})

    for row in (candidates or {}).get("candidates") or []:
        ref = str(row.get("object_ref"))
        facts = lineage.get(ref, {"kind_refs": [], "status": "unknown"})
        claimed = row.get("resource_kind")
        if row.get("ownership", "unknown") != "unknown":
            add("ownership_claim", ref, "ranking")
        if facts["status"] == "ambiguous":
            if claimed is not None:
                add("ranking_ambiguity_hidden", ref, "ranking")
        elif claimed is not None and not facts["kind_refs"]:
            add("ranking_kind_invented", ref, "ranking")
        elif claimed is not None and [claimed] != facts["kind_refs"]:
            add("ranking_kind_mismatch", ref, "ranking")
        status = (row.get("kind_lineage") or {}).get("status")
        if status is not None and status != facts["status"]:
            add("ranking_kind_mismatch", ref, "ranking")
    for proposal in (handoff or {}).get("proposals") or []:
        kind = proposal.get("resource_kind")
        sides = [proposal.get("owner") or {}, proposal.get("actor") or {}]
        single: set[str] = set()
        for side in sides:
            ref = str(side.get("object_ref"))
            facts = lineage.get(ref, {"kind_refs": [], "status": "unknown"})
            if side.get("ownership", "unknown") != "unknown":
                add("ownership_claim", ref, "handoff")
            if facts["status"] == "ambiguous":
                add("handoff_ambiguous_side", ref, "handoff")
            elif facts["kind_refs"]:
                single.update(facts["kind_refs"])
            # Legacy known-vocabulary kinds ("kind:<noun>") may come from resource_type without facts.
            if kind and facts["kind_refs"] and kind not in facts["kind_refs"]:
                add("handoff_kind_not_in_graph", ref, "handoff")
        if len(single) > 1:
            add("handoff_cross_kind_pair", str(sides[0].get("object_ref")), "handoff")
    return {
        "version": KIND_LINEAGE_VERSION,
        "objects": len(lineage),
        "status_counts": {
            status: sum(1 for row in lineage.values() if row["status"] == status)
            for status in ("explicit", "derived", "unknown", "ambiguous")
        },
        "violations": violations,
        "coherent": not violations,
        "ownership": "not_inferred_from_kind",
    }


# Resource correlation (idor-evidence-correctness-v3) ---------------------------------------
CORRELATION_VERSION = "bbtk.resource-correlation/1"
_KNOWN_KIND_STATUSES = frozenset({"explicit", "derived"})


def correlate_resources(owner: dict[str, Any], actor: dict[str, Any]) -> dict[str, Any]:
    """Relate two observed object references conservatively (pure, offline).

    Each side: ``kind`` (keyed kind id or None), ``kind_status`` (explicit/derived/unknown/
    ambiguous), ``namespace_key`` (from ``normalize_captured_identifier`` or None),
    ``account_ref`` / ``distinct_accounts_attested`` (human declaration), ``session_ref``,
    ``visibility`` (public/shared/private/None) and ``body_digest``.

    * Same digits under different kinds (``order 123`` vs ``user 123``) are ``different_kind``.
    * Unknown/ambiguous kinds keep the relation ``unknown`` (never guessed).
    * Different cookies/sessions alone never make accounts ``distinct`` - only an attestation.
    * Public or legitimately shared content, or an identical response both sides are entitled
      to, is ``legitimate_shared`` and never an IDOR signal.
    * ``idor_signal`` is only ever a *review* hint; nothing is confirmed.
    """
    reasons: list[str] = []
    kinds_known = all(side.get("kind") and side.get("kind_status") in _KNOWN_KIND_STATUSES for side in (owner, actor))
    if not kinds_known:
        relation = "unknown"
        reasons.append("kind_unknown_or_ambiguous")
    elif owner.get("kind") != actor.get("kind"):
        relation = "different_kind"
        reasons.append("same_identifier_digits_do_not_link_different_kinds")
    elif owner.get("namespace_key") and owner.get("namespace_key") == actor.get("namespace_key"):
        relation = "same_object"
    elif owner.get("namespace_key") and actor.get("namespace_key"):
        relation = "different_object"
    else:
        relation = "unknown"
        reasons.append("identifier_not_normalized")
    attested = bool(owner.get("distinct_accounts_attested") and actor.get("distinct_accounts_attested"))
    if attested and owner.get("account_ref") and owner.get("account_ref") != actor.get("account_ref"):
        accounts = "distinct_attested"
    elif owner.get("account_ref") and owner.get("account_ref") == actor.get("account_ref"):
        accounts = "same_account"
    else:
        accounts = "unknown"
        if owner.get("session_ref") != actor.get("session_ref"):
            reasons.append("different_sessions_do_not_prove_distinct_accounts")
    visibility = {owner.get("visibility"), actor.get("visibility")} & {"public", "shared"}
    shared_body = bool(owner.get("body_digest")) and owner.get("body_digest") == actor.get("body_digest")
    legitimate = bool(visibility) or (shared_body and owner.get("visibility") != "private")
    if visibility:
        reasons.append(f"resource_{sorted(visibility)[0]}")
    elif legitimate:
        reasons.append("identical_response_without_private_marker")
    idor_signal = relation == "same_object" and accounts == "distinct_attested" and not legitimate
    return {
        "version": CORRELATION_VERSION,
        "relation": relation,
        "accounts": accounts,
        "legitimate_shared": legitimate,
        "resource_kind": owner.get("kind") if relation in {"same_object", "different_object"} else None,
        "idor_review_signal": idor_signal,
        "reasons": sorted(set(reasons)),
        "confirmed": False,
        "ownership": "not_inferred_from_kind",
    }
