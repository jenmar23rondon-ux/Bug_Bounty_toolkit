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

__all__ = ["graph_object_kinds", "check_kind_coherence"]


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
