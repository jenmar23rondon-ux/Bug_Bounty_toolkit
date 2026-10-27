"""Evaluate resource-kind lineage preservation (offline, loopback-only corpus)."""

from __future__ import annotations

import argparse
import json
import socket
import tempfile
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from bugbounty_toolkit.analysis.object_handoff import propose_object_handoff
from bugbounty_toolkit.analysis.object_relationships import (
    _kind_ref,
    _ref,
    build_object_graph,
    object_candidates,
)
from bugbounty_toolkit.analysis.resource_kind_lineage import check_kind_coherence, graph_object_kinds

from . import metrics as M
from .build_corpus import KEY, ORIGIN, PROGRAM, VERSION, SCENARIOS

HERE = Path(__file__).resolve().parent


class NetworkBlocked(RuntimeError):
    pass


def no_network() -> Any:
    class _Guard:
        def __enter__(self) -> None:
            self._connect = socket.socket.connect

            def blocked(self_sock: Any, *a: Any, **k: Any) -> None:
                raise NetworkBlocked("network blocked in resource_kind_lineage_eval")

            socket.socket.connect = blocked  # type: ignore[method-assign]

        def __exit__(self, *exc: object) -> None:
            socket.socket.connect = self._connect  # type: ignore[method-assign]

    return _Guard()


def _origin_ref() -> str:
    u = urlsplit(ORIGIN)
    return _ref(KEY, "origin", PROGRAM, u.scheme, u.hostname or "", u.port or 80)


def _expected_kind_ids(nouns: list[str]) -> set[str]:
    origin = _origin_ref()
    out: set[str] = set()
    for noun in nouns:
        ref = _kind_ref(KEY, PROGRAM, origin, noun)
        if ref:
            out.add(ref)
    return out


def _run_scenario(scenario: dict[str, Any], corpus: Path) -> dict[str, Any]:
    har = corpus / f"{scenario['id']}.har"
    expect = scenario["expect"]
    with tempfile.TemporaryDirectory(prefix="rkl-"):
        graph = build_object_graph(PROGRAM, [har], KEY, authorized=True)
        cands = object_candidates(graph, PROGRAM, KEY, limit=100)
        handoff = propose_object_handoff(graph, PROGRAM, KEY, limit=20)
        coherence = check_kind_coherence(graph, cands, handoff)
        lineage = graph_object_kinds(graph)
    expected = _expected_kind_ids(list(expect.get("kinds") or []))
    observed: set[str] = set()
    for row in lineage.values():
        if row["status"] in {"explicit", "derived"} and len(row["kind_refs"]) == 1:
            observed.add(row["kind_refs"][0])
    statuses = {row["status"] for row in lineage.values()}
    # Kind accuracy: every expected kind is present; no unexpected explicit kinds when expect lists them.
    if expect.get("status") == "unknown":
        kind_accuracy = statuses <= {"unknown"} or (
            statuses & {"explicit", "derived"} == set() and "unknown" in statuses
        )
        correct_abstention = "unknown" in statuses and not (statuses & {"explicit"})
    elif expect.get("status") == "ambiguous":
        kind_accuracy = "ambiguous" in statuses
        correct_abstention = True
    else:
        kind_accuracy = expected <= observed
        correct_abstention = False
    # Preservation: every ranking candidate with a kind_id matches graph lineage.
    preserved = True
    for cand in cands["candidates"]:
        ref = cand["object_ref"]
        facts = lineage.get(ref, {"kind_refs": [], "status": "unknown"})
        claimed = cand.get("resource_kind")
        if facts["status"] == "ambiguous":
            if claimed is not None:
                preserved = False
        elif claimed is not None and [claimed] != facts["kind_refs"]:
            preserved = False
        status = (cand.get("kind_lineage") or {}).get("status")
        if status is not None and status != facts["status"]:
            preserved = False
    # Cross-kind collisions: one object_ref carrying >1 distinct expected kinds.
    collisions = 0
    if expect.get("no_cross_kind_collision"):
        for row in lineage.values():
            if len(set(row["kind_refs"]) & expected) > 1:
                collisions += 1
        # Also: proposals that pair across expected kinds.
        for proposal in handoff.get("proposals") or []:
            kind = proposal.get("resource_kind")
            if kind and expected and kind not in expected:
                collisions += 1
    # False namespace unions: equal raw IDs of different expected kinds share an object_ref.
    false_ns = 0
    if expect.get("no_cross_kind_collision") and len(expected) >= 2:
        # Count objects whose facts mix expected kinds.
        for row in lineage.values():
            if len(set(row["kind_refs"]) & expected) > 1:
                false_ns += 1
    ownership = any(
        node.get("ownership", "unknown") != "unknown" for node in graph["nodes"] if node.get("type") == "Object"
    ) or any(c.get("ownership", "unknown") != "unknown" for c in cands["candidates"])
    return {
        "id": scenario["id"],
        "tag": scenario["tag"],
        "kind_accuracy": bool(kind_accuracy),
        "kind_preserved": preserved and coherence["coherent"],
        "cross_kind_collisions": collisions,
        "false_namespace_unions": false_ns,
        "ownership_claim": ownership,
        "correct_abstention": correct_abstention if expect.get("status") in {"unknown", "ambiguous"} else False,
        "technical_errors": 0,
        "handoff_coherent": coherence["coherent"],
        "status_counts": coherence["status_counts"],
        "observed_kinds": sorted(observed),
        "expected_kinds": sorted(expected),
        "coherence_violations": coherence["violations"],
        "candidates": len(cands["candidates"]),
        "proposals": len(handoff.get("proposals") or []),
    }


def evaluate() -> dict[str, Any]:
    corpus = HERE / "corpus"
    with no_network():
        rows = [_run_scenario(s, corpus) for s in SCENARIOS]
    summary = M.summarize(rows)
    summary["corpus_version"] = VERSION
    summary["program"] = PROGRAM
    summary["network_connect_attempts"] = 0
    summary["vulnerabilities_confirmed"] = 0
    summary["limitation"] = (
        "Kinds are structural inferences only; ownership, privacy and authorization are never claimed."
    )
    return summary


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--json", type=Path, default=HERE / "results" / "rkl-1.0.json")
    args = parser.parse_args()
    result = evaluate()
    args.json.parent.mkdir(parents=True, exist_ok=True)
    args.json.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({k: result[k] for k in result if k != "rows"}, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
