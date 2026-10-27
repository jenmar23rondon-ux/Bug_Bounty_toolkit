"""Adversarial tests for resource-kind-lineage-v1 (offline only)."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from bugbounty_toolkit.analysis.object_handoff import propose_object_handoff
from bugbounty_toolkit.analysis.object_relationships import (
    KIND_LINEAGE_VERSION,
    build_object_graph,
    kind_lineage,
    kind_status,
    object_candidates,
)
from bugbounty_toolkit.analysis.resource_kind_lineage import check_kind_coherence, graph_object_kinds
from labs.resource_kind_lineage_eval import evaluate as lab
from labs.resource_kind_lineage_eval.build_corpus import KEY, PROGRAM, SCENARIOS

HERE = Path(__file__).resolve().parents[1]
CORPUS = HERE / "labs" / "resource_kind_lineage_eval" / "corpus"
RESULTS = HERE / "labs" / "resource_kind_lineage_eval" / "results" / "rkl-1.0.json"


def _har(entries: list[dict]) -> Path:
    tmp = tempfile.NamedTemporaryFile(suffix=".har", delete=False)
    path = Path(tmp.name)
    path.write_text(
        json.dumps({"log": {"version": "1.2", "creator": {"name": "t", "version": "1"}, "entries": entries}}),
        encoding="utf-8",
    )
    return path


class KindLineageUnitTests(unittest.TestCase):
    def test_kind_status_matrix(self) -> None:
        self.assertEqual(kind_status(set(), set()), "unknown")
        self.assertEqual(kind_status({"kind:user"}, {"path_collection"}), "explicit")
        self.assertEqual(kind_status({"kind:user"}, {"collection_container"}), "derived")
        self.assertEqual(kind_status({"kind:user", "kind:order"}, {"path_collection"}), "ambiguous")

    def test_kind_lineage_never_claims_ownership(self) -> None:
        row = kind_lineage({"kind:user"}, {"path_collection"}, {"obs-1"}, ["origin-1"])
        self.assertEqual(row["version"], KIND_LINEAGE_VERSION)
        self.assertEqual(row["ownership"], "not_inferred_from_kind")
        self.assertEqual(row["status"], "explicit")
        self.assertIsNone(kind_lineage({"a", "b"}, set(), set(), [])["kind_id"])

    def test_users_and_orders_same_raw_id_stay_apart(self) -> None:
        from labs.resource_kind_lineage_eval.build_corpus import _entry

        path = _har(
            [
                _entry("GET", "/users/7", "A", resp={"id": 7}),
                _entry("GET", "/orders/7", "A", resp={"id": 7}),
            ]
        )
        try:
            graph = build_object_graph(PROGRAM, [path], KEY, authorized=True)
            objects = [n for n in graph["nodes"] if n["type"] == "Object"]
            self.assertGreaterEqual(len(objects), 2)
            kinds = graph_object_kinds(graph)
            observed = {tuple(row["kind_refs"]) for row in kinds.values() if row["kind_refs"]}
            # Distinct single-kind objects; never one object carrying both kinds.
            self.assertTrue(all(len(k) == 1 for k in observed))
            flat = {k[0] for k in observed}
            self.assertGreaterEqual(len(flat), 2)
            for node in objects:
                self.assertEqual(node["ownership"], "unknown")
                self.assertEqual(node["privacy"], "unknown")
        finally:
            path.unlink(missing_ok=True)

    def test_array_ids_of_different_kinds_do_not_collapse(self) -> None:
        from labs.resource_kind_lineage_eval.build_corpus import _entry

        path = _har(
            [
                _entry("GET", "/bundle", "A", resp={"tickets": [{"id": 7}], "claims": [{"id": 7}]}),
            ]
        )
        try:
            graph = build_object_graph(PROGRAM, [path], KEY, authorized=True)
            kinds = graph_object_kinds(graph)
            collisions = sum(1 for row in kinds.values() if len(row["kind_refs"]) > 1)
            self.assertEqual(collisions, 0)
            cands = object_candidates(graph, PROGRAM, KEY)
            for row in cands["candidates"]:
                self.assertIn("kind_lineage", row)
                self.assertEqual(row["ownership"], "unknown")
                self.assertEqual(row["kind_lineage"]["ownership"], "not_inferred_from_kind")
            coherence = check_kind_coherence(graph, cands, propose_object_handoff(graph, PROGRAM, KEY))
            self.assertTrue(coherence["coherent"])
        finally:
            path.unlink(missing_ok=True)

    def test_ranking_exports_resource_kind_and_lineage(self) -> None:
        from labs.resource_kind_lineage_eval.build_corpus import _entry

        path = _har(
            [
                _entry("GET", "/crates/3", "A", resp={"id": 3}),
                _entry("GET", "/crates/3", "B", resp={"id": 3}),
            ]
        )
        try:
            graph = build_object_graph(PROGRAM, [path], KEY, authorized=True)
            cands = object_candidates(graph, PROGRAM, KEY)
            typed = [c for c in cands["candidates"] if c.get("resource_kind")]
            self.assertTrue(typed)
            for row in typed:
                self.assertEqual(row["kind_lineage"]["kind_id"], row["resource_kind"])
                self.assertIn(row["kind_lineage"]["status"], ("explicit", "derived"))
        finally:
            path.unlink(missing_ok=True)

    def test_ambiguous_object_hides_kind_from_ranking_and_handoff(self) -> None:
        """When one object carries conflicting kind_refs, ranking must not pick one."""
        graph = {
            "schema_version": "1.0",
            "type": "api-object-relationship-graph",
            "program": PROGRAM,
            "ranking_version": "2.0",
            "key_id": "key",
            "integrity": "x",
            "network_requests_sent": 0,
            "vulnerabilities_confirmed": 0,
            "sources": [],
            "nodes": [
                {"id": "obj-1", "type": "Object", "resource_type": "unknown", "ownership": "unknown"},
                {"id": "ep-1", "type": "Endpoint", "origin_ref": "o1"},
            ],
            "relations": [],
            "observations": [
                {
                    "id": "obs-1",
                    "endpoint_ref": "ep-1",
                    "session_ref": "s1",
                    "references": [
                        {
                            "object_ref": "obj-1",
                            "kind_ref": "kind:ticket",
                            "kind_basis": "typed_field_name",
                            "location": "path",
                            "typed": True,
                            "field_ref": "f1",
                        },
                        {
                            "object_ref": "obj-1",
                            "kind_ref": "kind:claim",
                            "kind_basis": "typed_field_name",
                            "location": "path",
                            "typed": True,
                            "field_ref": "f2",
                        },
                    ],
                    "provenance": [{"source_ref": "src", "locator": "entries[0]"}],
                }
            ],
        }
        lineage = graph_object_kinds(graph)
        self.assertEqual(lineage["obj-1"]["status"], "ambiguous")
        # Synthetic candidate claiming one of the kinds must be flagged.
        candidates = {
            "candidates": [
                {
                    "object_ref": "obj-1",
                    "resource_kind": "kind:ticket",
                    "kind_lineage": {"status": "explicit"},
                    "ownership": "unknown",
                }
            ]
        }
        result = check_kind_coherence(graph, candidates, {"proposals": []})
        self.assertFalse(result["coherent"])
        self.assertTrue(any(v["code"] == "ranking_ambiguity_hidden" for v in result["violations"]))

    def test_unknown_bare_id_abstains(self) -> None:
        from labs.resource_kind_lineage_eval.build_corpus import _entry

        path = _har([_entry("GET", "/payload", "A", resp={"id": 55})])
        try:
            graph = build_object_graph(PROGRAM, [path], KEY, authorized=True)
            kinds = graph_object_kinds(graph)
            self.assertTrue(kinds)
            self.assertTrue(all(row["status"] == "unknown" for row in kinds.values()))
        finally:
            path.unlink(missing_ok=True)


class KindLineageLabTests(unittest.TestCase):
    def test_corpus_pinned(self) -> None:
        from labs.resource_kind_lineage_eval.build_corpus import check

        # Corpus is committed + hash-pinned; never rewrite (offline-lab FS is read-only).
        check(CORPUS)

    def test_lab_metrics_pinned(self) -> None:
        result = lab.evaluate()
        self.assertEqual(result["scenarios"], 13)
        self.assertEqual(result["kind_accuracy"], 1.0)
        self.assertEqual(result["kind_preservation_rate"], 1.0)
        self.assertEqual(result["cross_kind_collisions"], 0)
        self.assertEqual(result["false_namespace_unions"], 0)
        self.assertEqual(result["ownership_claims"], 0)
        self.assertEqual(result["handoff_coherence_rate"], 1.0)
        self.assertEqual(result["network_connect_attempts"], 0)
        self.assertEqual(result["vulnerabilities_confirmed"], 0)
        pinned = json.loads(RESULTS.read_text(encoding="utf-8"))
        for key in (
            "kind_accuracy",
            "kind_preservation_rate",
            "cross_kind_collisions",
            "false_namespace_unions",
            "ownership_claims",
            "handoff_coherence_rate",
            "scenarios",
        ):
            self.assertEqual(result[key], pinned[key], key)

    def test_scenario_catalog_covers_spec(self) -> None:
        tags = {s["tag"] for s in SCENARIOS}
        for required in (
            "users-vs-orders-same-id",
            "identical-id-different-collections",
            "uuid-different-namespace",
            "singular-plural",
            "unconventional-noun",
            "nested-resources",
            "arrays",
            "schema-change-same-kind",
            "unknown-generic-id",
            "bare-id-field",
            "foreign-id-fields",
            "out-of-order-captures",
            "contradictory-kind-evidence",
        ):
            self.assertIn(required, tags)


if __name__ == "__main__":
    unittest.main()
