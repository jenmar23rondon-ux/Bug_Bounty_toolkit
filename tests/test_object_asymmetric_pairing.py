"""Offline asymmetric response->request pairing: human-review proposals only (synthetic fixtures)."""

from __future__ import annotations

import json
import os
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
from unittest.mock import patch

from bugbounty_toolkit.analysis import object_handoff
from bugbounty_toolkit.analysis.object_handoff import (
    ASYMMETRIC_RULE,
    default_lab_root,
    handoff_to_file,
    propose_object_handoff,
    run_object_discovery_lab,
)
from bugbounty_toolkit.analysis.object_relationships import build_object_graph, save_object_json
from bugbounty_toolkit.core.private_files import atomic_private_write

HOST = "http://127.0.0.1:8099"
KEY = b"a" * 32


def _entry(
    path: str,
    session: str | None,
    response: object | None = None,
    *,
    method: str = "GET",
    request_body: object | None = None,
    host: str = HOST,
) -> dict[str, object]:
    headers = [{"name": "Authorization", "value": "Bearer " + session}] if session else []
    request: dict[str, object] = {"method": method, "url": host + path, "headers": headers}
    if request_body is not None:
        request["postData"] = {"mimeType": "application/json", "text": json.dumps(request_body)}
    text = "" if response is None else json.dumps(response)
    return {"request": request, "response": {"status": 200, "content": {"mimeType": "application/json", "text": text}}}


def _asym(document: dict[str, object]) -> list[dict[str, object]]:
    proposals = document["proposals"]
    assert isinstance(proposals, list)
    return [row for row in proposals if row["pair_kind"] == "asymmetric_response_request"]


@unittest.skipUnless(os.name == "posix", "Secure private artifact I/O requires POSIX no-follow descriptors")
class AsymmetricPairingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def _graph(self, entries: list[dict[str, object]], name: str = "captures.har") -> tuple[dict, Path]:
        path = self.root / name
        har = {"log": {"version": "1.2", "creator": {"name": "t", "version": "1"}, "entries": entries}}
        path.write_text(json.dumps(har), encoding="utf-8")
        return build_object_graph("asym-lab", [path], KEY, authorized=True), path

    def _positive(self) -> tuple[dict, Path]:
        return self._graph(
            [
                _entry("/api/projects", "owner-a", {"data": {"project_id": 701}}, method="POST", request_body={"n": 1}),
                _entry(
                    "/api/projects",
                    "actor-b",
                    {"data": {"status": "ok"}},
                    method="POST",
                    request_body={"project_id": 702},
                ),
            ]
        )

    def test_response_only_identifier_forms_inferred_unconfirmed_proposal(self) -> None:
        graph, path = self._positive()
        document = propose_object_handoff(graph, "asym-lab", KEY, verify_inputs=[path], limit=10)
        rows = _asym(document)
        self.assertEqual(len(rows), 1)
        row = rows[0]
        self.assertEqual(row["resource_type"], "project")
        self.assertFalse(row["confirmed"])
        self.assertFalse(row["case_executable"])
        self.assertTrue(row["researcher_review_required"])
        self.assertEqual(row["relation"]["state"], "inferred")
        self.assertEqual(row["relation"]["ownership"], "unknown")
        self.assertEqual(row["relation"]["rule"], ASYMMETRIC_RULE)
        observed = {item["role"]: item for item in row["observed_identifiers"]}
        self.assertEqual(observed["owner"]["observed_in"], "response_json")
        self.assertEqual(observed["owner"]["type_basis"], "typed_field_name")
        self.assertEqual(observed["actor"]["observed_in"], "request")
        self.assertTrue(all(item["ownership"] == "unknown" for item in row["observed_identifiers"]))
        # Provenance points at the verified source commitment and HAR locators.
        sources = (
            {source["id"] for source in graph["sources"]}
            if isinstance(graph["sources"], list)
            else set(graph["sources"])
        )
        for role in ("owner", "actor"):
            self.assertIn(row[role]["source_ref"], sources)
            self.assertTrue(row[role]["locator"])
            self.assertTrue(row[role]["observation_ref"])
        self.assertNotEqual(row["owner"]["session_ref"], row["actor"]["session_ref"])
        self.assertLessEqual(row["score"], object_handoff.ASYMMETRIC_SCORE_CEILING)
        self.assertEqual(document["network_requests_sent"], 0)
        self.assertEqual(document["vulnerabilities_confirmed"], 0)
        self.assertEqual(document["response_identifiers"]["asymmetric_selected"], 1)
        rendered = json.dumps(document)
        self.assertNotIn("owner-a", rendered)
        self.assertNotIn("actor-b", rendered)
        self.assertNotIn("701", rendered)

    def test_request_only_mode_matches_previous_behavior(self) -> None:
        graph, _ = self._positive()
        document = propose_object_handoff(graph, "asym-lab", KEY, include_response_identifiers=False)
        self.assertEqual(document["total_proposals"], 0)
        self.assertFalse(document["response_identifiers"]["enabled"])

    def test_deterministic_ids_and_order(self) -> None:
        graph, _ = self._positive()
        first = propose_object_handoff(graph, "asym-lab", KEY)
        second = propose_object_handoff(graph, "asym-lab", KEY)
        self.assertEqual(first["proposals"], second["proposals"])

    def test_both_sides_response_only_is_not_paired(self) -> None:
        graph, _ = self._graph(
            [
                _entry("/api/session/summary", "owner-a", {"data": {"customer_id": 801}}),
                _entry("/api/session/summary", "actor-b", {"data": {"customer_id": 802}}),
                _entry("/api/customers/803", None, None),
            ]
        )
        document = propose_object_handoff(graph, "asym-lab", KEY)
        self.assertEqual(document["total_proposals"], 0)
        self.assertGreaterEqual(document["response_identifiers"]["observed"], 2)

    def test_bare_wrapper_id_is_observed_but_not_linked(self) -> None:
        graph, _ = self._graph(
            [
                _entry("/api/teams", "owner-a", {"data": {"id": 901}}, method="POST", request_body={"n": 1}),
                _entry("/api/teams", "actor-b", {"data": {}}, method="POST", request_body={"team_id": 902}),
            ]
        )
        document = propose_object_handoff(graph, "asym-lab", KEY)
        self.assertEqual(_asym(document), [])
        self.assertEqual(document["response_identifiers"]["excluded_bare_response_id"], 1)

    def test_shared_numeric_token_across_types_never_links(self) -> None:
        graph, _ = self._graph(
            [
                _entry("/api/summary", "owner-a", {"data": {"order_id": 777}}),
                _entry("/api/invoices?invoice_id=778", "actor-b", {"data": {}}),
                _entry("/api/invoices?invoice_id=777", "actor-b", {"data": {}}),
            ]
        )
        document = propose_object_handoff(graph, "asym-lab", KEY)
        self.assertEqual(_asym(document), [])

    def test_identifier_seen_by_several_sessions_is_shared_context(self) -> None:
        graph, _ = self._graph(
            [
                _entry("/api/tenants/31", "owner-a", {"data": {}}),
                _entry("/api/session/context", "owner-a", {"data": {"tenant_id": 30}}),
                _entry("/api/session/context", "actor-b", {"data": {"tenant_id": 30}}),
            ]
        )
        document = propose_object_handoff(graph, "asym-lab", KEY)
        self.assertEqual(_asym(document), [])
        self.assertEqual(document["response_identifiers"]["excluded_shared_context"], 1)

    def test_collection_container_array_is_type_evidence(self) -> None:
        graph, _ = self._graph(
            [
                _entry("/api/profile", "owner-a", {"data": {"addresses": [{"id": 61}, {"id": 63}]}}),
                _entry("/api/addresses/62", "actor-b", {"data": {"id": 62}}),
            ]
        )
        rows = _asym(propose_object_handoff(graph, "asym-lab", KEY))
        self.assertEqual(len(rows), 2)
        self.assertTrue(all(row["observed_identifiers"][0]["type_basis"] == "collection_container" for row in rows))
        self.assertTrue(all(row["resource_type"] == "address" for row in rows))

    def test_untyped_resource_and_cross_origin_are_not_linked(self) -> None:
        graph, _ = self._graph(
            [
                _entry("/api/things", "owner-a", {"data": {"widget_id": 5}}),
                _entry("/api/projects", "owner-a", {"data": {"project_id": 41}}),
                _entry("/api/projects/42", "actor-b", {"data": {}}, host="http://127.0.0.2:8099"),
            ]
        )
        document = propose_object_handoff(graph, "asym-lab", KEY)
        self.assertEqual(_asym(document), [])
        self.assertGreaterEqual(document["response_identifiers"]["excluded_untyped_resource"], 1)

    def test_unauthenticated_request_side_is_ignored(self) -> None:
        graph, _ = self._graph(
            [
                _entry("/api/projects", "owner-a", {"data": {"project_id": 51}}),
                _entry("/api/projects/52", None, {"data": {}}),
            ]
        )
        self.assertEqual(propose_object_handoff(graph, "asym-lab", KEY)["total_proposals"], 0)

    def test_candidate_filter(self) -> None:
        graph, _ = self._positive()
        row = _asym(propose_object_handoff(graph, "asym-lab", KEY))[0]
        focused = propose_object_handoff(graph, "asym-lab", KEY, candidate=row["owner"]["object_ref"])
        self.assertEqual(focused["status"], "proposals_ready")
        self.assertEqual(focused["proposals"][0]["id"], row["id"])
        missing = propose_object_handoff(graph, "asym-lab", KEY, candidate="object-" + "0" * 32)
        self.assertEqual(missing["status"], "insufficient_evidence")
        self.assertIn("asymmetric rule", missing["notes"][0])

    def test_bounds_truncate_deterministically(self) -> None:
        graph, _ = self._graph(
            [
                _entry("/api/profile", "owner-a", {"data": {"addresses": [{"id": 61}, {"id": 63}, {"id": 65}]}}),
                _entry("/api/addresses/62", "actor-b", {"data": {}}),
                _entry("/api/addresses/64", "actor-b", {"data": {}}),
            ]
        )
        with patch.object(object_handoff, "MAX_ASYMMETRIC_PAIRS", 1):
            document = propose_object_handoff(graph, "asym-lab", KEY)
        self.assertEqual(len(_asym(document)), 1)
        self.assertGreaterEqual(document["response_identifiers"]["truncated"], 1)
        with patch.object(object_handoff, "MAX_RESPONSE_SIDES", 1):
            document = propose_object_handoff(graph, "asym-lab", KEY)
        self.assertGreaterEqual(document["response_identifiers"]["truncated"], 1)
        self.assertEqual(len({row["owner"]["object_ref"] for row in _asym(document)}), 1)

    def test_materialize_asymmetric_pair_writes_snapshots_only(self) -> None:
        graph, path = self._positive()
        key_path = self.root / "key.bin"
        graph_path = self.root / "graph.json"
        atomic_private_write(key_path, KEY)
        save_object_json(graph_path, graph)
        pairs = self.root / "pairs"
        document = handoff_to_file(
            "asym-lab", graph_path, key_path, verify_inputs=[path], materialize_dir=pairs, limit=5
        )
        row = _asym(document)[0]
        self.assertTrue((pairs / f"{row['id']}-owner.http").is_file())
        self.assertTrue((pairs / f"{row['id']}-owner-response.http").is_file())
        self.assertTrue((pairs / f"{row['id']}-actor.http").is_file())
        self.assertFalse(any(name.suffix == ".json" for name in pairs.iterdir()))
        self.assertIn("--dry-run", row["suggested_discover_idor"])

    def test_cli_request_only_dry_run(self) -> None:
        from bugbounty_toolkit import cli

        graph, _ = self._positive()
        key_path = self.root / "key.bin"
        graph_path = self.root / "graph.json"
        atomic_private_write(key_path, KEY)
        save_object_json(graph_path, graph)
        outputs = []
        for extra in ([], ["--request-only"]):
            buf = StringIO()
            argv = ["bbtk", "object-handoff", "asym-lab", "--graph", str(graph_path), "--key-file", str(key_path)]
            with patch.object(cli.sys, "argv", argv + ["--dry-run"] + extra), redirect_stdout(buf):
                cli.main()
            outputs.append(json.loads(buf.getvalue().splitlines()[0]))
        self.assertEqual(outputs[0]["asymmetric_selected"], 1)
        self.assertEqual(outputs[1]["asymmetric_selected"], 0)
        self.assertEqual(outputs[1]["total_proposals"], 0)


class AsymmetricLabTests(unittest.TestCase):
    def test_eval_holdout_improves_over_request_only_without_false_positives(self) -> None:
        report = run_object_discovery_lab(default_lab_root(), split="eval", limit=10)["primary"]
        metrics = report["metrics"]
        before = report["request_only_comparison"]
        self.assertGreater(metrics["recall"], before["recall"])
        self.assertLess(metrics["fn_count"], before["fn_count"])
        self.assertEqual(metrics["fp_count"], 0)
        self.assertGreaterEqual(metrics["precision_at_3"], before["precision_at_3"])
        self.assertIn("project", metrics["true_positives"])
        self.assertIn("address", metrics["true_positives"])
        for negative in ("team", "tenant", "customer"):
            self.assertNotIn(negative, metrics["primary_queue_resource_types"])
        self.assertTrue(metrics["vulnerable_in_top3"])
        self.assertEqual(report["vulnerabilities_confirmed"], 0)

    def test_corpus_labels_cover_new_categories_in_both_splits(self) -> None:
        for split in ("dev", "eval"):
            labels = json.loads((default_lab_root() / split / "labels.json").read_text(encoding="utf-8"))
            self.assertEqual(labels["corpus_version"], object_handoff.LAB_CORPUS_VERSION)
            categories = {row["category"] for row in labels["labels"]}
            self.assertTrue(
                {"response-observed", "response-nested", "response-collision", "ambiguous-shared", "incomplete-capture"}
                <= categories
            )
            self.assertTrue(all(row["expected_confirmed"] is False for row in labels["labels"]))


if __name__ == "__main__":
    unittest.main()
