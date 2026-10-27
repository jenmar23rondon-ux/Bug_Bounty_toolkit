"""P1 open-vocabulary resource kinds: unit, integration and regression tests (synthetic, offline)."""

from __future__ import annotations

import json
import os
import socket
import tempfile
import unittest
from pathlib import Path
from typing import Any
from unittest.mock import patch

from bugbounty_toolkit.analysis import object_handoff
from bugbounty_toolkit.analysis.object_handoff import KIND_RULE, _position, _side_kind, propose_object_handoff
from bugbounty_toolkit.analysis.object_relationships import (
    _field_kind,
    _singular,
    build_object_graph,
    resource_kind_noun,
)

HOST = "http://127.0.0.1:8097"
KEY = b"k" * 32
PROGRAM = "kind-lab"


def _entry(path: str, session: str | None, response: object | None = None, *, body: object | None = None) -> dict:
    headers = [{"name": "Authorization", "value": "Bearer " + session}] if session else []
    request: dict[str, Any] = {"method": "POST" if body is not None else "GET", "url": HOST + path, "headers": headers}
    if body is not None:
        request["postData"] = {"mimeType": "application/json", "text": json.dumps(body)}
    text = "" if response is None else json.dumps(response)
    return {"request": request, "response": {"status": 200, "content": {"mimeType": "application/json", "text": text}}}


class NounUnitTests(unittest.TestCase):
    def test_singularization(self) -> None:
        for word, expected in (
            ("gadgets", "gadget"),
            ("policies", "policy"),
            ("boxes", "box"),
            ("batches", "batch"),
            ("status", "status"),
            ("analysis", "analysis"),
            ("class", "class"),
        ):
            self.assertEqual(_singular(word), expected, word)

    def test_known_vocabulary_preserved(self) -> None:
        self.assertEqual(resource_kind_noun("orders"), ("order", "known_vocabulary"))
        self.assertEqual(resource_kind_noun("addresses"), ("address", "known_vocabulary"))
        self.assertEqual(_field_kind("project_id"), "project")

    def test_open_vocabulary_kinds(self) -> None:
        self.assertEqual(resource_kind_noun("gadgets"), ("gadget", "open_vocabulary"))
        self.assertEqual(resource_kind_noun("estimates2"), ("estimates2", "open_vocabulary"))
        self.assertEqual(_field_kind("gadgetId"), "gadget")
        self.assertEqual(_field_kind("gadget_uuid"), "gadget")
        self.assertEqual(_field_kind("gadget_ids"), "gadget")

    def test_generic_ambiguous_and_unsafe_names_are_insufficient(self) -> None:
        for word in (
            "ref",
            "key",
            "data",
            "id",
            "ids",
            "results",
            "v2",
            "123",
            "x",
            "a-b",
            "lookup",
            "page",
            "id2",
            "data2",
            "page2",
            "z" * 60,
        ):
            self.assertIsNone(resource_kind_noun(word), word)
        for name in ("id", "uuid", "ref_id", "key_id", "data_id", "password_id", "token_id", "gadget"):
            self.assertIsNone(_field_kind(name), name)

    def test_position_and_side_kind(self) -> None:
        self.assertEqual(_position("path", "/path/3"), "path:/path/3")
        self.assertEqual(_position("request_json", "/gadget_ids/1"), "request_json:/gadget_ids/*")
        self.assertIsNone(_side_kind({"a", "b"}, "unknown", False))
        self.assertIsNone(_side_kind(set(), "unknown", True))
        self.assertEqual(_side_kind(set(), "order", True), "kind:order")
        self.assertIsNone(_side_kind(set(), "order", False))


@unittest.skipUnless(os.name == "posix", "Secure private artifact I/O requires POSIX no-follow descriptors")
class OpenVocabPairingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)

    def _doc(self, entries: list[dict]) -> tuple[dict, dict]:
        path = Path(self.temp.name) / "c.har"
        path.write_text(json.dumps({"log": {"version": "1.2", "entries": entries}}), encoding="utf-8")
        graph = build_object_graph(PROGRAM, [path], KEY, authorized=True)
        return graph, propose_object_handoff(graph, PROGRAM, KEY, limit=64)

    def test_nested_unknown_kinds_never_cross_positions(self) -> None:
        graph, doc = self._doc(
            [
                _entry("/x/hangars/900/gadgets/901", "a", {"ok": 1}),
                _entry("/x/hangars/910/gadgets/911", "b", {"ok": 1}),
            ]
        )
        kinds = {p["resource_kind"] for p in doc["proposals"]}
        self.assertEqual(len(doc["proposals"]), 2)
        self.assertEqual(len(kinds), 2)
        for proposal in doc["proposals"]:
            self.assertEqual(proposal["resource_type"], "unknown")
            self.assertFalse(proposal["confirmed"])
            self.assertFalse(proposal["case_executable"])
            self.assertTrue(proposal["researcher_review_required"])
            self.assertEqual(proposal["relation"]["kind_rule"], KIND_RULE)
            self.assertEqual(proposal["relation"]["ownership"], "unknown")
            for side in ("owner", "actor"):
                self.assertTrue(proposal[side]["source_ref"].startswith("source-"))
                self.assertTrue(proposal[side]["locator"])
        # Kind names never leak into exports: only keyed hashes.
        blob = json.dumps([graph, doc])
        self.assertNotIn("gadget", blob)
        self.assertNotIn("hangar", blob)

    def test_shared_parent_same_value_not_paired(self) -> None:
        _, doc = self._doc(
            [_entry("/x/hangars/900/gadgets/901", "a", {"ok": 1}), _entry("/x/hangars/900/gadgets/902", "b", {"ok": 1})]
        )
        self.assertEqual(len(doc["proposals"]), 1)

    def test_numeric_collision_across_kinds_not_paired(self) -> None:
        _, doc = self._doc(
            [
                _entry("/x/wallet", "a", {"coin": {"coin_id": 5000}}),
                _entry("/x/rebates/5001", "b", {"ok": 1}),
                _entry("/x/link", "a", body={"widget_id": 7, "sprocket_id": 8}),
                _entry("/x/link", "b", body={"widget_id": 8, "sprocket_id": 7}),
            ]
        )
        # widget/widget and sprocket/sprocket only; never coin->rebate nor widget->sprocket.
        self.assertEqual(len(doc["proposals"]), 2)
        self.assertEqual(len({p["resource_kind"] for p in doc["proposals"]}), 2)
        self.assertEqual(doc["response_identifiers"]["asymmetric_candidates"], 0)

    def test_open_vocab_cross_reference_recovered(self) -> None:
        _, doc = self._doc(
            [
                _entry("/x/desk", "a", {"items": [{"gizmo_id": 41}]}),
                _entry("/x/gizmos/42", "b", {"ok": 1}),
                _entry("/x/home", "a", {"sprockets": [{"id": 51}]}),
                _entry("/x/sprockets/52", "b", {"ok": 1}),
            ]
        )
        asym = [p for p in doc["proposals"] if p["pair_kind"] == "asymmetric_response_request"]
        self.assertEqual(len(asym), 2)
        self.assertEqual(
            {p["observed_identifiers"][0]["type_basis"] for p in asym}, {"typed_field_name", "collection_container"}
        )
        for proposal in asym:
            self.assertEqual(proposal["relation"]["state"], "inferred")
            self.assertFalse(proposal["confirmed"])

    def test_generic_and_bare_ids_routed_to_review(self) -> None:
        _, doc = self._doc(
            [
                _entry("/x/feed", "a", {"data": {"id": 61}}),
                _entry("/x/notes/62", "b", {"ok": 1}),
                _entry("/x/find?ref_id=1", "a", {"ok": 1}),
                _entry("/x/find?ref_id=2", "b", {"ok": 1}),
            ]
        )
        self.assertEqual(doc["total_proposals"], 0)
        kinds = doc["resource_kinds"]
        self.assertGreaterEqual(kinds["insufficient_evidence"], 2)
        self.assertEqual(kinds["routed_to"], "researcher_review")
        self.assertFalse(kinds["confirmed"])
        self.assertTrue(all(ref.startswith("object-") for ref in kinds["review_object_refs"]))

    def test_known_vocabulary_backward_compatible(self) -> None:
        _, doc = self._doc([_entry("/x/orders/1", "a", {"ok": 1}), _entry("/x/orders/2", "b", {"ok": 1})])
        self.assertEqual(
            [(p["resource_type"], p["resource_kind"]) for p in doc["proposals"]], [("order", "kind:order")]
        )

    def test_legacy_graph_without_kind_refs_still_pairs_known_types(self) -> None:
        graph, _ = self._doc([_entry("/x/orders/1", "a", {"ok": 1}), _entry("/x/orders/2", "b", {"ok": 1})])
        for observation in graph["observations"]:
            for fact in observation["references"]:
                fact.pop("kind_ref"), fact.pop("kind_basis")
        with patch.object(object_handoff, "validate_object_graph"):
            doc = propose_object_handoff(graph, PROGRAM, KEY)
        self.assertEqual([p["resource_kind"] for p in doc["proposals"]], ["kind:order"])

    def test_deterministic_offline(self) -> None:
        entries = [_entry("/x/hangars/900/gadgets/901", "a", {"ok": 1}), _entry("/x/hangars/910/gadgets/911", "b")]

        def guard(*_a: object, **_k: object) -> None:
            raise AssertionError("network used")

        with patch.object(socket.socket, "connect", guard), patch.object(socket, "getaddrinfo", guard):
            first = self._doc(entries)[1]
            second = self._doc(entries)[1]
        self.assertEqual(first, second)
        self.assertEqual(first["network_requests_sent"], 0)


if __name__ == "__main__":
    unittest.main()
