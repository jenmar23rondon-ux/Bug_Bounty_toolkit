"""Recover IDOR/BOLA object kinds from capture evidence without admitting a pair.

Synthetic fixtures only. A withheld pair stays withheld. Untyped values, cross-origin
values, and a path parent versus its nested child are not linked. Nothing is confirmed.

Recorded irb-1.0 ``implementation_sha256`` and ``evaluator_sha256`` changed with this
recovery. ``manifest_sha256`` did not: frozen captures, labels, and ``MANIFEST.sha256``
were not edited. Pair counts and scenario outcomes are unchanged.
"""

from __future__ import annotations

import json
import unittest
from pathlib import Path
from typing import Any

from bugbounty_toolkit.analysis.object_handoff import propose_object_handoff
from bugbounty_toolkit.analysis.object_relationships import build_object_graph, recover_linked_objects

HOST = "http://127.0.0.1:8177"
ALT = "http://127.0.0.1:8178"
KEY = b"\x42" * 32
PROGRAM = "idor-object-recall"


def _hit(
    ref: str,
    value: str,
    *,
    origin: str = "origin-a",
    kind: str | None = None,
    basis: str | None = None,
    location: str = "path",
    path_parent: bool = False,
    request: str = "req-1",
) -> dict[str, Any]:
    return {
        "object_ref": ref,
        "origin_ref": origin,
        "value": value,
        "kind_ref": kind,
        "basis": basis,
        "location": location,
        "path_parent": path_parent,
        "request_ref": request,
    }


def _entry(
    url: str,
    session: str,
    response: object | None = None,
    *,
    status: int = 200,
) -> dict[str, object]:
    text = "" if response is None else json.dumps(response)
    return {
        "request": {
            "method": "GET",
            "url": url,
            "headers": [{"name": "Authorization", "value": "Bearer " + session}],
        },
        "response": {"status": status, "content": {"mimeType": "application/json", "text": text}},
    }


class RecoveryRuleTests(unittest.TestCase):
    def test_route_template_names_the_path_object(self) -> None:
        rows = recover_linked_objects([_hit("path-1", "73101", kind="kind-payslip", basis="path_collection")])
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["object_ref"], "path-1")
        self.assertEqual(rows[0]["resource_kind"], "kind-payslip")
        self.assertEqual(rows[0]["rules"], ["route_template"])
        self.assertEqual(rows[0]["linked_object_refs"], [])
        self.assertFalse(rows[0]["confirmed"])
        self.assertNotIn("73101", json.dumps(rows))

    def test_typed_response_identifier_names_the_body_field(self) -> None:
        rows = recover_linked_objects(
            [
                _hit(
                    "body-1",
                    "73101",
                    kind="kind-payslip",
                    basis="typed_field_name",
                    location="response_json",
                )
            ]
        )
        self.assertEqual(rows[0]["rules"], ["typed_response_identifier"])
        self.assertEqual(rows[0]["resource_kind"], "kind-payslip")
        self.assertEqual(rows[0]["linked_object_refs"], [])

    def test_collection_container_names_a_bare_id(self) -> None:
        rows = recover_linked_objects(
            [
                _hit(
                    "container-1",
                    "73101",
                    kind="kind-payslip",
                    basis="collection_container",
                    location="response_json",
                )
            ]
        )
        self.assertEqual(rows[0]["rules"], ["collection_container"])
        self.assertFalse(rows[0]["confirmed"])

    def test_query_typed_identifier_names_without_a_response_body(self) -> None:
        rows = recover_linked_objects(
            [_hit("query-1", "75501", kind="kind-wallet", basis="typed_field_name", location="query")]
        )
        self.assertEqual(rows[0]["rules"], ["typed_identifier"])
        self.assertEqual(rows[0]["linked_object_refs"], [])

    def test_consistent_kind_across_captures_names_an_otherwise_untyped_value(self) -> None:
        rows = recover_linked_objects(
            [
                _hit(
                    "typed", "10", kind="kind-widget", basis="typed_field_name", location="response_json", request="a"
                ),
                _hit("untyped", "10", request="b"),
            ]
        )
        by_ref = {row["object_ref"]: row for row in rows}
        self.assertEqual(by_ref["untyped"]["rules"], ["consistent_kind"])
        self.assertEqual(by_ref["untyped"]["resource_kind"], "kind-widget")
        self.assertEqual(by_ref["untyped"]["linked_object_refs"], ["typed"])
        self.assertEqual(by_ref["typed"]["linked_object_refs"], ["untyped"])
        self.assertIn("consistent_kind", by_ref["typed"]["rules"])
        self.assertFalse(by_ref["untyped"]["confirmed"])

    def test_untyped_values_are_not_linked(self) -> None:
        rows = recover_linked_objects(
            [
                _hit("bare-a", "123", request="a"),
                _hit("bare-b", "456", request="b"),
                _hit("bare-c", "123", location="response_json", request="a"),
            ]
        )
        self.assertEqual(rows, [])

    def test_cross_origin_values_are_not_linked(self) -> None:
        rows = recover_linked_objects(
            [
                _hit("left", "76501", origin="origin-http", kind="kind-policy", basis="path_collection"),
                _hit(
                    "right", "76501", origin="origin-alt", kind="kind-policy", basis="path_collection", request="other"
                ),
            ]
        )
        by_ref = {row["object_ref"]: row for row in rows}
        self.assertEqual(set(by_ref), {"left", "right"})
        self.assertEqual(by_ref["left"]["linked_object_refs"], [])
        self.assertEqual(by_ref["right"]["linked_object_refs"], [])
        self.assertEqual(by_ref["left"]["resource_kind"], "kind-policy")

    def test_shared_parent_is_not_linked_to_the_nested_child(self) -> None:
        rows = recover_linked_objects(
            [
                _hit("account", "75700", kind="kind:account", basis="path_collection", path_parent=True),
                _hit("card", "75711", kind="kind-card", basis="path_collection", path_parent=False),
                _hit(
                    "card-body",
                    "75711",
                    kind="kind-card",
                    basis="collection_container",
                    location="response_json",
                ),
                _hit(
                    "account-body",
                    "75700",
                    kind="kind:account",
                    basis="typed_field_name",
                    location="response_json",
                ),
            ]
        )
        by_ref = {row["object_ref"]: row for row in rows}
        self.assertEqual(by_ref["account"]["resource_kind"], "kind:account")
        self.assertEqual(by_ref["card"]["resource_kind"], "kind-card")
        self.assertNotIn("card", by_ref["account"]["linked_object_refs"])
        self.assertNotIn("card-body", by_ref["account"]["linked_object_refs"])
        self.assertNotIn("account", by_ref["card"]["linked_object_refs"])
        self.assertNotIn("account-body", by_ref["card"]["linked_object_refs"])
        self.assertEqual(by_ref["card"]["linked_object_refs"], ["card-body"])
        self.assertEqual(by_ref["account"]["linked_object_refs"], ["account-body"])

    def test_same_value_parent_does_not_inherit_the_child_kind(self) -> None:
        rows = recover_linked_objects(
            [
                _hit("parent", "100", path_parent=True),
                _hit("child", "100", kind="kind-card", basis="path_collection", path_parent=False),
            ]
        )
        self.assertEqual([row["object_ref"] for row in rows], ["child"])
        self.assertEqual(rows[0]["linked_object_refs"], [])


class HandoffRecoveryTests(unittest.TestCase):
    def setUp(self) -> None:
        import tempfile

        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name)

    def _document(self, entries: list[dict[str, object]], *, gate: bool) -> dict[str, Any]:
        path = self.root / "captures.har"
        har = {"log": {"version": "1.2", "creator": {"name": "t", "version": "1"}, "entries": entries}}
        path.write_text(json.dumps(har), encoding="utf-8")
        graph = build_object_graph(PROGRAM, [path], KEY, authorized=True)
        self.graph = graph
        return propose_object_handoff(
            graph,
            PROGRAM,
            KEY,
            verify_inputs=[path],
            limit=64,
            compatibility_gate=gate,
        )

    def test_withheld_denial_still_names_the_route_object(self) -> None:
        document = self._document(
            [
                _entry(HOST + "/ib/payslips/73101", "owner", {"payslip": {"id": 73101}}),
                _entry(HOST + "/ib/payslips/73102", "actor", {"payslip": {"id": 73102}}),
                _entry(HOST + "/ib/payslips/73101", "actor", {"error": "forbidden", "ok": False}, status=403),
            ],
            gate=True,
        )
        self.assertEqual(document["total_proposals"], 0)
        self.assertGreaterEqual(document["compatibility_gate"]["withheld_authorization_denials"], 1)
        recovered = document["recovered_objects"]["objects"]
        self.assertTrue(any("route_template" in row["rules"] for row in recovered))
        self.assertTrue(all(row["confirmed"] is False for row in recovered))
        self.assertEqual(document["confirmed"], False)
        self.assertEqual(document["network_requests_sent"], 0)
        blob = json.dumps(document["recovered_objects"])
        self.assertNotIn("73101", blob)
        self.assertNotIn("73102", blob)
        self.assertNotIn("payslip", blob)

    def test_capture_fixtures_do_not_link_the_negative_cases(self) -> None:
        document = self._document(
            [
                _entry(
                    HOST + "/ib/accounts/75700/cards/75711",
                    "owner",
                    {"card": {"id": 75711, "account_id": 75700}},
                ),
                _entry(
                    HOST + "/ib/accounts/75701/cards/75712",
                    "actor",
                    {"card": {"id": 75712, "account_id": 75701}},
                ),
                _entry(ALT + "/ib/policies/76501", "actor", {"policy": {"id": 76501}}),
                _entry(HOST + "/api/data/5", "owner", {"data": {"id": 5}}),
                _entry(HOST + "/api/data/6", "actor", {"data": {"id": 6}}),
            ],
            gate=True,
        )
        recovered = {row["object_ref"]: row for row in document["recovered_objects"]["objects"]}
        for relation in self.graph["relations"]:
            if relation["relation"] != "PATH_CONTEXT":
                continue
            parent = str(relation["source"])
            child = str(relation["target"])
            self.assertNotIn(child, recovered.get(parent, {}).get("linked_object_refs", []))
            self.assertNotIn(parent, recovered.get(child, {}).get("linked_object_refs", []))
        for row in recovered.values():
            for peer in row["linked_object_refs"]:
                self.assertEqual(recovered[peer]["resource_kind"], row["resource_kind"])
        endpoints = {node["id"]: node.get("origin_ref") for node in self.graph["nodes"] if node["type"] == "Endpoint"}
        origins: dict[str, set[str]] = {}
        for observation in self.graph["observations"]:
            origin = str(endpoints.get(observation["endpoint_ref"]) or "")
            for fact in observation["references"]:
                origins.setdefault(str(fact["object_ref"]), set()).add(origin)
        for row in recovered.values():
            for peer in row["linked_object_refs"]:
                self.assertTrue(origins[row["object_ref"]] & origins[peer])
        self.assertEqual(document["network_requests_sent"], 0)
        self.assertFalse(document["confirmed"])


if __name__ == "__main__":
    unittest.main()
