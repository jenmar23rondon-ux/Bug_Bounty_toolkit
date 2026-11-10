"""Collapse equivalent IDOR/BOLA proposals without merging distinct relationships.

Synthetic captures only. A relationship is the HTTP method, normalized route template,
identifier location and kind, and account pair. Different identifier values, encodings,
query order, trailing slashes, and repeated captures are one proposal. Different object
parameters, account pairs, and HTTP methods stay separate. Nothing is confirmed.
"""

from __future__ import annotations

import json
import unittest
from pathlib import Path
from typing import Any

from bugbounty_toolkit.analysis.object_handoff import propose_object_handoff
from bugbounty_toolkit.analysis.object_relationships import build_object_graph

HOST = "http://127.0.0.1:8177"
KEY = b"\x5a" * 32
PROGRAM = "idor-dedupe"


def _entry(
    path: str,
    session: str,
    response: object | None = None,
    *,
    method: str = "GET",
    status: int = 200,
) -> dict[str, object]:
    headers = [{"name": "Authorization", "value": "Bearer " + session}]
    text = "" if response is None else json.dumps(response)
    return {
        "request": {"method": method, "url": HOST + path, "headers": headers},
        "response": {"status": status, "content": {"mimeType": "application/json", "text": text}},
    }


class ProposalDedupeTests(unittest.TestCase):
    def setUp(self) -> None:
        import tempfile

        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name)

    def _document(self, entries: list[dict[str, object]], *, gate: bool = False, limit: int = 64) -> dict[str, Any]:
        path = self.root / "captures.har"
        har = {"log": {"version": "1.2", "creator": {"name": "t", "version": "1"}, "entries": entries}}
        path.write_text(json.dumps(har), encoding="utf-8")
        graph = build_object_graph(PROGRAM, [path], KEY, authorized=True)
        return propose_object_handoff(
            graph,
            PROGRAM,
            KEY,
            verify_inputs=[path],
            limit=limit,
            compatibility_gate=gate,
        )

    def _rows(self, document: dict[str, Any], pair_kind: str | None = None) -> list[dict[str, Any]]:
        rows = document["proposals"]
        self.assertIsInstance(rows, list)
        typed = [row for row in rows if isinstance(row, dict)]
        if pair_kind is None:
            return typed
        return [row for row in typed if row.get("pair_kind") == pair_kind]

    def _object_refs(self, proposal: dict[str, Any]) -> set[str]:
        refs: set[str] = set()
        evidence = proposal.get("supporting_evidence")
        self.assertIsInstance(evidence, list)
        if isinstance(evidence, list):
            for row in evidence:
                self.assertIsInstance(row, dict)
                if isinstance(row, dict) and isinstance(row.get("object_ref"), str):
                    refs.add(row["object_ref"])
        return refs

    def _locators(self, proposal: dict[str, Any]) -> set[str]:
        found: set[str] = set()
        evidence = proposal.get("supporting_evidence")
        if isinstance(evidence, list):
            for row in evidence:
                if isinstance(row, dict) and isinstance(row.get("locator"), str):
                    found.add(row["locator"])
        return found

    def test_repeated_captures_collapse_and_keep_every_locator(self) -> None:
        entries: list[dict[str, object]] = []
        for _ in range(3):
            entries.append(_entry("/orders/10", "alice", {"order": {"id": 10}}))
            entries.append(_entry("/orders/11", "bob", {"order": {"id": 11}}))
        document = self._document(entries)
        rows = self._rows(document, "request_request")
        self.assertEqual(len(rows), 1)
        self.assertGreaterEqual(rows[0]["equivalent_proposal_count"], 3)
        self.assertEqual(len(self._locators(rows[0])), 6)
        self.assertFalse(rows[0]["confirmed"])
        self.assertEqual(document["network_requests_sent"], 0)
        self.assertEqual(document["vulnerabilities_confirmed"], 0)

    def test_query_order_trailing_slash_and_encoding_are_one_relationship(self) -> None:
        document = self._document(
            [
                _entry("/invoices?invoice_id=10&ts=1", "alice", {"ok": True}),
                _entry("/invoices?ts=2&invoice_id=11", "bob", {"ok": True}),
                _entry("/files/20", "alice", {"ok": True}),
                _entry("/files/21", "bob", {"ok": True}),
                _entry("/files/%32%32/", "alice", {"ok": True}),
                _entry("/files/%32%33/", "bob", {"ok": True}),
            ]
        )
        rows = self._rows(document, "request_request")
        # One invoice query relationship, plus the file spellings collapsed together.
        self.assertEqual(len(rows), 2)
        wide = [row for row in rows if len(self._locators(row)) >= 4]
        self.assertEqual(len(wide), 1)
        self.assertGreaterEqual(wide[0]["equivalent_proposal_count"], 2)
        self.assertEqual(len(self._object_refs(wide[0])), 4)

    def test_distinct_identifier_values_on_one_parameter_collapse(self) -> None:
        entries = [_entry(f"/rows/{index}", "alice" if index % 2 == 0 else "bob", {"ok": True}) for index in range(8)]
        document = self._document(entries)
        rows = self._rows(document)
        self.assertEqual(len(rows), 1)
        self.assertGreaterEqual(rows[0]["equivalent_proposal_count"], 16)
        self.assertEqual(len(self._object_refs(rows[0])), 8)
        self.assertFalse(rows[0]["confirmed"])

    def test_different_objects_account_pairs_methods_and_locations_do_not_merge(self) -> None:
        users_orders = self._rows(
            self._document(
                [
                    _entry("/users/1", "alice", {"ok": True}),
                    _entry("/users/2", "bob", {"ok": True}),
                    _entry("/orders/3", "alice", {"ok": True}),
                    _entry("/orders/4", "bob", {"ok": True}),
                ]
            ),
            "request_request",
        )
        self.assertEqual(len(users_orders), 2)
        self.assertEqual(len({str(row["resource_kind"]) for row in users_orders}), 2)

        # Four accounts and four ids form every account pair. Those pairs must stay separate.
        notes = self._rows(
            self._document(
                [
                    _entry("/notes/1", "alice", {"ok": True}),
                    _entry("/notes/2", "bob", {"ok": True}),
                    _entry("/notes/3", "carol", {"ok": True}),
                    _entry("/notes/4", "dave", {"ok": True}),
                ]
            ),
            "request_request",
        )
        self.assertEqual(len(notes), 6)
        self.assertEqual(len({str(row["resource_kind"]) for row in notes}), 1)

        tasks = self._rows(
            self._document(
                [
                    _entry("/tasks/1", "alice", {"ok": True}, method="GET"),
                    _entry("/tasks/2", "bob", {"ok": True}, method="GET"),
                    _entry("/tasks/3", "alice", {"ok": True}, method="POST"),
                    _entry("/tasks/4", "bob", {"ok": True}, method="POST"),
                ]
            ),
            "request_request",
        )
        self.assertEqual(len(tasks), 2)
        methods: set[str] = set()
        for row in tasks:
            hint = row.get("endpoint_hint")
            if isinstance(hint, dict):
                methods.add(str(hint.get("method")))
        self.assertEqual(methods, {"GET", "POST"})

        widgets = self._rows(
            self._document(
                [
                    _entry("/widgets/1", "alice", {"ok": True}),
                    _entry("/widgets/2", "bob", {"ok": True}),
                    _entry("/widgets?widget_id=3", "alice", {"ok": True}),
                    _entry("/widgets?widget_id=4", "bob", {"ok": True}),
                ]
            ),
            "request_request",
        )
        self.assertEqual(len(widgets), 2)
        self.assertEqual(
            {tuple(row["owner"]["locations"]) for row in widgets},
            {("path",), ("query",)},
        )

    def test_response_identifier_location_stays_distinct_from_the_path(self) -> None:
        """Path/path and response/path are different identifier locations.

        A benchmark cap of one can still count the second location as redundant.
        They must not collapse: a response observation is not the same slot as the path parameter.
        """
        document = self._document(
            [
                _entry("/bookings/31", "alice", {"booking": {"id": 31}}),
                _entry("/bookings/32", "bob", {"booking": {"id": 32}}),
            ]
        )
        rows = self._rows(document)
        kinds = {str(row["pair_kind"]) for row in rows}
        self.assertEqual(kinds, {"request_request", "asymmetric_response_request"})
        self.assertEqual(len(rows), 2)
        self.assertTrue(all(row["confirmed"] is False for row in rows))

    def test_authorization_denial_is_not_folded_back_into_a_proposal(self) -> None:
        document = self._document(
            [
                _entry("/orders/41", "alice", {"order": {"id": 41}}),
                _entry("/orders/42", "bob", {"error": "denied"}, status=403),
                _entry("/orders/43", "carol", {"order": {"id": 43}}),
                _entry("/orders/44", "dave", {"order": {"id": 44}}),
            ],
            gate=True,
        )
        self.assertGreaterEqual(len(document["withheld_incompatible"]), 1)
        self.assertTrue(
            all(row["withheld_reason"] == "authorization_denial" for row in document["withheld_incompatible"])
        )
        self.assertGreaterEqual(document["total_proposals"], 1)
        self.assertEqual(document["vulnerabilities_confirmed"], 0)
        self.assertFalse(document["confirmed"])
        rendered = json.dumps(document["proposals"])
        self.assertNotIn("denied", rendered)

    def test_collapse_is_deterministic(self) -> None:
        entries = [_entry(f"/rows/{index}", "alice" if index % 2 == 0 else "bob", {"ok": True}) for index in range(6)]
        first = self._document(entries)
        second = self._document(entries)
        self.assertEqual(first["proposals"], second["proposals"])
        self.assertEqual(first["total_proposals"], 1)
