from __future__ import annotations

import json
import os
import stat
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from bugbounty_toolkit.analysis.object_handoff import (
    capture_to_raw_http,
    handoff_to_file,
    propose_object_handoff,
)
from bugbounty_toolkit.analysis.object_relationships import (
    build_object_graph,
    object_candidates,
    save_object_json,
)
from bugbounty_toolkit.core.private_files import atomic_private_write
from bugbounty_toolkit.idor_discovery import discover_idor, discovery_summary


def _har(entries: list[dict]) -> dict:
    return {"log": {"version": "1.2", "creator": {"name": "test", "version": "1"}, "entries": entries}}


def _entry(url: str, session: str, body: dict | None = None, method: str = "GET", request_body=None):
    request = {
        "method": method,
        "url": url,
        "headers": [{"name": "Authorization", "value": "Bearer " + session}],
    }
    if request_body is not None:
        request["postData"] = {"mimeType": "application/json", "text": json.dumps(request_body)}
    return {
        "request": request,
        "response": {
            "status": 200,
            "content": {"mimeType": "application/json", "text": json.dumps(body or {})},
        },
    }


@unittest.skipUnless(os.name == "posix", "Secure private artifact I/O requires POSIX no-follow descriptors")
class ObjectHandoffTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.key = b"h" * 32
        self.key_path = self.root / "key.bin"
        self.graph_path = self.root / "graph.json"
        self.input = self.root / "captures.har"
        entries = [
            _entry("http://127.0.0.1:8099/api/orders/1001", "owner", {"data": {"id": 1001}}),
            _entry("http://127.0.0.1:8099/api/orders/1002", "actor", {"data": {"id": 1002}}),
            _entry("http://127.0.0.1:8099/api/wishlists/7", "owner", {"data": {"id": 7}}),
            _entry("http://127.0.0.1:8099/api/wishlists/7", "actor", {"data": {"id": 7}}),
            _entry("http://127.0.0.1:8099/api/carts/9", "solo", {"data": {"id": 9}}),
        ]
        self.input.write_text(json.dumps(_har(entries)))
        self.graph = build_object_graph("handoff-lab", [self.input], self.key, authorized=True)
        atomic_private_write(self.key_path, self.key)
        save_object_json(self.graph_path, self.graph)

    def test_proposals_are_offline_unconfirmed_and_deterministic(self) -> None:
        first = propose_object_handoff(self.graph, "handoff-lab", self.key, verify_inputs=[self.input], limit=10)
        second = propose_object_handoff(self.graph, "handoff-lab", self.key, verify_inputs=[self.input], limit=10)
        self.assertEqual(first["network_requests_sent"], 0)
        self.assertEqual(first["vulnerabilities_confirmed"], 0)
        self.assertFalse(first["confirmed"])
        self.assertEqual(first["proposals"], second["proposals"])
        self.assertGreaterEqual(first["total_proposals"], 1)
        self.assertTrue(all(not row["confirmed"] and not row["case_executable"] for row in first["proposals"]))
        self.assertTrue(any(row["resource_type"] == "order" for row in first["proposals"]))
        self.assertFalse(any(row["resource_type"] == "wishlist" for row in first["proposals"]))
        self.assertIn("discover-idor", first["proposals"][0]["suggested_discover_idor"])
        self.assertIn("--dry-run", first["proposals"][0]["suggested_discover_idor"])

    def test_single_session_candidate_is_insufficient_evidence(self) -> None:
        candidates = object_candidates(self.graph, "handoff-lab", self.key, limit=100)
        cart = next(row for row in candidates["candidates"] if row["resource_type"] == "cart")
        result = propose_object_handoff(
            self.graph,
            "handoff-lab",
            self.key,
            candidate=cart["object_ref"],
            verify_inputs=[self.input],
        )
        self.assertEqual(result["status"], "insufficient_evidence")
        self.assertEqual(result["total_proposals"], 0)
        self.assertEqual(result["network_requests_sent"], 0)

    def test_materialize_feeds_discover_idor_without_confirmation(self) -> None:
        materialize = self.root / "pairs"
        output = self.root / "handoff.json"
        document = handoff_to_file(
            "handoff-lab",
            self.graph_path,
            self.key_path,
            verify_inputs=[self.input],
            output=output,
            materialize_dir=materialize,
            limit=5,
        )
        self.assertTrue(output.is_file())
        order = next(row for row in document["proposals"] if row["resource_type"] == "order")
        command = order["suggested_discover_idor"]
        self.assertIn(str(materialize), command)
        # Resolve materialized paths from proposal command tokens.
        owner = materialize / f"{order['id']}-owner.http"
        actor = materialize / f"{order['id']}-actor.http"
        self.assertTrue(owner.is_file() and actor.is_file())
        if hasattr(os, "chmod"):
            self.assertEqual(stat.S_IMODE(owner.stat().st_mode), 0o600)
        discovery = discover_idor("handoff-lab", owner, actor, accounts_authorized=True)
        summary = discovery_summary(discovery)
        self.assertEqual(summary["network_requests_sent"], 0)
        self.assertFalse(summary["confirmed"])
        self.assertGreaterEqual(len(discovery.proposal["candidates"]), 1)
        # Ensure raw capture bodies are not echoed into the handoff JSON.
        rendered = output.read_text(encoding="utf-8")
        self.assertNotIn("Bearer owner", rendered)
        self.assertNotIn("Bearer actor", rendered)

    def test_dry_run_writes_nothing(self) -> None:
        output = self.root / "nope.json"
        materialize = self.root / "nope-pairs"
        document = handoff_to_file(
            "handoff-lab",
            self.graph_path,
            self.key_path,
            verify_inputs=[self.input],
            output=output,
            materialize_dir=materialize,
            dry_run=True,
        )
        self.assertTrue(document["dry_run"])
        self.assertFalse(output.exists())
        self.assertFalse(materialize.exists())

    def test_capture_to_raw_http_roundtrip_shape(self) -> None:
        from bugbounty_toolkit.analysis.object_relationships import indexed_capture_sources

        index = indexed_capture_sources("handoff-lab", [self.input], self.key)
        source = next(iter(index.values()))
        request, response = capture_to_raw_http(source)
        self.assertTrue(request.startswith(b"GET "))
        self.assertIn(b"Authorization:", request)
        self.assertIsNotNone(response)
        assert response is not None
        self.assertTrue(response.startswith(b"HTTP/1.1 "))

    def test_rejects_tampered_graph(self) -> None:
        bad = dict(self.graph)
        bad["integrity"] = "0" * 64
        with self.assertRaises(ValueError):
            propose_object_handoff(bad, "handoff-lab", self.key, verify_inputs=[self.input])

    def test_cli_object_handoff_dry_run(self) -> None:
        from bugbounty_toolkit import cli
        from io import StringIO
        from contextlib import redirect_stdout

        argv = [
            "bbtk",
            "--records-root",
            str(self.root / "records"),
            "object-handoff",
            "handoff-lab",
            "--graph",
            str(self.graph_path),
            "--key-file",
            str(self.key_path),
            "--verify-input",
            str(self.input),
            "--dry-run",
        ]
        buf = StringIO()
        with patch.object(cli.sys, "argv", argv), redirect_stdout(buf):
            cli.main()
        out = buf.getvalue()
        self.assertIn('"network_requests_sent": 0', out)
        self.assertIn("dry-run", out.lower())


if __name__ == "__main__":
    unittest.main()


@unittest.skipUnless(os.name == "posix", "Secure private artifact I/O requires POSIX no-follow descriptors")
class ObjectHandoffEdgeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.key = b"e" * 32

    def test_invalid_limit_and_candidate_type(self) -> None:
        captures = self.root / "c.har"
        captures.write_text(
            json.dumps(
                {
                    "log": {
                        "entries": [
                            _entry("http://127.0.0.1:8099/api/orders/1", "a", {"data": {"id": 1}}),
                            _entry("http://127.0.0.1:8099/api/orders/2", "b", {"data": {"id": 2}}),
                        ]
                    }
                }
            )
        )
        graph = build_object_graph("edge", [captures], self.key, authorized=True)
        with self.assertRaises(ValueError):
            propose_object_handoff(graph, "edge", self.key, limit=0)
        with self.assertRaises(ValueError):
            propose_object_handoff(graph, "edge", self.key, candidate=123)  # type: ignore[arg-type]
        with self.assertRaises(ValueError):
            propose_object_handoff(graph, "edge", self.key, materialize_dir=self.root / "out")

    def test_output_path_conflicts(self) -> None:
        captures = self.root / "c.har"
        captures.write_text(
            json.dumps(
                {
                    "log": {
                        "entries": [
                            _entry("http://127.0.0.1:8099/api/orders/1", "a", {"data": {"id": 1}}),
                            _entry("http://127.0.0.1:8099/api/orders/2", "b", {"data": {"id": 2}}),
                        ]
                    }
                }
            )
        )
        graph = build_object_graph("edge", [captures], self.key, authorized=True)
        key_path = self.root / "key.bin"
        graph_path = self.root / "graph.json"
        atomic_private_write(key_path, self.key)
        save_object_json(graph_path, graph)
        with self.assertRaises(ValueError):
            handoff_to_file(
                "edge",
                graph_path,
                key_path,
                verify_inputs=[captures],
                output=graph_path,
            )
        with self.assertRaises(ValueError):
            handoff_to_file(
                "edge",
                graph_path,
                key_path,
                verify_inputs=[captures],
                output=self.root / "out.json",
                materialize_dir=self.root / "out.json",
            )


class ObjectEfficacyLabErrorTests(unittest.TestCase):
    def test_bad_split_and_missing_corpus(self) -> None:
        with self.assertRaises(ValueError):
            from bugbounty_toolkit.analysis.object_handoff import run_object_discovery_lab

            run_object_discovery_lab(Path("/tmp"), split="nope")
        with tempfile.TemporaryDirectory() as tmp:
            from bugbounty_toolkit.analysis.object_handoff import run_object_discovery_lab

            with self.assertRaises(ValueError):
                run_object_discovery_lab(Path(tmp), split="eval")
