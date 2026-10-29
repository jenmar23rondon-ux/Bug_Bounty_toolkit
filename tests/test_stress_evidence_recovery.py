"""Bounded recovery regression cases; synthetic inputs and zero active checks."""

from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest
from typing import TypedDict

from bugbounty_toolkit.analysis.har_import import import_har
from bugbounty_toolkit.analysis.object_handoff import propose_object_handoff
from bugbounty_toolkit.analysis.object_relationships import (
    build_object_graph,
    indexed_capture_sources,
    validate_object_graph,
)
from labs.adversarial_idor_eval.evaluate import no_network
from labs.independent_research_eval.evaluate import run_scenario, score

ROOT = Path(__file__).resolve().parents[1]
KEY = b"s" * 32


class HarLimits(TypedDict):
    max_bytes: int
    max_message_bytes: int


def entry(number: int, body: object) -> dict[str, object]:
    return {
        "request": {
            "method": "GET",
            "url": f"http://127.0.0.1:8011/api-tokens/{number}",
            "headers": [{"name": "Authorization", "value": f"Bearer synthetic-{number}"}],
        },
        "response": {
            "status": 200,
            "content": {"mimeType": "application/json", "text": json.dumps(body)},
        },
    }


class StressRecoveryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.path = self.root / "capture.har"

    def write(self, rows: list[dict[str, object]]) -> bytes:
        raw = json.dumps({"log": {"entries": rows}}).encode()
        self.path.write_bytes(raw)
        return raw

    def test_three_original_stress_failures_are_reviewable_not_confirmed(self) -> None:
        split = ROOT / "labs/independent_research_eval/stress"
        truth = json.loads((split / "ground_truth.json").read_text(encoding="utf-8"))
        for case in truth["scenarios"]:
            if case["id"] not in {"S01", "S03", "S04"}:
                continue
            with self.subTest(case=case["id"]):
                predicted = run_scenario(split, case, keep=self.root)
                self.assertEqual(score(case, predicted)["predicted_outcome"], "reviewable")
                self.assertEqual(predicted["network_attempts"], 0)
                self.assertEqual(predicted["confirmed"], 0)
                self.assertEqual(predicted["leak_scan"]["shareable_leaks"], 0)
                report = json.loads((self.root / case["id"] / "e2e-report.json").read_text(encoding="utf-8"))
                self.assertTrue(all(row["error"] is None for row in report["idor_proposals"]))

    def test_research_budget_is_explicit_bounded_and_reused_for_handoff(self) -> None:
        self.write([entry(i, {"id": i}) for i in range(512)])
        with no_network():
            with self.assertRaises(ValueError):
                build_object_graph("lab", [self.path], KEY, authorized=True, independent_windows=True)
            graph = build_object_graph(
                "lab", [self.path], KEY, authorized=True, independent_windows=True, research_profile=True
            )
            self.assertEqual(graph["capture_import"]["accepted"], 512)
            validate_object_graph(graph, "lab", KEY)
            index = indexed_capture_sources("lab", [self.path], KEY, independent_windows=True, research_profile=True)
            self.assertEqual(len(index), 512)
            handoff = propose_object_handoff(
                graph, "lab", KEY, verify_inputs=[self.path], materialize_dir=self.root / "pairs", limit=1
            )
            self.assertEqual(handoff["network_requests_sent"], 0)
            self.write([entry(i, {"id": i}) for i in range(513)])
            for operation in (
                lambda: build_object_graph(
                    "lab", [self.path], KEY, authorized=True, independent_windows=True, research_profile=True
                ),
                lambda: indexed_capture_sources(
                    "lab", [self.path], KEY, independent_windows=True, research_profile=True
                ),
            ):
                with self.assertRaises(ValueError):
                    operation()

    def test_body_depth_extension_preserves_default_and_absolute_guards(self) -> None:
        nested: object = {"id": 701}
        for _ in range(60):
            nested = {"wrapper": nested}
        raw = self.write([entry(701, nested), entry(702, {"id": 702})])
        limits: HarLimits = {"max_bytes": 1_000_000, "max_message_bytes": 100_000}
        self.assertEqual(import_har(raw, **limits).summary()["reasons"], {"body_json_too_deep": 1})
        self.assertEqual(import_har(raw, max_body_depth=64, **limits).summary()["accepted"], 2)
        for _ in range(5):
            nested = {"wrapper": nested}
        raw = self.write([entry(701, nested), entry(702, {"id": 702})])
        self.assertEqual(import_har(raw, max_body_depth=64, **limits).summary()["reasons"], {"body_json_too_deep": 1})
        for invalid in (0, 65, True):
            with self.assertRaises(ValueError):
                import_har(raw, max_body_depth=invalid, **limits)

    def test_resource_metadata_is_pseudonymized_and_copied_credentials_stay_excluded(self) -> None:
        for value in ("801", True):
            self.write([entry(801, {"credentials": {"id": value, "value": "PRIVATE-SYNTHETIC"}})])
            graph = build_object_graph("lab", [self.path], KEY, authorized=True)
            self.assertNotIn("PRIVATE-SYNTHETIC", json.dumps(graph))
            if isinstance(value, str):
                self.assertFalse(any(n["type"] == "Object" for n in graph["nodes"]))
        self.write([entry(801, {"api_tokens": {"id": 801, "value": "PRIVATE-SYNTHETIC"}})])
        graph = build_object_graph("lab", [self.path], KEY, authorized=True)
        self.assertTrue(any(n["type"] == "Object" for n in graph["nodes"]))
        text = json.dumps(graph)
        self.assertNotIn("PRIVATE-SYNTHETIC", text)
        self.assertNotIn('"801"', text)
        self.assertNotIn("api_tokens", text)
        self.write([entry(801, {"access_tokens": [{"id": 801, "token": "PRIVATE-SYNTHETIC"}]})])
        graph = build_object_graph("lab", [self.path], KEY, authorized=True)
        self.assertTrue(
            any(ref["location"] == "response_json" for o in graph["observations"] for ref in o["references"])
        )
        self.assertNotIn("PRIVATE-SYNTHETIC", json.dumps(graph))
        self.write([entry(801, {"api_tokens": {"id": 801}, "token": 801})])
        graph = build_object_graph("lab", [self.path], KEY, authorized=True)
        self.assertFalse(any(n["type"] == "Object" for n in graph["nodes"]))
        for name in ("password", "secret", "authorization", "cookie", "credentials"):
            with self.subTest(sensitive_container=name):
                self.write([entry(801, {name: {"id": 801}})])
                graph = build_object_graph("lab", [self.path], KEY, authorized=True)
                self.assertFalse(any(n["type"] == "Object" for n in graph["nodes"]))
