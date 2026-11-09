"""Request-compatibility gate for IDOR/BOLA proposal precision.

The gate is opt-in on ``propose_object_handoff`` and on by default in the offline
research pipeline. It must not confirm findings or drop a contradictory 403 that
still returns the resource (A06).
"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from typing import Any

from bugbounty_toolkit.analysis.object_handoff import propose_object_handoff
from bugbounty_toolkit.analysis.object_relationships import build_object_graph

ROOT = Path(__file__).resolve().parents[1]
FINAL = ROOT / "labs" / "independent_research_eval" / "final"
KEY = b"\x11" * 32
PROGRAM = "pairing-precision-v5"


def _captures(scenario_id: str) -> list[Path]:
    folder = FINAL / "captures"
    if scenario_id == "C02":
        return [folder / "C02-0.http", folder / "C02-1.http"]
    return [folder / f"{scenario_id}.har"]


def _handoff(scenario_id: str, *, gate: bool) -> dict[str, Any]:
    captures = _captures(scenario_id)
    graph = build_object_graph(PROGRAM, captures, KEY, authorized=True, independent_windows=True, research_profile=True)
    with tempfile.TemporaryDirectory() as temporary:
        document = propose_object_handoff(
            graph,
            PROGRAM,
            KEY,
            verify_inputs=captures,
            limit=64,
            materialize_dir=Path(temporary),
            compatibility_gate=gate,
        )
    return document


class PairingPrecisionGateTests(unittest.TestCase):
    def test_gate_defaults_off(self) -> None:
        captures = _captures("A03")
        graph = build_object_graph(
            PROGRAM, captures, KEY, authorized=True, independent_windows=True, research_profile=True
        )
        document = propose_object_handoff(graph, PROGRAM, KEY, verify_inputs=captures, limit=8)
        self.assertNotIn("compatibility_gate", document)
        self.assertGreaterEqual(document["total_proposals"], 1)
        self.assertTrue(all(row["confirmed"] is False for row in document["proposals"]))

    def test_false_pair_classes_are_withheld_and_true_pairs_stay(self) -> None:
        # No ideal pair: every admitted proposal was a false pairing class.
        for scenario_id in ("A02", "A03", "A05", "A07", "A08", "A09", "B06", "B08", "C02", "C05", "C07", "E03", "E05"):
            with self.subTest(scenario=scenario_id):
                document = _handoff(scenario_id, gate=True)
                self.assertEqual(document["total_proposals"], 0, scenario_id)
                self.assertEqual(document["network_requests_sent"], 0)
                self.assertFalse(document["confirmed"])
                self.assertEqual(document["vulnerabilities_confirmed"], 0)
        # Legitimate or contradictory-success pairs remain proposals.
        for scenario_id in ("A01", "A06", "A10", "B01", "E04", "E06"):
            with self.subTest(scenario=scenario_id):
                document = _handoff(scenario_id, gate=True)
                self.assertGreaterEqual(document["total_proposals"], 1, scenario_id)
                self.assertTrue(all(row["confirmed"] is False for row in document["proposals"]))

    def test_denial_evidence_is_kept_out_of_the_proposal_list(self) -> None:
        for scenario_id in ("A02", "A05", "A08", "A09", "C05"):
            with self.subTest(scenario=scenario_id):
                document = _handoff(scenario_id, gate=True)
                withheld = document["withheld_incompatible"]
                self.assertGreaterEqual(len(withheld), 1)
                self.assertTrue(all(row["withheld_reason"] == "authorization_denial" for row in withheld))
                self.assertTrue(all(row["confirmed"] is False for row in withheld))
                self.assertEqual(document["proposals"], [])

    def test_public_and_non_get_are_not_denial_controls(self) -> None:
        for scenario_id in ("A03", "E03", "C07", "E05", "A07", "B06"):
            with self.subTest(scenario=scenario_id):
                document = _handoff(scenario_id, gate=True)
                self.assertEqual(document["withheld_incompatible"], [])
                self.assertGreaterEqual(document["compatibility_gate"]["withheld_other"], 1)
