"""Tests for the local AI evidence assistant (deterministic primary + mock AI)."""

from __future__ import annotations

import json
import unittest
from dataclasses import replace
from unittest.mock import patch

from bugbounty_toolkit import ai_mock_server as mocks
from bugbounty_toolkit.analysis.ai_backend import AISelection
from bugbounty_toolkit.analysis.ai_providers import PROVIDER_REGISTRY
from bugbounty_toolkit.analysis.local_ai_evidence_assistant import (
    assist_evidence,
    deterministic_assist,
    _parse_assistant,
)
from labs.local_ai_evidence_assistant_eval.evaluate import (
    _enricher,
    _faithful,
    _inventor,
    evaluate,
    final_is_frozen,
    load_split,
)


def _evidence() -> dict[str, object]:
    return {
        "type": "access-control",
        "classification": "candidate",
        "controls_valid": True,
        "steps": [
            {
                "step": "owner_read",
                "status_code": 200,
                "owner_private_match": True,
                "owner_resource_match": True,
            },
            {
                "step": "cross_read",
                "status_code": 200,
                "owner_private_match": True,
                "owner_resource_match": True,
            },
        ],
    }


class LocalAIEvidenceAssistantTests(unittest.TestCase):
    def test_response_contract_rejects_adversarial_structures(self) -> None:
        valid = dict(
            summary="Candidate",
            explanation="Needs human review",
            pending_questions=[],
            contradictions=[],
            draft_notes="Review controls",
            missing_data_suggestions=[],
            limitations=["Advisory only"],
        )
        mutations: list[dict[str, object]] = [
            {"finding_confirmed": True},
            {"pending_questions": "execute request"},
            {"summary": {"execute": "request"}},
            {"summary": "x" * 401 + " execute request"},
            {"limitations": [False]},
            {"contradictions": ["item"] * 9},
        ]
        for change in mutations:
            with self.subTest(change=change):
                package, issues = _parse_assistant(json.dumps({**valid, **change}), set())
                self.assertIsNone(package)
                self.assertTrue(issues)
        self.assertIsNotNone(_parse_assistant(json.dumps(valid), set())[0])

    def test_bad_model_response_preserves_deterministic_fallback(self) -> None:
        with patch("bugbounty_toolkit.analysis.local_ai_evidence_assistant.dispatch_chat", return_value="{}"):
            result = assist_evidence(_evidence(), selection=AISelection("ollama", "synthetic"))
        self.assertEqual(result["ai"]["status"], "rejected")
        self.assertEqual(result["primary"], "deterministic")
        self.assertFalse(result["finding_confirmed"])
        self.assertTrue(result["deterministic"]["summary"])

    def test_deterministic_never_confirms(self) -> None:
        out = deterministic_assist(_evidence())
        self.assertIs(out["package"]["finding_confirmed"], False)
        self.assertTrue(out["package"]["summary"])

    def test_dry_run_primary_deterministic(self) -> None:
        out = assist_evidence(_evidence(), dry_run=True)
        self.assertEqual(out["primary"], "deterministic")
        self.assertIs(out["finding_confirmed"], False)
        self.assertIs(out["ledger_mutated"], False)
        self.assertIs(out["requests_executed"], False)
        self.assertIs(out["cloud_api_used"], False)

    def test_faithful_mock_does_not_beat_baseline(self) -> None:
        with mocks.MockLocalAIServer(_faithful, models=("mock-assist",)) as server:
            selection = AISelection(
                "ollama",
                "mock-assist",
                timeout=30.0,
                spec=replace(PROVIDER_REGISTRY["ollama"], port=server.port, allowed_ports=(server.port,)),
            )
            out = assist_evidence(_evidence(), selection=selection)
        self.assertEqual(out["primary"], "deterministic")
        self.assertFalse(out["ai_improved_advisory"])
        self.assertIs(out["finding_confirmed"], False)

    def test_enricher_improves_advisory_but_primary_stays_deterministic(self) -> None:
        with mocks.MockLocalAIServer(_enricher, models=("mock-assist",)) as server:
            selection = AISelection(
                "ollama",
                "mock-assist",
                timeout=30.0,
                spec=replace(PROVIDER_REGISTRY["ollama"], port=server.port, allowed_ports=(server.port,)),
            )
            out = assist_evidence(_evidence(), selection=selection)
        self.assertTrue(out["ai_improved_advisory"])
        self.assertEqual(out["primary"], "deterministic")
        self.assertEqual(out["advisory_enrichment"], "local_ai")

    def test_inventor_rejected(self) -> None:
        with mocks.MockLocalAIServer(_inventor, models=("mock-assist",)) as server:
            selection = AISelection(
                "ollama",
                "mock-assist",
                timeout=30.0,
                spec=replace(PROVIDER_REGISTRY["ollama"], port=server.port, allowed_ports=(server.port,)),
            )
            out = assist_evidence(_evidence(), selection=selection)
        self.assertEqual(out["ai"]["status"], "rejected")
        self.assertEqual(out["primary"], "deterministic")

    def test_final_frozen_and_metrics(self) -> None:
        self.assertTrue(final_is_frozen())
        metrics = evaluate(load_split("final"))
        self.assertEqual(metrics["secret_leaks"], 0)
        self.assertEqual(metrics["finding_confirmed_true"], 0)
        self.assertEqual(metrics["mismatches"], [])
        self.assertEqual(metrics["primary_deterministic_rate"], 1.0)

    def test_canaries_absent_from_output(self) -> None:
        case = load_split("dev")[4]
        out = assist_evidence(case["evidence"], dry_run=True)
        blob = json.dumps(out)
        for canary in case["canaries"]:
            self.assertNotIn(canary, blob)


if __name__ == "__main__":
    unittest.main()
