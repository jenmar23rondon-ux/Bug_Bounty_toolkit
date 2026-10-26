from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from bugbounty_toolkit.analysis.evidence_ledger import add_candidate, add_evidence, new_ledger, upsert_surface
from bugbounty_toolkit.reporting.dossier_schema import DOSSIER_SCHEMA, SCHEMA_VERSION
from bugbounty_toolkit.reporting.dossier_verifier import (
    build_verified_dossier_from_evidence,
    dossier_fingerprint,
    minimize_dossier_for_share,
    render_verified_dossier_markdown,
    verify_research_dossier,
    write_verified_dossier,
)
from labs.verified_dossier_eval.metrics import compare_splits, evaluate_split

SCHEMA_DOC = Path(__file__).resolve().parents[1] / "docs" / "schemas" / "verified-dossier-v1.schema.json"


class DossierVerifierUnitTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.program_dir = self.root / "prog"
        (self.program_dir / "evidence").mkdir(parents=True)
        (self.program_dir / "evidence" / "a.json").write_text(
            '{"type":"access-control","classification":"candidate"}', encoding="utf-8"
        )
        self.ledger = new_ledger("prog")
        upsert_surface(
            self.ledger,
            {"surface_id": "s1", "kind": "endpoint", "ref": "/a", "status": "investigated", "fingerprint": "fp"},
        )
        add_evidence(self.ledger, self.program_dir, "e1", "evidence/a.json", tool="manual", surface_fingerprint="fp")
        add_candidate(self.ledger, "c1", "s1", "idor", "alice", ["e1"])

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_schema_doc_matches_code(self) -> None:
        self.assertEqual(json.loads(SCHEMA_DOC.read_text(encoding="utf-8")), DOSSIER_SCHEMA)

    def test_complete_package_requires_human_when_unconfirmed(self) -> None:
        dossier = verify_research_dossier(
            {
                "candidate_id": "c1",
                "declared_ledger_state": "candidate",
                "expected_behavior": "deny",
                "expected_behavior_source": "lab_spec",
                "observed_behavior": "candidate signal",
                "observed_behavior_refs": ["e1"],
                "claims": [
                    {"claim_id": "a", "kind": "ledger_state", "text": "candidate", "evidence_refs": ["e1"]},
                    {"claim_id": "b", "kind": "observed_behavior", "text": "seen", "evidence_refs": ["e1"]},
                    {
                        "claim_id": "c",
                        "kind": "expected_behavior",
                        "text": "deny",
                        "source": "lab_spec",
                        "evidence_refs": [],
                    },
                ],
            },
            self.ledger,
            program_dir=self.program_dir,
        )
        self.assertEqual(dossier["schema_version"], SCHEMA_VERSION)
        self.assertEqual(dossier["validation_result"], "human_validation_required")
        self.assertFalse(dossier["finding_confirmed"])
        self.assertFalse(dossier["ledger_mutated"])
        self.assertEqual(dossier["network_requests_sent"], 0)
        self.assertEqual(dossier["auto_confirmations"], 0)

    def test_rejects_http_200_as_unauthorized(self) -> None:
        dossier = verify_research_dossier(
            {
                "candidate_id": "c1",
                "http_200_as_unauthorized": True,
                "claims": [
                    {
                        "claim_id": "x",
                        "kind": "classification",
                        "text": "HTTP 200 unauthorized IDOR",
                        "evidence_refs": ["e1"],
                    }
                ],
            },
            self.ledger,
            program_dir=self.program_dir,
        )
        self.assertEqual(dossier["validation_result"], "unsupported_claim")
        self.assertFalse(dossier["finding_confirmed"])

    def test_rejects_broken_and_altered_refs(self) -> None:
        broken = verify_research_dossier(
            {
                "candidate_id": "c1",
                "claims": [
                    {"claim_id": "g", "kind": "evidence_reference", "text": "ghost", "evidence_refs": ["e-ghost"]}
                ],
            },
            self.ledger,
            program_dir=self.program_dir,
        )
        self.assertEqual(broken["validation_result"], "missing_evidence")
        (self.program_dir / "evidence" / "a.json").write_text('{"changed":true}', encoding="utf-8")
        stale = verify_research_dossier(
            {
                "candidate_id": "c1",
                "claims": [{"claim_id": "o", "kind": "observed_behavior", "text": "x", "evidence_refs": ["e1"]}],
            },
            self.ledger,
            program_dir=self.program_dir,
        )
        self.assertEqual(stale["validation_result"], "stale_evidence")

    def test_model_cannot_confirm(self) -> None:
        dossier = verify_research_dossier(
            {
                "candidate_id": "c1",
                "ai_confirmation": True,
                "treat_ai_as_confirmed": True,
                "claims": [
                    {"claim_id": "ai", "kind": "ai_conclusion", "text": "Model confirmed", "evidence_refs": ["e1"]},
                    {"claim_id": "cf", "kind": "confirmation", "text": "confirmed by llm", "evidence_refs": ["e1"]},
                ],
            },
            self.ledger,
            program_dir=self.program_dir,
        )
        self.assertFalse(dossier["finding_confirmed"])
        self.assertIn(dossier["validation_result"], {"human_validation_required", "unsupported_claim"})

    def test_shareable_strips_paths_and_reuses_renderers(self) -> None:
        dossier = build_verified_dossier_from_evidence(
            {"type": "access-control", "classification": "candidate", "token": "sekrit-value-911"},
            self.ledger,
            "c1",
            program_dir=self.program_dir,
            expected_behavior="deny cross read",
            expected_behavior_source="lab_spec",
            private=True,
        )
        shared = minimize_dossier_for_share(dossier)
        self.assertFalse(shared["private"])
        blob = json.dumps(shared)
        self.assertIn("[redacted-local-path]", blob)
        self.assertNotIn("evidence/a.json", blob)
        md = render_verified_dossier_markdown(dossier)
        self.assertIn("Verified research dossier", md)
        out = self.root / "d.json"
        write_verified_dossier(dossier, out, fmt="json")
        self.assertTrue(out.is_file())
        self.assertEqual(len(dossier_fingerprint(dossier)), 64)

    def test_does_not_mutate_ledger(self) -> None:
        before = json.dumps(self.ledger, sort_keys=True)
        verify_research_dossier(
            {"candidate_id": "c1", "claims": [{"claim_id": "a", "kind": "ledger_state", "text": "candidate"}]},
            self.ledger,
            program_dir=self.program_dir,
        )
        self.assertEqual(json.dumps(self.ledger, sort_keys=True), before)


class DossierEvalLabTests(unittest.TestCase):
    def test_final_corpus_passes_with_zero_false_confirmations(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            result = evaluate_split("final", Path(tmp) / "final")
        failed = [row["id"] for row in result["scenarios"] if not row["passed"]]
        self.assertEqual(failed, [], msg=json.dumps(result["scenarios"], indent=2))
        self.assertEqual(result["false_confirmations_accepted"], 0)
        self.assertEqual(result["security"]["network_requests_sent"], 0)
        self.assertEqual(result["security"]["auto_confirmations"], 0)
        self.assertEqual(result["security"]["ledger_mutations"], 0)

    def test_dev_and_final_compare(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            result = compare_splits(root / "dev", root / "final")
        self.assertEqual(result["final"]["scenarios_passed"], result["final"]["scenario_count"])
        self.assertIn("before_after", result)


if __name__ == "__main__":
    unittest.main()
