"""IDOR/BOLA end-to-end research quality: full offline contract + independent lab."""

from __future__ import annotations

import hashlib
import json
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from bugbounty_toolkit.analysis.idor_e2e_research import (
    EXPIRED_TOKEN_MARKER,
    STAGES,
    run_e2e_research,
    verify_artifacts,
    ArtifactRecord,
    ResearchSession,
)
from labs.adversarial_idor_eval.evaluate import KEY, no_network
from labs.idor_e2e_research import build_corpus, evaluate as evaluate_mod

ROOT = Path(__file__).resolve().parents[1]
FROZEN = ROOT / "labs" / "idor_e2e_research" / "frozen"
PROGRAM = "idor-e2e-research-test"


class CorpusIntegrityTests(unittest.TestCase):
    def test_frozen_manifest_matches_bytes(self) -> None:
        lines = (FROZEN / "MANIFEST.sha256").read_text(encoding="utf-8").strip().splitlines()
        self.assertEqual(len(lines), 2)
        for line in lines:
            digest, name = line.split("  ")
            data = (FROZEN / name).read_bytes()
            self.assertEqual(hashlib.sha256(data).hexdigest(), digest)

    def test_regeneration_is_byte_identical_into_temp(self) -> None:
        tmp = Path(tempfile.mkdtemp())
        try:
            build_corpus.write(tmp)
            for name in ("captures.har", "ground_truth.json", "MANIFEST.sha256"):
                self.assertEqual((tmp / name).read_bytes(), (FROZEN / name).read_bytes(), name)
        finally:
            shutil.rmtree(tmp)

    def test_fifteen_independent_scenarios(self) -> None:
        gt = json.loads((FROZEN / "ground_truth.json").read_text(encoding="utf-8"))
        ids = [s["id"] for s in gt["scenarios"]]
        self.assertEqual(ids, [f"R{i:02d}" for i in range(1, 16)])
        self.assertTrue(all(s.get("expected_confirmed") is False for s in gt["scenarios"]))
        self.assertEqual(gt["origin"], "http://127.0.0.1:8155")


class EndToEndResearchTests(unittest.TestCase):
    def test_valid_cases_survive_large_damaged_capture_without_network(self) -> None:
        with tempfile.TemporaryDirectory() as directory, no_network() as attempts:
            root = Path(directory)
            document = json.loads((FROZEN / "captures.har").read_text(encoding="utf-8"))
            document["log"]["entries"] = [
                {"request": {"method": "GET"}, "response": {}} for _ in range(300)
            ] + document["log"]["entries"]
            capture = root / "damaged.har"
            capture.write_text(json.dumps(document), encoding="utf-8")
            report = run_e2e_research(PROGRAM, [capture], root / "run", key=KEY, limit=64)
        self.assertEqual(attempts["count"], 0)
        self.assertGreaterEqual(report["eligibility_summary"]["case_eligible"], 1)
        self.assertEqual(report["vulnerabilities_confirmed"], 0)
        self.assertEqual(report["access_checks_executed"], 0)
        self.assertEqual(report["pending_contracts"], [])

    def test_full_pipeline_offline_and_unconfirmed(self) -> None:
        with no_network() as attempts:
            tmp = Path(tempfile.mkdtemp())
            try:
                report = run_e2e_research(PROGRAM, [FROZEN / "captures.har"], tmp, key=KEY, limit=64)
            finally:
                shutil.rmtree(tmp)
        self.assertEqual(attempts["count"], 0)
        self.assertEqual(report["pending_contracts"], [])
        self.assertEqual(report["network_requests_sent"], 0)
        self.assertEqual(report["access_checks_executed"], 0)
        self.assertEqual(report["vulnerabilities_confirmed"], 0)
        self.assertEqual(set(report["stages"]), set(STAGES))
        self.assertTrue(all(v == "ok" for v in report["stages"].values()))
        self.assertTrue(report["eligibility_summary"]["case_eligible"] >= 1)
        self.assertTrue(all(not c.get("confirmed") for c in report["ledger"]["candidates"]))
        self.assertTrue(all(r["requires_human_review"] and not r["confirmed"] for r in report["control_reviews"]))
        self.assertTrue(
            all(not r["ownership_inferred"] and not r["fabricated_controls"] for r in report["control_reviews"])
        )
        # Distinguishes technical vs legitimate rejection classes when present.
        codes = {c["code"] for c in report["classifications"]}
        self.assertTrue(codes)

    def test_resume_reuses_artifacts_without_reimport(self) -> None:
        with no_network():
            tmp = Path(tempfile.mkdtemp())
            try:
                first = run_e2e_research(PROGRAM, [FROZEN / "captures.har"], tmp, key=KEY, limit=32)
                session = Path(first["session_path"])
                with mock.patch("bugbounty_toolkit.analysis.idor_e2e_research.build_object_graph") as mocked:
                    resumed = run_e2e_research(
                        PROGRAM,
                        [FROZEN / "captures.har"],
                        tmp,
                        key=KEY,
                        resume_session=session,
                    )
                    mocked.assert_not_called()
                self.assertTrue(resumed["resumed"])
                self.assertEqual(resumed["artifact_issues"], [])
            finally:
                shutil.rmtree(tmp)

    def test_modified_evidence_blocks_resume(self) -> None:
        with no_network():
            tmp = Path(tempfile.mkdtemp())
            try:
                first = run_e2e_research(PROGRAM, [FROZEN / "captures.har"], tmp, key=KEY, limit=32)
                session_path = Path(first["session_path"])
                raw = json.loads(session_path.read_text(encoding="utf-8"))
                pair = next(a for a in raw["artifacts"] if a["kind"] == "materialized_pair")
                Path(pair["path"]).write_bytes(Path(pair["path"]).read_bytes() + b"\n#x\n")
                blocked = run_e2e_research(
                    PROGRAM,
                    [FROZEN / "captures.har"],
                    tmp,
                    key=KEY,
                    resume_session=session_path,
                )
                self.assertFalse(blocked["resumed"])
                self.assertTrue(any(i["code"] == "ARTIFACT_MODIFIED" for i in blocked["artifact_issues"]))
            finally:
                shutil.rmtree(tmp)

    def test_expired_token_marker_detected(self) -> None:
        session = ResearchSession(
            session_id="x",
            program=PROGRAM,
            version=1,
            type="bbtk-idor-e2e-research-session/1",
            capture_paths=[],
            capture_sha256={},
            origin_refs=[],
            stages_completed=[],
            artifacts=[],
        )
        tmp = Path(tempfile.mkdtemp())
        try:
            path = tmp / "pair.http"
            path.write_text(f"GET /x HTTP/1.1\n\n{EXPIRED_TOKEN_MARKER}\n", encoding="utf-8")
            session.artifacts.append(
                ArtifactRecord(
                    name="p",
                    path=str(path),
                    sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
                    kind="materialized_pair",
                )
            )
            issues = verify_artifacts(session)
            self.assertTrue(any(i["code"] == "EVIDENCE_EXPIRED" for i in issues))
        finally:
            shutil.rmtree(tmp)

    def test_eval_harness_metrics_safe(self) -> None:
        metrics = evaluate_mod.evaluate(FROZEN)
        self.assertEqual(metrics["safety"]["network_connect_attempts"], 0)
        self.assertEqual(metrics["safety"]["access_checks_executed"], 0)
        self.assertEqual(metrics["safety"]["vulnerabilities_confirmed"], 0)
        self.assertTrue(metrics["safety"]["pending_contracts_empty"])
        self.assertTrue(metrics["stages_ok"])
        self.assertTrue(metrics["provenance_integrity"]["altered_evidence_detected"])
        self.assertTrue(metrics["provenance_integrity"]["expired_token_present"])
        self.assertTrue(metrics["provenance_integrity"]["expired_evidence_flagged"])
        self.assertTrue(metrics["control_reviews_require_human"])
        self.assertEqual(metrics["pending_contracts"], [])
        self.assertEqual(len(metrics["scenario_ids"]), 15)


class EvalIntegrityAlignmentTests(unittest.TestCase):
    def test_pipeline_pending_contracts_empty(self) -> None:
        from labs.eval_integrity import pipeline

        self.assertEqual(pipeline.PENDING_CONTRACTS, ())


if __name__ == "__main__":
    unittest.main()
