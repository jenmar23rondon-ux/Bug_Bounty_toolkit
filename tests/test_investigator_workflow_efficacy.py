from __future__ import annotations

import hashlib
import json
import socket
import tempfile
import unittest
from pathlib import Path

from bugbounty_toolkit import __version__
from labs.investigator_workflow_efficacy import FINDING_CONFIRMED
from labs.investigator_workflow_efficacy.corpus import document
from labs.investigator_workflow_efficacy.evaluate import load_split, manifest_matches, run_report
from labs.investigator_workflow_efficacy.freeze import dumps
from labs.investigator_workflow_efficacy.guard import LoopbackGuard
from labs.investigator_workflow_efficacy.real_world import main as real_world_main
from labs.investigator_workflow_efficacy.secrets import CANARY, leak_count
from labs.investigator_workflow_efficacy.server import LabServer
from labs.investigator_workflow_efficacy.tutorial import COMMANDS, run_tutorial

LAB = Path(__file__).resolve().parents[1] / "labs" / "investigator_workflow_efficacy"
TUTORIAL = Path(__file__).resolve().parents[1] / "docs" / "from-burp-capture-to-verified-dossier.md"
RESULTS = LAB / "results" / "dispositions.json"


class InvestigatorWorkflowEfficacyTests(unittest.TestCase):
    def test_version_and_confirmation_policy(self) -> None:
        self.assertEqual(__version__, "0.2.2")
        self.assertFalse(FINDING_CONFIRMED)

    def test_frozen_cases_match_corpus_and_manifest(self) -> None:
        for split in ("dev", "final", "stress"):
            text = dumps(document(split))
            on_disk = (LAB / split / "cases.json").read_text(encoding="utf-8")
            self.assertEqual(on_disk, text)
            self.assertTrue(manifest_matches(split))
            digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
            self.assertEqual((LAB / split / "MANIFEST.sha256").read_text(encoding="utf-8").split()[0], digest)

    def test_guard_blocks_non_loopback(self) -> None:
        with LoopbackGuard() as guard:
            sock = socket.socket()
            sock.settimeout(0.2)
            with self.assertRaises(OSError):
                sock.connect(("10.1.1.1", 9))
            sock.close()
        self.assertEqual(guard.external, 1)
        self.assertEqual(guard.loopback, 0)

    def test_server_refuses_non_loopback_bind(self) -> None:
        with self.assertRaises(ValueError):
            LabServer([], host="10.1.1.1")

    def test_real_world_protocol_does_not_run(self) -> None:
        self.assertEqual(real_world_main([]), 2)

    def test_lab_safety_and_recorded_dispositions(self) -> None:
        report = run_report(["dev", "final", "stress"])
        self.assertEqual(report["external_requests"], 0)
        self.assertEqual(report["secret_leaks"], 0)
        self.assertEqual(report["finding_confirmed_true"], 0)
        self.assertFalse(report["finding_confirmed"])
        self.assertIn("human_minutes", report["NOT_MEASURED"])
        recorded = json.loads(RESULTS.read_text(encoding="utf-8"))
        fresh: dict[str, dict[str, str]] = {}
        for split, payload in report["splits"].items():
            self.assertGreater(payload["loopback_requests"], 0)
            self.assertEqual(payload["external_requests"], 0)
            self.assertFalse(payload["bbtk"]["workflow_finding_confirmed"])
            self.assertEqual(payload["bbtk"]["workflow_executions"], 0)
            self.assertIn("wf-control_review", payload["bbtk"]["workflow_next_reviewable_tasks"])
            for arm in ("manual", "bbtk"):
                self.assertEqual(payload[arm]["finding_confirmed_true"], 0)
                for row in payload["dispositions"][arm]:
                    self.assertIn(row["disposition"], {"review", "reject", "abstain"})
                    self.assertFalse(row["finding_confirmed"])
                    fresh[f"{split}:{arm}:{row['case_id']}"] = row["disposition"]
        self.assertEqual(fresh, recorded)
        self.assertEqual(fresh["dev:manual:A-dev-vuln-order"], "review")
        self.assertEqual(fresh["dev:bbtk:A-dev-vuln-order"], "review")
        self.assertEqual(fresh["stress:manual:S-xss-duplicate"], "reject")
        self.assertEqual(fresh["stress:bbtk:S-xss-duplicate"], "reject")
        self.assertNotIn(CANARY, json.dumps(report))

    def test_tutorial_commands_match_doc_and_execute(self) -> None:
        doc = TUTORIAL.read_text(encoding="utf-8")
        for command in COMMANDS:
            self.assertIn(command, doc)
        with tempfile.TemporaryDirectory(prefix="iwe-tutorial-") as tmp:
            root = Path(tmp)
            output = run_tutorial(root)
            disclosure = (root / "records" / "iwe-tutorial" / "reports" / "disclosure.json").read_text(encoding="utf-8")
            ledger = (root / "records" / "iwe-tutorial" / "reports" / "ledger.md").read_text(encoding="utf-8")
            imported = (
                root / "records" / "iwe-tutorial" / "inputs" / "requests" / "A-dev-vuln-order-request.txt"
            ).read_text(encoding="utf-8")
            shareable = "\n".join((output, disclosure, ledger, imported))
        self.assertEqual(leak_count(shareable), 0)
        self.assertIn("finding_confirmed", disclosure)
        parsed = json.loads(disclosure)
        self.assertFalse(parsed["finding_confirmed"])
        self.assertIn("[redacted]", imported)
        self.assertIn("cand-order", ledger)

    def test_split_loader_covers_every_workflow(self) -> None:
        for split in ("dev", "final", "stress"):
            workflows = {case["workflow"] for case in load_split(split)}
            self.assertEqual(workflows, {"A", "B", "C"})


if __name__ == "__main__":
    unittest.main()
