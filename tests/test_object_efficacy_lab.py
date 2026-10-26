from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from bugbounty_toolkit.analysis.object_handoff import default_lab_root, run_object_discovery_lab


class ObjectEfficacyLabTests(unittest.TestCase):
    def test_eval_lab_meets_acceptance_gates(self) -> None:
        root = default_lab_root()
        self.assertTrue((root / "eval" / "captures.har").is_file())
        self.assertTrue((root / "eval" / "labels.json").is_file())
        self.assertTrue((root / "dev" / "captures.har").is_file())
        result = run_object_discovery_lab(root, split="eval", limit=10)
        primary = result["primary"]
        metrics = primary["metrics"]
        self.assertEqual(result["network_requests_sent"], 0)
        self.assertEqual(result["vulnerabilities_confirmed"], 0)
        self.assertFalse(result["confirmed"])
        self.assertTrue(metrics["vulnerable_in_top3"], metrics)
        self.assertEqual(metrics["confirmed_findings"], 0)
        self.assertGreaterEqual(metrics["precision_at_3"], 0.5)
        self.assertGreaterEqual(metrics["recall"], 0.5)
        # Protected may be proposed structurally but never confirmed.
        self.assertIn("protected", metrics["per_relation"])
        self.assertEqual(metrics["confirmed_findings"], 0)
        # Negative session-only / public cases must not become confirmed findings.
        self.assertEqual(metrics["fp_count"], 0)
        self.assertNotIn("wishlist", metrics.get("true_positives", []))

    def test_dev_and_eval_are_separated(self) -> None:
        root = default_lab_root()
        dev_labels = json.loads((root / "dev" / "labels.json").read_text(encoding="utf-8"))
        eval_labels = json.loads((root / "eval" / "labels.json").read_text(encoding="utf-8"))
        self.assertEqual(dev_labels["split"], "dev")
        self.assertEqual(eval_labels["split"], "eval")
        self.assertIn("not tune", eval_labels["tuning_policy"].lower())
        self.assertNotEqual(
            (root / "dev" / "captures.har").read_bytes(),
            (root / "eval" / "captures.har").read_bytes(),
        )

    def test_lab_is_deterministic(self) -> None:
        root = default_lab_root()
        first = run_object_discovery_lab(root, split="eval")
        second = run_object_discovery_lab(root, split="eval")
        self.assertEqual(
            first["primary"]["metrics"]["primary_queue_resource_types"],
            second["primary"]["metrics"]["primary_queue_resource_types"],
        )
        self.assertEqual(first["primary"]["metrics"]["precision_at_3"], second["primary"]["metrics"]["precision_at_3"])
        self.assertEqual(first["primary"]["handoff_proposals"], second["primary"]["handoff_proposals"])

    def test_cli_lab_dry_run(self) -> None:
        from bugbounty_toolkit import cli
        from io import StringIO
        from contextlib import redirect_stdout

        buf = StringIO()
        argv = ["bbtk", "lab", "object-discover", "--dry-run", "--split", "eval"]
        with patch.object(cli.sys, "argv", argv), redirect_stdout(buf):
            cli.main()
        out = buf.getvalue()
        self.assertIn("vulnerable_in_top3", out)
        self.assertIn('"network_requests_sent": 0', out)

    def test_metrics_json_write(self) -> None:
        from bugbounty_toolkit import cli
        from io import StringIO
        from contextlib import redirect_stdout

        with tempfile.TemporaryDirectory() as tmp:
            destination = Path(tmp) / "metrics.json"
            buf = StringIO()
            argv = [
                "bbtk",
                "lab",
                "object-discover",
                "--split",
                "eval",
                "--metrics-json",
                str(destination),
            ]
            with patch.object(cli.sys, "argv", argv), redirect_stdout(buf):
                cli.main()
            payload = json.loads(destination.read_text(encoding="utf-8"))
            self.assertEqual(payload["type"], "api-object-discovery-efficacy-lab")
            self.assertEqual(payload["network_requests_sent"], 0)
            self.assertTrue(payload["primary"]["metrics"]["vulnerable_in_top3"])


if __name__ == "__main__":
    unittest.main()
