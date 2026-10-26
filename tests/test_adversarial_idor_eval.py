"""Reproducibility, safety and regression-guard tests for the frozen adversarial IDOR/BOLA corpus.

These tests pin MEASURED behaviour (they are not acceptance gates tuned to pass) so that
any change to the pipeline that moves the frozen-corpus numbers is visible in review.
"""

from __future__ import annotations

import hashlib
import json
import socket
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LAB = ROOT / "labs" / "adversarial_idor_eval"
sys.path.insert(0, str(LAB))

import build_corpus  # noqa: E402
import evaluate  # noqa: E402

SNAPSHOT = LAB / "results" / "v0.2.2-main-47c8a30.json"


class AdversarialCorpusFrozenTests(unittest.TestCase):
    def test_manifest_hashes_match(self) -> None:
        for line in (LAB / "frozen" / "MANIFEST.sha256").read_text(encoding="utf-8").splitlines():
            digest, name = line.split("  ")
            data = (LAB / "frozen" / name).read_bytes()
            self.assertEqual(hashlib.sha256(data).hexdigest(), digest, name)

    def test_generator_is_byte_identical(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            build_corpus.build(Path(tmp))
            for name in ("captures.har", "ground_truth.json", "MANIFEST.sha256"):
                self.assertEqual((Path(tmp) / name).read_bytes(), (LAB / "frozen" / name).read_bytes(), name)

    def test_independent_of_dev_eval_and_synthetic_loopback(self) -> None:
        har = json.loads((LAB / "frozen" / "captures.har").read_text(encoding="utf-8"))
        gt = json.loads((LAB / "frozen" / "ground_truth.json").read_text(encoding="utf-8"))
        self.assertIn("do not tune", gt["tuning_policy"].lower())
        old = set()
        for split in ("dev", "eval"):
            doc = json.loads(
                (ROOT / "labs" / "object_discovery_lab" / split / "captures.har").read_text(encoding="utf-8")
            )
            old |= {e["request"]["url"] for e in doc["log"]["entries"]}
        urls = [e["request"]["url"] for e in har["log"]["entries"]]
        self.assertFalse(old & set(urls))
        self.assertTrue(all(u.startswith("http://127.0.0.1:8137/adv/") for u in urls))
        classes = {s["class"] for s in gt["scenarios"]}
        self.assertEqual(classes, {"positive", "negative", "ambiguous"})
        tags = {s["adversarial_tag"] for s in gt["scenarios"]}
        for required in (
            "shared-ids",
            "nested-objects",
            "arrays",
            "uuid",
            "cross-reference",
            "multi-session",
            "public-objects",
            "partial-responses",
            "hierarchical-permissions",
            "incomplete-captures",
        ):
            self.assertIn(required, tags)
        self.assertTrue(all(s["expected_confirmed"] is False for s in gt["scenarios"]))


class AdversarialEvaluationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.result = evaluate.strip_volatile(evaluate.evaluate())

    def test_offline_no_network_and_nothing_confirmed(self) -> None:
        r = self.result
        self.assertEqual(r["safety"]["network_connect_attempts"], 0)
        self.assertEqual(r["pairing"]["network_requests_sent_reported"], 0)
        self.assertEqual(r["pairing"]["confirmed_flags"], 0)
        self.assertEqual(r["case_discovery"]["confirmed_flags"], 0)
        self.assertEqual(r["confirmation"]["confirmed_by_pipeline"], 0)
        self.assertFalse(r["confirmation"]["measurable_offline"])

    def test_network_guard_restores_socket(self) -> None:
        before = socket.socket.connect
        with evaluate.no_network():
            with self.assertRaises(evaluate.NetworkBlocked):
                socket.create_connection(("127.0.0.1", 9))
        self.assertIs(socket.socket.connect, before)

    def test_deterministic_and_matches_committed_snapshot(self) -> None:
        again = evaluate.strip_volatile(evaluate.evaluate())
        self.assertEqual(self.result, again)
        snapshot = json.loads(SNAPSHOT.read_text(encoding="utf-8"))
        for stage in ("discovery", "pairing", "case_discovery", "bounds_probes", "primary_run_input"):
            self.assertEqual(self.result[stage], snapshot[stage], stage)

    def test_bounds_probes_fail_closed(self) -> None:
        probes = self.result["bounds_probes"]
        self.assertTrue(probes)
        for name, outcome in probes.items():
            self.assertFalse(outcome["accepted"], name)

    def test_measured_numbers_pinned(self) -> None:
        d, p, c = self.result["discovery"], self.result["pairing"], self.result["case_discovery"]
        self.assertEqual((d["expected_found"], d["expected_objects"]), (12, 12))
        self.assertEqual(d["precision_at_k"]["1"], 0.0)
        self.assertEqual(d["exported_resource_types"], ["unknown"])
        self.assertEqual(
            (p["proposals"], p["tp_proposals"], p["fp_proposals"], p["ambiguous_proposals"]), (23, 13, 6, 4)
        )
        self.assertEqual(p["false_negatives"], ["S04:ticket", "S11:subscription"])
        self.assertEqual(p["manual_review_rate"], 1.0)
        self.assertEqual((c["tp_pairs"], c["tp_pairs_with_case"]), (13, 8))


if __name__ == "__main__":
    unittest.main()
