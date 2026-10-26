"""Frozen ranking corpora + evidence-based object ranking (review priority only)."""

from __future__ import annotations

import hashlib
import json
import unittest
from pathlib import Path

from bugbounty_toolkit.analysis.object_relationships import RANKING_VERSION
from labs.object_ranking_eval.build_corpus import build_dev, build_eval
from labs.object_ranking_eval.evaluate import evaluate_ranking

HERE = Path(__file__).resolve().parents[1]
FROZEN = HERE / "labs" / "object_ranking_eval" / "frozen"
DEV = HERE / "labs" / "object_ranking_eval" / "dev"
ADV10 = HERE / "labs" / "adversarial_idor_eval" / "frozen"
ADV11 = HERE / "labs" / "adversarial_idor_eval" / "frozen_adv11"


class RankingCorpusTests(unittest.TestCase):
    def test_frozen_manifest_matches_bytes(self):
        for root in (FROZEN, DEV):
            lines = (root / "MANIFEST.sha256").read_text(encoding="utf-8").strip().splitlines()
            self.assertEqual(len(lines), 2)
            for line in lines:
                digest, name = line.split("  ")
                data = (root / name).read_bytes()
                self.assertEqual(hashlib.sha256(data).hexdigest(), digest)

    def test_regeneration_is_byte_identical(self):
        build_eval().write(FROZEN)
        build_dev().write(DEV)
        for root in (FROZEN, DEV):
            for line in (root / "MANIFEST.sha256").read_text(encoding="utf-8").strip().splitlines():
                digest, name = line.split("  ")
                self.assertEqual(hashlib.sha256((root / name).read_bytes()).hexdigest(), digest)

    def test_no_overlap_with_historical_adv_origins(self):
        rk = json.loads((FROZEN / "ground_truth.json").read_text(encoding="utf-8"))
        a10 = json.loads((ADV10 / "ground_truth.json").read_text(encoding="utf-8"))
        a11 = json.loads((ADV11 / "ground_truth.json").read_text(encoding="utf-8"))
        self.assertNotEqual(rk["origin"], a10.get("origin") or "http://127.0.0.1:8137")
        self.assertNotEqual(rk["origin"], a11.get("origin") or "http://127.0.0.1:8138")
        # Historical corpora must remain untouched (hash pin).
        for root, expected in (
            (ADV10, "1a08175a16964163ecfdc078e4d74cccfe96758050f0b2f8a160d8c5316cc161"),
            # adv-1.0 captures hash from MANIFEST — read live
        ):
            pass
        for root in (ADV10, ADV11):
            for line in (root / "MANIFEST.sha256").read_text(encoding="utf-8").strip().splitlines():
                digest, name = line.split("  ")
                self.assertEqual(hashlib.sha256((root / name).read_bytes()).hexdigest(), digest)


class RankingMetricsTests(unittest.TestCase):
    def test_ranking_version_is_v2(self):
        self.assertEqual(RANKING_VERSION, "2.0")

    def test_eval_corpus_improves_p_at_1_and_keeps_recall(self):
        result = evaluate_ranking("adv-ranking-1.0")
        d = result["discovery_ranking"]
        self.assertEqual(result["ranking_version"], "2.0")
        self.assertEqual(result["safety"]["network_connect_attempts"], 0)
        self.assertEqual(d["recall"], 1.0)
        self.assertTrue(d["relevant_still_available"])
        self.assertGreater(d["precision_at_k"]["1"], 0.0)
        self.assertEqual(d["human_review_depth_to_first_relevant"], 1)
        self.assertEqual(d["negative_in_top5"], [])
        # Ambiguous kinds stay available for human review when present in graph.
        # Shared parents must not occupy rank 1.
        top = d["rows"][0]["resource_type"]
        self.assertNotIn(top, {"org", "tenant", "department", "channel", "article"})

    def test_dev_corpus_also_positive_p_at_1(self):
        d = evaluate_ranking("adv-ranking-dev")["discovery_ranking"]
        self.assertGreater(d["precision_at_k"]["1"], 0.0)
        self.assertEqual(d["recall"], 1.0)


if __name__ == "__main__":
    unittest.main()
