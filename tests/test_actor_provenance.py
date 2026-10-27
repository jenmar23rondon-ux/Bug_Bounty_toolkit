"""Adversarial offline provenance tests. No access checks are performed."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import asdict, replace
import json
from pathlib import Path
import socket
import tempfile
import unittest
from unittest.mock import patch

from bugbounty_toolkit.analysis.actor_provenance import (
    associate_actors,
    load_manifest,
    pwnfox_color,
    validate_manifest,
)
from labs.actor_provenance_eval.corpus import KEY, PROGRAM, corpus
from labs.actor_provenance_eval.evaluate import evaluate


class ActorProvenanceTests(unittest.TestCase):
    def test_corpus_metrics_and_no_network(self) -> None:
        with patch.object(socket.socket, "connect", side_effect=AssertionError("network prohibited")):
            before = evaluate(baseline=True)
            after = evaluate()
        self.assertEqual(after["association_accuracy"], 1)
        self.assertEqual(after["incorrect_associations"], 0)
        self.assertEqual(after["secrets_exposed"], 0)
        self.assertNotEqual(after["association_accuracy"], before["association_accuracy"])
        self.assertEqual(after["correct_abstentions"], 7)

    def test_deterministic_immutable_and_private(self) -> None:
        records, manifest, _ = corpus()
        snapshot = [asdict(r) for r in records], deepcopy(manifest)
        first = associate_actors(records, manifest, program=PROGRAM, key=KEY)
        self.assertEqual(first, associate_actors(reversed(records), manifest, program=PROGRAM, key=KEY))
        self.assertEqual(snapshot, ([asdict(r) for r in records], manifest))
        encoded = json.dumps(first)
        for private in ("CANARY", "capture.har", "synthetic.invalid", records[0].session_fingerprint):
            self.assertNotIn(str(private), encoded)
        self.assertTrue(first["different_capture_times"])
        self.assertEqual(sum(r["session_change_observed"] for r in first["captures"]), 1)
        self.assertTrue(all(c["resolution"] == "human_review_required" for c in first["conflicts"]))

    def test_program_isolation(self) -> None:
        records, manifest, _ = corpus()
        first = associate_actors(records, manifest, program=PROGRAM, key=KEY)
        with self.assertRaises(ValueError):
            associate_actors(records, manifest, program="other", key=KEY)
        manifest["program"] = "other"
        second = associate_actors(records, manifest, program="other", key=KEY)
        for field in ("capture_ref", "session_ref", "account_ref", "source_ref", "evidence_ref"):
            a = {r[field] for r in first["captures"] if r[field]}
            b = {r[field] for r in second["captures"] if r[field]}
            self.assertFalse(a & b)

    def test_color_cookie_browser_do_not_assert_identity(self) -> None:
        records, manifest, _ = corpus()
        for row in manifest["labels"]:
            row.pop("account", None)
            row.pop("declared_by_human", None)
            row["browser"] = "same browser"
            row["pwnfox_color"] = "red"
        manifest["distinct_accounts"] = []
        result = associate_actors(records, manifest, program=PROGRAM, key=KEY)
        self.assertTrue(all(r["account_ref"] is None for r in result["captures"]))
        self.assertEqual(result["distinct_accounts"], [])
        self.assertEqual(len({r["browser_ref"] for r in result["captures"]}), 1)

    def test_distinct_accounts_requires_explicit_pair(self) -> None:
        records, manifest, _ = corpus()
        # Remove the contradictory label, retain two consistent human accounts.
        manifest["labels"] = manifest["labels"][:2]
        result = associate_actors(records[:2], manifest, program=PROGRAM, key=KEY)
        self.assertEqual(len(result["distinct_accounts"]), 1)
        manifest["distinct_accounts"] = []
        result = associate_actors(records[:2], manifest, program=PROGRAM, key=KEY)
        self.assertEqual(result["distinct_accounts"], [])

    def test_strict_validation_no_echo(self) -> None:
        _, manifest, _ = corpus()
        changes: list[dict[str, object]] = [
            {"token": "private"},
            {"label": []},
            {"label": "invalid"},
            {"account": "private", "declared_by_human": False},
            {"account": "a", "label": "unknown"},
            {"browser": 42},
            {"pwnfox_color": []},
            {"pwnfox_color": "CANARY-secret"},
            {"locator": ""},
            {"declared_by_human": 1},
        ]
        for change in changes:
            candidate = deepcopy(manifest)
            candidate["labels"][0].update(change)
            with self.subTest(change=list(change)), self.assertRaises(ValueError) as error:
                validate_manifest(candidate)
            self.assertNotIn("CANARY-secret", str(error.exception))
        for pair in (["a", "a"], ["a", "missing"], [[], "a"]):
            candidate = deepcopy(manifest)
            candidate["distinct_accounts"] = [pair]
            with self.assertRaises(ValueError):
                validate_manifest(candidate)

    def test_missing_ambiguous_and_raw_fingerprints_fail_closed(self) -> None:
        records, manifest, _ = corpus()
        for candidate in (
            records[:-1],
            records + [records[0]],
            [replace(records[0], evidence_id="replaced-capture")] + records[1:],
            [replace(records[0], session_fingerprint="plaintext")] + records[1:],
        ):
            with self.assertRaises(ValueError):
                associate_actors(candidate, manifest, program=PROGRAM, key=KEY)
        with self.assertRaises(ValueError):
            associate_actors(records, manifest, program=PROGRAM, key=b"short")

    def test_local_manifest_bounds_duplicates(self) -> None:
        _, manifest, _ = corpus()
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "manifest.json"
            path.write_text(json.dumps(manifest))
            self.assertEqual(load_manifest(path), manifest)
            for raw in ('{"schema":1,"schema":2}', "{bad", "[]", "x" * 1_000_001):
                path.write_text(raw)
                with self.assertRaises(ValueError):
                    load_manifest(path)

    def test_pwnfox_capture_adapter(self) -> None:
        self.assertEqual(pwnfox_color({"request": {"headers": [{"name": "X-PwnFox-Color", "value": "Blue"}]}}), "blue")
        self.assertEqual(pwnfox_color({"X-PwnFox-Color": "red"}), "red")
        self.assertIsNone(pwnfox_color({"Cookie": "private"}))
        self.assertIsNone(pwnfox_color([{"name": "X-PwnFox-Color", "value": "red"}] * 2))
        self.assertIsNone(pwnfox_color(None))


if __name__ == "__main__":
    unittest.main()
