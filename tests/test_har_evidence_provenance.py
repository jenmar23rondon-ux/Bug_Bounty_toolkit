import copy
from dataclasses import asdict
import json
from pathlib import Path
import socket
import tempfile
import unittest
from unittest.mock import patch

from bugbounty_toolkit import cli
from bugbounty_toolkit.analysis import evidence_engine
from bugbounty_toolkit.analysis.evidence_engine import correlations_from_bundle, import_evidence
from bugbounty_toolkit.analysis.har_import import ENTRY_REASONS
from bugbounty_toolkit.analysis.har_provenance import (
    CAPTURE_IMPORT_SCHEMA,
    entry_digest,
    locator_index,
    validate_capture_provenance,
    verify_capture_sources,
)
from bugbounty_toolkit.core.redaction import redact_text
from labs.har_provenance_eval.evaluate import evaluate
from labs.har_provenance_eval.fixtures import CANARY, entry, fixtures, har, over_limit_entries

SALT = b"\x01" * 32


class HarEvidenceProvenanceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.fixtures = fixtures()

    def tearDown(self):
        self.temp.cleanup()

    def path(self, name, data=None):
        path = self.root / f"{name}.har"
        path.write_bytes(self.fixtures[name]["data"] if data is None else data)
        return path

    def summary(self, bundle, position=0):
        return bundle["inputs"][position]["capture_import"]

    def test_compat_records_are_identical_to_the_historical_importer(self):
        for name, spec in self.fixtures.items():
            with self.subTest(name=name):
                path = self.path(name)
                with patch.object(evidence_engine.secrets, "token_bytes", return_value=SALT):
                    bundle = import_evidence([path], "har")
                legacy = evidence_engine.deduplicate(
                    evidence_engine._har(path, json.loads(spec["data"]), SALT)  # noqa: SLF001
                )
                self.assertEqual(bundle["records"], json.loads(json.dumps([asdict(r) for r in legacy])))
                self.assertEqual(bundle["summary"]["records_parsed"], self.summary(bundle)["records_emitted"])
                self.assertEqual(bundle["schema_version"], "1.1")

    def test_summary_reports_exact_reasons_counts_and_indices(self):
        for name, spec in self.fixtures.items():
            with self.subTest(name=name):
                summary = self.summary(import_evidence([self.path(name)], "har"))
                reported = {row["index"]: row["reason"] for row in summary["rejected_entries"]}
                self.assertEqual(reported, spec["rejected"])
                self.assertEqual(summary["duplicate_entries"], spec.get("duplicates", 0))
                self.assertEqual(summary["schema"], CAPTURE_IMPORT_SCHEMA)
                self.assertEqual(summary["entries_accepted"] + summary["entries_rejected"], summary["entries_declared"])
                self.assertTrue(set(reported) <= set(ENTRY_REASONS) | set(reported))

    def test_partial_mode_emits_only_valid_entries_with_original_locators(self):
        path = self.path("non_consecutive_locators")
        bundle = import_evidence([path], "har", "partial")
        summary = self.summary(bundle)
        self.assertEqual(summary["emitted_entry_indices"], [1, 4, 6])
        locators = sorted(p["locator"] for r in bundle["records"] for p in r["provenance"])
        self.assertEqual(locators, ["/log/entries[1]", "/log/entries[4]", "/log/entries[6]"])
        self.assertFalse(any(row["emitted_as_record"] for row in summary["rejected_entries"]))
        self.assertTrue(validate_capture_provenance(bundle)["valid"])

    def test_compat_flags_legacy_emitted_invalid_entries(self):
        bundle = import_evidence([self.path("incomplete_request")], "har")
        row = self.summary(bundle)["rejected_entries"][0]
        self.assertEqual(row, {"index": 0, "reason": "request_missing", "emitted_as_record": True})
        self.assertTrue(validate_capture_provenance(bundle)["valid"])

    def test_strict_mode_rejects_any_invalid_entry_and_accepts_clean_files(self):
        with self.assertRaisesRegex(ValueError, "strict_entry_rejected"):
            import_evidence([self.path("partial")], "har", "strict")
        bundle = import_evidence([self.path("valid")], "har", "strict")
        self.assertEqual(self.summary(bundle)["mode"], "strict")
        with self.assertRaisesRegex(ValueError, "Unsupported HAR import mode"):
            import_evidence([self.path("valid")], "har", "lenient")

    def test_duplicate_json_keys_never_pair_request_with_another_response(self):
        bundle = import_evidence([self.path("duplicate_json_keys")], "har", "partial")
        self.assertEqual(self.summary(bundle)["rejected_entries"][0]["reason"], "duplicate_json_keys")
        self.assertEqual(self.summary(bundle)["emitted_entry_indices"], [0])
        container = b'{"log": {"entries": [], "entries": ' + self.fixtures["valid"]["data"][20:-1] + b"}"
        path = self.path("container", container)
        with self.assertRaisesRegex(ValueError, "duplicate_json_keys"):
            import_evidence([path], "har", "partial")
        self.assertTrue(self.summary(import_evidence([path], "har"))["container_duplicate_keys"])

    def test_limits_are_unchanged_for_general_import_and_documented_for_resilient_modes(self):
        path = self.path("n33", over_limit_entries(33))
        self.assertEqual(import_evidence([path], "har")["summary"]["records_parsed"], 33)
        self.assertEqual(import_evidence([path], "har", "partial")["summary"]["records_parsed"], 33)
        big = self.path("n4097", over_limit_entries(4097))
        self.assertEqual(self.summary(import_evidence([big], "har"))["entries_declared"], 4097)
        with self.assertRaisesRegex(ValueError, "entries_over_hard_limit"):
            import_evidence([big], "har", "partial")
        with patch.object(evidence_engine, "MAX_RECORDS", 2):
            with self.assertRaisesRegex(ValueError, "limit"):
                import_evidence([self.path("valid")], "har")

    def test_no_secrets_bodies_or_urls_in_summaries(self):
        bundle = import_evidence([self.path("synthetic_credentials")], "har")
        text = json.dumps([row["capture_import"] for row in bundle["inputs"]]) + json.dumps(bundle["capture_origin"])
        for forbidden in (CANARY, "example.test", "/me", "Bearer", "token"):
            self.assertNotIn(forbidden, text)
        self.assertNotIn(CANARY, json.dumps(bundle))

    def test_hashes_are_reproducible_and_verifiable_from_the_original_file(self):
        path = self.path("partial")
        first, second = import_evidence([path], "har"), import_evidence([path], "har")
        self.assertEqual(first["inputs"], second["inputs"])
        files = {str(path.resolve()): path}
        self.assertTrue(verify_capture_sources(first, files)["valid"])
        entries = json.loads(self.fixtures["partial"]["data"])["log"]["entries"]
        self.assertEqual(self.summary(first)["entry_sha256"]["3"], entry_digest(entries[3]))
        tampered = bytearray(self.fixtures["partial"]["data"])
        tampered[tampered.index(b"/users/3")] = ord("X")
        path.write_bytes(bytes(tampered))
        self.assertEqual(verify_capture_sources(first, files)["issues"][0]["code"], "source_hash_mismatch")
        forged = copy.deepcopy(first)
        forged["inputs"][0]["capture_import"]["source_sha256"] = __import__("hashlib").sha256(tampered).hexdigest()
        codes = {issue["code"] for issue in verify_capture_sources(forged, files)["issues"]}
        self.assertEqual(codes, {"entry_hash_mismatch"})
        self.assertEqual(verify_capture_sources(first, {})["issues"][0]["code"], "source_unavailable")

    def test_same_file_imported_twice_keeps_both_accounts_valid(self):
        path = self.path("valid")
        bundle = import_evidence([path, path], "har")
        self.assertEqual(bundle["summary"]["records_parsed"], 6)
        self.assertEqual(bundle["summary"]["records_unique"], 3)
        self.assertEqual(bundle["capture_origin"]["records_merged_by_deduplication"], 3)
        self.assertEqual(bundle["capture_origin"]["records_emitted"], 6)
        self.assertTrue(validate_capture_provenance(bundle)["valid"])

    def test_validator_detects_metadata_that_disagrees_with_records(self):
        base = import_evidence([self.path("partial"), self.path("multi_origin")], "har")
        self.assertTrue(validate_capture_provenance(base)["valid"])

        def mutate(fn):
            bundle = copy.deepcopy(base)
            fn(bundle)
            result = validate_capture_provenance(bundle)
            self.assertFalse(result["valid"])
            return {issue["code"] for issue in result["issues"]}

        s = lambda b: b["inputs"][0]["capture_import"]  # noqa: E731
        cases = {
            "accepted_rejected_mismatch": lambda b: s(b).update(entries_accepted=3),
            "reason_tally_mismatch": lambda b: s(b)["rejections_by_reason"].update(entry_not_object=2),
            "records_emitted_mismatch": lambda b: s(b).update(records_emitted=9),
            "record_locators_mismatch": lambda b: s(b)["emitted_entry_indices"].remove(3),
            "emitted_flag_mismatch": lambda b: s(b)["rejected_entries"][1].update(emitted_as_record=False),
            "rejected_entry_emitted": lambda b: s(b).update(mode="partial"),
            "entry_digest_mismatch": lambda b: s(b)["entry_sha256"].pop("0"),
            "duplicate_count_exceeds_accepted": lambda b: s(b).update(duplicate_entries=5),
            "processed_count_mismatch": lambda b: s(b).update(omitted_by_limits=1),
            "rejected_index_invalid": lambda b: s(b)["rejected_entries"][0].update(index=99),
            "rejected_entry_malformed": lambda b: s(b)["rejected_entries"][0].update(reason="made_up"),
            "schema_unknown": lambda b: s(b).update(schema="other/9"),
            "count_malformed": lambda b: s(b).update(entries_declared="4"),
            "mode_unknown": lambda b: s(b).update(mode="lenient"),
            "source_hash_malformed": lambda b: s(b).update(source_sha256="x"),
            "truncation_flag_mismatch": lambda b: s(b).update(truncated=True),
            "records_parsed_mismatch": lambda b: b["inputs"][0].update(records_parsed=1),
            "bundle_records_parsed_mismatch": lambda b: b["summary"].update(records_parsed=1),
            "summary_missing": lambda b: b["inputs"][1].pop("capture_import"),
            "summary_malformed": lambda b: b["inputs"][0].update(capture_import=[]),
            "foreign_locator": lambda b: b["records"][0]["provenance"][0].update(locator="/item[1]"),
            "rejections_malformed": lambda b: s(b).update(rejected_entries={}),
            "emitted_malformed": lambda b: s(b).update(emitted_entry_indices="0"),
            "emitted_index_invalid": lambda b: s(b)["emitted_entry_indices"].append(50),
            "rejected_count_mismatch": lambda b: s(b).update(entries_rejected=1, entries_accepted=3),
            "input_malformed": lambda b: b["inputs"].append("x"),
        }
        for code, fn in cases.items():
            with self.subTest(code=code):
                self.assertIn(code, mutate(fn))
        self.assertEqual(validate_capture_provenance({"inputs": None})["issues"][0]["code"], "bundle_malformed")

    def test_old_bundles_and_non_har_inputs_remain_readable(self):
        bundle = import_evidence([self.path("valid")], "har")
        old = copy.deepcopy(bundle)
        old["inputs"][0].pop("capture_import")
        old.pop("capture_origin")
        self.assertEqual(validate_capture_provenance(old), {"status": "absent", "valid": True, "issues": []})
        old_path = self.root / "old.json"
        old_path.write_text(json.dumps(old), encoding="utf-8")
        self.assertNotIn("capture_provenance", correlations_from_bundle(old_path))
        new_path = self.root / "new.json"
        new_path.write_text(json.dumps(bundle), encoding="utf-8")
        result = correlations_from_bundle(new_path)["capture_provenance"]
        self.assertEqual((result["status"], result["valid"], result["issue_codes"]), ("checked", True, []))
        http = self.root / "req.http"
        http.write_text("GET /a HTTP/1.1\r\nHost: api.example.test\r\n\r\n", encoding="utf-8")
        plain = import_evidence([http], "http")
        self.assertNotIn("capture_import", plain["inputs"][0])
        self.assertNotIn("capture_origin", plain)

    def test_no_network_and_cli_mode_flag(self):
        with patch.object(socket.socket, "connect", side_effect=AssertionError("network")):
            out = self.root / "bundle.json"
            args = cli.build_parser().parse_args(
                [
                    "evidence",
                    "import",
                    "prog",
                    "--input",
                    str(self.path("partial")),
                    "--har-mode",
                    "partial",
                    "--output",
                    str(out),
                ]
            )
            with patch("sys.stdout"):
                args.func(args)
        bundle = json.loads(out.read_text(encoding="utf-8"))
        self.assertEqual(self.summary(bundle)["mode"], "partial")

    def test_redaction_short_circuit_is_exact_and_fast(self):
        self.assertNotIn("abc", redact_text("token=abc"))
        self.assertEqual(redact_text('{"x": "A"}'), '{"x": "A"}')
        self.assertEqual(redact_text("A" * 300_000), "A" * 300_000)
        self.assertIn("[redacted]", redact_text("note: my_access_token: abc def"))

    def test_locator_index_and_huge_entry(self):
        self.assertEqual(locator_index("/log/entries[12]"), 12)
        self.assertIsNone(locator_index("/item[1]"))
        self.assertIsNone(locator_index(None))
        data = har([entry("/big", response='"' + "B" * (1024 * 1024) + '"')])
        bundle = import_evidence([self.path("big", data)], "har")
        self.assertEqual(self.summary(bundle)["records_emitted"], 1)

    def test_lab_evaluation_metrics(self):
        totals = evaluate(frozenset({"huge_entry"}))["totals"]
        self.assertEqual(totals["valid_preserved"], totals["valid_entries"])
        self.assertEqual(totals["invalid_reported_exact"], totals["invalid_entries"])
        self.assertEqual(totals["summary_valid"], totals["imported"])
        self.assertEqual((totals["secret_leaks"], totals["network_attempts"]), (0, 0))


if __name__ == "__main__":
    unittest.main()
