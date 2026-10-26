"""Resilient HAR import: per-entry isolation, strict mode, provenance, no secrets, offline only."""

from __future__ import annotations

import contextlib
import hashlib
import io
import json
import logging
import os
from pathlib import Path
import socket
import sys
import tempfile
import unittest
from unittest.mock import patch

from bugbounty_toolkit.analysis import har_import
from bugbounty_toolkit.analysis.har_import import (
    ENTRY_REASONS,
    FATAL_REASONS,
    HarImportError,
    import_har,
    json_depth,
)
from bugbounty_toolkit.analysis.object_handoff import propose_object_handoff
from bugbounty_toolkit.analysis.object_relationships import (
    build_object_graph,
    discover_to_file,
    indexed_capture_sources,
)

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "examples" / "har-recovery"
KEY = hashlib.sha256(b"har-recovery-tests").digest()
PROGRAM = "har-recovery"
MARK = "SYNTH-SECRET"
PII = "synthetic.person@example.test"
LIMITS = {"max_bytes": 32 * 1024 * 1024, "max_message_bytes": 1_000_000}

# fixture -> (entries, accepted indices, {index: reason})
EXPECTED = {
    "valid": (5, [0, 1, 2, 3, 4], {}),
    "malformed_among_valid": (5, [0, 1, 3, 4], {2: "entry_not_object"}),
    "incomplete_requests": (
        6,
        [0, 5],
        {1: "url_invalid", 2: "method_invalid", 3: "request_missing", 4: "request_body_malformed"},
    ),
    "incomplete_responses": (
        7,
        [0, 6],
        {
            1: "response_missing",
            2: "body_json_invalid",
            3: "response_base64_invalid",
            4: "unsupported_content_encoding",
            5: "response_content_malformed",
        },
    ),
    "deep_json": (4, [0, 3], {1: "body_json_too_deep", 2: "entry_too_deep"}),
    "duplicates": (4, [0, 1, 2, 3], {}),
    "synthetic_secrets": (4, [1, 2, 3], {0: "url_embedded_credentials"}),
    "adversarial_mixing": (
        5,
        [4],
        {0: "response_missing", 1: "request_missing", 2: "duplicate_json_keys", 3: "response_missing"},
    ),
}
FATAL = {
    "invalid_truncated_file": "json_invalid",
    "invalid_no_entries": "log_entries_missing",
    "invalid_empty_entries": "entries_empty",
    "invalid_duplicate_log": "duplicate_json_keys",
    "invalid_all_entries_bad": "no_valid_entries",
    "invalid_deep_document": "json_too_deep",
    "invalid_not_utf8": "not_utf8",
    "over_count": "entries_over_limit",
}


def fixture(name: str) -> Path:
    return FIXTURES / f"{name}.har"


@contextlib.contextmanager
def no_network():
    def blocked(*_a, **_k):
        raise AssertionError("network attempted during offline HAR import")

    with (
        patch.object(socket.socket, "connect", blocked),
        patch.object(socket.socket, "connect_ex", blocked),
        patch("socket.create_connection", blocked),
        patch("socket.getaddrinfo", blocked),
        patch("urllib.request.urlopen", blocked),
    ):
        yield


class HarImportUnitTests(unittest.TestCase):
    def test_fixtures_are_reproducible(self):
        builder = FIXTURES / "build_fixtures.py"
        with tempfile.TemporaryDirectory() as tmp:
            namespace: dict = {"__name__": "fixtures", "__file__": str(Path(tmp) / "build_fixtures.py")}
            exec(compile(builder.read_text(encoding="utf-8"), str(builder), "exec"), namespace)
            namespace["main"]()
            for path in sorted(FIXTURES.glob("*.har")):
                self.assertEqual((Path(tmp) / path.name).read_bytes(), path.read_bytes(), path.name)

    def test_partial_recovery_per_fixture(self):
        with no_network():
            for name, (total, accepted, rejected) in EXPECTED.items():
                with self.subTest(name):
                    result = import_har(fixture(name).read_bytes(), **LIMITS)
                    summary = result.summary()
                    self.assertEqual(summary["entries_total"], total)
                    self.assertEqual([s.locator for s in result.accepted], [f"/log/entries[{i}]" for i in accepted])
                    self.assertEqual({r["index"]: r["reason"] for r in summary["rejected_entries"]}, rejected)
                    self.assertEqual(summary["accepted"] + summary["rejected"], total)
                    self.assertFalse(summary["truncated"])
                    self.assertTrue(set(summary["reasons"]) <= set(ENTRY_REASONS))

    def test_strict_rejects_any_invalid_entry_and_accepts_clean_files(self):
        for name, (_, _, rejected) in EXPECTED.items():
            with self.subTest(name):
                data = fixture(name).read_bytes()
                if rejected:
                    with self.assertRaises(HarImportError) as ctx:
                        import_har(data, strict=True, **LIMITS)
                    self.assertEqual(ctx.exception.reason, "strict_entry_rejected")
                else:
                    self.assertEqual(import_har(data, strict=True, **LIMITS).summary()["mode"], "strict")

    def test_file_fatal_errors_in_both_modes(self):
        for name, reason in FATAL.items():
            for strict in (False, True):
                with self.subTest(name, strict=strict):
                    with self.assertRaises(HarImportError) as ctx:
                        import_har(fixture(name).read_bytes(), strict=strict, **LIMITS)
                    expected = "strict_entry_rejected" if strict and reason == "no_valid_entries" else reason
                    self.assertEqual(ctx.exception.reason, expected)
                    self.assertIn(ctx.exception.reason, FATAL_REASONS)
                    self.assertNotIn(MARK, str(ctx.exception))

    def test_oversized_file_and_entry(self):
        data = fixture("valid").read_bytes()
        with self.assertRaises(HarImportError) as ctx:
            import_har(data, max_bytes=len(data) - 1, max_message_bytes=1_000_000)
        self.assertEqual(ctx.exception.reason, "file_too_large")
        doc = json.loads(data)
        doc["log"]["entries"][1]["response"]["content"]["text"] = json.dumps({"id": 1, "pad": "x" * 2048})
        result = import_har(json.dumps(doc).encode(), max_bytes=1 << 20, max_message_bytes=1024)
        self.assertEqual(result.summary()["rejected_entries"], [{"index": 1, "reason": "message_too_large"}])
        doc["log"]["entries"] = doc["log"]["entries"][:1] * (har_import.MAX_HAR_ENTRIES_DECLARED + 1)
        with self.assertRaises(HarImportError) as ctx:
            import_har(json.dumps(doc).encode(), allow_truncate=True, **LIMITS)
        self.assertEqual(ctx.exception.reason, "entries_over_hard_limit")

    def test_over_count_is_fatal_unless_truncation_is_explicit(self):
        data = fixture("over_count").read_bytes()
        result = import_har(data, allow_truncate=True, **LIMITS)
        summary = result.summary()
        self.assertTrue(summary["truncated"])
        self.assertEqual((summary["accepted"], summary["rejected"]), (32, 8))
        self.assertEqual(summary["reasons"], {"over_entry_limit": 8})
        self.assertEqual(result.accepted[-1].locator, "/log/entries[31]")
        with self.assertRaises(ValueError):
            import_har(data, strict=True, allow_truncate=True, **LIMITS)

    def test_never_cross_pairs_request_and_response(self):
        for name in EXPECTED:
            doc = json.loads(fixture(name).read_text(encoding="utf-8"))
            for source in import_har(fixture(name).read_bytes(), **LIMITS).accepted:
                index = int(source.locator.split("[")[1].rstrip("]"))
                entry = doc["log"]["entries"][index]
                self.assertEqual(source.url, entry["request"]["url"])
                self.assertEqual(source.response_body, entry["response"]["content"]["text"])
                self.assertEqual(source.status_code, entry["response"]["status"])
        accepted = import_har(fixture("adversarial_mixing").read_bytes(), **LIMITS).accepted
        self.assertEqual([s.url for s in accepted], ["https://api.example.test/v1/orders/8005"])
        self.assertNotIn("8999", accepted[0].response_body)

    def test_recovered_entries_are_individually_strict_valid(self):
        """Partial mode never accepts an entry that strict mode would reject on its own."""
        for name in EXPECTED:
            doc = json.loads(fixture(name).read_text(encoding="utf-8"))
            for source in import_har(fixture(name).read_bytes(), **LIMITS).accepted:
                index = int(source.locator.split("[")[1].rstrip("]"))
                single = json.dumps({"log": {"entries": [doc["log"]["entries"][index]]}}).encode()
                import_har(single, strict=True, **LIMITS)

    def test_duplicates_kept_with_distinct_locators_and_counted(self):
        summary = import_har(fixture("duplicates").read_bytes(), **LIMITS).summary()
        self.assertEqual(summary["duplicate_entries"], 2)

    def test_json_depth_ignores_brackets_inside_strings(self):
        self.assertEqual(json_depth('{"a": "[[[[{{{{", "b": [1, {"c": "\\"]]]"}]}'), 3)
        self.assertEqual(json_depth("[]"), 1)
        self.assertEqual(json_depth('"plain"'), 0)

    def test_remaining_entry_reasons(self):
        base = json.loads(fixture("valid").read_text(encoding="utf-8"))["log"]["entries"][0]

        def reason(mutate):
            entry = json.loads(json.dumps(base))
            mutate(entry)
            return har_import.entry_reason(entry, 0, 1_000_000)[0]

        self.assertEqual(reason(lambda e: e["request"].update(url="ftp://api.example.test/x")), "url_invalid")
        self.assertEqual(reason(lambda e: e["request"].update(url="https://api.example.test:99999/x")), "url_invalid")
        self.assertEqual(
            reason(lambda e: e["request"].update(url="https://a.test/" + "x" * 9000)), "url_structural_limit"
        )
        self.assertEqual(
            reason(lambda e: e["request"].update(headers=[{"name": f"h{i}", "value": "v"} for i in range(300)])),
            "headers_limit",
        )
        wide = {"items": [{"id": i} for i in range(5000)]}
        self.assertEqual(
            reason(lambda e: e["response"]["content"].update(text=json.dumps(wide))), "body_json_structure_limit"
        )
        self.assertIsNone(
            reason(lambda e: e["response"]["content"].update(text="plain text body", mimeType="text/plain"))
        )


class HarPipelineTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def graph(self, names, **options):
        with no_network():
            return build_object_graph(PROGRAM, [fixture(n) for n in names], KEY, authorized=True, **options)

    def test_graph_reports_capture_import_and_original_locators(self):
        graph = self.graph(["malformed_among_valid", "incomplete_responses"])
        ci = graph["capture_import"]
        self.assertEqual((ci["mode"], ci["accepted"], ci["rejected"], ci["truncated"]), ("partial", 6, 6, False))
        self.assertEqual(ci["network_validation"], "none")
        self.assertEqual(graph["network_requests_sent"], 0)
        self.assertEqual(graph["vulnerabilities_confirmed"], 0)
        locators = {p["locator"] for o in graph["observations"] for p in o["provenance"]}
        self.assertEqual(locators, {f"/log/entries[{i}]" for i in (0, 1, 3, 4, 6)})
        self.assertEqual(len(ci["sources"]), 2)
        self.assertEqual({s["id"] for s in graph["sources"]}, {s["source_ref"] for s in ci["sources"]})

    def test_strict_pipeline_rejects_and_names_only_reason_code(self):
        with self.assertRaises(ValueError) as ctx:
            self.graph(["malformed_among_valid"], strict=True)
        self.assertTrue(str(ctx.exception).endswith("(reason: strict_entry_rejected)"))
        self.assertEqual(self.graph(["valid"], strict=True)["capture_import"]["mode"], "strict")
        with self.assertRaises(ValueError):
            self.graph(["valid"], strict=True, allow_truncate=True)

    def test_clean_files_identical_across_modes(self):
        partial, strict = self.graph(["valid"]), self.graph(["valid"], strict=True)
        for key in ("nodes", "relations", "observations", "sources", "summary"):
            self.assertEqual(partial[key], strict[key])

    def test_deterministic(self):
        names = list(EXPECTED)
        self.assertEqual(self.graph(names), self.graph(names))

    def test_over_count_requires_explicit_truncation(self):
        with self.assertRaises(ValueError) as ctx:
            self.graph(["over_count"])
        self.assertIn("entries_over_limit", str(ctx.exception))
        graph = self.graph(["over_count"], allow_truncate=True)
        self.assertTrue(graph["capture_import"]["truncated"])
        self.assertTrue(graph["capture_import"]["truncate_allowed"])
        self.assertEqual(graph["summary"]["observations"], 32)

    def test_object_reference_overflow_isolated_per_entry(self):
        doc = json.loads(fixture("valid").read_text(encoding="utf-8"))
        doc["log"]["entries"][2]["response"]["content"]["text"] = json.dumps({"data": [{"id": n} for n in range(100)]})
        path = self.root / "overflow.har"
        path.write_text(json.dumps(doc), encoding="utf-8")
        with no_network():
            graph = build_object_graph(PROGRAM, [path], KEY, authorized=True)
            with self.assertRaises(ValueError):
                build_object_graph(PROGRAM, [path], KEY, authorized=True, strict=True)
        row = graph["capture_import"]["sources"][0]
        self.assertEqual(row["rejected_entries"], [{"index": 2, "reason": "object_reference_limit"}])
        self.assertEqual((row["accepted"], graph["sources"][0]["captures"]), (4, 4))

    def test_handoff_index_follows_graph_mode(self):
        paths = [fixture("malformed_among_valid")]
        with no_network():
            index = indexed_capture_sources(PROGRAM, paths, KEY)
            self.assertEqual(sorted(locator for _, locator in index), [f"/log/entries[{i}]" for i in (0, 1, 3, 4)])
            graph = build_object_graph(PROGRAM, paths, KEY, authorized=True)
            result = propose_object_handoff(
                graph, PROGRAM, KEY, verify_inputs=paths, limit=8, materialize_dir=self.root / "pairs"
            )
        self.assertEqual(result["network_requests_sent"], 0)
        for proposal in result["proposals"]:
            self.assertFalse(proposal.get("confirmed"))

    def test_no_secrets_or_pii_in_graph_errors_logs_or_cli_output(self):
        from bugbounty_toolkit import cli

        names = [*EXPECTED, *FATAL]
        texts = []
        log_stream = io.StringIO()
        handler = logging.StreamHandler(log_stream)
        logging.getLogger().addHandler(handler)
        logging.getLogger().setLevel(logging.DEBUG)
        try:
            texts.append(json.dumps(self.graph(list(EXPECTED))))
            for name in names:
                for extra in ([], ["--strict"], ["--allow-truncate"]):
                    out, err = io.StringIO(), io.StringIO()
                    argv = [
                        "bbtk",
                        "object-discover",
                        PROGRAM,
                        "--input",
                        str(fixture(name)),
                        "--attest-authorized-captures",
                        "--dry-run",
                        *extra,
                    ]
                    with (
                        no_network(),
                        patch.object(sys, "argv", argv),
                        contextlib.redirect_stdout(out),
                        contextlib.redirect_stderr(err),
                    ):
                        try:
                            cli.main()
                        except SystemExit:
                            pass
                    texts += [out.getvalue(), err.getvalue()]
        finally:
            logging.getLogger().removeHandler(handler)
        texts.append(log_stream.getvalue())
        blob = "\n".join(texts)
        self.assertIn("capture_import", blob)
        for needle in (MARK, PII, "user:", "Bearer", "sid="):
            self.assertNotIn(needle, blob)

    def test_cli_flags_and_summary(self):
        from bugbounty_toolkit import cli

        def run(*extra):
            out = io.StringIO()
            argv = ["bbtk", "object-discover", PROGRAM, "--input", str(fixture("incomplete_requests"))]
            argv += ["--attest-authorized-captures", "--dry-run", *extra]
            with no_network(), patch.object(sys, "argv", argv), contextlib.redirect_stdout(out):
                try:
                    cli.main()
                    code = 0
                except SystemExit as exc:
                    code = exc.code
            return code, out.getvalue()

        code, text = run()
        self.assertEqual(code, 0)
        summary = json.loads(text.splitlines()[0])["capture_import"]
        self.assertEqual((summary["accepted"], summary["rejected"]), (2, 4))
        self.assertIn("Partial HAR recovery", text)
        self.assertNotEqual(run("--strict")[0], 0)

    def test_discover_to_file_threads_options(self):
        with no_network():
            graph, _ = discover_to_file(
                PROGRAM,
                [fixture("over_count")],
                self.root / "key.bin",
                self.root / "graph.json",
                authorized=True,
                dry_run=True,
                allow_truncate=True,
            )
        self.assertTrue(graph["capture_import"]["truncated"])
        self.assertFalse(os.path.exists(self.root / "graph.json"))


if __name__ == "__main__":
    unittest.main()
