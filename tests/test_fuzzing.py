import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from bugbounty_toolkit.core.records import RecordStore, ProgramPaths
from bugbounty_toolkit.core.scope_validator import ScopeValidator
from bugbounty_toolkit.fuzzing.ffuf_runner import FfufOptions, FfufRunner
from bugbounty_toolkit.fuzzing.results_parser import (
    build_authorization_followups,
    classify_ffuf_results,
    parse_ffuf_results,
)
from bugbounty_toolkit.utils.exceptions import ExternalToolError


class FuzzingTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.store = RecordStore(ProgramPaths(self.root, "lab"))
        self.store.paths.scope_file.write_text("https://example.com\n!https://example.com/admin\n")
        self.runner = FfufRunner(self.store, ScopeValidator(self.store.paths.scope_file))
        self.wordlist = self.root / "words.txt"
        self.wordlist.write_text("api\nsearch\n")

    def tearDown(self):
        self.store.close()
        self.temp.cleanup()

    def test_parser_deduplicates_identical_results(self):
        path = self.root / "results.json"
        result = {"url": "https://example.com/api", "status": 200, "length": 100, "words": 10, "lines": 2}
        path.write_text(json.dumps({"results": [result, result, {**result, "url": "https://example.com/search"}]}))
        self.assertEqual(len(parse_ffuf_results(path)), 2)

    def test_parser_rejects_malformed_top_level_and_skips_malformed_rows(self):
        path = self.root / "results.json"
        path.write_text(
            json.dumps({"results": [None, {"url": 12, "status": 200}, {"url": "https://example.com/a", "status": 200}]})
        )
        self.assertEqual(len(parse_ffuf_results(path)), 1)
        path.write_text("[]")
        with self.assertRaisesRegex(ValueError, "results array"):
            parse_ffuf_results(path)

    def test_classification_compares_with_baseline_without_claiming_vulnerability(self):
        baseline = {"status": 200, "length": 100, "words": 10, "lines": 2}
        raw = [
            {"url": "https://example.com/api/orders/123", "status": 200, "length": 110, "words": 10, "lines": 2},
            {"url": "https://example.com/api/orders/456", "status": 200, "length": 400, "words": 35, "lines": 8},
            {"url": "https://example.com/api/missing", "status": 404, "length": 100, "words": 10, "lines": 2},
            {"url": "https://example.com/api/blocked", "status": 429, "length": 50, "words": 4, "lines": 1},
        ]
        results = classify_ffuf_results(raw, baseline)
        self.assertEqual(
            [item["classification"] for item in results],
            ["generic_response", "endpoint_candidate", "not_found", "rate_limited"],
        )
        self.assertNotIn("confirmed", json.dumps(results))
        followups = build_authorization_followups(results)
        self.assertEqual(followups[0]["route_template"], "/api/orders/{id}")
        self.assertFalse(followups[0]["vulnerability_confirmed"])
        self.assertEqual(followups[0]["resource_privacy"], "unknown")

    def test_missing_baseline_is_inconclusive_and_does_not_emit_access_followup(self):
        result = {"url": "https://example.com/api/orders/123", "status": 200, "length": 400}
        classified = classify_ffuf_results([result], None)
        self.assertEqual(classified[0]["classification"], "inconclusive")
        self.assertEqual(build_authorization_followups(classified), [])

    def test_baseline_detects_wildcard_404_and_authentication_routes(self):
        wildcard = classify_ffuf_results(
            [{"url": "https://example.com/random", "status": 404, "length": 20, "words": 3, "lines": 1}],
            {"status": 404, "length": 20, "words": 3, "lines": 1},
        )
        login = classify_ffuf_results(
            [{"url": "https://example.com/login", "status": 200, "length": 500, "words": 50, "lines": 20}],
            {"status": 200, "length": 20, "words": 3, "lines": 1},
        )
        login_redirect = classify_ffuf_results(
            [
                {
                    "url": "https://example.com/private",
                    "status": 302,
                    "length": 0,
                    "words": 0,
                    "lines": 0,
                    "redirectlocation": "/login",
                }
            ],
            {"status": 404, "length": 20, "words": 3, "lines": 1},
        )
        self.assertEqual(wildcard[0]["classification"], "generic_response")
        self.assertEqual(login[0]["classification"], "authentication_route")
        self.assertEqual(login_redirect[0]["classification"], "authentication_redirect")

    def test_all_generated_destinations_are_checked_before_launch(self):
        self.wordlist.write_text("api\nadmin\n")
        with patch("bugbounty_toolkit.fuzzing.ffuf_runner.subprocess.run") as run, self.assertRaises(ValueError):
            self.runner.run(FfufOptions("https://example.com/FUZZ", self.wordlist))
        run.assert_not_called()

    def test_fuzz_host_and_missing_keyword_are_rejected(self):
        for url in ("https://FUZZ.example.com/api", "https://example.com/api"):
            with self.subTest(url=url), self.assertRaises(ValueError):
                self.runner.validate(FfufOptions(url, self.wordlist))

    def test_runner_writes_json_output_and_explicit_limits(self):
        def fake_ffuf(command, **kwargs):
            output = Path(command[command.index("-o") + 1])
            output.write_text(json.dumps({"results": []}))
            return SimpleNamespace(wait=lambda timeout: 0)

        with (
            patch("bugbounty_toolkit.fuzzing.ffuf_runner.shutil.which", return_value="ffuf"),
            patch("bugbounty_toolkit.fuzzing.ffuf_runner.subprocess.Popen", side_effect=fake_ffuf) as run,
        ):
            output, results = self.runner.run(
                FfufOptions("https://example.com/FUZZ", self.wordlist, threads=2, rate=1, max_entries=1)
            )
        command = run.call_args.args[0]
        self.assertIn("-r=false", command)
        self.assertIn("-recursion=false", command)
        self.assertIn("-rate", command)
        self.assertIn("-maxtime", command)
        self.assertTrue(output.exists())
        self.assertEqual(results, [])
        self.assertEqual(self.store.counts()["runs"], 1)

    def test_runner_builds_capped_unique_input_and_source_hash_metadata(self):
        self.wordlist.write_text("api\nsearch\napi\nadmin\n", encoding="utf-8")
        entries = self.runner.preview_entries(FfufOptions("https://example.com/FUZZ", self.wordlist, max_entries=2))
        self.assertEqual(entries, ("api", "search"))

    def test_baseline_rate_limit_prevents_ffuf_launch(self):
        client = SimpleNamespace(
            send=lambda request: SimpleNamespace(
                status_code=429,
                body_text="slow down",
                body_size=9,
                duration_ms=1,
                headers={"content-type": "text/plain"},
            )
        )
        runner = FfufRunner(self.store, self.runner.scope, client)
        with (
            patch("bugbounty_toolkit.fuzzing.ffuf_runner.shutil.which", return_value="ffuf"),
            patch("bugbounty_toolkit.fuzzing.ffuf_runner.subprocess.Popen") as process,
        ):
            evidence, results = runner.run(FfufOptions("https://example.com/FUZZ", self.wordlist))
        process.assert_not_called()
        self.assertEqual(results, [])
        saved = json.loads(evidence.read_text(encoding="utf-8"))
        self.assertEqual(saved["status"], "stopped_rate_limited_baseline")

    def test_runner_records_baseline_classifications_and_wordlist_fingerprint(self):
        client = SimpleNamespace(
            send=lambda request: SimpleNamespace(
                status_code=404,
                body_text="generic not found",
                body_size=17,
                duration_ms=2,
                headers={"content-type": "text/plain"},
            )
        )
        runner = FfufRunner(self.store, self.runner.scope, client)

        def fake_ffuf(command, **kwargs):
            output = Path(command[command.index("-o") + 1])
            output.write_text(
                json.dumps(
                    {
                        "results": [
                            {
                                "url": "https://example.com/api/orders/123",
                                "status": 200,
                                "length": 90,
                                "words": 12,
                                "lines": 4,
                            }
                        ]
                    }
                )
            )
            return SimpleNamespace(wait=lambda timeout: 0)

        with (
            patch("bugbounty_toolkit.fuzzing.ffuf_runner.shutil.which", return_value="ffuf"),
            patch("bugbounty_toolkit.fuzzing.ffuf_runner.subprocess.Popen", side_effect=fake_ffuf),
        ):
            evidence_path, results = runner.run(FfufOptions("https://example.com/FUZZ", self.wordlist, max_entries=1))
        evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
        self.assertEqual(evidence["baseline"]["status"], 404)
        self.assertRegex(evidence["selected_wordlist_sha256"], r"^[0-9a-f]{64}$")
        self.assertEqual(evidence["limits"]["planned_requests_upper_bound"], 2)
        self.assertEqual(results[0]["classification"], "endpoint_candidate")
        self.assertEqual(evidence["followup_candidates"][0]["route_template"], "/api/orders/{id}")

    def test_supervisor_terminates_ffuf_on_wall_clock_timeout(self):
        class TimedOutProcess:
            stopped = False

            def wait(self, timeout=None):
                if self.stopped:
                    return -15
                raise __import__("subprocess").TimeoutExpired("ffuf", timeout)

            def poll(self):
                return None if not self.stopped else -15

            def terminate(self):
                self.stopped = True

            def kill(self):
                self.stopped = True

        process = TimedOutProcess()
        with patch("bugbounty_toolkit.fuzzing.ffuf_runner.subprocess.Popen", return_value=process):
            with self.assertRaisesRegex(ExternalToolError, "wall-clock limit"):
                self.runner._run_process(["ffuf"], {}, self.root / "timeout.log", 0.01)
        self.assertTrue(process.stopped)
