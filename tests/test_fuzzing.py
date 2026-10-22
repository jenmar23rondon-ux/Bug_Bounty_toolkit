import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from bugbounty_toolkit.core.records import RecordStore, ProgramPaths
from bugbounty_toolkit.core.scope_validator import ScopeValidator
from bugbounty_toolkit.fuzzing.ffuf_runner import FfufOptions, FfufRunner
from bugbounty_toolkit.fuzzing.results_parser import parse_ffuf_results


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
            return SimpleNamespace(returncode=0)

        with (
            patch("bugbounty_toolkit.fuzzing.ffuf_runner.shutil.which", return_value="ffuf"),
            patch("bugbounty_toolkit.fuzzing.ffuf_runner.subprocess.run", side_effect=fake_ffuf) as run,
        ):
            output, results = self.runner.run(FfufOptions("https://example.com/FUZZ", self.wordlist, threads=2, rate=1))
        command = run.call_args.args[0]
        self.assertIn("-r=false", command)
        self.assertIn("-recursion=false", command)
        self.assertIn("-rate", command)
        self.assertTrue(output.exists())
        self.assertEqual(results, [])
        self.assertEqual(self.store.counts()["runs"], 1)
