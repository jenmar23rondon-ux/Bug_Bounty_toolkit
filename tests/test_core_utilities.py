import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from bugbounty_toolkit.core.checks import render_checklist
from bugbounty_toolkit.core.records import ProgramPaths, RecordStore
from bugbounty_toolkit.core.runner import run_tool
from bugbounty_toolkit.fuzzing.wordlist_loader import preview_wordlist, require_wordlist
from bugbounty_toolkit.requests_engine.parameters import load_parameter_names, parse_parameter_items, with_parameter
from bugbounty_toolkit.utils.logger import setup_logger


class CoreUtilityTests(unittest.TestCase):
    def test_parameter_parsing_preserves_values_and_replaces_only_named_key(self):
        self.assertEqual(parse_parameter_items([" q =a=b", "blank"]), {"q": "a=b", "blank": ""})
        with self.assertRaisesRegex(ValueError, "cannot be empty"):
            parse_parameter_items([" =value"])
        self.assertEqual(
            with_parameter("https://example.test/?q=old&x=1&q=again#frag", "q", "new value"),
            "https://example.test/?x=1&q=new+value#frag",
        )

    def test_parameter_file_ignores_comments_deduplicates_and_requires_file(self):
        with tempfile.TemporaryDirectory() as directory:
            file = Path(directory) / "params.txt"
            file.write_text("# comment\nq=one\nq:two\nname\n", encoding="utf-8")
            self.assertEqual(load_parameter_names(file), ["q", "name"])
            with self.assertRaises(FileNotFoundError):
                load_parameter_names(Path(directory) / "missing")

    def test_wordlist_validation_and_preview(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            wordlist = root / "words.txt"
            wordlist.write_text("# comment\n\nadmin\napi\n", encoding="utf-8")
            self.assertEqual(preview_wordlist(wordlist, 1), ["admin"])
            with self.assertRaisesRegex(ValueError, "not a file"):
                require_wordlist(root)
            with self.assertRaisesRegex(FileNotFoundError, "Wordlist not found"):
                require_wordlist(root / "missing")

    def test_external_runner_records_success_and_failure_without_shell(self):
        with tempfile.TemporaryDirectory() as directory:
            store = RecordStore(ProgramPaths(Path(directory), "lab"))
            with (
                patch("bugbounty_toolkit.core.runner.tool_exists", return_value=True),
                patch(
                    "bugbounty_toolkit.core.runner.subprocess.run", return_value=SimpleNamespace(returncode=0)
                ) as run,
            ):
                output = run_tool(store, "fixture", "example.test", ["fixture", "literal value"])
            self.assertTrue(output.is_file())
            self.assertEqual(store.runs()[0]["return_code"], 0)
            self.assertEqual(run.call_args.args[0], ["fixture", "literal value"])
            with patch("bugbounty_toolkit.core.runner.tool_exists", return_value=False):
                with self.assertRaisesRegex(RuntimeError, "not found"):
                    run_tool(store, "fixture", None, ["missing-tool"])
            with (
                patch("bugbounty_toolkit.core.runner.tool_exists", return_value=True),
                patch("bugbounty_toolkit.core.runner.subprocess.run", return_value=SimpleNamespace(returncode=2)),
            ):
                with self.assertRaisesRegex(RuntimeError, "exited with code 2"):
                    run_tool(store, "fixture", None, ["fixture"])
            self.assertEqual(len(store.runs()), 2)
            store.close()

    def test_logger_writes_file_and_replaces_existing_handlers(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "nested" / "toolkit.log"
            logger = setup_logger(path, verbose=True)
            logger.debug("private local diagnostic")
            self.assertIn("private local diagnostic", path.read_text(encoding="utf-8"))
            first_handlers = tuple(logger.handlers)
            setup_logger()
            self.assertFalse(any(handler in logger.handlers for handler in first_handlers))

    def test_checklist_contains_topics_and_review_items(self):
        checklist = render_checklist()
        self.assertIn("# Vulnerability Review Checklist", checklist)
        self.assertIn("## IDOR / Object Authorization", checklist)
        self.assertIn("- [ ]", checklist)


if __name__ == "__main__":
    unittest.main()
