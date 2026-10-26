import os
import tempfile
import unittest
from pathlib import Path
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
            root = Path(directory)
            fixture = root / "fixture"
            fixture.write_text("#!/bin/sh\nprintf '%s\\n' \"$@\"\n", encoding="utf-8")
            fixture.chmod(0o755)
            allowed = frozenset({"fixture"})
            common = {
                "contact_external": False,
                "allowed_executables": allowed,
                "allowed_path_roots": (root.resolve(),),
                "timeout_seconds": 5.0,
            }
            with patch.dict("os.environ", {"PATH": str(root) + os.pathsep + os.environ.get("PATH", "")}):
                output = run_tool(store, "fixture", "example.test", ["fixture", "literal value"], **common)
                self.assertTrue(output.is_file())
                self.assertIn("literal value", output.read_text(encoding="utf-8"))
                self.assertEqual(store.runs()[0]["return_code"], 0)
                with self.assertRaisesRegex(Exception, "not found|not in the allowlist"):
                    run_tool(store, "missing-tool", None, ["missing-tool"], **common)
                # overwrite fixture to fail
                fixture.write_text("#!/bin/sh\nexit 2\n", encoding="utf-8")
                fixture.chmod(0o755)
                with self.assertRaisesRegex(Exception, "exited with code 2"):
                    run_tool(store, "fixture", None, [str(fixture)], **common)
            self.assertGreaterEqual(len(store.runs()), 2)
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
