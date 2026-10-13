import importlib.util
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch


SCRIPT = Path(__file__).resolve().parents[1] / "skills" / "bugbounty-executor" / "scripts" / "run_plan.py"
SPEC = importlib.util.spec_from_file_location("bbtk_skill_plan", SCRIPT)
runner = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(runner)


class SkillPlanTests(unittest.TestCase):
    def test_unsupported_actions_and_options_are_rejected(self):
        for plan in (
            {"program": "lab", "action": "recon", "url": "https://example.com"},
            {"program": "lab", "action": "request", "url": "https://example.com", "automation_allowed": True},
            {"program": "../escape", "action": "request", "url": "https://example.com"},
            {"program": "lab", "action": "request", "url": "https://example.com", "rate": False},
            {"program": "lab", "action": "request", "url": "https://example.com", "raw_request": "captured.txt"},
        ):
            with self.subTest(plan=plan), self.assertRaises(ValueError):
                runner.build_command(plan)

    def test_argument_values_remain_literal(self):
        body = '$(unexpected-command); "quoted"'
        plan = {"program": "lab", "action": "request", "url": "https://example.com", "headers": ["X-Example: --help"], "data": body}
        command = runner.build_command(plan)
        self.assertIn("--data=" + body, command)
        self.assertIn("--header=X-Example: --help", command)

    def test_failed_preflight_is_not_retried_or_executed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "bugbounty_toolkit").mkdir()
            (root / "bugbounty_toolkit" / "cli.py").touch()
            with patch.object(runner.subprocess, "run", return_value=SimpleNamespace(returncode=1)) as process:
                code = runner.run_plan({"program": "lab", "action": "request", "url": "https://example.com"}, root, execute=True)
            self.assertEqual(code, 1)
            process.assert_called_once()
            self.assertIn("--dry-run", process.call_args.args[0])
