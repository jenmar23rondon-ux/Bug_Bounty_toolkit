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
    def test_native_access_plan_keeps_credentials_in_a_case_file(self):
        command = runner.build_command(
            {
                "program": "lab",
                "action": "access-check",
                "case_file": "registros/lab/private/case.json",
                "rate": 0.1,
                "max_tests": 3,
            }
        )
        self.assertIn("access-check", command)
        self.assertIn("--case-file=registros/lab/private/case.json", command)
        range_command = runner.build_command(
            {"program": "lab", "action": "access-check", "case_file": "case.json", "range": "1-10"}
        )
        self.assertIn("--range=1-10", range_command)
        bounded_command = runner.build_command(
            {
                "program": "lab",
                "action": "access-check",
                "case_file": "case.json",
                "range": "1-10",
                "max_range": 10,
                "concurrency": 2,
                "min_interval": 0.02,
            }
        )
        self.assertIn("--max-range=10", bounded_command)
        self.assertIn("--concurrency=2", bounded_command)
        self.assertIn("--min-interval=0.02", bounded_command)
        with self.assertRaises(ValueError):
            runner.build_command(
                {
                    "program": "lab",
                    "action": "access-check",
                    "case_file": "case.json",
                    "cookies": ["session=not-in-argv"],
                }
            )
        with self.assertRaises(ValueError):
            runner.build_command({"program": "lab", "action": "access-check"})
        command = runner.build_command(
            {
                "program": "lab",
                "action": "xss",
                "routes": "routes",
                "parameters": "parameters",
                "html_parser": "html5lib",
            }
        )
        self.assertIn("--html-parser=html5lib", command)

    def test_sqli_uses_the_bounded_runner_not_an_external_scanner(self):
        command = runner.build_command(
            {
                "program": "lab",
                "action": "sqli",
                "routes": "routes.txt",
                "parameters": "parameters.txt",
                "max_tests": 6,
                "rate": 0.1,
            }
        )
        self.assertIn("sqli", command)
        self.assertIn("--max-tests=6", command)
        self.assertIn("--rate=0.1", command)
        with self.assertRaises(ValueError):
            runner.build_command({"program": "lab", "action": "sqlmap", "url": "https://example.com"})

        budgeted = runner.build_command(
            {
                "program": "lab",
                "action": "request",
                "url": "https://example.com/health",
                "run_max_requests": 2,
                "run_max_seconds": 15.5,
                "run_max_concurrency": 1,
            }
        )
        self.assertIn("--run-max-requests=2", budgeted)
        self.assertIn("--run-max-seconds=15.5", budgeted)
        self.assertIn("--run-max-concurrency=1", budgeted)

    def test_topic_plans_support_opt_in_flags_for_all_new_workflows(self):
        xss = runner.build_command(
            {"program": "lab", "action": "xss", "routes": "routes", "parameters": "params", "confirm_exec": True}
        )
        self.assertIn("--confirm-exec", xss)
        sqli = runner.build_command(
            {"program": "lab", "action": "sqli", "routes": "routes", "parameters": "params", "deep": True}
        )
        self.assertIn("--deep", sqli)
        cors = runner.build_command(
            {"program": "lab", "action": "cors-check", "url": "https://example.com/a", "rate": 0.5}
        )
        self.assertIn("cors-check", cors)
        self.assertIn("--url=https://example.com/a", cors)
        redirect = runner.build_command(
            {"program": "lab", "action": "open-redirect", "url": "https://example.com/login?next=%2F", "param": "next"}
        )
        self.assertIn("open-redirect", redirect)
        self.assertIn("--param=next", redirect)
        with self.assertRaisesRegex(ValueError, "boolean"):
            runner.build_command(
                {"program": "lab", "action": "xss", "routes": "r", "parameters": "p", "confirm_exec": "yes"}
            )

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
        plan = {
            "program": "lab",
            "action": "request",
            "url": "https://example.com",
            "headers": ["X-Example: --help"],
            "data": body,
        }
        command = runner.build_command(plan)
        self.assertIn("--data=" + body, command)
        self.assertIn("--header=X-Example: --help", command)

    def test_failed_preflight_is_not_retried_or_executed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "bugbounty_toolkit").mkdir()
            (root / "bugbounty_toolkit" / "cli.py").touch()
            with patch.object(runner.subprocess, "run", return_value=SimpleNamespace(returncode=1)) as process:
                code = runner.run_plan(
                    {"program": "lab", "action": "request", "url": "https://example.com"}, root, execute=True
                )
            self.assertEqual(code, 1)
            process.assert_called_once()
            self.assertIn("--dry-run", process.call_args.args[0])
