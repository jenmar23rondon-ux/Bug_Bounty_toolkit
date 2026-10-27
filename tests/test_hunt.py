import json
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from bugbounty_toolkit import cli
from bugbounty_toolkit.core.records import ProgramPaths, RecordStore
from bugbounty_toolkit.core.scope_validator import ScopeValidator
from bugbounty_toolkit.core.settings import ExecutorSettings
from bugbounty_toolkit.hunt import HuntTask, allocate_request_budgets, collect_findings, parse_module_selection


class HuntTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.paths = ProgramPaths(self.root / "records", "lab")
        self.store = RecordStore(self.paths)
        self.paths.scope_file.write_text("target.example\n", encoding="utf-8")
        self.scope = ScopeValidator(self.paths.scope_file)
        self.settings = ExecutorSettings(max_tests=100, requests_per_second=1000)
        self.routes = self.root / "routes.txt"
        self.routes.write_text("/search?id=1\n", encoding="utf-8")
        self.params = self.root / "params.txt"
        self.params.write_text("next\n", encoding="utf-8")
        self.case_file = self.root / "case.json"
        self.case_file.write_text("{}\n", encoding="utf-8")

    def tearDown(self):
        try:
            self.store.close()
        except Exception:
            pass
        self.temp.cleanup()

    def args(self, *options):
        return cli.build_parser().parse_args(
            [
                "hunt",
                "lab",
                "--base-url",
                "https://target.example/",
                "--routes",
                str(self.routes),
                "--params",
                str(self.params),
                "--case-file",
                str(self.case_file),
                "--max-tests",
                "40",
                *options,
            ]
        )

    def fresh_store(self):
        return RecordStore(self.paths)

    def invoke(self, args, run_task, run_child=None):
        store = self.fresh_store()
        context = patch.object(cli, "executor_context", return_value=(store, self.settings, self.scope))
        child = patch.object(cli, "_run_hunt_child", side_effect=run_child or (lambda *a, **k: None))
        execute = patch.object(cli, "_execute_hunt_task", side_effect=run_task)
        with context, child, execute, redirect_stdout(StringIO()):
            cli.cmd_hunt(args)

    @staticmethod
    def consume(budget, url, count):
        for _ in range(count):
            lease = budget.acquire(url)
            lease.start()
            lease.finish(True)
            lease.release()

    def make_task_runner(self, calls, rate_limited_module=None):
        def run(_parser, task, allocation, _settings, _ai, budget, _limiter, store, base_url):
            calls.append(task.module)
            count = allocation
            status = "completed"
            if task.module == rate_limited_module:
                count = 1
                status = "rate_limited"
            self.consume(budget, base_url, count)
            row_classification = {
                "cors-check": "SEGURO",
                "ssrf-check": "possible",
                "open-redirect": "VULNERABLE",
                "xss": "possible",
                "sqli": "candidate",
                "access-check": "not_observed",
            }[task.module]
            topic = {"cors-check": "cors", "access-check": "access-control"}.get(task.module, task.module)
            evidence = {
                "type": topic,
                "url": base_url,
                "requests_attempted": count,
                "results": [
                    {"classification": row_classification, "status_code": 429 if status == "rate_limited" else 200}
                ],
            }
            if task.module == "access-check":
                evidence["steps"] = evidence.pop("results")
                evidence["classification"] = row_classification
            if task.module == "open-redirect":
                evidence["parameter"] = task.parameters[0]
            if task.module == "xss":
                evidence["ai_review"] = {
                    "status": "available",
                    "assessment": {"decision": "inconclusive", "summary": "Manual browser review remains necessary."},
                }
            evidence_dir = cli._hunt_evidence_dir(store, task.module)
            evidence_path = cli.write_evidence_json(evidence_dir, evidence, prefix="test")
            return {
                "task_id": task.task_id,
                "module": task.module,
                "status": status,
                "requests_started": count,
                "evidence_paths": [str(evidence_path)],
            }

        return run

    def test_module_selection_and_allocation_are_bounded(self):
        self.assertEqual(parse_module_selection("xss,cors-check", None), ("cors-check", "xss"))
        self.assertEqual(
            parse_module_selection(None, "sqli"),
            ("cors-check", "ssrf-check", "open-redirect", "xss", "access-check"),
        )
        tasks = [
            HuntTask("a", "cors-check", (), 4, 4, 4),
            HuntTask("b", "xss", (), 20, 1, 1),
            HuntTask("c", "sqli", (), 12, 3, 3),
        ]
        allocation = allocate_request_budgets(tasks, 7)
        self.assertLessEqual(sum(allocation.values()), 7)
        self.assertTrue(all(allocation[task.task_id] <= task.estimated_requests for task in tasks))

    def test_finding_report_handles_unavailable_ai_review(self):
        evidence_path = self.root / "xss-evidence.json"
        evidence_path.write_text(
            json.dumps(
                {
                    "type": "xss",
                    "ai_review": "unavailable",
                    "results": [{"classification": "possible", "status_code": 200}],
                }
            ),
            encoding="utf-8",
        )
        findings = collect_findings([{"module": "xss", "evidence_paths": [str(evidence_path)]}])
        self.assertEqual(len(findings), 1)
        self.assertIsNone(findings[0]["ai_decision"])
        self.assertIsNone(findings[0]["ai_reason"])

    def test_full_flow_orders_modules_and_writes_consolidated_reports(self):
        calls = []
        self.invoke(self.args("--ai-review"), self.make_task_runner(calls))
        reports = list(self.paths.reports_dir.glob("*-hunt.json"))
        self.assertEqual(len(reports), 1)
        report = json.loads(reports[0].read_text(encoding="utf-8"))
        self.assertEqual(
            calls,
            ["cors-check", "open-redirect", "xss", "sqli", "access-check"],
            json.dumps(report, indent=2),
        )
        self.assertEqual(
            [item["module"] for item in report["modules"]],
            ["cors-check", "ssrf-check", "open-redirect", "xss", "sqli", "access-check"],
        )
        self.assertEqual({item["module"]: item["status"] for item in report["modules"]}["ssrf-check"], "skipped")
        self.assertLessEqual(report["budget"]["requests_started"], report["budget"]["max_tests"])
        self.assertEqual([item["severity"] for item in report["findings"]], ["high", "high", "medium"])
        self.assertEqual(report["findings"][0]["type"], "open-redirect")
        html = reports[0].with_suffix(".html").read_text(encoding="utf-8")
        self.assertIn("AI second opinion", html)
        self.assertIn("Manual browser review remains necessary.", html)

    def test_rate_limit_stops_its_module_and_later_modules_continue(self):
        calls = []
        args = self.args("--only", "cors-check,xss", "--max-tests", "20")
        self.invoke(args, self.make_task_runner(calls, rate_limited_module="cors-check"))
        self.assertEqual(calls, ["cors-check", "xss"])
        report_path = next(self.paths.reports_dir.glob("*-hunt.json"))
        report = json.loads(report_path.read_text(encoding="utf-8"))
        modules = {item["module"]: item for item in report["modules"]}
        self.assertEqual(modules["cors-check"]["status"], "rate_limited")
        self.assertEqual(modules["xss"]["status"], "completed")

    def test_only_runs_selected_modules(self):
        calls = []
        self.invoke(self.args("--only", "xss"), self.make_task_runner(calls))
        self.assertEqual(calls, ["xss"])
        report_path = next(self.paths.reports_dir.glob("*-hunt.json"))
        report = json.loads(report_path.read_text(encoding="utf-8"))
        modules = {item["module"]: item for item in report["modules"]}
        self.assertEqual(modules["xss"]["status"], "completed")
        self.assertEqual(modules["cors-check"]["status"], "skipped")

    def test_hunt_propagates_contextual_xss_and_union_sqli_opt_ins(self):
        args = self.args("--only", "xss,sqli", "--confirm-exec", "--deep", "--union", "--union-max-columns", "3")
        tasks, _, _ = cli._hunt_tasks(args, self.scope)
        by_module = {task.module: task for task in tasks}
        self.assertIn("--confirm-exec", by_module["xss"].argv)
        self.assertIn("--deep", by_module["sqli"].argv)
        self.assertIn("--union", by_module["sqli"].argv)
        self.assertIn("3", by_module["sqli"].argv)
        self.assertEqual(by_module["sqli"].minimum_requests, 12)

    def test_hunt_confirmable_modules_exclude_csrf_and_ssrf_needs_explicit_inputs(self):
        from bugbounty_toolkit.hunt import MODULE_ORDER

        self.assertNotIn("csrf-audit", MODULE_ORDER)
        args = self.args(
            "--only",
            "ssrf-check",
            "--ssrf-url",
            "https://target.example/fetch?url=x",
            "--ssrf-param",
            "url",
        )
        tasks, static, _ = cli._hunt_tasks(args, self.scope)
        self.assertEqual([task.module for task in tasks], ["ssrf-check"])
        self.assertEqual([task.estimated_requests for task in tasks], [6])
        self.assertNotIn("ssrf-check", static)
        skipped = self.args("--only", "ssrf-check")
        _, static_skip, _ = cli._hunt_tasks(skipped, self.scope)
        self.assertEqual(static_skip["ssrf-check"]["status"], "skipped")

    def test_global_request_cap_is_never_exceeded(self):
        calls = []
        self.invoke(
            self.args("--only", "xss", "--max-tests", "2"),
            self.make_task_runner(calls),
        )
        report = json.loads(next(self.paths.reports_dir.glob("*-hunt.json")).read_text(encoding="utf-8"))
        self.assertEqual(calls, ["xss"])
        self.assertEqual(report["budget"]["requests_started"], 2)
        self.assertEqual(report["budget"]["remaining"], 0)

    def test_module_error_is_recorded_and_later_module_runs(self):
        calls = []
        runner = self.make_task_runner(calls)

        def fail_cors(_parser, task, *_args):
            if task.module == "cors-check":
                calls.append(task.module)
                raise RuntimeError("simulated module failure")
            return runner(_parser, task, *_args)

        self.invoke(self.args("--only", "cors-check,xss"), fail_cors)
        self.assertEqual(calls, ["cors-check", "xss"])
        report = json.loads(next(self.paths.reports_dir.glob("*-hunt.json")).read_text(encoding="utf-8"))
        modules = {item["module"]: item for item in report["modules"]}
        self.assertEqual(modules["cors-check"]["status"], "error")
        self.assertEqual(modules["xss"]["status"], "completed")

    def test_dry_run_validates_without_running_any_task(self):
        args = self.args("--only", "cors-check,xss", "--dry-run", "--max-tests", "8")
        store = self.fresh_store()
        client = Mock()
        with (
            patch.object(cli, "executor_context", return_value=(store, self.settings, self.scope)),
            patch.object(cli, "client_for", return_value=client),
            patch.object(cli, "_execute_hunt_task") as execute,
            redirect_stdout(StringIO()),
        ):
            cli.cmd_hunt(args)
        execute.assert_not_called()
        client.send.assert_not_called()
        report = json.loads(next(self.paths.reports_dir.glob("*-hunt.json")).read_text(encoding="utf-8"))
        self.assertTrue(report["dry_run"])
        self.assertEqual(report["budget"]["requests_started"], 0)

    def test_resume_skips_completed_modules_after_cancellation(self):
        calls = []
        runner = self.make_task_runner(calls)

        def interrupt_after_first(*args):
            if calls and args[1].module == "xss":
                calls.append("xss-interrupted")
                raise KeyboardInterrupt
            return runner(*args)

        self.invoke(self.args("--only", "cors-check,xss"), interrupt_after_first)
        cancelled = json.loads(next(self.paths.reports_dir.glob("*-hunt.json")).read_text(encoding="utf-8"))
        self.assertEqual(cancelled["status"], "cancelled")
        calls.clear()
        self.invoke(self.args("--only", "cors-check,xss", "--resume"), self.make_task_runner(calls))
        self.assertEqual(calls, ["xss"])
        progress = json.loads((self.paths.reports_dir / "hunt-progress.json").read_text(encoding="utf-8"))
        self.assertTrue(progress["complete"])


if __name__ == "__main__":
    unittest.main()
