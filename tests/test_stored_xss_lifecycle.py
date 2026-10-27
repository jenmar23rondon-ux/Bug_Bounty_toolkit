"""Stored XSS lifecycle lab: declared outcomes, loopback chain, no auto-confirm."""

from __future__ import annotations

import hashlib
import json
import socket
import unittest
from pathlib import Path
from unittest.mock import patch
from urllib.error import HTTPError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from bugbounty_toolkit import __version__
from bugbounty_toolkit.xss.stored_local import _payload, run_stored_local

from labs.stored_xss_lifecycle_eval.evaluate import (
    REUSED_ENTRYPOINT,
    chromium_available,
    evaluate,
    final_is_frozen,
    load_split,
)
from labs.stored_xss_lifecycle_eval.evidence import count_secret_leaks, integrity_sha256
from labs.stored_xss_lifecycle_eval.network import NetworkGuard
from labs.stored_xss_lifecycle_eval.server import base_url, configure, fetch_state, make_server, reset, serve

ROOT = Path(__file__).resolve().parents[1]
DOM_HOOKS = {
    "bugbounty_toolkit/xss/dom_local.py": "fe7f35df1752cd443f0964bbdfbb4bdb0f71dbacda3dd1d6e22eeda942f7c660",
    "bugbounty_toolkit/xss/playwright_confirm.py": "09114d13bfe375f6f10ce31fd7ade78525f66e2144a01885cec31a6c9b2dddeb",
}
CHAIN = {
    "bugbounty_toolkit/xss/stored_local.py": "3bade658e43a65ba072167cf7bc71ea1527d1f7255b74618067284c89069d053",
    "bugbounty_toolkit/xss/parameter_tester.py": "eadfcda548e9c66a128c4336f93fa02a4048a92d672f89eb28bf045ffbc4eff0",
    "bugbounty_toolkit/xss/evidence_record.py": "9dad0cf912d5b4460235fd50ee6321789a9d166e4351b98e7a1c6985cf6a8a8e",
}
SCENARIOS = (
    "saved_never_rendered",
    "reflect_on_write_only",
    "safe_text",
    "html_escaped_on_render",
    "sanitize_on_save",
    "sanitize_on_render",
    "chromium_execution",
    "marker_present_no_execution",
    "csp_block",
    "second_user_view",
    "wrong_permissions",
    "not_found",
    "write_ok_view_missing",
    "write_rejected",
    "truncated_persist",
    "browser_timeout",
    "interaction_required",
)


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class CorpusTests(unittest.TestCase):
    def test_version_stays_0_2_2(self) -> None:
        self.assertEqual(__version__, "0.2.2")

    def test_dev_and_final_declare_cases_1_through_17(self) -> None:
        for split in ("dev", "final"):
            payload = json.loads((ROOT / "labs/stored_xss_lifecycle_eval" / split / "cases.json").read_text())
            self.assertTrue(payload["declared_before_run"])
            self.assertFalse(payload["finding_confirmed"])
            cases = load_split(split)
            self.assertEqual([case["number"] for case in cases], list(range(1, 18)))
            self.assertEqual([case["scenario"] for case in cases], list(SCENARIOS))
            for case in cases:
                self.assertTrue(case["expected_outcome_declared_before_run"])
                expected = case["expected"]
                self.assertIsInstance(expected, dict)
                self.assertFalse(expected["finding_confirmed"])
                self.assertFalse(expected["pipeline_confirms_finding"])
                self.assertIn("execution_expected", expected)
                self.assertIn("marker_in_html", expected)
                self.assertIn("write_status", expected)

    def test_timeout_budget_is_declared_shorter_than_the_view_delay(self) -> None:
        for split in ("dev", "final"):
            for case in load_split(split):
                inputs = case["inputs"]
                self.assertIsInstance(inputs, dict)
                if case["expected"]["browser_error"] is True:
                    self.assertGreater(inputs["view_delay_s"], inputs["browser_timeout_s"] + 0.5)

    def test_final_manifest_matches_cases_bytes(self) -> None:
        self.assertTrue(final_is_frozen())

    def test_final_truncation_differs_from_dev_without_changing_the_outcome(self) -> None:
        dev = {case["scenario"]: case for case in load_split("dev")}
        final = {case["scenario"]: case for case in load_split("final")}
        self.assertEqual(dev["truncated_persist"]["inputs"]["truncate_at"], 12)
        self.assertEqual(final["truncated_persist"]["inputs"]["truncate_at"], 10)
        self.assertEqual(dev["truncated_persist"]["expected"], final["truncated_persist"]["expected"])
        self.assertLess(
            dev["browser_timeout"]["inputs"]["view_delay_s"], final["browser_timeout"]["inputs"]["view_delay_s"]
        )
        self.assertEqual(dev["browser_timeout"]["expected"], final["browser_timeout"]["expected"])

    def test_p05_dom_hooks_and_stored_chain_are_untouched(self) -> None:
        for relative, digest in {**DOM_HOOKS, **CHAIN}.items():
            self.assertEqual(_sha256(ROOT / relative), digest, relative)


class ServerTests(unittest.TestCase):
    def test_refuses_non_loopback_bind(self) -> None:
        with self.assertRaises(ValueError):
            make_server("203.0.113.5", 0)

    def test_truncate_10_drops_the_marker_and_reset_clears_storage(self) -> None:
        payload = _payload("bbtkxss0123456789ab", True)
        with serve() as server:
            origin = base_url(server)
            configure(origin, "truncated_persist", 10, 0)
            body = urlencode({"content": payload}).encode("utf-8")
            request = Request(f"{origin}/comments", data=body, method="POST")
            with urlopen(request, timeout=2) as response:
                self.assertEqual(response.status, 201)
                location = response.headers["Location"]
            with urlopen(f"{origin}{location}", timeout=2) as view:
                text = view.read().decode("utf-8")
                self.assertEqual(view.status, 200)
                self.assertNotIn("bbtkxss0123456789ab", text)
                self.assertNotIn("onerror", text)
            state = fetch_state(origin)
            self.assertEqual(state["record_count"], 1)
            self.assertNotIn("onerror", json.dumps(state))
            self.assertFalse(state["finding_confirmed"])
            reset(origin)
            cleared = fetch_state(origin)
            self.assertEqual(cleared["record_count"], 0)
            self.assertEqual(cleared["event_count"], 0)

    def test_wrong_permissions_view_has_no_body_marker(self) -> None:
        with serve() as server:
            origin = base_url(server)
            configure(origin, "wrong_permissions", 12, 0)
            body = urlencode({"content": "bbtkxss0123456789ab"}).encode("utf-8")
            with urlopen(Request(f"{origin}/comments", data=body, method="POST"), timeout=2) as response:
                self.assertEqual(response.status, 201)
                location = response.headers["Location"]
            with self.assertRaises(HTTPError) as caught:
                urlopen(f"{origin}{location}", timeout=2)
            self.assertEqual(caught.exception.code, 403)


class GuardTests(unittest.TestCase):
    def test_non_loopback_connect_is_blocked_and_counted(self) -> None:
        with NetworkGuard() as guard:
            sock = socket.socket()
            try:
                with self.assertRaises(OSError):
                    sock.connect(("203.0.113.5", 9))
            finally:
                sock.close()
            self.assertEqual(guard.external_requests, 1)
            self.assertEqual(guard.loopback_attempts, 0)

    def test_secret_scanner_flags_synthetic_shapes_and_ignores_markers(self) -> None:
        self.assertEqual(count_secret_leaks("bbtkxss0123456789ab"), 0)
        sample = "AKIA" + "0" * 16
        self.assertEqual(count_secret_leaks(sample), 1)
        self.assertEqual(
            integrity_sha256({"finding_confirmed": False, "integrity_sha256": "ignored"}),
            integrity_sha256({"finding_confirmed": False}),
        )


class LifecycleTests(unittest.TestCase):
    def test_dev_mock_three_runs_reuse_stored_local_and_do_not_confirm(self) -> None:
        with patch("labs.stored_xss_lifecycle_eval.evaluate.run_stored_local", wraps=run_stored_local) as spy:
            report = evaluate("dev", runs=3, browser="mock")
        self.assertEqual(spy.call_count, 17 * 3)
        self.assertEqual(report["reused_entrypoint"], REUSED_ENTRYPOINT)
        self.assertEqual(report["version"], "0.2.2")
        self.assertEqual(report["browser_mode"], "mock")
        self.assertFalse(report["chromium_available"])
        self.assertFalse(chromium_available())
        self.assertTrue(report["gates_passed"])
        self.assertFalse(report["finding_confirmed"])
        self.assertEqual(report["external_requests"], 0)
        self.assertGreater(report["loopback_attempts"], 0)
        self.assertEqual(report["secret_leaks"], 0)
        self.assertEqual(report["automatic_confirmations"], 0)
        self.assertEqual(report["browser_processes_observed"], 0)
        metrics = report["metrics"]
        self.assertEqual(metrics["persistence_correctness"], 1.0)
        self.assertEqual(metrics["render_recall"], 1.0)
        self.assertEqual(metrics["cleanup_success_rate"], 1.0)
        self.assertEqual(metrics["declared_outcome_accuracy"], 1.0)
        self.assertEqual(metrics["write_success_confirmed"], 0)
        self.assertEqual(metrics["marker_only_execution_claims"], 0)
        self.assertEqual(metrics["exec_precision"], "NOT_MEASURED")
        self.assertEqual(metrics["status_disagreements"], 0)
        blob = json.dumps(report)
        self.assertNotIn("onerror", blob)
        self.assertNotIn("<img", blob)
        self.assertNotIn("window.__bbtk_xss_marker", blob)
        for case in report["cases"]:
            self.assertFalse(case["finding_confirmed"])
            self.assertFalse(case["pipeline_finding_confirmed"])
            self.assertFalse(case["pipeline_confirmed"])
            self.assertFalse(case["pipeline_execution_claim"])
            self.assertEqual(case["execution_observed"], "NOT_MEASURED")
            self.assertTrue(case["cleanup_ok"])
            self.assertFalse(case["mismatches"])
            evidence = case["evidence"]
            self.assertFalse(evidence["finding_confirmed"])
            self.assertEqual(evidence["integrity_sha256"], integrity_sha256(evidence))
            if case["marker_in_html"] is True:
                self.assertIsNot(case["execution_observed"], True)
            write_status = case["write_status"]
            if isinstance(write_status, int) and 200 <= write_status < 300:
                self.assertFalse(case["pipeline_finding_confirmed"])
        self.assertEqual(len(report["cases"]), 17)
        self.assertEqual(len(report["per_run"]), 3)


if __name__ == "__main__":
    unittest.main()
