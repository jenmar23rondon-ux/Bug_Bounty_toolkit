"""XSS real-browser lab: mock CI path, loopback isolation, optional Chromium."""

from __future__ import annotations

import hashlib
import json
import time
import unittest
from unittest.mock import patch
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any

from bugbounty_toolkit import __version__
from bugbounty_toolkit.xss.evidence_record import DomObservation
from labs.xss_real_browser_eval.evaluate import (
    main,
    cases_as_scenarios,
    final_is_frozen,
    parser_rows,
    run_split,
)
from labs.xss_real_browser_eval.isolation import RequestLedger, is_allowed_loopback_http
from labs.xss_real_browser_eval.metrics import browser_metrics, parser_metrics, reproducibility
from labs.xss_real_browser_eval.observe import fetch_loopback, mock_case_row
from labs.xss_real_browser_eval.secrets import secret_leak_count
from labs.xss_real_browser_eval.server import LoopbackLab, render_endpoint
from labs.xss_real_browser_eval.spec import (
    EXTERNAL_PROBE_HTTP,
    LETTERS,
    canonical_json,
    payload_for,
    scenarios_for,
)
from labs.xss_real_browser_eval.states import lab_state

LAB = Path(__file__).resolve().parents[1] / "labs" / "xss_real_browser_eval"
ROOT = Path(__file__).resolve().parents[1]


class LiveExitStatusTests(unittest.TestCase):
    def check(self, chromium: dict[str, Any], repeat: int = 1) -> int:
        with (
            patch("labs.xss_real_browser_eval.evaluate.probe_chromium", return_value={"available": False}),
            patch("labs.xss_real_browser_eval.evaluate.run_split", return_value={"chromium": chromium}),
            patch("builtins.print"),
        ):
            return main(["--mode", "live", "--split", "final", "--repeat", str(repeat)])

    def test_live_unavailable_is_a_failure_instead_of_a_successful_skip(self) -> None:
        self.assertEqual(self.check({"status": "NOT_MEASURED"}), 1)

    def test_live_gate_rejects_wrong_or_incomplete_observations(self) -> None:
        for run in ({"mismatches": [{"id": "A"}], "evidence_completeness": 1.0}, {"evidence_completeness": 0.5}):
            self.assertEqual(self.check({"status": "measured", "runs": [run]}), 1)
        self.assertEqual(self.check({"status": "measured", "runs": []}), 1)

    def test_live_gate_requires_reproducibility_for_repeated_runs(self) -> None:
        report: dict[str, Any] = {"status": "measured", "runs": [{"mismatches": [], "evidence_completeness": 1.0}]}
        self.assertEqual(self.check(report), 0)
        self.assertEqual(self.check(report, repeat=2), 1)
        report["reproducibility"] = {"state_agreement": 1.0}
        self.assertEqual(self.check(report, repeat=2), 0)


class SpecTests(unittest.TestCase):
    def test_version_stays_0_2_2(self) -> None:
        self.assertEqual(__version__, "0.2.2")
        text = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
        self.assertIn('version = "0.2.2"', text)

    def test_endpoints_a_through_p_and_synthetic_markers(self) -> None:
        for split in ("dev", "final"):
            cases = scenarios_for(split)
            self.assertEqual(tuple(case.letter for case in cases), LETTERS)
            markers = [case.marker for case in cases]
            self.assertEqual(len(markers), len(set(markers)))
            for case in cases:
                self.assertTrue(case.marker.startswith("bbtkxss"))
                self.assertTrue(case.marker.isalnum())
                payload = payload_for(case.payload_kind, case.marker)
                self.assertNotIn("localStorage", payload)
                self.assertNotIn("cookie", payload.lower())
                self.assertNotIn("http://", payload)
                self.assertNotIn("ws://", payload)

    def test_committed_spec_matches_generator_and_final_hash(self) -> None:
        self.assertTrue(final_is_frozen())
        for split in ("dev", "final"):
            raw = (LAB / split / "scenarios.json").read_text(encoding="utf-8")
            self.assertEqual(raw, canonical_json(split))
        digest = hashlib.sha256((LAB / "final" / "scenarios.json").read_bytes()).hexdigest()
        pinned = (LAB / "final" / "MANIFEST.sha256").read_text(encoding="utf-8").split()[0]
        self.assertEqual(digest, pinned)
        self.assertEqual(cases_as_scenarios("final")[0].marker.startswith("bbtkxssfin"), True)


class IsolationTests(unittest.TestCase):
    def test_only_literal_loopback_http_is_allowed(self) -> None:
        self.assertTrue(is_allowed_loopback_http("http://127.0.0.1:9/a"))
        self.assertTrue(is_allowed_loopback_http("http://[::1]/a"))
        for blocked in (
            "http://localhost/a",
            "http://203.0.113.10/bbtk-xss-probe",
            "https://example.com/",
            "http://user:pass@127.0.0.1/",
            "file:///etc/passwd",
            "ws://127.0.0.1/socket",
        ):
            self.assertFalse(is_allowed_loopback_http(blocked), blocked)

    def test_external_http_is_aborted_and_not_counted_as_sent(self) -> None:
        ledger = RequestLedger()

        class _Request:
            def __init__(self, url: str) -> None:
                self.url = url

        class _Route:
            def __init__(self, url: str) -> None:
                self.request = _Request(url)
                self.action: str | None = None

            def continue_(self) -> None:
                self.action = "continue"

            def abort(self) -> None:
                self.action = "abort"

        external = _Route(EXTERNAL_PROBE_HTTP)
        local = _Route("http://127.0.0.1:9/a")
        self.assertEqual(ledger.apply_http(external), "block")
        self.assertEqual(external.action, "abort")
        self.assertEqual(ledger.apply_http(local), "allow")
        self.assertEqual(local.action, "continue")
        self.assertEqual(ledger.external_requests, 0)
        self.assertGreaterEqual(ledger.blocked_external, 1)

    def test_websocket_route_does_not_connect_or_close(self) -> None:
        ledger = RequestLedger()

        class _Socket:
            url = "ws://203.0.113.10/bbtk-xss-probe"

            def close(self) -> None:
                raise AssertionError("close() deadlocks inside the sync route callback")

            def connect_to_server(self) -> None:
                raise AssertionError("external websocket must not be connected")

        self.assertEqual(ledger.apply_websocket(_Socket()), "block")
        self.assertEqual(ledger.websocket_blocked, 1)
        self.assertEqual(ledger.external_requests, 0)
        self.assertGreaterEqual(ledger.blocked_external, 1)

    def test_fetch_refuses_non_loopback(self) -> None:
        with self.assertRaises(ValueError):
            fetch_loopback("http://203.0.113.10/bbtk-xss-probe")

    def test_server_binds_loopback_and_does_not_set_cookies(self) -> None:
        with LoopbackLab() as lab:
            self.assertTrue(lab.base_url.startswith("http://127.0.0.1:"))
            status, content_type, body, csp = fetch_loopback(lab.base_url + "/b?q=bbtkxssdevb")
        self.assertEqual(status, 200)
        self.assertIn("text/html", content_type)
        self.assertIsNone(csp)
        self.assertIn("bbtkxssdevb", body)
        self.assertNotIn("<img", body)
        rendered = render_endpoint("/o", "bbtkxssdevo")
        header_names = {name.lower() for name, _value in rendered.headers}
        self.assertNotIn("set-cookie", header_names)
        self.assertIn("203.0.113.10", rendered.body.decode("utf-8"))
        started = time.perf_counter()
        hung = render_endpoint("/p", "bbtkxssdevp")
        self.assertLess(time.perf_counter() - started, 0.5)
        self.assertIn("/p-hold", hung.body.decode("utf-8"))
        self.assertEqual(secret_leak_count(rendered.body.decode("utf-8")), 0)


class StateAndMetricsTests(unittest.TestCase):
    def test_browser_failure_is_never_execution(self) -> None:
        state = lab_state(
            DomObservation(browser_failed=True, marker_executed=True, sinks=("innerHTML",)),
            reflected=True,
        )
        self.assertEqual(state, "inconclusive_browser_error")
        self.assertEqual(
            lab_state(DomObservation(sinks=("innerHTML",), source_observed=True), reflected=True),
            "sink_reached",
        )
        self.assertEqual(
            lab_state(DomObservation(csp_blocked=True), reflected=True),
            "execution_blocked",
        )
        self.assertEqual(lab_state(DomObservation(sanitized=True, sinks=("innerHTML",)), reflected=False), "sanitized")

    def test_mock_pipeline_matches_spec_and_is_not_a_live_result(self) -> None:
        cases = scenarios_for("dev")
        rows = [mock_case_row(case) for case in cases]
        self.assertTrue(all(row["measurement"] == "mock_fixture" for row in rows))
        self.assertTrue(all(row["finding_confirmed"] is False and row["confirmed"] is False for row in rows))
        metrics = browser_metrics(rows, cases)
        self.assertEqual(metrics["table"], "mock_fixture")
        self.assertEqual(metrics["execution_precision"], 1.0)
        self.assertEqual(metrics["execution_recall"], 1.0)
        self.assertEqual(metrics["false_positives"], 0)
        self.assertEqual(metrics["false_negatives"], 0)
        self.assertEqual(metrics["external_requests"], 0)
        self.assertEqual(metrics["csp_blocked_correct_rate"], 1.0)
        self.assertEqual(metrics["safe_sink_correct_rate"], 1.0)
        self.assertEqual(metrics["evidence_completeness"], 1.0)
        self.assertEqual(secret_leak_count(json.dumps(rows)), 0)

    def test_reproducibility_reports_not_measured_for_one_run(self) -> None:
        rows = [mock_case_row(case) for case in scenarios_for("dev")]
        single = reproducibility([rows])
        self.assertEqual(single["status"], "NOT_MEASURED")
        changed = [dict(row) for row in rows]
        changed[0]["state"] = "inconclusive"
        compared = reproducibility([rows, changed])
        self.assertEqual(compared["status"], "measured")
        self.assertEqual(compared["disagreements"][0]["scenario_id"], "A")
        self.assertLess(compared["state_agreement"], 1.0)

    def test_parser_against_loopback_matches_frozen_expectations(self) -> None:
        cases = cases_as_scenarios("dev")
        with LoopbackLab() as lab:
            rows = parser_rows(lab.base_url, cases)
        metrics = parser_metrics(rows, cases)
        self.assertEqual(metrics["mismatches"], [])
        self.assertEqual(metrics["context_accuracy"], 1.0)
        self.assertEqual(metrics["decision_accuracy"], 1.0)
        self.assertEqual(metrics["browser_time_ms"], 0.0)
        self.assertEqual(metrics["external_requests"], 0)
        self.assertTrue(metrics["finding_confirmed_always_false"])
        by_id = {row["scenario_id"]: row for row in rows}
        # Parser gap kept on purpose: F executes in Chromium but the static classifier
        # sees a closed JavaScript string.
        self.assertEqual(by_id["F"]["decision"], "escaped_safe")
        self.assertEqual(by_id["L"]["decision"], "escaped_safe")
        self.assertEqual(secret_leak_count(json.dumps(rows)), 0)


class MockEvaluateTests(unittest.TestCase):
    def test_mock_mode_does_not_invent_chromium_metrics(self) -> None:
        report = run_split(
            "dev",
            mode="mock",
            repeat=1,
            gate={"available": False, "reason": "unit test", "browser_version": None},
        )
        self.assertEqual(report["chromium"]["status"], "NOT_MEASURED")
        self.assertEqual(report["chromium"]["external_requests"], "NOT_MEASURED")
        self.assertNotIn("runs", report["chromium"])
        self.assertEqual(report["mock_ci_pipeline"]["false_positives"], 0)
        self.assertTrue(report["parser"]["finding_confirmed_always_false"])
        self.assertEqual(report["parser"]["external_requests"], 0)


class LiveChromiumTests(unittest.TestCase):
    gate: dict[str, Any]

    @classmethod
    def setUpClass(cls) -> None:
        from labs.xss_real_browser_eval.chromium_gate import probe_chromium

        gate = probe_chromium()
        if not gate.get("available"):
            raise unittest.SkipTest(str(gate.get("reason")))
        cls.gate = gate

    def test_live_dev_matrix_and_checker_agree_on_execution(self) -> None:
        report = run_split("dev", mode="live", repeat=1, gate=self.gate)
        chromium = report["chromium"]
        self.assertEqual(chromium["status"], "measured")
        self.assertEqual(chromium["external_requests"], 0)
        self.assertEqual(chromium["external_socket_observations"], 0)
        self.assertFalse(chromium["finding_confirmed"])
        run = chromium["runs"][0]
        self.assertEqual(run["false_positives"], 0)
        self.assertEqual(run["false_negatives"], 0)
        self.assertEqual(run["execution_precision"], 1.0)
        self.assertEqual(run["execution_recall"], 1.0)
        self.assertEqual(run["mismatches"], [])
        self.assertEqual(run["secret_leaks"], 0)
        self.assertEqual(chromium["reproducibility"]["status"], "NOT_MEASURED")
        rows = {row["scenario_id"]: row for row in report["chromium_rows"][0]}
        self.assertGreaterEqual(rows["O"]["blocked_external"], 1)
        self.assertEqual(rows["O"]["external_requests"], 0)
        self.assertEqual(rows["P"]["state"], "inconclusive_browser_error")
        self.assertIsNotNone(rows["P"]["browser_error"])
        self.assertTrue(all(row["finding_confirmed"] is False for row in rows.values()))
        self.assertLess(rows["P"]["runtime_ms"], 5000)

        from bugbounty_toolkit.core.scope_validator import ScopeValidator
        from bugbounty_toolkit.xss.playwright_confirm import PlaywrightExecutionChecker

        dev = {case.letter: case for case in scenarios_for("dev")}
        with TemporaryDirectory() as tmp, LoopbackLab() as lab:
            scope = Path(tmp) / "scope.txt"
            scope.write_text("127.0.0.1\n", encoding="utf-8")
            checker = PlaywrightExecutionChecker(ScopeValidator(scope))
            try:
                executed = checker.confirm(
                    lab.base_url + "/a?" + _query(dev["A"]),
                    dev["A"].marker,
                    local_only=True,
                )
                escaped = checker.confirm(
                    lab.base_url + "/b?" + _query(dev["B"]),
                    dev["B"].marker,
                    local_only=True,
                )
            finally:
                checker.close()
        self.assertTrue(executed["marker_observed"])
        self.assertFalse(escaped["marker_observed"])
        self.assertNotEqual(executed.get("finding_confirmed", False), True)


def _query(case: object) -> str:
    from urllib.parse import urlencode

    from labs.xss_real_browser_eval.spec import Scenario, payload_for

    assert isinstance(case, Scenario)
    return urlencode({"q": payload_for(case.payload_kind, case.marker)})


if __name__ == "__main__":
    unittest.main()
