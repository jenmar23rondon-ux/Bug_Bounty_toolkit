"""Local-only DOM XSS probes and their conservative evidence classifications."""

import ipaddress
import json
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase
from unittest.mock import Mock
from urllib.parse import parse_qs, unquote, urlsplit

from bugbounty_toolkit.xss.dom_local import dom_probe_url, require_literal_loopback, run_dom_local
from bugbounty_toolkit.utils.exceptions import ToolkitError


class DomLocalProbeTests(TestCase):
    def test_loopback_only_preflight(self):
        for allowed in ("http://127.0.0.1:8181/test", "http://[::1]:8181/test"):
            require_literal_loopback(allowed)
        for rejected in (
            "https://example.com/test",
            "http://localhost:8181/",
            "file:///etc/passwd",
            "http://127.0.0.1.evil.invalid",
            "http://user:secret@127.0.0.1/",
            "http://127.0.0.1/test#fragment",
            "http://192.0.2.1/",
        ):
            with self.subTest(url=rejected), self.assertRaises(ValueError):
                require_literal_loopback(rejected)

    def test_query_and_fragment_generation(self):
        base = "http://127.0.0.1:8181/dom?other=1"
        q = dom_probe_url(base, "q", "<img src=x>", "query")
        h = dom_probe_url(base, "q", "<img src=x>", "hash")
        self.assertEqual(parse_qs(urlsplit(q).query), {"other": ["1"], "q": ["<img src=x>"]})
        self.assertEqual(urlsplit(q).fragment, "")
        self.assertEqual(unquote(urlsplit(h).fragment), "<img src=x>")
        self.assertEqual(parse_qs(urlsplit(h).query), {"other": ["1"]})
        with self.assertRaises(ValueError):
            dom_probe_url(base, "q", "m", "postMessage")

    def test_four_bounded_browser_observations_without_confirming_a_finding(self):
        checker = Mock()

        def check(url, marker, headers, *, local_only):
            self.assertTrue(local_only)
            self.assertTrue(ipaddress.ip_address(urlsplit(url).hostname).is_loopback)
            self.assertIn(marker, url)
            payload = unquote(urlsplit(url).fragment) or parse_qs(urlsplit(url).query)["q"][0]
            active = "onerror=" in payload
            return {
                "source_marker_present": True,
                "dom_sinks": ["innerHTML"] if active else [],
                "marker_observed": active,
                "alert_observed": active,
            }

        checker.confirm.side_effect = check
        with TemporaryDirectory() as tmp:
            path, results = run_dom_local(
                ["http://127.0.0.1:8181/dom"],
                ["q"],
                checker,
                Path(tmp),
                max_tests=4,
            )
            saved = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(checker.confirm.call_count, 4)
        self.assertEqual(len(results), 4)
        self.assertEqual(
            [r["classification"] for r in results],
            [
                "source_present_only",
                "execution_observed",
                "source_present_only",
                "execution_observed",
            ],
        )
        self.assertFalse(any(r["confirmed"] for r in results))
        self.assertEqual(saved["type"], "dom_xss_local")
        self.assertNotIn("<img", path.name)

    def test_preflight_blocks_all_probes_if_one_route_is_remote(self):
        checker = Mock()
        with TemporaryDirectory() as tmp, self.assertRaises(ValueError):
            run_dom_local(
                ["http://127.0.0.1:8181/", "https://example.org/"],
                ["q"],
                checker,
                Path(tmp),
                max_tests=4,
            )
        checker.confirm.assert_not_called()

    def test_small_test_cap_and_browser_budget_failure(self):
        checker = Mock()
        checker.confirm.return_value = {"source_marker_present": True, "dom_sinks": ["innerHTML"]}
        with TemporaryDirectory() as tmp:
            path, results = run_dom_local(
                ["http://127.0.0.1:8181/"],
                ["q"],
                checker,
                Path(tmp),
                max_tests=1,
            )
            self.assertEqual(len(results), 1)
            self.assertEqual(results[0]["classification"], "sink_reached")
            self.assertEqual(json.loads(path.read_text())["stop_reason"], "test_cap")
        checker.confirm.side_effect = ToolkitError("Run request budget exhausted")
        with TemporaryDirectory() as tmp:
            path, results = run_dom_local(
                ["http://127.0.0.1:8181/"],
                ["q"],
                checker,
                Path(tmp),
                max_tests=4,
            )
            self.assertEqual(len(results), 1)
            self.assertEqual(results[0]["classification"], "error")
            self.assertEqual(json.loads(path.read_text())["stop_reason"], "browser_or_budget_error")
