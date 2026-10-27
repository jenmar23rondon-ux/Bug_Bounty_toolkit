"""Loopback Chrome checks for early DOM hooks. Skips when Chrome is unavailable."""

from __future__ import annotations

import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from bugbounty_toolkit.xss.dom_observer import observe_loopback

MARKER = "bbtkxssbrowserv3"
_CHROME_ARGS = ["--no-sandbox", "--disable-dev-shm-usage"]


def _page(kind: str) -> bytes:
    if kind == "early":
        body = (
            "<!doctype html><div id=result></div><script>"
            "const value = decodeURIComponent(location.hash.slice(1));"
            "document.querySelector('#result').innerHTML = value;"
            "</script>"
        )
    elif kind == "unread":
        body = "<!doctype html><p>static laboratory page</p>"
    elif kind == "async":
        body = (
            "<!doctype html><script>"
            "const value = decodeURIComponent(location.hash.slice(1));"
            "setTimeout(() => { document.body.innerHTML = value;"
            "window.__bbtk_xss_marker = value; }, 400);"
            "</script>"
        )
    elif kind == "child":
        body = (
            "<!doctype html><body><div id=out></div><script>"
            "const value = new URLSearchParams(location.search).get('q') || '';"
            "document.getElementById('out').innerHTML = value;"
            "window.__bbtk_xss_marker = value;"
            "</script></body>"
        )
    elif kind == "docurl":
        body = (
            "<!doctype html><body><div id=out></div><script>"
            "const value = document.URL;"
            "document.getElementById('out').innerHTML = value;"
            "</script></body>"
        )
    elif kind == "frame":
        body = f"<!doctype html><iframe id=child src='/child?q={MARKER}'></iframe>"
    elif kind == "isolated":
        body = f"<!doctype html><iframe id=iso sandbox src='/child?q={MARKER}'></iframe>"
    elif kind == "text":
        body = "<!doctype html><body><script>document.body.textContent = document.URL;</script></body>"
    elif kind == "external":
        body = "<!doctype html><script>fetch('http://203.0.113.10/synth').catch(() => {});</script>"
    elif kind == "click":
        body = (
            "<!doctype html><button id=go>go</button><script>"
            "document.getElementById('go').addEventListener('click', () => {"
            "document.body.innerHTML = decodeURIComponent(location.hash.slice(1));"
            "});</script>"
        )
    else:
        body = "<!doctype html><p>missing</p>"
    return body.encode("utf-8")


class _Lab(BaseHTTPRequestHandler):
    def log_message(self, *_args: object) -> None:
        return

    def do_GET(self) -> None:  # noqa: N802 — stdlib handler name
        kind = self.path.split("?", 1)[0].strip("/") or "unread"
        payload = _page(kind)
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)


def _chrome_ready() -> bool:
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        return False
    try:
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(channel="chrome", headless=True, args=_CHROME_ARGS)
            browser.close()
    except Exception:
        return False
    return True


@unittest.skipUnless(_chrome_ready(), "system Chrome is not launchable via Playwright")
class DomObservabilityBrowserTests(unittest.TestCase):
    server: ThreadingHTTPServer
    thread: threading.Thread
    base: str

    @classmethod
    def setUpClass(cls) -> None:
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), _Lab)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.base = f"http://127.0.0.1:{cls.server.server_port}"

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()
        cls.thread.join(timeout=5)
        cls.server.server_close()

    def _observe(self, url: str, **kwargs: Any) -> dict[str, Any]:
        record: dict[str, Any] = observe_loopback(
            url,
            MARKER,
            case_id="browser",
            navigation_id="nav-browser",
            channel="chrome",
            launch_args=_CHROME_ARGS,
            **kwargs,
        )
        return record

    def test_early_hook_sees_inert_sink_and_source_read(self) -> None:
        record = self._observe(f"{self.base}/early#{MARKER}", async_budget_ms=150)
        self.assertEqual(record["outcome"], "observed")
        # This Chrome build exposes location getters as non-configurable instance
        # accessors, so a hash read is not claimed. The sink still is.
        self.assertFalse(record["source_observed"])
        self.assertTrue(record["source_available"])
        self.assertIn("innerHTML", record["sink_refs"])
        self.assertFalse(record["execution_evidence"]["executed"])
        self.assertFalse(record["finding_confirmed"])
        self.assertEqual(record["external_requests"], 0)
        self.assertEqual(record["instrumentation_status"], "partial")
        self.assertTrue(any("location.hash_unhookable" in item for item in record["technical_errors"]))

    def test_url_marker_without_a_read_stays_unobserved(self) -> None:
        record = self._observe(f"{self.base}/unread#{MARKER}", async_budget_ms=100)
        self.assertTrue(record["source_available"])
        self.assertFalse(record["source_observed"])
        self.assertEqual(record["outcome"], "not_observed")
        self.assertEqual(record["external_requests"], 0)

    def test_async_sink_is_inside_v3_budget_and_outside_a_short_one(self) -> None:
        short = self._observe(f"{self.base}/async#{MARKER}", async_budget_ms=150)
        long = self._observe(f"{self.base}/async#{MARKER}", async_budget_ms=800)
        self.assertFalse(short["execution_evidence"]["executed"])
        self.assertTrue(long["execution_evidence"]["executed"])
        self.assertEqual(long["execution_evidence"]["mechanism"], "marker_assignment")
        self.assertFalse(long["finding_confirmed"])

    def test_same_origin_frame_is_observed_and_isolated_frame_is_not(self) -> None:
        same = self._observe(f"{self.base}/frame", async_budget_ms=200)
        isolated = self._observe(f"{self.base}/isolated", async_budget_ms=200)
        child = next(frame for frame in same["frames"] if frame["frame_id"] == "child")
        blocked = next(frame for frame in isolated["frames"] if frame["frame_id"] == "iso")
        self.assertEqual(child["outcome"], "observed")
        self.assertIn("innerHTML", child["sink_refs"])
        self.assertTrue(child["execution_evidence"]["executed"])
        self.assertEqual(blocked["outcome"], "unsupported")
        self.assertEqual(blocked["sink_refs"], [])
        self.assertFalse(blocked["execution_evidence"]["executed"])
        self.assertIn("sop_not_bypassed", blocked["limitations"])

    def test_textcontent_and_click_and_blocked_external_fetch(self) -> None:
        text = self._observe(f"{self.base}/text#{MARKER}", async_budget_ms=100)
        idle = self._observe(f"{self.base}/click#{MARKER}", async_budget_ms=100)
        clicked = self._observe(
            f"{self.base}/click#{MARKER}",
            async_budget_ms=100,
            interactions=[{"op": "click", "selector": "#go"}],
        )
        external = self._observe(f"{self.base}/external", async_budget_ms=100)
        self.assertTrue(text["source_observed"])
        self.assertIn("document.URL", text["source_refs"])
        self.assertEqual(text["sink_refs"], [])
        self.assertFalse(text["execution_evidence"]["executed"])
        docurl = self._observe(f"{self.base}/docurl?q={MARKER}", async_budget_ms=100)
        self.assertTrue(docurl["source_observed"])
        self.assertIn("document.URL", docurl["source_refs"])
        self.assertIn("innerHTML", docurl["sink_refs"])
        self.assertFalse(docurl["execution_evidence"]["executed"])
        self.assertEqual(idle["sink_refs"], [])
        self.assertIn("innerHTML", clicked["sink_refs"])
        self.assertFalse(clicked["execution_evidence"]["executed"])
        self.assertGreaterEqual(external["external_requests"], 1)
        self.assertNotIn("203.0.113.10", str(external))

    def test_remote_url_is_rejected_before_navigation(self) -> None:
        with self.assertRaises(ValueError):
            observe_loopback(
                "https://example.com/",
                MARKER,
                case_id="nope",
                navigation_id="nav",
                channel="chrome",
                launch_args=_CHROME_ARGS,
            )


if __name__ == "__main__":
    unittest.main()
