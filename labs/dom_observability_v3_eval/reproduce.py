"""Reproduce the four DOM local v2 limits on loopback.

Trace outcomes come from the v2/v3 classifiers. Live outcomes use system Chrome
when Playwright can launch it. The stock Playwright Chromium build is reported
as NOT_MEASURED when that browser is not installed. This script does not send
non-loopback traffic; external fetches are aborted.
"""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from bugbounty_toolkit.xss.dom_observability import classify_case, early_hook_script
from labs.dom_observability_v3_eval.corpus import build_cases

_CHROME_ARGS = ["--no-sandbox", "--disable-dev-shm-usage"]
_TRACE_IDS = (
    "dev-prehook-inert",
    "dev-settimeout",
    "dev-isolated-frame",
    "dev-url-unread",
)


def _trace_notes() -> list[dict[str, Any]]:
    cases = {case["case_id"]: case for case in build_cases("dev")}
    notes = []
    for case_id in _TRACE_IDS:
        case = cases[case_id]
        v2 = classify_case(case, generation="v2")
        v3 = classify_case(case, generation="v3")
        notes.append(
            {
                "case_id": case_id,
                "method": "trace_model",
                "v2_outcome": v2["outcome"],
                "v2_legacy_classification": v2["legacy_v2"]["classification"],
                "v2_source_marker_present": v2["legacy_v2"]["source_marker_present"],
                "v3_outcome": v3["outcome"],
                "v3_source_observed": v3["source_observed"],
                "v3_source_available": v3["source_available"],
                "v3_executed": v3["execution_evidence"]["executed"],
                "finding_confirmed": False,
            }
        )
    return notes


def _live_notes() -> dict[str, Any]:
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        return {"status": "NOT_MEASURED", "reason": "playwright python package is not installed"}
    try:
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(channel="chrome", headless=True, args=_CHROME_ARGS)
            browser.close()
    except Exception as exc:
        return {"status": "NOT_MEASURED", "reason": f"system Chrome launch failed: {type(exc).__name__}"}

    from bugbounty_toolkit.xss.dom_observer import observe_loopback

    marker = "bbtkxssrepro01"

    class _Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args: object) -> None:
            return

        def do_GET(self) -> None:  # noqa: N802
            path = self.path.split("?", 1)[0]
            if path == "/early":
                body = (
                    "<!doctype html><div id=out></div><script>"
                    "document.getElementById('out').innerHTML = decodeURIComponent(location.hash.slice(1));"
                    "</script>"
                )
            elif path == "/async":
                body = (
                    "<!doctype html><body><script>"
                    "const value = decodeURIComponent(location.hash.slice(1));"
                    "setTimeout(() => { document.body.innerHTML = value; window.__bbtk_xss_marker = value; }, 400);"
                    "</script></body>"
                )
            elif path == "/child":
                body = (
                    "<!doctype html><body><div id=out></div><script>"
                    "const value = new URLSearchParams(location.search).get('q') || '';"
                    "document.getElementById('out').innerHTML = value;"
                    "window.__bbtk_xss_marker = value;"
                    "</script></body>"
                )
            elif path == "/isolated":
                body = f"<!doctype html><iframe id=iso sandbox src='/child?q={marker}'></iframe>"
            else:
                body = "<!doctype html><p>static</p>"
            payload = body.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_port}"
    try:

        def observe(url: str, **kwargs: Any) -> dict[str, Any]:
            return observe_loopback(
                url,
                marker,
                case_id="repro",
                navigation_id="nav-repro",
                channel="chrome",
                launch_args=_CHROME_ARGS,
                **kwargs,
            )

        late_attach = _late_attach_sink(base, marker)
        early = observe(f"{base}/early#{marker}", async_budget_ms=150)
        unread = observe(f"{base}/unread#{marker}", async_budget_ms=100)
        short = observe(f"{base}/async#{marker}", async_budget_ms=150)
        long = observe(f"{base}/async#{marker}", async_budget_ms=800)
        isolated = observe(f"{base}/isolated", async_budget_ms=200)
        blocked = next(frame for frame in isolated["frames"] if frame["frame_id"] == "iso")
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()

    chromium_note = _stock_chromium_status()
    return {
        "status": "MEASURED",
        "browser": "system-chrome-via-playwright",
        "external_requests": early["external_requests"]
        + unread["external_requests"]
        + short["external_requests"]
        + long["external_requests"]
        + isolated["external_requests"],
        "finding_confirmed": False,
        "stock_playwright_chromium": chromium_note,
        "limits": {
            "sink_before_hooks": {
                "early_init_script_sink": early["sink_refs"],
                "early_init_script_executed": early["execution_evidence"]["executed"],
                "instrumentation_status": early["instrumentation_status"],
                "late_attach_sinks": late_attach,
                "note": (
                    "DOM local v2 already uses add_init_script, which records this inert "
                    "innerHTML sink and does not treat it as execution. Installing the same "
                    "hook after load misses the sink. location.hash is non-configurable in "
                    "this Chrome, so that read is not claimed."
                ),
            },
            "async_after_load": {
                "budget_150ms_executed": short["execution_evidence"]["executed"],
                "budget_800ms_executed": long["execution_evidence"]["executed"],
                "note": "A 400ms setTimeout is outside a 150ms window and inside an 800ms window. DOM local v2 waits at most 300ms.",
            },
            "isolated_frame": {
                "outcome": blocked["outcome"],
                "sink_refs": blocked["sink_refs"],
                "executed": blocked["execution_evidence"]["executed"],
            },
            "source_in_url_never_read": {
                "source_available": unread["source_available"],
                "source_observed": unread["source_observed"],
                "outcome": unread["outcome"],
            },
        },
    }


def _late_attach_sink(base: str, marker: str) -> list[str]:
    """Install the v3 hook after the inline sink has already run."""
    from playwright.sync_api import sync_playwright

    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(channel="chrome", headless=True, args=_CHROME_ARGS)
        try:
            page = browser.new_page()
            page.goto(f"{base}/early#{marker}", wait_until="domcontentloaded", timeout=5000)
            page.evaluate(early_hook_script(marker))
            sinks = page.evaluate("() => (window.__bbtk_obs_v3 && window.__bbtk_obs_v3.sinks) || []")
        finally:
            browser.close()
    if not isinstance(sinks, list):
        return []
    return sorted({str(item.get("sink")) for item in sinks if isinstance(item, dict) and item.get("sink")})


def _stock_chromium_status() -> dict[str, str]:
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        return {"status": "NOT_MEASURED", "reason": "playwright is not installed"}
    try:
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=True)
            browser.close()
    except Exception as exc:
        return {
            "status": "NOT_MEASURED",
            "reason": f"bundled Playwright Chromium is not installed ({type(exc).__name__})",
        }
    return {"status": "MEASURED", "reason": "bundled Chromium launched"}


def main() -> int:
    report = {
        "finding_confirmed": False,
        "traces": _trace_notes(),
        "live": _live_notes(),
    }
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
