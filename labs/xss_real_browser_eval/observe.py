"""Navigate one disposable scenario in a fresh Chromium context.

Observations are measured. A navigation timeout or page crash becomes
``inconclusive_browser_error`` and never a confirmed finding. Screenshots are
not taken.
"""

from __future__ import annotations

import json
import os
import time
import tracemalloc
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from bugbounty_toolkit.core.redaction import redact_text, redact_url
from bugbounty_toolkit.xss.evidence_record import observation_from_checker

from .isolation import RequestLedger, external_socket_count, is_allowed_loopback_http
from .spec import Scenario, payload_for, scenario_url
from .states import REQUIRED_ROW_FIELDS, evidence_for, lab_state, seal

LAUNCH_ARGS = (
    "--disable-background-networking",
    "--disable-component-update",
    "--disable-sync",
    "--disable-default-apps",
    "--disable-extensions",
    "--no-first-run",
    "--disable-domain-reliability",
    "--disable-client-side-phishing-detection",
    "--metrics-recording-only",
    "--disable-features=Translate,OptimizationHints,MediaRouter",
)

_SINK_SCRIPT = """(() => {
  const marker = __BBTK_MARKER__;
  window.__bbtk_dom_sinks = [];
  const record = name => {
    if (!window.__bbtk_dom_sinks.includes(name)) window.__bbtk_dom_sinks.push(name);
  };
  const descriptor = Object.getOwnPropertyDescriptor(Element.prototype, 'innerHTML');
  if (descriptor && descriptor.set && descriptor.configurable) {
    Object.defineProperty(Element.prototype, 'innerHTML', {
      configurable: descriptor.configurable,
      enumerable: descriptor.enumerable,
      get: descriptor.get,
      set(value) {
        if (String(value).includes(marker)) record('innerHTML');
        return descriptor.set.call(this, value);
      }
    });
  }
  const outer = Object.getOwnPropertyDescriptor(Element.prototype, 'outerHTML');
  if (outer && outer.set && outer.configurable) {
    Object.defineProperty(Element.prototype, 'outerHTML', {
      configurable: outer.configurable, enumerable: outer.enumerable,
      get: outer.get,
      set(value) {
        if (String(value).includes(marker)) record('outerHTML');
        return outer.set.call(this, value);
      }
    });
  }
  const insertAdjacent = Element.prototype.insertAdjacentHTML;
  if (typeof insertAdjacent === 'function') {
    Element.prototype.insertAdjacentHTML = function(position, value) {
      if (String(value).includes(marker)) record('insertAdjacentHTML');
      return insertAdjacent.call(this, position, value);
    };
  }
  for (const name of ['write', 'writeln']) {
    const original = Document.prototype[name];
    Document.prototype[name] = function(...values) {
      if (values.map(String).join('').includes(marker)) record('document.' + name);
      return original.apply(this, values);
    };
  }
})();"""


class _RefuseRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(
        self,
        req: urllib.request.Request,
        fp: Any,
        code: int,
        msg: str,
        headers: Any,
        newurl: str,
    ) -> None:
        raise urllib.error.HTTPError(req.full_url, code, "redirect blocked", headers, fp)


def fetch_loopback(url: str, timeout: float = 2.0) -> tuple[int, str, str, str | None]:
    """GET a literal loopback URL. Redirects and non-loopback hosts are refused."""
    without_fragment = url.split("#", 1)[0]
    if not is_allowed_loopback_http(without_fragment):
        raise ValueError("refusing non-loopback fetch")
    opener = urllib.request.build_opener(_RefuseRedirect)
    request = urllib.request.Request(without_fragment, method="GET")
    with opener.open(request, timeout=timeout) as response:
        status = int(response.status)
        content_type = str(response.headers.get("Content-Type", ""))
        csp_raw = response.headers.get("Content-Security-Policy")
        csp = str(csp_raw) if csp_raw else None
        body = response.read(1_000_000).decode("utf-8", errors="replace")
    return status, content_type, body, csp


def public_navigation_url(url: str) -> str:
    parsed = urlsplit(url)
    without = urlunsplit((parsed.scheme, parsed.netloc, parsed.path, parsed.query, ""))
    safe = redact_url(without)
    if parsed.fragment:
        return safe + "#fragment-present"
    return safe


def _origin(url: str) -> str:
    parsed = urlsplit(url)
    return f"{parsed.scheme}://{parsed.netloc}"


def _rss_tree(root_pid: int) -> int:
    total = 0
    stack = [root_pid]
    seen: set[int] = set()
    while stack:
        pid = stack.pop()
        if pid in seen:
            continue
        seen.add(pid)
        status = Path(f"/proc/{pid}/status")
        try:
            text = status.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for line in text.splitlines():
            if line.startswith("VmRSS:"):
                total += int(line.split()[1]) * 1024
                break
        children = Path(f"/proc/{pid}/task/{pid}/children")
        try:
            tokens = children.read_text(encoding="utf-8").split()
        except OSError:
            tokens = []
        for token in tokens:
            if token.isdigit():
                stack.append(int(token))
    return total


def _scrub(text: str) -> str:
    cleaned = redact_text(text) or ""
    return cleaned[:300]


class ChromiumSession:
    """One browser process. Each scenario gets a new context and is then closed."""

    def __init__(self) -> None:
        self._manager: Any = None
        self._browser: Any = None
        self.peak_rss_bytes = 0
        self.external_sockets = 0

    def __enter__(self) -> ChromiumSession:
        from playwright.sync_api import sync_playwright

        self._manager = sync_playwright()
        playwright = self._manager.start()
        self._browser = playwright.chromium.launch(headless=True, args=list(LAUNCH_ARGS))
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def close(self) -> None:
        if self._browser is not None:
            self._browser.close()
            self._browser = None
        if self._manager is not None:
            self._manager.__exit__(None, None, None)
            self._manager = None

    def run_case(self, base_url: str, case: Scenario) -> dict[str, Any]:
        if self._browser is None:
            raise RuntimeError("Chromium session is not open")
        url = scenario_url(base_url, case)
        http_status, content_type, body, csp_header = fetch_loopback(url)
        reflected = case.marker in body
        ledger = RequestLedger()
        console_errors: list[str] = []
        page_errors: list[str] = []
        dialogs: list[str] = []
        alert_observed = False
        captured: dict[str, Any] = {"status": None, "content_type": None, "csp": None}
        browser_error: str | None = None
        download_only = False
        marker_observed = False
        source_observed = False
        sanitized = False
        sinks: list[str] = []
        sockets = 0
        py_peak = 0
        started = time.perf_counter()
        tracemalloc.start()
        context = self._browser.new_context(service_workers="block")
        try:
            context.add_init_script(_SINK_SCRIPT.replace("__BBTK_MARKER__", json.dumps(case.marker)))
            context.route("**/*", lambda route: ledger.apply_http(route))
            context.route_web_socket("**/*", lambda websocket: ledger.apply_websocket(websocket))
            page = context.new_page()

            def on_response(response: Any) -> None:
                response_url = str(response.url).split("#", 1)[0]
                if response_url == url.split("#", 1)[0] and captured["status"] is None:
                    captured["status"] = int(response.status)
                    headers = response.headers
                    captured["content_type"] = headers.get("content-type")
                    captured["csp"] = headers.get("content-security-policy")

            def on_dialog(dialog: Any) -> None:
                nonlocal alert_observed
                message = str(dialog.message)
                dialogs.append(_scrub(f"{dialog.type}:{message}"))
                if dialog.type == "alert" and case.marker in message:
                    alert_observed = True
                dialog.accept()

            page.on("response", on_response)
            page.on("dialog", on_dialog)
            page.on(
                "console",
                lambda message: console_errors.append(_scrub(str(message.text))) if message.type == "error" else None,
            )
            page.on("pageerror", lambda error: page_errors.append(_scrub(str(error))))
            try:
                page.goto(url, wait_until="domcontentloaded", timeout=case.timeout_ms)
            except Exception as exc:
                text = str(exc)
                download_error = type(exc).__name__ == "Error" and "download" in text.lower()
                if "Download is starting" in text or download_error:
                    download_only = True
                else:
                    browser_error = type(exc).__name__
            if browser_error is None and not download_only:
                try:
                    page.wait_for_timeout(150)
                    marker_observed = bool(page.evaluate("marker => window.__bbtk_xss_marker === marker", case.marker))
                    source_observed = bool(
                        page.evaluate(
                            "marker => location.search.includes(marker) || location.hash.includes(marker)",
                            case.marker,
                        )
                    )
                    sanitized = bool(page.evaluate("() => window.__bbtk_sanitized === true"))
                    raw_sinks = page.evaluate("() => window.__bbtk_dom_sinks || []")
                    if isinstance(raw_sinks, list):
                        sinks = [item for item in raw_sinks if isinstance(item, str)]
                except Exception as exc:
                    browser_error = type(exc).__name__
                    page_errors.append(_scrub(str(exc)))
            elif download_only:
                parsed = urlsplit(url)
                source_observed = case.marker in parsed.query or case.marker in parsed.fragment
            sockets = external_socket_count(os.getpid())
            self.external_sockets = max(self.external_sockets, sockets)
            rss = _rss_tree(os.getpid())
            self.peak_rss_bytes = max(self.peak_rss_bytes, rss)
        finally:
            _, py_peak = tracemalloc.get_traced_memory()
            tracemalloc.stop()
            context.close()
        runtime_ms = round((time.perf_counter() - started) * 1000.0, 3)
        csp = captured["csp"] if isinstance(captured["csp"], str) else csp_header
        observation = observation_from_checker(
            {
                "marker_observed": marker_observed,
                "alert_observed": alert_observed,
                "source_marker_present": source_observed,
                "dom_sinks": sinks,
                "sanitized": sanitized,
                "console_errors": console_errors,
                "page_errors": page_errors,
                "browser_failed": browser_error is not None,
                "interaction_required": False,
            },
            csp_header=csp if isinstance(csp, str) else None,
        )
        state = lab_state(observation, reflected=reflected)
        status = captured["status"] if captured["status"] is not None else http_status
        observed_type = captured["content_type"] if isinstance(captured["content_type"], str) else content_type
        evidence = evidence_for(
            case_id=f"{case.letter}-{case.name}",
            lab_label=state,
            observation=observation,
            csp_header=csp if isinstance(csp, str) else None,
            technical_errors=[*console_errors, *page_errors],
        )
        row = {
            "scenario_id": case.letter,
            "letter": case.letter,
            "name": case.name,
            "navigation_url": public_navigation_url(url),
            "origin": _origin(url),
            "status": status,
            "content_type": observed_type.split(";", 1)[0].strip().lower(),
            "source_observed": observation.source_observed,
            "sink_reached": bool(observation.sinks),
            "sinks": list(observation.sinks),
            "marker_execution": observation.marker_executed,
            "csp_error": observation.csp_blocked
            or any("content security policy" in item.lower() for item in console_errors),
            "browser_error": browser_error,
            "runtime_ms": runtime_ms,
            "allowed_requests": ledger.allowed_requests,
            "blocked_requests": ledger.blocked_requests,
            "blocked_external": ledger.blocked_external,
            "websocket_blocked": ledger.websocket_blocked,
            "external_requests": ledger.external_requests,
            "external_sockets": sockets,
            "state": state,
            "reflected_in_body": reflected,
            "download_only": download_only,
            "dialogs": dialogs,
            "measurement": "chromium",
            "python_tracemalloc_peak_bytes": py_peak,
            "evidence": evidence,
            "payload_kind": case.payload_kind,
        }
        sealed = seal(row)
        missing = [key for key in REQUIRED_ROW_FIELDS if key not in sealed]
        if missing:
            raise RuntimeError(f"incomplete instrumentation: {missing}")
        return sealed


def mock_case_row(case: Scenario) -> dict[str, Any]:
    """Fixture row for CI. Not a Chromium measurement."""
    from bugbounty_toolkit.xss.evidence_record import DomObservation

    state = case.expected_browser_state
    observation = DomObservation(
        source_observed=state == "source_observed",
        sinks=("innerHTML",) if state == "sink_reached" else (),
        marker_executed=state == "execution_observed",
        sanitized=state == "sanitized",
        csp_blocked=state == "execution_blocked",
        browser_failed=state == "inconclusive_browser_error",
    )
    # Rebuild via the same state function so the fixture cannot drift from the mapper.
    derived = lab_state(observation, reflected=case.reflected_in_body and state == "reflection_observed")
    if derived != state:
        raise RuntimeError(f"mock fixture for {case.letter} derived {derived}, spec says {state}")
    evidence = evidence_for(
        case_id=f"{case.letter}-{case.name}",
        lab_label=derived,
        observation=observation,
        csp_header="default-src 'none'" if state == "execution_blocked" else None,
        technical_errors=["Content Security Policy blocked inline handler"] if state == "execution_blocked" else [],
    )
    row = {
        "scenario_id": case.letter,
        "letter": case.letter,
        "name": case.name,
        "navigation_url": "http://127.0.0.1/mock",
        "origin": "http://127.0.0.1",
        "status": None if state == "inconclusive_browser_error" else 200,
        "content_type": "application/json" if case.letter == "G" else "text/html",
        "source_observed": observation.source_observed,
        "sink_reached": bool(observation.sinks),
        "sinks": list(observation.sinks),
        "marker_execution": observation.marker_executed,
        "csp_error": observation.csp_blocked,
        "browser_error": "TimeoutError" if state == "inconclusive_browser_error" else None,
        "runtime_ms": 0.0,
        "allowed_requests": 0,
        "blocked_requests": 0,
        "blocked_external": 0,
        "websocket_blocked": 0,
        "external_requests": 0,
        "external_sockets": 0,
        "state": derived,
        "reflected_in_body": case.reflected_in_body,
        "download_only": False,
        "dialogs": [],
        "measurement": "mock_fixture",
        "python_tracemalloc_peak_bytes": 0,
        "evidence": evidence,
        "payload_kind": case.payload_kind,
    }
    return seal(row)


def assert_marker_safe(marker: str) -> None:
    if not marker.startswith("bbtkxss") or not marker.isalnum():
        raise ValueError("refusing a non-synthetic marker")
    payload_for("plain", marker)
