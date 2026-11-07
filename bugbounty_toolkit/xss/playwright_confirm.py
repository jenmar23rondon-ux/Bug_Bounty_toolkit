from __future__ import annotations

import importlib.util
import json
import os
import signal
import threading
from urllib.parse import urlsplit
from typing import Any

from ..core.redaction import redact_text
from ..core.rate_limiter import RateLimiter
from ..core.scope_validator import ScopeValidator
from ..core.execution_budget import ExecutionBudget
from ..utils.exceptions import ToolkitError


def _browser_child_pids(root_pid: int) -> set[int]:
    """Chromium processes descended from ``root_pid``. Empty when /proc is unavailable."""
    if not os.path.isdir("/proc"):
        return set()
    children: dict[int, list[int]] = {}
    for name in os.listdir("/proc"):
        if not name.isdigit():
            continue
        pid = int(name)
        try:
            with open(os.path.join("/proc", name, "status"), encoding="utf-8", errors="replace") as handle:
                status = handle.read()
        except OSError:
            continue
        ppid: int | None = None
        for line in status.splitlines():
            if line.startswith("PPid:"):
                ppid = int(line.split()[1])
                break
        if ppid is not None:
            children.setdefault(ppid, []).append(pid)
    found: set[int] = set()
    stack = [root_pid]
    while stack:
        current = stack.pop()
        for child in children.get(current, ()):
            if child not in found:
                found.add(child)
                stack.append(child)
    browsers: set[int] = set()
    for pid in found:
        try:
            with open(os.path.join("/proc", str(pid), "cmdline"), "rb") as handle:
                command = handle.read()
        except OSError:
            continue
        if b"chrome" in command or b"chromium" in command or b"headless_shell" in command:
            browsers.add(pid)
    return browsers


def _kill_browser_children(root_pid: int) -> None:
    for pid in _browser_child_pids(root_pid):
        try:
            os.kill(pid, signal.SIGKILL)
        except OSError:
            pass


def require_playwright_installed() -> None:
    if importlib.util.find_spec("playwright") is None:
        raise RuntimeError(
            "--confirm-exec requires Playwright. Install it with "
            "'python -m pip install -e .[xss]' and install Chromium with "
            "'python -m playwright install chromium'."
        )


def classify_execution(reflected: bool, marker_observed: bool, alert_observed: bool) -> str:
    if marker_observed or alert_observed:
        return "confirmed"
    return "reflected_not_executed" if reflected else "not_reflected"


def _origin(url: str) -> tuple[str, str, int | None]:
    parsed = urlsplit(url)
    scheme = parsed.scheme.lower()
    port = parsed.port or (443 if scheme == "https" else 80 if scheme == "http" else None)
    return scheme, (parsed.hostname or "").lower(), port


def _session_cookies(url: str, cookie_header: str) -> list[dict[str, str]]:
    """Playwright cookies for this navigation origin. Values are not logged."""
    parsed = urlsplit(url.split("#", 1)[0])
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("Session cookies require an absolute http(s) URL.")
    origin = f"{parsed.scheme}://{parsed.netloc}/"
    cookies: list[dict[str, str]] = []
    for part in cookie_header.split(";"):
        piece = part.strip()
        if not piece:
            continue
        if "=" not in piece:
            raise ValueError("Session cookie must be name=value.")
        name, value = piece.split("=", 1)
        name = name.strip()
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'"}:
            value = value[1:-1]
        if not name or any(char in name for char in "\r\n;,"):
            raise ValueError("Session cookie name is invalid.")
        if any(char in value for char in "\r\n"):
            raise ValueError("Session cookie value is invalid.")
        cookies.append({"name": name, "value": value, "url": origin})
    if not cookies:
        raise ValueError("Session cookie header was empty.")
    return cookies


_DOM_MARKER_PRESENT = """marker => {
  const root = document.documentElement;
  if (!root) return false;
  if (String(root.innerHTML).includes(marker)) return true;
  const body = document.body;
  return !!(body && typeof body.innerText === 'string' && body.innerText.includes(marker));
}"""


class _BrowserRequestBudget:
    """Apply scope, cadence, and shared execution leases to browser requests."""

    def __init__(
        self,
        scope: ScopeValidator,
        expected_origin: tuple[str, str, int | None],
        budget: ExecutionBudget | None,
        rate_limiter: RateLimiter | None,
        initial_url: str = "",
        observed_sinks: set[str] | None = None,
    ) -> None:
        self.scope = scope
        self.expected_origin = expected_origin
        self.initial_url = initial_url
        self.budget = budget
        self.rate_limiter = rate_limiter
        self.observed_sinks = observed_sinks if observed_sinks is not None else set()
        self.error: Exception | None = None
        self._pending: dict[tuple[str, str, str], list[Any]] = {}
        self._lock = threading.Lock()

    @staticmethod
    def _key(request: Any) -> tuple[str, str, str]:
        return request.url, request.method, request.resource_type

    def handle(self, route: Any) -> None:
        request = route.request
        lease = None
        started = False
        try:
            is_navigation = getattr(request, "is_navigation_request", None)
            if callable(is_navigation) and is_navigation() and request.url != self.initial_url:
                self.observed_sinks.add("location")
            if _origin(request.url) != self.expected_origin:
                route.abort()
                return
            try:
                self.scope.require(request.url)
            except ValueError:
                route.abort()
                return
            if self.budget is not None:
                lease = self.budget.try_acquire(request.url)
                if lease is None:
                    navigation = callable(is_navigation) and is_navigation()
                    if navigation:
                        self.error = ToolkitError("Run concurrency limit blocked the browser navigation.")
                    route.abort()
                    return
            remaining = self.budget.remaining_seconds() if self.budget is not None else None
            if self.rate_limiter is not None:
                self.rate_limiter.wait(max_wait=remaining)
            if lease is not None:
                lease.start()
                started = True
                with self._lock:
                    self._pending.setdefault(self._key(request), []).append(lease)
            try:
                route.continue_()
            except Exception:
                if lease is not None and started:
                    self._forget(request, lease)
                    lease.finish(False)
                    lease.release()
                raise
        except Exception as exc:
            if lease is not None and not started:
                lease.release()
            self.error = exc
            try:
                route.abort()
            except Exception:
                pass

    def finish(self, request: Any, successful: bool) -> None:
        with self._lock:
            leases = self._pending.get(self._key(request))
            lease = leases.pop(0) if leases else None
            if leases == []:
                self._pending.pop(self._key(request), None)
        if lease is not None:
            lease.finish(successful)
            if self.budget is not None:
                self.budget.observe_completion()
            lease.release()

    def _forget(self, request: Any, lease: Any) -> None:
        with self._lock:
            key = self._key(request)
            leases = self._pending.get(key, [])
            if lease in leases:
                leases.remove(lease)
            if not leases:
                self._pending.pop(key, None)

    def close(self) -> None:
        with self._lock:
            pending = [lease for leases in self._pending.values() for lease in leases]
            self._pending.clear()
        for lease in pending:
            lease.finish(False)
            lease.release()


class PlaywrightExecutionChecker:
    """Run the harmless marker payload in a headless, same-origin-only page."""

    def __init__(
        self,
        scope: ScopeValidator,
        timeout_ms: int = 10000,
        rate_limiter: RateLimiter | None = None,
        execution_budget: ExecutionBudget | None = None,
    ):
        if timeout_ms <= 0:
            raise ValueError("Browser timeout must be positive.")
        self.scope = scope
        self.timeout_ms = timeout_ms
        self.rate_limiter = rate_limiter
        self.execution_budget = execution_budget
        self._manager = None
        self._playwright = None
        self._browser = None

    def _start(self) -> None:
        require_playwright_installed()
        try:
            from playwright.sync_api import sync_playwright

            self._manager = sync_playwright()
            self._playwright = self._manager.start()
            self._browser = self._playwright.chromium.launch(headless=True)
        except Exception as exc:
            self.close()
            if "playwright" in str(exc).lower() or "executable" in str(exc).lower():
                raise RuntimeError(
                    "Playwright Chromium is unavailable. Run 'python -m playwright install chromium'."
                ) from exc
            raise RuntimeError(f"Could not start headless Playwright: {type(exc).__name__}") from exc

    def confirm(
        self,
        url: str,
        marker: str,
        headers: dict[str, str] | None = None,
        *,
        local_only: bool = False,
        dom: bool = False,
    ) -> dict[str, object]:
        """Load one in-scope URL and report marker, alert, and DOM-sink observations.

        ``local_only`` still requires a literal loopback URL. ``dom`` is the
        in-scope DOM mode: same origin guard and shared budget, no loopback
        requirement. It does not treat a sink or a DOM reflection as execution.
        """
        if local_only:
            from .dom_local import require_literal_loopback

            require_literal_loopback(url.split("#", 1)[0])
        self.scope.require(url)
        if self._browser is None:
            self._start()

        cookie_header: str | None = None
        if dom:
            browser_headers = {}
            for key, value in (headers or {}).items():
                lowered = key.lower()
                if lowered in {"host", "content-length", "transfer-encoding"}:
                    continue
                if lowered == "cookie":
                    cookie_header = value
                    continue
                browser_headers[key] = value
        else:
            browser_headers = {
                key: value
                for key, value in (headers or {}).items()
                if key.lower() not in {"host", "content-length", "transfer-encoding"}
            }
        context = self._browser.new_context(
            extra_http_headers=browser_headers,
            service_workers="block",
        )
        if cookie_header:
            try:
                context.add_cookies(_session_cookies(url, cookie_header))
            except Exception as exc:
                context.close()
                if isinstance(exc, ValueError):
                    raise ToolkitError(str(exc)) from None
                raise ToolkitError("Could not apply the session cookie to the browser context.") from None
        expected_origin = _origin(url)
        observed_sinks: set[str] = set()
        request_budget = _BrowserRequestBudget(
            self.scope,
            expected_origin,
            self.execution_budget,
            self.rate_limiter,
            url.split("#", 1)[0],
            observed_sinks,
        )
        init_script = """(() => {
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
            })();""".replace("__BBTK_MARKER__", json.dumps(marker))
        context.add_init_script(init_script)
        context.route("**/*", request_budget.handle)
        blocked_websockets = 0

        def block_websocket(_websocket: Any) -> None:
            nonlocal blocked_websockets
            blocked_websockets += 1
            # An intercepted socket never connects unless connect_to_server() is called.
            # Calling close() inside the synchronous callback can deadlock Playwright.

        context.route_web_socket("**/*", block_websocket)
        page = context.new_page()
        page.on("requestfinished", lambda request: request_budget.finish(request, True))
        page.on("requestfailed", lambda request: request_budget.finish(request, False))
        dialogs: list[dict[str, str]] = []
        console_errors: list[str] = []
        page_errors: list[str] = []
        matching_alert_observed = False

        def on_dialog(dialog: Any) -> None:
            nonlocal matching_alert_observed
            # Dismiss first. Redaction or a stuck accept must not leave the modal
            # up: Playwright pauses navigation until the dialog is gone, and that
            # pause ignores the goto timeout.
            try:
                message = str(dialog.message)
            except Exception:
                message = ""
            try:
                dialog.accept()
            except Exception:
                pass
            matching_alert_observed |= dialog.type == "alert" and message == marker
            dialogs.append({"type": dialog.type, "text": (redact_text(message) or "")[:300]})

        page.on("dialog", on_dialog)
        page.on(
            "console",
            lambda message: console_errors.append(redact_text(message.text)[:300]) if message.type == "error" else None,
        )
        page.on("pageerror", lambda error: page_errors.append(redact_text(str(error))[:300]))
        try:
            remaining = self.execution_budget.remaining_seconds() if self.execution_budget is not None else None
            timeout_ms = (
                min(self.timeout_ms, max(1, int(remaining * 1000))) if remaining is not None else self.timeout_ms
            )
            try:
                page.goto(url, wait_until="domcontentloaded", timeout=timeout_ms)
            except Exception as exc:
                if request_budget.error is not None:
                    raise request_budget.error
                if self.execution_budget is not None:
                    self.execution_budget.remaining_seconds()
                raise ToolkitError(f"Headless browser navigation failed: {type(exc).__name__}") from None
            if request_budget.error is not None:
                raise request_budget.error
            # A javascript: payload is exercised only when the page reflected our exact marker.
            page.evaluate(
                """marker => {
                const link = [...document.querySelectorAll('a[href^="javascript:"]')]
                    .find(item => item.href.includes(marker));
                if (link) link.click();
            }""",
                marker,
            )
            if local_only or dom:
                # Give bounded event-driven DOM updates a chance to run.
                # local_only keeps the historical 300ms cap; dom uses the same cap.
                try:
                    page.wait_for_function(
                        "marker => window.__bbtk_xss_marker === marker",
                        arg=marker,
                        timeout=min(timeout_ms, 300),
                    )
                except Exception as exc:
                    if type(exc).__name__ != "TimeoutError":
                        raise
            marker_observed = page.evaluate("marker => window.__bbtk_xss_marker === marker", marker)
            observe_source = local_only or dom
            source_marker_present = (
                bool(
                    page.evaluate(
                        "marker => location.search.includes(marker) || location.hash.includes(marker)", marker
                    )
                )
                if observe_source
                else False
            )
            dom_marker_present = bool(page.evaluate(_DOM_MARKER_PRESENT, marker)) if dom else False
            observed_sinks.update(page.evaluate("() => window.__bbtk_dom_sinks || []"))
            if request_budget.error is not None:
                raise request_budget.error
            if self.execution_budget is not None:
                self.execution_budget.remaining_seconds()
            alert_observed = matching_alert_observed
            result: dict[str, object] = {
                "classification": classify_execution(True, bool(marker_observed), alert_observed),
                "marker_observed": bool(marker_observed),
                "source_marker_present": source_marker_present,
                "alert_observed": alert_observed,
                "blocked_websockets": blocked_websockets,
                "dom_sinks": sorted(observed_sinks),
                "dialogs": dialogs,
                "console_errors": console_errors,
                "page_errors": page_errors,
            }
            if dom:
                # Additive. Callers that do not pass dom=True keep the previous keys.
                result["dom_marker_present"] = dom_marker_present
            return result
        finally:
            try:
                context.close()
            finally:
                request_budget.close()

    def close(self) -> None:
        browser = self._browser
        self._browser = None
        if browser is not None:
            try:
                browser.close()
            except Exception:
                _kill_browser_children(os.getpid())
        manager = self._manager
        self._manager = None
        self._playwright = None
        if manager is None:
            return
        # A failed start() has no connection; calling __exit__ then raises AttributeError.
        if getattr(manager, "_connection", None) is None:
            return
        try:
            # Playwright Sync API: ContextManager exposes start()/__exit__, not stop().
            manager.__exit__(None, None, None)
        except Exception:
            _kill_browser_children(os.getpid())
