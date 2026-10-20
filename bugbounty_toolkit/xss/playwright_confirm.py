from __future__ import annotations

import importlib.util
from urllib.parse import urlsplit

from ..core.redaction import redact_text
from ..core.rate_limiter import RateLimiter
from ..core.scope_validator import ScopeValidator


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


class PlaywrightExecutionChecker:
    """Run the harmless marker payload in a headless, same-origin-only page."""

    def __init__(self, scope: ScopeValidator, timeout_ms: int = 10000,
                 rate_limiter: RateLimiter | None = None):
        if timeout_ms <= 0:
            raise ValueError("Browser timeout must be positive.")
        self.scope = scope
        self.timeout_ms = timeout_ms
        self.rate_limiter = rate_limiter
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

    def confirm(self, url: str, marker: str, headers: dict[str, str] | None = None) -> dict[str, object]:
        self.scope.require(url)
        if self._browser is None:
            self._start()

        browser_headers = {key: value for key, value in (headers or {}).items()
                           if key.lower() not in {"host", "content-length", "transfer-encoding"}}
        context = self._browser.new_context(extra_http_headers=browser_headers)
        expected_origin = _origin(url)

        def same_origin_only(route) -> None:
            if _origin(route.request.url) == expected_origin:
                try:
                    self.scope.require(route.request.url)
                except ValueError:
                    route.abort()
                    return
                if self.rate_limiter:
                    self.rate_limiter.wait()
                route.continue_()
            else:
                route.abort()

        context.route("**/*", same_origin_only)
        page = context.new_page()
        dialogs: list[dict[str, str]] = []
        console_errors: list[str] = []
        page_errors: list[str] = []

        def on_dialog(dialog) -> None:
            dialogs.append({"type": dialog.type, "text": redact_text(dialog.message)[:300]})
            dialog.accept()

        page.on("dialog", on_dialog)
        page.on("console", lambda message: console_errors.append(redact_text(message.text)[:300])
                 if message.type == "error" else None)
        page.on("pageerror", lambda error: page_errors.append(redact_text(str(error))[:300]))
        try:
            page.goto(url, wait_until="domcontentloaded", timeout=self.timeout_ms)
            # A javascript: payload is exercised only when the page reflected our exact marker.
            page.evaluate("""marker => {
                const link = [...document.querySelectorAll('a[href^="javascript:"]')]
                    .find(item => item.href.includes(marker));
                if (link) link.click();
            }""", marker)
            marker_observed = page.evaluate("marker => window.__bbtk_xss_marker === marker", marker)
            alert_observed = any(item["type"] == "alert" for item in dialogs)
            return {
                "classification": classify_execution(True, bool(marker_observed), alert_observed),
                "marker_observed": bool(marker_observed),
                "alert_observed": alert_observed,
                "dialogs": dialogs,
                "console_errors": console_errors,
                "page_errors": page_errors,
            }
        finally:
            context.close()

    def close(self) -> None:
        if self._browser is not None:
            self._browser.close()
            self._browser = None
        if self._manager is not None:
            self._manager.stop()
            self._manager = None
            self._playwright = None
