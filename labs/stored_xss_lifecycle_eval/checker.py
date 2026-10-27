"""Browser stand-in for the stored-XSS lifecycle lab.

``run_stored_local`` calls ``checker.confirm``. This mock performs the loopback
GET that stands in for navigation and never reports marker execution. Live
Chromium remains ``NOT_MEASURED`` when the browser binary is absent.
"""

from __future__ import annotations

import socket
from typing import Mapping
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from bugbounty_toolkit.utils.exceptions import ToolkitError
from bugbounty_toolkit.xss.dom_local import require_literal_loopback


class MockLoopbackChecker:
    """Loopback navigation without a browser and without an execution claim."""

    def __init__(self, timeout_s: float = 5.0) -> None:
        if timeout_s <= 0:
            raise ValueError("Browser timeout must be positive.")
        self.timeout_s = timeout_s
        self.mode = "mock"
        self.last: dict[str, object] | None = None

    def confirm(
        self,
        url: str,
        marker: str,
        headers: Mapping[str, str] | None = None,
        *,
        local_only: bool = False,
    ) -> dict[str, object]:
        del marker, local_only
        target = url.split("#", 1)[0]
        require_literal_loopback(target)
        safe_headers = {
            key: value
            for key, value in (headers or {}).items()
            if key.lower() not in {"host", "content-length", "transfer-encoding", "cookie", "authorization"}
        }
        request = Request(target, headers=safe_headers, method="GET")
        try:
            with urlopen(request, timeout=self.timeout_s) as response:
                response.read(65_536)
        except HTTPError as exc:
            exc.read(65_536)
        except (TimeoutError, socket.timeout) as exc:
            self.last = _unmeasured_error(type(exc).__name__)
            raise ToolkitError(f"Headless browser navigation failed: {type(exc).__name__}") from None
        except URLError as exc:
            reason = exc.reason
            name = type(reason).__name__ if reason is not None else type(exc).__name__
            self.last = _unmeasured_error(name)
            if isinstance(reason, (TimeoutError, socket.timeout)):
                raise ToolkitError(f"Headless browser navigation failed: {name}") from None
            raise ToolkitError(f"Headless browser navigation failed: {name}") from None
        # The mock fetched the view. It did not run JavaScript.
        observed = {
            "classification": "not_executed_mock",
            "marker_observed": False,
            "alert_observed": False,
            "source_marker_present": False,
            "dom_sinks": [],
            "dialogs": [],
            "console_errors": [],
            "page_errors": [],
            "browser_mode": "mock",
            "live_execution": "NOT_MEASURED",
        }
        self.last = observed
        return observed

    def close(self) -> None:
        return


def _unmeasured_error(name: str) -> dict[str, object]:
    return {
        "marker_observed": False,
        "alert_observed": False,
        "browser_mode": "mock",
        "browser_error": name[:80],
        "live_execution": "NOT_MEASURED",
    }
