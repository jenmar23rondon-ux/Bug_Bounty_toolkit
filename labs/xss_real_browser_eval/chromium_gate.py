"""Detect whether Playwright can launch Chromium. Never invent a version."""

from __future__ import annotations

import importlib.util
import os
from typing import Any


def probe_chromium() -> dict[str, Any]:
    """Return availability and versions. ``available`` is false when launch fails."""
    if importlib.util.find_spec("playwright") is None:
        return {
            "available": False,
            "reason": "playwright package is not installed",
            "browser_version": None,
            "playwright_version": None,
        }
    import playwright

    try:
        from playwright.sync_api import sync_playwright
    except Exception as exc:
        return {
            "available": False,
            "reason": f"playwright import failed: {type(exc).__name__}",
            "browser_version": None,
            "playwright_version": getattr(playwright, "__version__", None),
        }
    try:
        with sync_playwright() as manager:
            executable = manager.chromium.executable_path
            if not os.path.isfile(executable):
                return {
                    "available": False,
                    "reason": "Playwright Chromium binary is not installed",
                    "browser_version": None,
                    "playwright_version": getattr(playwright, "__version__", None),
                    "executable_present": False,
                }
            browser = manager.chromium.launch(headless=True)
            try:
                version = browser.version
            finally:
                browser.close()
    except Exception as exc:
        return {
            "available": False,
            "reason": f"Chromium launch failed: {type(exc).__name__}",
            "browser_version": None,
            "playwright_version": getattr(playwright, "__version__", None),
        }
    return {
        "available": True,
        "reason": None,
        "browser_version": version,
        "playwright_version": getattr(playwright, "__version__", None),
        "executable_present": True,
    }
