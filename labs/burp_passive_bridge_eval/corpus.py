"""Synthetic, runtime-only captures. No network, stored credentials, or Burp dependency."""

from __future__ import annotations

import secrets
from bugbounty_toolkit.burp_passive_bridge import Selection

ORIGIN = "https://lab.invalid"
TIME = "2026-01-01T12:00:00+00:00"


def capture(index: int, *, account: int = 1, missing: bool = False, secret: str = "") -> Selection:
    request = (
        f"GET /items/{index} HTTP/1.1\r\nHost: lab.invalid\r\nCookie: session={account}-{secret}\r\n\r\n"
    ).encode()
    response = ("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n" + '{"item":' + str(index) + "}").encode()
    return Selection(ORIGIN, request, None if missing else response, TIME)


def corpus() -> list[Selection]:
    secret = secrets.token_urlsafe(24)
    return [capture(i, account=1 + i % 2, secret=secret) for i in range(50)]
