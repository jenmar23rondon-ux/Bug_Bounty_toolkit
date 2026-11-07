"""Disposable loopback pages for DOM XSS confirmation.

``/vulnerable`` copies ``location.hash`` or the ``q`` query into ``innerHTML``.
``/safe`` copies the same value into ``textContent``. The HTTP body is static:
the marker is never reflected by the server. The process does not open sockets
except the loopback listener it is asked to bind.
"""

from __future__ import annotations

import ipaddress
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Literal
from urllib.parse import urlsplit

_SINK = Literal["innerHTML", "textContent"]


_VALUE = "const value = new URLSearchParams(location.search).get('q') ?? decodeURIComponent(location.hash.slice(1));"


def _external_image(external_origin: str) -> str:
    if not external_origin:
        return ""
    parsed = urlsplit(external_origin)
    host = parsed.hostname or ""
    try:
        loopback = ipaddress.ip_address(host).is_loopback
    except ValueError:
        loopback = False
    if parsed.scheme != "http" or not loopback:
        raise ValueError("The DOM lab sentinel must be an HTTP loopback origin.")
    return f'<img src="{parsed.scheme}://{parsed.netloc}/third-party" alt="">'


def _document(script: str, external_origin: str) -> bytes:
    # Same-origin asset proves session headers stay on the target origin.
    # The optional image is a different port and must be blocked by the checker.
    body = (
        "<!doctype html><html><body>"
        f'{_external_image(external_origin)}<img src="/session-asset" alt="">'
        f'<div id="sink"></div><script>{script}</script></body></html>'
    )
    return body.encode("utf-8")


def _page(sink: _SINK, external_origin: str) -> bytes:
    assignment = "innerHTML" if sink == "innerHTML" else "textContent"
    return _document(
        _VALUE + f'document.getElementById("sink").{assignment} = value;',
        external_origin,
    )


class DomXssHandler(BaseHTTPRequestHandler):
    """Static DOM pages. Observed session headers stay in memory for the lab test."""

    external_origin: str = ""
    observed: list[dict[str, str]] = []
    lock: threading.Lock = threading.Lock()

    def log_message(self, format: str, *args: object) -> None:
        return

    @classmethod
    def reset(cls) -> None:
        with cls.lock:
            cls.observed.clear()
            cls.external_origin = ""

    @classmethod
    def snapshot(cls) -> list[dict[str, str]]:
        with cls.lock:
            return [dict(item) for item in cls.observed]

    def _remember(self) -> None:
        cookie = self.headers.get("Cookie") or ""
        token = self.headers.get("X-Lab-Token") or ""
        record = {
            "path": urlsplit(self.path).path,
            "cookie": cookie[:200],
            "token": token[:200],
        }
        with self.lock:
            self.observed.append(record)

    def _send(self, status: int, body: bytes, content_type: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        self._remember()
        path = urlsplit(self.path).path
        if path == "/favicon.ico":
            self._send(204, b"", "text/plain")
            return
        if path in {"/favicon.ico", "/session-asset"}:
            self._send(204, b"", "text/plain")
            return
        origin = self.external_origin
        if path == "/vulnerable":
            self._send(200, _page("innerHTML", origin), "text/html; charset=utf-8")
            return
        if path == "/safe":
            self._send(200, _page("textContent", origin), "text/html; charset=utf-8")
            return
        if path == "/unrelated-alert":
            self._send(
                200,
                _document("alert('Welcome');" + _VALUE + 'document.getElementById("sink").innerHTML = value;', origin),
                "text/html; charset=utf-8",
            )
            return
        if path == "/prefixed-alert":
            self._send(
                200,
                _document(
                    _VALUE + "alert('prefix-' + value);" + 'document.getElementById("sink").innerHTML = value;',
                    origin,
                ),
                "text/html; charset=utf-8",
            )
            return
        if path == "/wrong-marker":
            self._send(
                200,
                _document(
                    "window.__bbtk_xss_marker='not-our-marker';alert('not-our-marker');"
                    + _VALUE
                    + 'document.getElementById("sink").innerHTML = value;',
                    origin,
                ),
                "text/html; charset=utf-8",
            )
            return
        if path == "/alert-only":
            self._send(
                200,
                _document(
                    _VALUE + 'document.getElementById("sink").textContent = value;alert(value);',
                    origin,
                ),
                "text/html; charset=utf-8",
            )
            return
        if path == "/bounce":
            self._send(
                200,
                _document("location.replace('/land' + location.search + location.hash);", origin),
                "text/html; charset=utf-8",
            )
            return
        if path == "/land":
            self._send(200, b"<!doctype html><html><body>landed</body></html>", "text/html; charset=utf-8")
            return
        if path == "/redirect-cross":
            target = origin or "http://127.0.0.1:9"
            self._send(
                200,
                _document(f"location.replace({target!r} + '/steal' + location.search);", origin),
                "text/html; charset=utf-8",
            )
            return
        # Same-origin image loads (img src=x) must fail fast so onerror can run.
        self._send(404, b"", "text/plain")


def serve(host: str = "127.0.0.1", port: int = 0) -> ThreadingHTTPServer:
    """Bind a lab listener. Non-loopback hosts are rejected before the socket opens."""
    try:
        address = ipaddress.ip_address(host)
    except ValueError as exc:
        raise ValueError("DOM XSS lab binds to loopback only.") from exc
    if not address.is_loopback:
        raise ValueError("DOM XSS lab binds to loopback only.")
    return ThreadingHTTPServer((host, port), DomXssHandler)
