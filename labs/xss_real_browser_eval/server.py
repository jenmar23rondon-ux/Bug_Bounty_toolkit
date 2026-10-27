"""Disposable loopback server for XSS browser scenarios A–P.

The process binds ``127.0.0.1`` only and never opens an outbound socket.
Payloads are reflected or read by page scripts. Nothing here writes cookies,
``localStorage``, or an exfiltration request.
"""

from __future__ import annotations

import html
import json
import threading
import time
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Mapping
from urllib.parse import parse_qs, urlsplit

from .spec import EXTERNAL_PROBE_HTTP, EXTERNAL_PROBE_WS

CSP_BLOCK = "default-src 'none'; script-src 'none'; object-src 'none'; base-uri 'none'; img-src 'none'"
# Long enough that a 1s navigation budget expires first. The handler returns;
# it does not spin.
HOLD_SECONDS = 5.0


def js_string_escape(value: str) -> str:
    return (
        value.replace("\\", "\\\\")
        .replace('"', '\\"')
        .replace("'", "\\'")
        .replace("\r", "\\r")
        .replace("\n", "\\n")
        .replace("<", "\\u003c")
        .replace(">", "\\u003e")
    )


def _page(inner: str) -> str:
    return "<!doctype html><html><body>" + inner + "</body></html>"


@dataclass(frozen=True)
class Rendered:
    status: int
    content_type: str
    headers: tuple[tuple[str, str], ...]
    body: bytes


def render_endpoint(path: str, value: str) -> Rendered:
    """Return the bytes for one lab route. ``value`` is the decoded ``q`` parameter."""
    extra: list[tuple[str, str]] = []
    if path == "/a":
        body, content_type = _page(value), "text/html; charset=utf-8"
    elif path == "/b":
        body, content_type = _page(f"<p>{html.escape(value)}</p>"), "text/html; charset=utf-8"
    elif path == "/c":
        escaped = html.escape(value, quote=True)
        body, content_type = _page(f'<input id="q" value="{escaped}">'), "text/html; charset=utf-8"
    elif path == "/d":
        body, content_type = _page(f'<input id="q" value="{value}">'), "text/html; charset=utf-8"
    elif path == "/e":
        body = _page(f'<script>var q = "{js_string_escape(value)}";</script>')
        content_type = "text/html; charset=utf-8"
    elif path == "/f":
        body = _page(f'<script>var q = "{value}";</script>')
        content_type = "text/html; charset=utf-8"
    elif path == "/g":
        body = json.dumps({"q": value, "note": "non-executing-json"}, separators=(",", ":"))
        content_type = "application/json; charset=utf-8"
    elif path == "/h":
        body = _page(
            "<div id='out'></div><script>"
            "var value = decodeURIComponent((location.hash || '').replace(/^#/, ''));"
            "document.getElementById('out').innerHTML = value;"
            "</script>"
        )
        content_type = "text/html; charset=utf-8"
    elif path == "/i":
        body = _page(
            "<div id='out'></div><script>"
            "var value = new URLSearchParams(location.search).get('q') || '';"
            "document.getElementById('out').innerHTML = value;"
            "</script>"
        )
        content_type = "text/html; charset=utf-8"
    elif path == "/j":
        body = _page(
            "<div id='out'></div><script>"
            "var raw = new URLSearchParams(location.search).get('q') || '';"
            "var clean = raw.replace(/[<>\"'`]/g, '');"
            "if (clean !== raw) window.__bbtk_sanitized = true;"
            "document.getElementById('out').innerHTML = clean;"
            "</script>"
        )
        content_type = "text/html; charset=utf-8"
    elif path == "/k":
        body = _page(
            "<div id='out'></div><script>"
            "var value = new URLSearchParams(location.search).get('q') || '';"
            "document.getElementById('out').textContent = value;"
            "</script>"
        )
        content_type = "text/html; charset=utf-8"
    elif path == "/l":
        literal = json.dumps(value)
        body = _page(f"<div id='out'></div><script>document.getElementById('out').innerHTML = {literal};</script>")
        content_type = "text/html; charset=utf-8"
    elif path == "/m":
        body, content_type = _page(value), "text/html; charset=utf-8"
        extra.append(("Content-Security-Policy", CSP_BLOCK))
    elif path == "/n":
        body, content_type = _page(f"<p>{html.escape(value)}</p>"), "text/html; charset=utf-8"
    elif path == "/o":
        body = _page(
            f"<p>{html.escape(value)}</p>"
            f"<img src='{EXTERNAL_PROBE_HTTP}' alt=''>"
            "<script>"
            f"fetch({json.dumps(EXTERNAL_PROBE_HTTP)}).catch(function(){{}}"
            ");"
            f"try{{new WebSocket({json.dumps(EXTERNAL_PROBE_WS)});}}catch(e){{}}"
            "</script>"
        )
        content_type = "text/html; charset=utf-8"
    elif path == "/p-hold":
        time.sleep(HOLD_SECONDS)
        body, content_type = "", "text/javascript; charset=utf-8"
    elif path == "/p":
        # Document returns immediately. A same-origin script never arrives within the
        # navigation budget, so the browser reports a timeout instead of execution.
        body = _page(f"<p>{html.escape(value)}</p><script src='/p-hold'></script>")
        content_type = "text/html; charset=utf-8"
    else:
        body, content_type = "not found", "text/plain; charset=utf-8"
        return Rendered(404, content_type, (("X-Content-Type-Options", "nosniff"),), body.encode("utf-8"))

    encoded = body.encode("utf-8")
    headers = [
        ("X-Content-Type-Options", "nosniff"),
        ("Cache-Control", "no-store"),
        *extra,
    ]
    return Rendered(200, content_type, tuple(headers), encoded)


class LabHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlsplit(self.path)
        value = parse_qs(parsed.query, keep_blank_values=True).get("q", [""])[0]
        rendered = render_endpoint(parsed.path, value)
        self.send_response(rendered.status)
        self.send_header("Content-Type", rendered.content_type)
        self.send_header("Content-Length", str(len(rendered.body)))
        for name, header_value in rendered.headers:
            self.send_header(name, header_value)
        self.end_headers()
        try:
            self.wfile.write(rendered.body)
        except BrokenPipeError:
            # Scenario P aborts /p-hold when the navigation budget expires.
            return

    def log_message(self, format: str, *args: object) -> None:
        return


class LoopbackLab:
    """Serve endpoints A–P on an ephemeral ``127.0.0.1`` port."""

    def __init__(self) -> None:
        self._httpd = ThreadingHTTPServer(("127.0.0.1", 0), LabHandler)
        self._thread: threading.Thread | None = None

    @property
    def base_url(self) -> str:
        host, port = self._httpd.server_address[:2]
        if str(host) != "127.0.0.1":
            raise RuntimeError("lab server must bind 127.0.0.1")
        return f"http://127.0.0.1:{int(port)}"

    def start(self) -> str:
        if self._thread is not None:
            return self.base_url
        self._thread = threading.Thread(target=self._httpd.serve_forever, name="xss-browser-lab", daemon=True)
        self._thread.start()
        return self.base_url

    def close(self) -> None:
        self._httpd.shutdown()
        if self._thread is not None:
            self._thread.join(timeout=5)
            self._thread = None
        self._httpd.server_close()

    def __enter__(self) -> LoopbackLab:
        self.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()


def header_map(rendered: Rendered) -> Mapping[str, str]:
    return dict(rendered.headers)
