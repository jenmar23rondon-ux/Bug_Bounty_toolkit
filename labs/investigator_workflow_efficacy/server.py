"""Loopback-only disposable app for workflows A, B, and C."""

from __future__ import annotations

import ipaddress
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qs, urlsplit

from .render import render_exchange


class LabServer:
    def __init__(self, cases: list[dict[str, Any]], host: str = "127.0.0.1", port: int = 0) -> None:
        if not ipaddress.ip_address(host).is_loopback:
            raise ValueError("investigator workflow lab binds to loopback only")
        mapping = {str(case["id"]): case for case in cases}
        handler = _handler_factory(mapping)

        class _Bound(ThreadingHTTPServer):
            allow_reuse_address = True

        self.httpd = _Bound((host, port), handler)
        self.thread = threading.Thread(target=self.httpd.serve_forever, name="iwe-lab", daemon=True)

    @property
    def url(self) -> str:
        host, port = self.httpd.server_address[:2]
        if isinstance(host, bytes):
            host = host.decode("ascii")
        return f"http://{host}:{port}"

    def __enter__(self) -> LabServer:
        self.thread.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join(timeout=3)


def _handler_factory(cases: dict[str, dict[str, Any]]) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def do_GET(self) -> None:  # noqa: N802
            parsed = urlsplit(self.path)
            parts = [part for part in parsed.path.split("/") if part]
            if parts == ["health"]:
                self._send(200, {"Content-Type": "application/json"}, b'{"ok":true}')
                return
            if len(parts) == 2 and parts[0] == "lab" and parts[1] in cases:
                role = parse_qs(parsed.query).get("role", ["request"])[0]
                if role not in {"owner", "actor", "request"}:
                    self._send(400, {"Content-Type": "text/plain"}, b"bad role")
                    return
                query = {key: values[0] for key, values in parse_qs(parsed.query).items() if values}
                status, headers, body = render_exchange(cases, cases[parts[1]], role, query)
                payload = body.encode("utf-8")
                headers = dict(headers)
                headers["Content-Length"] = str(len(payload))
                self._send(status, headers, payload)
                return
            self._send(404, {"Content-Type": "text/plain"}, b"not found")

        def _send(self, status: int, headers: dict[str, str], body: bytes) -> None:
            self.send_response(status)
            for key, value in headers.items():
                self.send_header(key, value)
            if "Content-Length" not in headers:
                self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, fmt: str, *args: Any) -> None:
            return

    return Handler


def load_cases(path_text: str) -> list[dict[str, Any]]:
    data = json.loads(path_text)
    cases = data["cases"]
    if not isinstance(cases, list):
        raise ValueError("cases must be a list")
    return cases
