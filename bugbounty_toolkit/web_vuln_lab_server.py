"""Deterministic loopback-only XSS/SQLi fixtures; no browser or database is used."""

from __future__ import annotations

import argparse
from html import escape
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import ipaddress
import json
from typing import Any
from urllib.parse import parse_qs, urlsplit


class _Handler(BaseHTTPRequestHandler):
    """Serve fixed vulnerability fixtures without logging query values."""

    server_version = "BountyToolkit-WebLab/1.0"

    def log_message(self, _format: str, *args: Any) -> None:
        return

    def _send(self, status: int, content_type: str, body: str) -> None:
        encoded = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def do_GET(self) -> None:
        parsed = urlsplit(self.path)
        query = parse_qs(parsed.query, keep_blank_values=True)
        value = query.get("q", [""])[0][:2048]

        if parsed.path == "/healthz":
            self._send(200, "application/json; charset=utf-8", '{"status":"ready"}')
        elif parsed.path == "/xss/reflected":
            body = (
                "<!doctype html><p>static fixture response</p>"
                if query.get("mode") == ["missing"]
                else f"<!doctype html><p>{value}</p>"
            )
            self._send(200, "text/html; charset=utf-8", body)
        elif parsed.path == "/xss/escaped":
            self._send(200, "text/html; charset=utf-8", f"<!doctype html><p>{escape(value)}</p>")
        elif parsed.path == "/xss/ambiguous":
            self._send(200, "application/json; charset=utf-8", json.dumps({"preview": value}))
        elif parsed.path == "/sqli/vulnerable":
            # Deliberately simulate an error signature; this route has no database.
            if "'" in value or '"' in value:
                self._send(500, "text/plain; charset=utf-8", "You have an error in your SQL syntax")
            else:
                self._send(200, "application/json; charset=utf-8", '{"items":[{"id":"fixture"}]}')
        elif parsed.path == "/sqli/protected":
            # Fixed output models parameterized handling and never parses SQL.
            self._send(200, "application/json; charset=utf-8", '{"items":[]}')
        elif parsed.path == "/sqli/ambiguous":
            # A generic server error is a negative/ambiguous control, not a SQL signature.
            self._send(500, "text/plain; charset=utf-8", "Temporary fixture service error")
        else:
            self._send(404, "application/json; charset=utf-8", '{"error":"not_found"}')


class _LoopbackHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def make_server(host: str = "127.0.0.1", port: int = 8181) -> ThreadingHTTPServer:
    """Build a deterministic fixture server, refusing every non-loopback bind."""
    try:
        address = ipaddress.ip_address(host)
    except ValueError as exc:
        raise ValueError("The web vulnerability lab binds only to an IP loopback address.") from exc
    if not address.is_loopback or type(port) is not int or not 0 <= port <= 65535:
        raise ValueError("The web vulnerability lab binds only to loopback and a valid TCP port.")
    return _LoopbackHTTPServer((host, port), _Handler)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8181)
    args = parser.parse_args()
    server = make_server(args.host, args.port)
    print(
        f"Web vulnerability lab listening on http://{args.host}:{server.server_address[1]} (loopback only)", flush=True
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
