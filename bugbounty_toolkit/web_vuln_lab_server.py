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
        elif parsed.path == "/sqli/boolean":
            mode = (query.get("mode") or ["stable"])[0]
            self._send(200, "application/json; charset=utf-8", boolean_fixture_body(self.server, mode, value))
        elif parsed.path == "/sqli/fingerprint":
            family = (query.get("family") or [""])[0]
            text = FINGERPRINT_BODIES.get(family)
            if text is None:
                self._send(404, "application/json; charset=utf-8", '{"error":"not_found"}')
            elif "'" in value or '"' in value:
                self._send(200, "text/plain; charset=utf-8", text)
            else:
                self._send(200, "application/json; charset=utf-8", '{"items":[]}')
        elif parsed.path == "/xss/header":
            reflected = (self.headers.get("Referer") or "")[:2048]
            self._send(200, "text/html; charset=utf-8", f"<!doctype html><p>{reflected}</p>")
        else:
            self._send(404, "application/json; charset=utf-8", '{"error":"not_found"}')

    def do_POST(self) -> None:
        parsed = urlsplit(self.path)
        length_header = self.headers.get("Content-Length") or "0"
        try:
            length = int(length_header)
        except ValueError:
            length = 0
        raw = self.rfile.read(max(0, min(length, 8192)))
        text = raw.decode("utf-8", errors="replace")
        if parsed.path == "/xss/json":
            try:
                document = json.loads(text)
            except json.JSONDecodeError:
                self._send(400, "text/plain; charset=utf-8", "invalid json")
                return
            value = document.get("q", "") if isinstance(document, dict) else ""
            reflected = value if isinstance(value, str) else ""
            self._send(200, "text/html; charset=utf-8", f"<!doctype html><p>{reflected}</p>")
            return
        if parsed.path == "/xss/form":
            form = parse_qs(text, keep_blank_values=True)
            value = form.get("q", [""])[0][:2048]
            self._send(200, "text/html; charset=utf-8", f"<!doctype html><p>{value}</p>")
            return
        if parsed.path == "/sqli/json":
            try:
                document = json.loads(text)
            except json.JSONDecodeError:
                self._send(400, "text/plain; charset=utf-8", "invalid json")
                return
            value = document.get("q", "") if isinstance(document, dict) else ""
            text_value = value if isinstance(value, str) else ""
            if "'" in text_value or '"' in text_value:
                self._send(500, "text/plain; charset=utf-8", "You have an error in your SQL syntax")
            else:
                self._send(200, "application/json; charset=utf-8", '{"items":[{"id":"fixture"}]}')
            return
        self._send(404, "application/json; charset=utf-8", '{"error":"not_found"}')


FINGERPRINT_BODIES = {
    "mysql": "You have an error in your SQL syntax",
    "postgresql": "PostgreSQL syntax error at or near SELECT",
    "mssql": "Unclosed quotation mark after the character string",
    "oracle": "ORA-20001: invalid SQL",
    "sqlite": "sqlite3.OperationalError: near token",
}
_BOOLEAN_TRUE = '{"rows":1}'
_BOOLEAN_FALSE = '{"rows":0}'
_BOOLEAN_BASE = '{"rows":"baseline"}'
_BOOLEAN_CHANGED = '{"rows":"baseline-changed"}'
_BOOLEAN_SAME = '{"rows":"same"}'


def boolean_fixture_body(server: object, mode: str, value: str) -> str:
    """Deterministic boolean bodies. No database is queried."""
    counts = getattr(server, "boolean_counts", None)
    if not isinstance(counts, dict):
        counts = {"baseline": 0, "boolean": 0}
        setattr(server, "boolean_counts", counts)
    is_true = "1=1" in value
    is_false = "1=2" in value
    if mode == "second-miss":
        if is_true or is_false:
            counts["boolean"] = int(counts.get("boolean", 0)) + 1
            if int(counts["boolean"]) <= 2:
                return _BOOLEAN_TRUE if is_true else _BOOLEAN_FALSE
            return _BOOLEAN_SAME
        return _BOOLEAN_BASE
    if mode == "unstable":
        if is_true:
            return _BOOLEAN_TRUE
        if is_false:
            return _BOOLEAN_FALSE
        quoted = "'" in value or '"' in value
        delayed = "SLEEP" in value or "pg_sleep" in value or "WAITFOR" in value
        if not quoted and not delayed:
            counts["baseline"] = int(counts.get("baseline", 0)) + 1
            if int(counts["baseline"]) >= 2:
                return _BOOLEAN_CHANGED
        return _BOOLEAN_BASE
    if is_true:
        return _BOOLEAN_TRUE
    if is_false:
        return _BOOLEAN_FALSE
    return _BOOLEAN_BASE


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
