"""Deterministic loopback API fixtures for context-aware discovery planning labs.

Known routes, unknown routes, parameters, wildcard pages, protected endpoints and
ambiguous responses. Binds only to loopback. No credentials, no real data, no
external network. Discovery signals only — never claims a vulnerability.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qs, urlsplit

# Ground-truth route inventory for the lab (also mirrored in labs/context_fuzz_lab/ground_truth.json).
KNOWN_ROUTES: dict[str, tuple[int, dict[str, Any]]] = {
    "/api/v1/health": (200, {"status": "ok"}),
    "/api/v1/orders": (200, {"items": [{"id": "lab-1"}]}),
    "/api/v1/orders/lab-1": (200, {"id": "lab-1", "owner": "fixture"}),
    "/api/v1/users": (200, {"items": [{"id": "lab-u1"}]}),
    "/api/v1/search": (200, {"q": None, "items": []}),
    "/api/v1/status": (200, {"ready": True}),
    "/api/docs": (200, {"openapi": "3.0.0", "paths": ["/api/v1/orders"]}),
    "/healthz": (200, {"status": "ready"}),
}
PROTECTED_ROUTES: dict[str, tuple[int, dict[str, Any]]] = {
    "/api/v1/admin": (401, {"error": "authentication_required"}),
    "/api/v1/internal": (403, {"error": "access_denied"}),
}
WILDCARD_BODY = {"error": "not_found", "wildcard": True}
AMBIGUOUS_BODY = {"message": "ok", "hint": "same shape for many paths"}


class _Handler(BaseHTTPRequestHandler):
    server_version = "BountyToolkit-ContextFuzzLab/1.0"

    def log_message(self, _format: str, *args: Any) -> None:
        return

    def _send(self, status: int, payload: dict[str, Any]) -> None:
        body = json.dumps(payload, sort_keys=True).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Server", "context-fuzz-lab")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        parsed = urlsplit(self.path)
        path = parsed.path
        query = parse_qs(parsed.query, keep_blank_values=True)
        if path in KNOWN_ROUTES:
            status, payload = KNOWN_ROUTES[path]
            if path == "/api/v1/search":
                payload = {"q": (query.get("q", [""])[0])[:64], "items": []}
            self._send(status, payload)
            return
        if path in PROTECTED_ROUTES:
            status, payload = PROTECTED_ROUTES[path]
            self._send(status, payload)
            return
        if path.startswith("/api/v1/wildcard/"):
            self._send(200, WILDCARD_BODY)
            return
        if path.startswith("/api/v1/ambiguous/"):
            self._send(200, AMBIGUOUS_BODY)
            return
        # Unknown routes under /api/v1 return a distinct 404 shape for baseline comparison.
        if path.startswith("/api/"):
            self._send(404, {"error": "not_found", "path": "unknown"})
            return
        self._send(404, {"error": "not_found"})


class _LoopbackHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def make_server(host: str = "127.0.0.1", port: int = 8191) -> ThreadingHTTPServer:
    """Build the fixture server; refuse every non-loopback bind."""
    try:
        address = ipaddress.ip_address(host)
    except ValueError as exc:
        raise ValueError("The context-fuzz lab binds only to an IP loopback address.") from exc
    if not address.is_loopback or type(port) is not int or not 0 <= port <= 65535:
        raise ValueError("The context-fuzz lab binds only to loopback and a valid TCP port.")
    return _LoopbackHTTPServer((host, port), _Handler)


def main() -> None:
    parser = argparse.ArgumentParser(description="Loopback context-aware fuzzing lab API")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8191)
    args = parser.parse_args()
    server = make_server(args.host, args.port)
    print(f"context-fuzz lab listening on http://{args.host}:{args.port}/healthz (loopback only)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
