"""Deterministic loopback-only HTTP application for the IDOR/BOLA lab."""

from __future__ import annotations

import argparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import ipaddress
import json
from typing import Any
from urllib.parse import parse_qs, urlsplit


TOKENS = {"owner": "lab-owner-token", "actor": "lab-actor-token"}
ORDERS = {
    "1001": {"id": "1001", "marker": "owner-order-marker-1001"},
    "1002": {"id": "1002", "marker": "actor-order-marker-1002"},
}


class _Handler(BaseHTTPRequestHandler):
    """Serve fixed lab fixtures without logging credentials or request bodies."""

    server_version = "BountyToolkit-IDOR-Lab/1.0"

    def log_message(self, _format: str, *args: Any) -> None:
        return

    def _send_json(self, status: int, body: dict[str, Any], authorization: str | None = None) -> None:
        encoded = json.dumps(body, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(encoded)))
        if authorization is not None:
            self.send_header("Authorization", authorization)
        self.end_headers()
        self.wfile.write(encoded)

    def do_POST(self) -> None:
        if urlsplit(self.path).path != "/login":
            self._send_json(404, {"success": False})
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length < 1 or length > 8192:
                self._send_json(413, {"success": False, "error": "invalid_body_size"})
                return
            body = json.loads(self.rfile.read(length))
        except (ValueError, json.JSONDecodeError):
            self._send_json(400, {"success": False, "error": "invalid_json"})
            return
        user = body.get("user") if isinstance(body, dict) else None
        token = TOKENS.get(user) if isinstance(user, str) else None
        if token is None:
            self._send_json(401, {"success": False})
            return
        self._send_json(200, {"success": True, "user": user}, f"Bearer {token}")

    def do_GET(self) -> None:
        parsed = urlsplit(self.path)
        query = parse_qs(parsed.query, keep_blank_values=True)
        if parsed.path == "/healthz":
            self._send_json(200, {"success": True, "status": "ready"})
            return
        if parsed.path == "/api/public/status":
            resource_id = query.get("id", [None])[0]
            if resource_id in ORDERS:
                self._send_json(
                    200,
                    {
                        "success": True,
                        "data": {
                            "id": resource_id,
                            "marker": f"public-status-marker-{resource_id}",
                        },
                    },
                )
                return
            self._send_json(200, {"success": True, "data": {"status": "ok"}})
            return
        segments = parsed.path.strip("/").split("/")
        if len(segments) != 3 or segments[:2] != ["api", "orders"]:
            self._send_json(404, {"success": False})
            return
        supplied = self.headers.get("Authorization", "")
        user = next((name for name, token in TOKENS.items() if supplied == f"Bearer {token}"), None)
        if user is None:
            self._send_json(401, {"success": False})
            return
        resource_id = segments[2]
        if resource_id not in ORDERS:
            self._send_json(404, {"success": False})
            return
        # Deliberate lab flaw: actor can read owner order 1001. Owner cannot read actor order.
        if user == "owner" and resource_id != "1001":
            self._send_json(403, {"success": False})
            return
        data: dict[str, str | bool] = dict(ORDERS[resource_id])
        if query.get("debug") == ["1"]:
            data["debug"] = True
        self._send_json(200, {"success": True, "data": data})


class _LoopbackHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def make_server(host: str = "127.0.0.1", port: int = 8099) -> ThreadingHTTPServer:
    """Create the lab server only on a loopback address; port zero selects a free port."""
    try:
        address = ipaddress.ip_address(host)
    except ValueError as exc:
        raise ValueError("The IDOR lab binds only to an IP loopback address.") from exc
    if not address.is_loopback or type(port) is not int or not 0 <= port <= 65535:
        raise ValueError("The IDOR lab binds only to loopback and a valid TCP port.")
    return _LoopbackHTTPServer((host, port), _Handler)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8099)
    args = parser.parse_args()
    server = make_server(args.host, args.port)
    port = server.server_address[1]
    print(f"IDOR lab listening on http://{args.host}:{port} (loopback only)", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
