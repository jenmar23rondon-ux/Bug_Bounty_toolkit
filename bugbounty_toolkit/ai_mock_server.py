"""Deterministic loopback mock for Ollama and OpenAI-compatible chat APIs (tests and benchmarks only).

The mock never calls a real model. A ``behavior`` callable maps the parsed evidence
bundle from the request to a canned reply, so every run is reproducible.
"""

from __future__ import annotations

import json
import threading
import time
from collections.abc import Callable
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

Reply = dict[str, Any]
Behavior = Callable[[dict[str, Any]], Reply]


def assessment(decision: str, cite_for: list[str], cite_against: list[str], **extra: Any) -> dict[str, Any]:
    body: dict[str, Any] = {
        "decision": decision,
        "summary": f"Mock {decision} assessment.",
        "evidence_for": [{"ref": ref, "note": "mock citation"} for ref in cite_for],
        "evidence_against": [{"ref": ref, "note": "mock citation"} for ref in cite_against],
        "unresolved_questions": ["Is the object ownership mapping verified?"],
        "missing_controls": ["owner_baseline_read"],
        "limitations": ["Mock reply."],
    }
    body.update(extra)
    return body


def to_legacy(content: dict[str, Any]) -> dict[str, Any]:
    """Map a v1-shaped mock reply onto the legacy ``REVIEW_SCHEMA`` (extra fields are preserved)."""
    v1_keys = {"evidence_for", "evidence_against", "unresolved_questions", "missing_controls"}
    legacy = {key: value for key, value in content.items() if key not in v1_keys}
    cited = list(content.get("evidence_for", [])) + list(content.get("evidence_against", []))
    legacy["evidence"] = [f"{item.get('ref')}: {item.get('note')}" for item in cited if isinstance(item, dict)][:5]
    legacy.setdefault("limitations", [])
    return legacy


def ref_for(bundle: dict[str, Any], field: str) -> str | None:
    for row in bundle.get("observations", []):
        if row.get("field") == field:
            return str(row["ref"])
    return None


def rule_based(bundle: dict[str, Any]) -> Reply:
    """A faithful deterministic 'model': follows the bundle's own predicates."""
    rows = bundle.get("observations")
    if rows is None:  # legacy packet: top-level fields, refs are the field names
        rows = [{"ref": key, "field": key, "value": value} for key, value in bundle.items()]
    observations = {row["field"]: row for row in rows}
    if observations.get("controls_valid", {}).get("value") is False:
        return {"content": assessment("inconclusive", [], [observations["controls_valid"]["ref"]])}
    private = observations.get("private_evidence_observed")
    controls = observations.get("controls_valid")
    if private and private["value"] is True and controls and controls["value"] is True:
        return {"content": assessment("candidate", [private["ref"], controls["ref"]], [])}
    if private and private["value"] is False and observations.get("cross_read_observed", {}).get("value") is True:
        return {"content": assessment("not_observed", [], [private["ref"]])}
    against = [controls["ref"]] if controls and controls["value"] is False else []
    return {"content": assessment("inconclusive", [], against)}


class MockLocalAIServer:
    """Serve /api/chat, /api/tags, /v1/chat/completions and /v1/models on 127.0.0.1:<ephemeral>."""

    def __init__(self, behavior: Behavior = rule_based, models: tuple[str, ...] = ("mock-model",)) -> None:
        self.behavior = behavior
        self.models = models
        self.requests: list[dict[str, Any]] = []
        self.lock = threading.Lock()
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, format: str, *args: Any) -> None:
                return

            def _send(self, status: int, payload: bytes, headers: dict[str, str] | None = None) -> None:
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                for key, value in (headers or {}).items():
                    self.send_header(key, value)
                self.end_headers()
                try:
                    self.wfile.write(payload)
                except (BrokenPipeError, ConnectionResetError):
                    return

            def do_GET(self) -> None:
                with outer.lock:
                    outer.requests.append({"method": "GET", "path": self.path, "headers": dict(self.headers)})
                if self.path == "/api/tags":
                    self._send(200, json.dumps({"models": [{"name": name} for name in outer.models]}).encode())
                elif self.path == "/v1/models":
                    self._send(200, json.dumps({"data": [{"id": name} for name in outer.models]}).encode())
                else:
                    self._send(404, b"{}")

            def do_POST(self) -> None:
                length = int(self.headers.get("Content-Length", "0"))
                raw = self.rfile.read(length)
                body = json.loads(raw.decode("utf-8"))
                with outer.lock:
                    outer.requests.append(
                        {"method": "POST", "path": self.path, "headers": dict(self.headers), "body": body, "raw": raw}
                    )
                if self.path not in {"/api/chat", "/v1/chat/completions"}:
                    self._send(404, b"{}")
                    return
                if body.get("model") not in outer.models:
                    self._send(404, b'{"error":"model not found"}')
                    return
                user = next((m["content"] for m in body["messages"] if m["role"] == "user"), "")
                start = user.find("{")
                try:
                    bundle = json.loads(user[start:]) if start >= 0 else {}
                except json.JSONDecodeError:
                    bundle = {}
                reply = outer.behavior(bundle)
                if "sleep" in reply:
                    time.sleep(float(reply["sleep"]))
                if "status" in reply:
                    self._send(int(reply["status"]), b"{}", reply.get("headers"))
                    return
                if "raw_envelope" in reply:
                    self._send(200, reply["raw_envelope"])
                    return
                content = reply["content"]
                legacy = "evidence" in body.get("format", {}).get("properties", {})
                if legacy and isinstance(content, dict):
                    content = to_legacy(content)
                text = content if isinstance(content, str) else json.dumps(content)
                complete = reply.get("complete", True)
                if self.path == "/api/chat":
                    envelope: dict[str, Any] = {
                        "model": body["model"],
                        "message": {"role": "assistant", "content": text},
                        "done": complete,
                        "done_reason": "stop" if complete else "length",
                    }
                    if reply.get("tool_calls"):
                        envelope["message"]["tool_calls"] = [{"function": {"name": "shell"}}]
                else:
                    message: dict[str, Any] = {"role": "assistant", "content": text}
                    if reply.get("tool_calls"):
                        message["tool_calls"] = [{"type": "function", "function": {"name": "shell"}}]
                    envelope = {
                        "model": body["model"],
                        "choices": [
                            {"index": 0, "message": message, "finish_reason": "stop" if complete else "length"}
                        ],
                    }
                self._send(200, json.dumps(envelope).encode())

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.server.daemon_threads = True
        self.port = int(self.server.server_address[1])
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def __enter__(self) -> MockLocalAIServer:
        self.thread.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self.server.shutdown()
        self.server.server_close()
