"""Disposable in-memory comment fixture for the stored-XSS lifecycle lab.

Loopback only. No database, no cookies, no third-party callbacks. Each test
configures one scenario, then deletes every record before the next test.
"""

from __future__ import annotations

import hashlib
import json
import re
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass
from html import escape
from html.parser import HTMLParser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Iterator
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qs, urlsplit
from urllib.request import Request, urlopen
import ipaddress

MARKER_RE = re.compile(r"bbtkxss[0-9a-fA-F]{12}")
TAG_RE = re.compile(r"<[^>]*>")
STORAGE_ID_RE = re.compile(r"^cmt-[0-9]+$")

SCENARIOS = frozenset(
    {
        "saved_never_rendered",
        "reflect_on_write_only",
        "safe_text",
        "html_escaped_on_render",
        "sanitize_on_save",
        "sanitize_on_render",
        "chromium_execution",
        "marker_present_no_execution",
        "csp_block",
        "second_user_view",
        "wrong_permissions",
        "not_found",
        "write_ok_view_missing",
        "write_rejected",
        "truncated_persist",
        "browser_timeout",
        "interaction_required",
    }
)

_MAX_BODY = 65_536
_CSP = "default-src 'none'; script-src 'none'; img-src 'none'"


class _ImgParser(HTMLParser):
    """Detect a real ``<img onerror>`` element. Script data is not markup."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.executable = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag.lower() != "img":
            return
        for name, _value in attrs:
            if name.lower() == "onerror":
                self.executable = True


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _marker_present(text: str) -> bool:
    return MARKER_RE.search(text) is not None


def _executable_img(body: str, content_type: str) -> bool:
    if not content_type.startswith("text/html"):
        return False
    parser = _ImgParser()
    try:
        parser.feed(body)
        parser.close()
    except Exception:
        return False
    return parser.executable


def _csp_restrictive(header: str | None) -> bool:
    if not header:
        return False
    script: str | None = None
    for part in header.split(";"):
        piece = part.strip()
        if not piece:
            continue
        name, _, value = piece.partition(" ")
        if name.lower() == "script-src":
            script = value
        elif name.lower() == "default-src" and script is None:
            script = value
    if script is None:
        return False
    tokens = script.split()
    return "'unsafe-inline'" not in tokens and "'unsafe-hashes'" not in tokens


def _page(inner: str, *, interaction: bool = False) -> str:
    flag = ' data-bbtk-interaction="required"' if interaction else ""
    return f"<!doctype html><html><body{flag}>{inner}</body></html>"


@dataclass
class StoredRecord:
    storage_id: str
    original_text: str
    stored_text: str
    truncated: bool
    sanitized_on_save: bool

    def public(self) -> dict[str, object]:
        return {
            "storage_id": self.storage_id,
            "original_length": len(self.original_text),
            "stored_length": len(self.stored_text),
            "truncated": self.truncated,
            "sanitized_on_save": self.sanitized_on_save,
            "original_sha256": _sha256(self.original_text),
            "stored_sha256": _sha256(self.stored_text),
        }


@dataclass(frozen=True)
class _PreparedView:
    generation: int
    delay_s: float
    scenario: str
    truncate_at: int
    record: StoredRecord | None


@dataclass(frozen=True)
class _Outgoing:
    status: int
    content_type: str
    body: str
    extra_headers: tuple[tuple[str, str], ...]
    render_context: str
    sanitize_path: str
    storage_id: str | None
    truncated: bool


class LabState:
    """In-memory comments. Raw text stays in the process and is dropped on reset."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.generation = 0
        self.next_id = 1
        self.records: dict[str, StoredRecord] = {}
        self.events: list[dict[str, object]] = []
        self.scenario = "safe_text"
        self.truncate_at = 12
        self.view_delay_s = 0.0

    def configure(self, scenario: str, truncate_at: int, view_delay_s: float) -> None:
        if scenario not in SCENARIOS:
            raise ValueError(f"Unknown stored-XSS lifecycle scenario: {scenario}")
        if type(truncate_at) is not int or truncate_at <= 0:
            raise ValueError("truncate_at must be a positive integer.")
        if isinstance(view_delay_s, bool) or not isinstance(view_delay_s, (int, float)) or view_delay_s < 0:
            raise ValueError("view_delay_s must be a non-negative number.")
        with self._lock:
            self.generation += 1
            self.records.clear()
            self.events.clear()
            self.next_id = 1
            self.scenario = scenario
            self.truncate_at = truncate_at
            self.view_delay_s = float(view_delay_s)

    def reset(self) -> None:
        with self._lock:
            self.generation += 1
            self.records.clear()
            self.events.clear()
            self.next_id = 1

    def is_current(self, generation: int) -> bool:
        with self._lock:
            return self.generation == generation

    def snapshot(self) -> dict[str, object]:
        with self._lock:
            return {
                "record_count": len(self.records),
                "event_count": len(self.events),
                "generation": self.generation,
                "scenario": self.scenario,
                "records": [record.public() for record in self.records.values()],
                "events": [dict(event) for event in self.events],
                "finding_confirmed": False,
            }

    def accept_write(self, payload: str, actor: str) -> _Outgoing:
        with self._lock:
            scenario = self.scenario
            if scenario == "not_found":
                outgoing = _Outgoing(
                    404,
                    "application/json; charset=utf-8",
                    '{"error":"not_found"}',
                    (),
                    "not_found",
                    "none",
                    None,
                    False,
                )
                self._remember_write(outgoing, payload, persisted=False, actor=actor)
                return outgoing
            if scenario == "write_rejected":
                outgoing = _Outgoing(
                    400, "application/json; charset=utf-8", '{"error":"rejected"}', (), "empty", "none", None, False
                )
                self._remember_write(outgoing, payload, persisted=False, actor=actor)
                return outgoing
            if scenario == "reflect_on_write_only":
                body = _page(f"<p>{payload}</p>")
                outgoing = _Outgoing(200, "text/html; charset=utf-8", body, (), "omitted", "none", None, False)
                self._remember_write(outgoing, payload, persisted=False, actor=actor)
                return outgoing

            stored, truncated, sanitized = _persist(payload, scenario, self.truncate_at)
            storage_id = f"cmt-{self.next_id}"
            self.next_id += 1
            self.records[storage_id] = StoredRecord(storage_id, payload, stored, truncated, sanitized)
            location = f"/comments/{storage_id}"
            body = json.dumps({"id": storage_id, "stored": True}, sort_keys=True)
            outgoing = _Outgoing(
                201,
                "application/json; charset=utf-8",
                body,
                (("Location", location),),
                "stored",
                "save" if sanitized else "none",
                storage_id,
                truncated,
            )
            self._remember_write(outgoing, payload, persisted=True, actor=actor)
            return outgoing

    def prepare_view(self, storage_id: str | None) -> _PreparedView:
        with self._lock:
            record = None
            if storage_id is not None:
                record = self.records.get(storage_id)
            elif self.records:
                record = next(reversed(self.records.values()))
            copied = None
            if record is not None:
                copied = StoredRecord(
                    record.storage_id,
                    record.original_text,
                    record.stored_text,
                    record.truncated,
                    record.sanitized_on_save,
                )
            return _PreparedView(self.generation, self.view_delay_s, self.scenario, self.truncate_at, copied)

    def finish_view(self, prepared: _PreparedView, actor: str) -> _Outgoing | None:
        with self._lock:
            if self.generation != prepared.generation:
                return None
            outgoing = _render(prepared.scenario, prepared.record)
            self.events.append(_view_event(outgoing, actor))
            return outgoing

    def _remember_write(self, outgoing: _Outgoing, payload: str, *, persisted: bool, actor: str) -> None:
        self.events.append(
            {
                "kind": "write",
                "status": outgoing.status,
                "actor": actor,
                "storage_id": outgoing.storage_id,
                "persisted": persisted,
                "truncated": outgoing.truncated,
                "sanitize_path": outgoing.sanitize_path,
                "marker_in_write_body": _marker_present(outgoing.body),
                "content_type": outgoing.content_type,
                "body_sha256": _sha256(outgoing.body),
                "payload_sha256": _sha256(payload),
                "finding_confirmed": False,
            }
        )


def _persist(payload: str, scenario: str, truncate_at: int) -> tuple[str, bool, bool]:
    if scenario == "sanitize_on_save":
        return payload.replace("<", "").replace(">", ""), False, True
    if scenario == "truncated_persist":
        return payload[:truncate_at], len(payload) > truncate_at, False
    return payload, False, False


def _render(scenario: str, record: StoredRecord | None) -> _Outgoing:
    text = "" if record is None else record.stored_text
    storage_id = None if record is None else record.storage_id
    truncated = bool(record and record.truncated)

    if scenario == "saved_never_rendered":
        return _html(200, _page("<p>No comments rendered.</p>"), "omitted", "none", storage_id, truncated)
    if scenario == "reflect_on_write_only":
        return _html(200, _page("<p>Nothing stored.</p>"), "omitted", "none", None, False)
    if scenario == "safe_text":
        return _plain(text, "text_plain", "none", storage_id, truncated)
    if scenario == "html_escaped_on_render":
        return _html(
            200, _page(f'<div id="comment">{escape(text)}</div>'), "html_escaped", "render", storage_id, truncated
        )
    if scenario == "sanitize_on_save":
        return _html(
            200, _page(f'<div id="comment">{escape(text)}</div>'), "sanitized_save", "save", storage_id, truncated
        )
    if scenario == "sanitize_on_render":
        stripped = TAG_RE.sub("", text)
        return _html(
            200,
            _page(f'<div id="comment">{escape(stripped)}</div>'),
            "sanitized_render",
            "render",
            storage_id,
            truncated,
        )
    if scenario == "chromium_execution":
        return _html(200, _page(f'<div id="comment">{text}</div>'), "html_raw", "none", storage_id, truncated)
    if scenario == "marker_present_no_execution":
        return _html(200, _page(f"<p>{escape(text)}</p>"), "html_text_marker", "render", storage_id, truncated)
    if scenario == "csp_block":
        return _html(
            200,
            _page(f'<div id="comment">{text}</div>'),
            "html_raw_csp",
            "none",
            storage_id,
            truncated,
            extra=(("Content-Security-Policy", _CSP),),
        )
    if scenario == "second_user_view":
        return _html(200, _page(f"<p>{escape(text)}</p>"), "second_viewer", "render", storage_id, truncated)
    if scenario == "wrong_permissions":
        return _json(403, '{"error":"forbidden"}', "forbidden", storage_id, truncated)
    if scenario in {"not_found", "write_ok_view_missing"}:
        return _json(404, '{"error":"not_found"}', "not_found", storage_id, truncated)
    if scenario == "write_rejected":
        return _html(200, _page("<p>No comment.</p>"), "empty", "none", None, False)
    if scenario == "truncated_persist":
        return _plain(text, "truncated", "none", storage_id, truncated)
    if scenario == "browser_timeout":
        # Reached only when the client waited out the delay. The lab timeout
        # is shorter than the delay, so a measured run should not get here.
        return _html(
            200, _page(f'<div id="comment">{escape(text)}</div>'), "timeout_late", "render", storage_id, truncated
        )
    if scenario == "interaction_required":
        payload = json.dumps(text)
        inner = (
            '<button id="show" type="button">Show</button>'
            "<script>document.getElementById('show').addEventListener('click', function () {"
            f"document.body.insertAdjacentHTML('beforeend', {payload});"
            "});</script>"
        )
        return _html(200, _page(inner, interaction=True), "interaction_gated", "none", storage_id, truncated)
    raise ValueError(f"Unknown stored-XSS lifecycle scenario: {scenario}")


def _html(
    status: int,
    body: str,
    render_context: str,
    sanitize_path: str,
    storage_id: str | None,
    truncated: bool,
    extra: tuple[tuple[str, str], ...] = (),
) -> _Outgoing:
    return _Outgoing(
        status, "text/html; charset=utf-8", body, extra, render_context, sanitize_path, storage_id, truncated
    )


def _plain(body: str, render_context: str, sanitize_path: str, storage_id: str | None, truncated: bool) -> _Outgoing:
    return _Outgoing(200, "text/plain; charset=utf-8", body, (), render_context, sanitize_path, storage_id, truncated)


def _json(status: int, body: str, render_context: str, storage_id: str | None, truncated: bool) -> _Outgoing:
    return _Outgoing(status, "application/json; charset=utf-8", body, (), render_context, "none", storage_id, truncated)


def _view_event(outgoing: _Outgoing, actor: str) -> dict[str, object]:
    csp = dict(outgoing.extra_headers).get("Content-Security-Policy")
    return {
        "kind": "view",
        "status": outgoing.status,
        "actor": actor,
        "storage_id": outgoing.storage_id,
        "content_type": outgoing.content_type,
        "render_context": outgoing.render_context,
        "sanitize_path": outgoing.sanitize_path,
        "truncated": outgoing.truncated,
        "marker_in_html": _marker_present(outgoing.body),
        "executable_img": _executable_img(outgoing.body, outgoing.content_type),
        "interaction_required": 'data-bbtk-interaction="required"' in outgoing.body,
        "csp_restrictive": _csp_restrictive(csp),
        "csp_directives": _csp_names(csp),
        "body_sha256": _sha256(outgoing.body),
        "finding_confirmed": False,
    }


def _csp_names(header: str | None) -> list[str]:
    if not header:
        return []
    names: list[str] = []
    for part in header.split(";"):
        piece = part.strip()
        if not piece:
            continue
        names.append(piece.split(" ", 1)[0].lower())
    return names


class LabHandler(BaseHTTPRequestHandler):
    server_version = "BountyToolkit-StoredXssLifecycle/0.2"
    protocol_version = "HTTP/1.1"

    def log_message(self, _format: str, *args: object) -> None:
        return

    def do_GET(self) -> None:
        self._dispatch("GET")

    def do_POST(self) -> None:
        self._dispatch("POST")

    def _dispatch(self, method: str) -> None:
        if not _client_is_loopback(self.client_address[0]):
            self._emit(403, "application/json; charset=utf-8", '{"error":"loopback_only"}', ())
            return
        parsed = urlsplit(self.path)
        path = parsed.path
        try:
            if method == "POST" and path == "/__lab/config":
                self._config()
            elif method == "POST" and path == "/__lab/reset":
                self._lab().reset()
                self._emit(200, "application/json; charset=utf-8", '{"reset":true,"finding_confirmed":false}', ())
            elif method == "GET" and path == "/__lab/state":
                body = json.dumps(self._lab().snapshot(), sort_keys=True)
                self._emit(200, "application/json; charset=utf-8", body, ())
            elif method == "POST" and path == "/comments":
                self._write()
            elif method == "GET" and (path == "/comments/latest" or path.startswith("/comments/")):
                self._view(path)
            else:
                self._emit(404, "application/json; charset=utf-8", '{"error":"not_found"}', ())
        except ValueError as exc:
            message = json.dumps({"error": "bad_request", "reason": str(exc)[:200]})
            self._emit(400, "application/json; charset=utf-8", message, ())

    def _config(self) -> None:
        payload = json.loads(self._read_body().decode("utf-8"))
        if not isinstance(payload, dict):
            raise ValueError("Config must be a JSON object.")
        scenario = payload.get("scenario")
        truncate_at = payload.get("truncate_at")
        view_delay_s = payload.get("view_delay_s", 0)
        if not isinstance(scenario, str) or not isinstance(truncate_at, int) or isinstance(truncate_at, bool):
            raise ValueError("Config requires scenario and truncate_at.")
        if isinstance(view_delay_s, bool) or not isinstance(view_delay_s, (int, float)):
            raise ValueError("view_delay_s must be numeric.")
        self._lab().configure(scenario, truncate_at, float(view_delay_s))
        self._emit(200, "application/json; charset=utf-8", '{"configured":true,"finding_confirmed":false}', ())

    def _write(self) -> None:
        form = parse_qs(self._read_body().decode("utf-8", errors="replace"), keep_blank_values=True)
        payload = form.get("content", [""])[0]
        actor = _actor(self.headers.get("X-Lab-Actor"), default="writer")
        outgoing = self._lab().accept_write(payload, actor)
        self._emit(outgoing.status, outgoing.content_type, outgoing.body, outgoing.extra_headers)

    def _view(self, path: str) -> None:
        storage_id: str | None
        if path == "/comments/latest":
            storage_id = None
        else:
            storage_id = path.rsplit("/", 1)[-1]
            if STORAGE_ID_RE.fullmatch(storage_id) is None:
                self._emit(404, "application/json; charset=utf-8", '{"error":"not_found"}', ())
                return
        prepared = self._lab().prepare_view(storage_id)
        if prepared.delay_s > 0 and not _sleep_until(prepared.delay_s, self._lab(), prepared.generation):
            return
        actor = _actor(self.headers.get("X-Lab-Actor"), default="viewer")
        outgoing = self._lab().finish_view(prepared, actor)
        if outgoing is None:
            return
        self._emit(outgoing.status, outgoing.content_type, outgoing.body, outgoing.extra_headers)

    def _read_body(self) -> bytes:
        raw_length = self.headers.get("Content-Length", "0")
        try:
            length = int(raw_length)
        except ValueError as exc:
            raise ValueError("Content-Length must be an integer.") from exc
        if length < 0 or length > _MAX_BODY:
            raise ValueError("Request body exceeds the lab limit.")
        return self.rfile.read(length)

    def _emit(self, status: int, content_type: str, body: str, extra: tuple[tuple[str, str], ...]) -> None:
        encoded = body.encode("utf-8")
        try:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(encoded)))
            self.send_header("Cache-Control", "no-store")
            for name, value in extra:
                self.send_header(name, value)
            self.end_headers()
            self.wfile.write(encoded)
        except (BrokenPipeError, ConnectionResetError):
            return

    def _lab(self) -> LabState:
        server = self.server
        if not isinstance(server, LabHTTPServer):
            raise RuntimeError("Stored XSS lifecycle handler is bound to the wrong server.")
        return server.lab


class LabHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address: tuple[str, int], handler: type[LabHandler]) -> None:
        super().__init__(address, handler)
        self.lab = LabState()


def _client_is_loopback(host: object) -> bool:
    try:
        return ipaddress.ip_address(str(host)).is_loopback
    except ValueError:
        return False


def _actor(header: str | None, *, default: str) -> str:
    if header in {"writer", "viewer"}:
        return header
    return default


def _sleep_until(delay_s: float, lab: LabState, generation: int) -> bool:
    deadline = time.monotonic() + delay_s
    while time.monotonic() < deadline:
        if not lab.is_current(generation):
            return False
        remaining = deadline - time.monotonic()
        time.sleep(min(0.05, max(0.0, remaining)))
    return lab.is_current(generation)


def make_server(host: str = "127.0.0.1", port: int = 0) -> LabHTTPServer:
    """Bind a disposable comment lab. Non-loopback hosts are refused."""
    try:
        address = ipaddress.ip_address(host)
    except ValueError as exc:
        raise ValueError("The stored XSS lifecycle lab binds only to a loopback address.") from exc
    if not address.is_loopback or type(port) is not int or not 0 <= port <= 65535:
        raise ValueError("The stored XSS lifecycle lab binds only to loopback and a valid TCP port.")
    return LabHTTPServer((host, port), LabHandler)


def base_url(server: LabHTTPServer) -> str:
    host, port = server.server_address[:2]
    if isinstance(host, bytes):
        host = host.decode("ascii")
    return f"http://{host}:{port}"


def _request(url: str, payload: dict[str, object] | None = None, timeout: float = 2.0) -> dict[str, object]:
    data = None if payload is None else json.dumps(payload).encode("utf-8")
    headers = {"Content-Type": "application/json"} if data is not None else {}
    method = "POST" if data is not None else "GET"
    request = Request(url, data=data, headers=headers, method=method)
    try:
        with urlopen(request, timeout=timeout) as response:
            parsed = json.loads(response.read().decode("utf-8"))
    except HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")[:300]
        raise RuntimeError(f"Lab control request failed with HTTP {exc.code}: {detail}") from exc
    except URLError as exc:
        raise RuntimeError(f"Lab control request failed: {type(exc.reason).__name__}") from exc
    if not isinstance(parsed, dict):
        raise RuntimeError("Lab control response must be a JSON object.")
    return parsed


def configure(url: str, scenario: str, truncate_at: int, view_delay_s: float) -> None:
    _request(
        f"{url}/__lab/config",
        {"scenario": scenario, "truncate_at": truncate_at, "view_delay_s": view_delay_s},
    )


def reset(url: str) -> None:
    _request(f"{url}/__lab/reset", {})


def fetch_state(url: str) -> dict[str, object]:
    return _request(f"{url}/__lab/state")


@contextmanager
def serve(host: str = "127.0.0.1", port: int = 0) -> Iterator[LabHTTPServer]:
    server = make_server(host, port)
    worker = threading.Thread(target=server.serve_forever, name="stored-xss-lifecycle-lab", daemon=True)
    worker.start()
    try:
        yield server
    finally:
        server.shutdown()
        worker.join(timeout=3)
        server.server_close()
