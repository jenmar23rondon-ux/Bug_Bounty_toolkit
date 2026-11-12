"""Tolerant offline ingestion for incomplete, malformed and mixed captures.

This module does not replace the strict replay parser or the HAR file-fatal
guards. It is the shared contract for turning HAR, Burp XML and textual
HTTP/1.0, HTTP/1.1, HTTP/2 and HTTP/3 exports into exchanges plus enumerated
diagnostics. It never sends network traffic, never marks a finding confirmed,
and never fills a missing field with a guessed value.

Textual ``HTTP/2`` and ``HTTP/3`` lines are export text, not binary frames.
"""

from __future__ import annotations

import base64
import codecs
import gzip
import re
import zlib
from dataclasses import dataclass
import xml.etree.ElementTree as ET
from typing import Any
from urllib.parse import urlsplit

from ..burp_import import MAX_EXCHANGE_BYTES, MAX_EXCHANGES, MAX_ITEM_BYTES, _child_text, _local_name
from .authorization_denial import AuthorizationOutcome, Outcome
from .evidence_engine import CaptureSource
from .har_import import (
    ENTRY_REASONS,
    HTTP_METHODS,
    HarImportError,
    entry_reason,
    load_har_entries,
)

SCHEMA = "bbtk.capture-ingestion/1"
_SUPPORTED_VERSIONS = frozenset({"HTTP/1.0", "HTTP/1.1", "HTTP/2", "HTTP/3"})
_VERSION_ALIASES = {"HTTP/2.0": "HTTP/2", "H2": "HTTP/2", "H3": "HTTP/3"}
_REQUEST_LINE = re.compile(r"^([A-Za-z]{1,16})[ \t]+([^ \t]+)[ \t]+(HTTP/(?:1\.[01]|2|3))$", re.I)
_STATUS_VERSION = re.compile(r"^(HTTP/(?:1\.[01]|2|3))[ \t]+([1-5][0-9]{2})(?:[ \t]+\S.*)?$", re.I)
_CHARSET = re.compile(r"charset\s*=\s*\"?([A-Za-z0-9._-]+)", re.I)
_SENSITIVE = frozenset(
    {
        "cookie",
        "authorization",
        "proxy-authorization",
        "set-cookie",
        "location",
        "content-type",
        "content-encoding",
        "content-length",
    }
)
_SESSION = frozenset({"cookie", "authorization", "proxy-authorization"})
_REDIRECTS = frozenset({301, 302, 303, 307, 308})
_RECOVERABLE_HAR = frozenset(
    {"response_missing", "unsupported_content_encoding", "response_base64_invalid", "response_content_malformed"}
)
_AMBIGUOUS = frozenset(
    {
        "ambiguous_header",
        "ambiguous_session",
        "ambiguous_redirect",
        "contradictory_status",
        "contradictory_url",
        "status_malformed",
        "nul_rejected",
        "unrecognized_message",
    }
)
_PARTIAL = frozenset(
    {
        "response_missing",
        "request_missing",
        "incomplete_message",
        "content_length_mismatch",
        "content_encoding_invalid",
        "content_encoding_br_undecoded",
        "content_encoding_unsupported",
        "body_charset_undecoded",
        "charset_unknown",
        "redirect_missing_location",
        "response_base64_invalid",
        "request_base64_invalid",
        "scheme_unspecified",
        "obsolete_line_folding",
        "malformed_header",
        "headers_limit",
        "exchange_too_large",
        "unsupported_http_version",
        "method_invalid",
        "status_missing",
        "transfer_encoding_present",
        "item_malformed",
    }
)
# These do not by themselves change a clean legacy evidence record.
# Present on ordinary request-only or version-alias captures. They must not replace
# the historical evidence record for an otherwise unambiguous message.
NON_BLOCKING_DIAGNOSTICS = frozenset(
    {"response_missing", "duplicate_header_identical", "http_version_alias", "scheme_unspecified"}
)


@dataclass(frozen=True)
class ParseDiagnostic:
    """Content-free parse note. ``code`` is enumerated; no header values or URLs."""

    code: str
    index: int | None = None
    severity: str = "warning"

    def as_dict(self) -> dict[str, object]:
        return {"code": self.code, "index": self.index, "severity": self.severity}


@dataclass(frozen=True)
class NormalizedExchange:
    """One captured exchange. Unknown fields stay ``None``; they are not guessed."""

    index: int
    origin_format: str
    http_version: str | None
    method: str | None
    target: str | None
    url: str | None
    request_headers: tuple[tuple[str, str], ...]
    confident_request_headers: tuple[tuple[str, str], ...]
    request_body: str | None
    response_present: bool
    status_code: int | None
    response_headers: tuple[tuple[str, str], ...]
    confident_response_headers: tuple[tuple[str, str], ...]
    response_body: str | None
    locations: tuple[str, ...]
    session_state: str
    confidence_cap: str
    diagnostics: tuple[str, ...]

    def to_capture_source(self) -> CaptureSource | None:
        """Project unambiguous fields into the existing discovery source model."""
        if self.method not in HTTP_METHODS or not self.url:
            return None
        return CaptureSource(
            "burp",
            f"/items/{self.index}",
            self.url,
            self.method,
            dict(self.confident_request_headers),
            self.request_body or "",
            dict(self.confident_response_headers),
            "" if self.response_body is None else self.response_body,
            self.status_code,
            None,
        )


@dataclass(frozen=True)
class IngestionReport:
    """Result of one buffer. Malformed content is reported here and does not raise."""

    format: str
    exchanges: tuple[NormalizedExchange, ...]
    diagnostics: tuple[ParseDiagnostic, ...]
    fatal: str | None = None
    truncated: bool = False

    @property
    def network_requests_sent(self) -> int:
        return 0

    @property
    def vulnerabilities_confirmed(self) -> int:
        return 0

    def summary(self) -> dict[str, object]:
        reasons: dict[str, int] = {}
        for diagnostic in self.diagnostics:
            reasons[diagnostic.code] = reasons.get(diagnostic.code, 0) + 1
        for exchange in self.exchanges:
            for code in exchange.diagnostics:
                reasons[code] = reasons.get(code, 0) + 1
        accepted = sum(1 for exchange in self.exchanges if exchange.confidence_cap == "observed")
        partial = sum(1 for exchange in self.exchanges if exchange.confidence_cap != "observed")
        rejected = sum(1 for diagnostic in self.diagnostics if diagnostic.severity == "rejected")
        return {
            "schema": SCHEMA,
            "format": self.format,
            "mode": "fatal" if self.fatal else "partial" if partial or rejected or self.truncated else "observed",
            "fatal": self.fatal,
            "entries_total": len(self.exchanges) + rejected,
            "accepted": accepted,
            "partial": partial,
            "rejected": rejected,
            "truncated": self.truncated,
            "reasons": reasons,
            "rejected_entries": [
                {"index": diagnostic.index, "reason": diagnostic.code}
                for diagnostic in self.diagnostics
                if diagnostic.severity == "rejected"
            ],
            "duplicate_entries": 0,
            "network_requests_sent": 0,
            "vulnerabilities_confirmed": 0,
        }


def ingest_capture(data: bytes, *, base_url: str | None = None, response: bytes | None = None) -> IngestionReport:
    """Parse one local buffer. Content failures become diagnostics, not exceptions."""
    try:
        return _ingest(data, base_url=base_url, response=response)
    except (ValueError, TypeError, UnicodeError, RecursionError, ET.ParseError):
        fatal = ParseDiagnostic("ingest_failed", None, "fatal")
        return IngestionReport("unknown", (), (fatal,), "ingest_failed")


def render_response(exchange: NormalizedExchange) -> str:
    """Rebuild a textual response from fields that were actually observed."""
    version = exchange.http_version if exchange.http_version in _SUPPORTED_VERSIONS else "HTTP/1.1"
    status = f"{version} {exchange.status_code}" if exchange.status_code is not None else version
    lines = [status]
    for name, value in exchange.confident_response_headers:
        # Framing headers describe the wire bytes. The body below is the decoded
        # observation, so those headers are not copied onto it.
        if name.lower() in {"content-length", "content-encoding", "transfer-encoding"}:
            continue
        if any(char in "\r\n" for char in name + value):
            continue
        lines.append(f"{name}: {value}")
    body = "" if exchange.response_body is None else exchange.response_body
    return "\r\n".join(lines) + "\r\n\r\n" + body


def assess_ingested_pair(owner: NormalizedExchange, actor: NormalizedExchange) -> AuthorizationOutcome:
    """Assess a pair from normalized exchanges, then apply the confidence cap.

    ``possible_access`` is withheld unless both exchanges are unambiguous.
    A login-redirect denial that depends on disagreeing Location values is
    withheld as well. Nothing returned here sets access as confirmed.
    """
    from .authorization_denial import assess_pair_authorization

    base = assess_pair_authorization(render_response(owner), render_response(actor))
    return _cap_outcome(base, owner.diagnostics + actor.diagnostics, (owner.confidence_cap, actor.confidence_cap))


def apply_confidence_cap(
    outcome: AuthorizationOutcome, owner_raw: str | bytes | None, actor_raw: str | bytes | None
) -> AuthorizationOutcome:
    """Lower an authorization outcome when either raw capture is ambiguous.

    Clean textual captures keep the outcome the existing classifier produced.
    """
    diagnostics: list[str] = []
    caps: list[str] = []
    for raw in (owner_raw, actor_raw):
        exchange = _exchange_for_raw(raw)
        if exchange is None:
            caps.append("partial")
            continue
        caps.append(exchange.confidence_cap)
        diagnostics.extend(exchange.diagnostics)
    return _cap_outcome(outcome, tuple(diagnostics), tuple(caps))


def fallback_discovery_sources(data: bytes, base_url: str | None) -> tuple[list[CaptureSource], dict[str, Any]]:
    """Recover discovery sources when the strict HTTP/1.x importer rejects a file.

    Security limits and wholly unreadable files still raise ``ValueError`` with
    an enumerated code. Sibling exchanges that are usable are kept.
    """
    report = ingest_capture(data, base_url=base_url)
    if report.fatal:
        raise ValueError(report.fatal)
    sources: list[CaptureSource] = []
    rejected: list[dict[str, object]] = [
        {"index": diagnostic.index, "reason": diagnostic.code}
        for diagnostic in report.diagnostics
        if diagnostic.severity == "rejected"
    ]
    for exchange in report.exchanges:
        source = exchange.to_capture_source()
        parsed = urlsplit(source.url) if source and source.url else None
        if (
            source is None
            or parsed is None
            or parsed.scheme not in {"http", "https"}
            or not parsed.hostname
            or parsed.username
            or parsed.password
            or len(source.url or "") > 8192
        ):
            rejected.append(
                {
                    "index": exchange.index,
                    "reason": exchange.diagnostics[0] if exchange.diagnostics else "request_incomplete",
                }
            )
            continue
        sources.append(source)
    if not sources:
        raise ValueError("no_valid_entries")
    summary = report.summary()
    summary["format"] = "burp"
    summary["mode"] = "partial"
    summary["rejected_entries"] = rejected
    summary["rejected"] = len(rejected)
    return sources, summary


def _cap_outcome(
    outcome: AuthorizationOutcome, diagnostics: tuple[str, ...] | list[str], caps: tuple[str, ...]
) -> AuthorizationOutcome:
    new_outcome: Outcome = outcome.outcome
    reasons = list(outcome.reasons)
    diagnostic_set = set(diagnostics)
    if new_outcome == "possible_access" and any(cap != "observed" for cap in caps):
        new_outcome = "inconclusive"
        reasons.append("ingestion_confidence_cap")
    if new_outcome == "cross_account_denied" and "ambiguous_redirect" in diagnostic_set:
        new_outcome = "inconclusive"
        reasons.append("ambiguous_redirect")
    if new_outcome == outcome.outcome:
        return outcome
    annotation = dict(outcome.annotation) if outcome.annotation else None
    if annotation is not None:
        annotation["authorization_outcome"] = "inconclusive"
        annotation["access_confirmed"] = False
    return AuthorizationOutcome(
        outcome=new_outcome,
        owner=outcome.owner,
        actor=outcome.actor,
        annotation=annotation,
        reasons=tuple(reasons),
    )


def _exchange_for_raw(raw: str | bytes | None) -> NormalizedExchange | None:
    if raw is None:
        return None
    if isinstance(raw, str):
        if not raw.strip():
            return None
        data = raw.encode("utf-8")
    else:
        if not bytes(raw).strip():
            return None
        data = bytes(raw)
    report = ingest_capture(data)
    if report.fatal or not report.exchanges:
        return None
    return report.exchanges[0]


def _ingest(data: bytes, *, base_url: str | None, response: bytes | None) -> IngestionReport:
    if len(data) > MAX_ITEM_BYTES or (response is not None and len(response) > MAX_ITEM_BYTES):
        return _fatal("unknown", "file_too_large")
    stripped = data.lstrip()
    if not stripped:
        return _fatal("unknown", "empty_input")
    if response is not None and stripped.startswith((b"<", b"{", b"\xef\xbb\xbf{")):
        report = _ingest(data, base_url=base_url, response=None)
        extra = ParseDiagnostic("separate_response_unsupported", None, "warning")
        return IngestionReport(
            report.format, report.exchanges, report.diagnostics + (extra,), report.fatal, report.truncated
        )
    if stripped.startswith(b"<"):
        return _ingest_burp(data, base_url)
    if stripped.startswith((b"{", b"\xef\xbb\xbf{")):
        return _ingest_har(data, base_url)
    return _ingest_raw(data, response, base_url)


def _fatal(fmt: str, code: str) -> IngestionReport:
    return IngestionReport(fmt, (), (ParseDiagnostic(code, None, "fatal"),), code)


def _ingest_har(data: bytes, base_url: str | None) -> IngestionReport:
    try:
        entries = load_har_entries(data, max_bytes=MAX_ITEM_BYTES)
    except HarImportError as exc:
        return _fatal("har", exc.reason)
    diagnostics: list[ParseDiagnostic] = []
    exchanges: list[NormalizedExchange] = []
    truncated = len(entries) > MAX_EXCHANGES
    for index, entry in enumerate(entries):
        if index >= MAX_EXCHANGES:
            diagnostics.append(ParseDiagnostic("over_exchange_limit", index, "rejected"))
            continue
        reason, source = entry_reason(entry, index, MAX_EXCHANGE_BYTES)
        if reason is None and source is not None:
            exchanges.append(_from_har_source(entry, index, source, base_url))
        elif reason in _RECOVERABLE_HAR or (reason == "body_json_invalid" and _needs_body_decode(entry)):
            recovered = _recover_har(entry, index, reason, base_url)
            if recovered is None:
                diagnostics.append(ParseDiagnostic(reason, index, "rejected"))
            else:
                exchanges.append(recovered)
        else:
            code = reason if reason in ENTRY_REASONS else "item_malformed"
            diagnostics.append(ParseDiagnostic(code, index, "rejected"))
    if not exchanges and not diagnostics:
        return _fatal("har", "entries_empty")
    return IngestionReport("har", tuple(exchanges), tuple(diagnostics), None, truncated)


def _from_har_source(
    entry: dict[str, Any], index: int, source: CaptureSource, base_url: str | None
) -> NormalizedExchange:
    raw_request = entry.get("request")
    raw_response = entry.get("response")
    request: dict[str, Any] = raw_request if isinstance(raw_request, dict) else {}
    response: dict[str, Any] = raw_response if isinstance(raw_response, dict) else {}
    diagnostics: list[str] = []
    request_pairs = _har_header_pairs(request.get("headers"))
    response_pairs = _har_header_pairs(response.get("headers"))
    if request_pairs is None:
        request_pairs = tuple((str(key), str(value)) for key, value in (source.request_headers or {}).items())
        diagnostics.append("malformed_header")
    if response_pairs is None:
        response_pairs = tuple((str(key), str(value)) for key, value in (source.response_headers or {}).items())
        diagnostics.append("malformed_header")
    version = _har_version(entry.get("httpVersion") or request.get("httpVersion"), diagnostics)
    method = source.method if source.method in HTTP_METHODS else None
    if source.method and method is None:
        diagnostics.append("method_invalid")
    url, url_diagnostics = _observed_url(source.url, request_pairs, base_url, None)
    diagnostics.extend(url_diagnostics)
    status = source.status_code if isinstance(source.status_code, int) and 100 <= source.status_code <= 599 else None
    if response and status is None:
        diagnostics.append("status_missing" if response.get("status") in (None, "") else "status_malformed")
    body, body_diagnostics = _har_body(response, response_pairs)
    diagnostics.extend(body_diagnostics)
    if isinstance(source.request_body, str):
        request_body: str | None = source.request_body
    else:
        request_body = None
    return _exchange(
        index,
        "har",
        version,
        method,
        source.url,
        url,
        request_pairs,
        request_body,
        True,
        status,
        response_pairs,
        body,
        diagnostics,
    )


def _recover_har(entry: Any, index: int, reason: str, base_url: str | None) -> NormalizedExchange | None:
    if not isinstance(entry, dict):
        return None
    request = entry.get("request")
    if not isinstance(request, dict):
        return None
    method = request.get("method")
    raw_url = request.get("url")
    if not isinstance(method, str) or method not in HTTP_METHODS or not isinstance(raw_url, str):
        return None
    request_pairs = _har_header_pairs(request.get("headers")) or ()
    # Keep a missing-response mark. Other recoverable reasons are replaced by the
    # decoder's own code when it still fails, and disappear when decoding succeeds.
    diagnostics = ["response_missing"] if reason == "response_missing" else []
    version = _har_version(entry.get("httpVersion") or request.get("httpVersion"), diagnostics)
    url, url_diagnostics = _observed_url(raw_url, request_pairs, base_url, None)
    diagnostics.extend(url_diagnostics)
    post = request.get("postData")
    request_body = post.get("text") if isinstance(post, dict) and isinstance(post.get("text"), str) else ""
    response = entry.get("response")
    if not isinstance(response, dict):
        return _exchange(
            index, "har", version, method, raw_url, url, request_pairs, request_body, False, None, (), None, diagnostics
        )
    response_pairs = _har_header_pairs(response.get("headers")) or ()
    status = _status_value(response.get("status"))
    if status is None:
        diagnostics.append("status_missing" if response.get("status") in (None, "") else "status_malformed")
    body, body_diagnostics = _har_body(response, response_pairs)
    diagnostics.extend(body_diagnostics)
    return _exchange(
        index,
        "har",
        version,
        method,
        raw_url,
        url,
        request_pairs,
        request_body,
        True,
        status,
        response_pairs,
        body,
        diagnostics,
    )


def _har_body(response: dict[str, Any], headers: tuple[tuple[str, str], ...]) -> tuple[str | None, list[str]]:
    content = response.get("content")
    if not isinstance(content, dict):
        return None, ["response_content_malformed"]
    text = content.get("text", "")
    if not isinstance(text, str):
        return None, ["response_content_malformed"]
    encoding = content.get("encoding")
    diagnostics: list[str] = []
    payload: bytes
    if encoding in (None, ""):
        return text, []
    if encoding == "base64":
        try:
            payload = base64.b64decode(text, validate=True)
        except (ValueError, TypeError):
            return None, ["response_base64_invalid"]
    elif isinstance(encoding, str) and encoding.lower() in {"gzip", "deflate", "br", "brotli"}:
        try:
            payload = text.encode("latin-1")
        except UnicodeEncodeError:
            return None, ["content_encoding_invalid"]
    else:
        return None, ["content_encoding_unsupported"]
    return _decode_payload(payload, headers, diagnostics)


def _ingest_burp(data: bytes, base_url: str | None) -> IngestionReport:
    if re.search(rb"<!\s*(?:DOCTYPE|ENTITY)\b", data, re.I):
        return _fatal("burp-xml", "xml_dtd_forbidden")
    if b"\x00" in data:
        return _fatal("burp-xml", "nul_rejected")
    try:
        root = ET.fromstring(data)
    except (ET.ParseError, ValueError, RecursionError):
        return _fatal("burp-xml", "xml_malformed")
    items = [node for node in root.iter() if _local_name(node.tag) == "item"]
    if not items:
        return _fatal("burp-xml", "burp_no_items")
    diagnostics: list[ParseDiagnostic] = []
    exchanges: list[NormalizedExchange] = []
    truncated = len(items) > MAX_EXCHANGES
    for index, item in enumerate(items):
        if index >= MAX_EXCHANGES:
            diagnostics.append(ParseDiagnostic("over_exchange_limit", index, "rejected"))
            continue
        exchange, rejected = _burp_item(item, index, base_url)
        if exchange is None:
            diagnostics.append(ParseDiagnostic(rejected or "item_malformed", index, "rejected"))
        else:
            exchanges.append(exchange)
    return IngestionReport("burp-xml", tuple(exchanges), tuple(diagnostics), None, truncated)


def _burp_item(item: ET.Element, index: int, base_url: str | None) -> tuple[NormalizedExchange | None, str | None]:
    requests = [child for child in list(item) if _local_name(child.tag) == "request"]
    responses = [child for child in list(item) if _local_name(child.tag) == "response"]
    if len(requests) != 1 or len(responses) > 1:
        return None, "item_malformed"
    request_bytes, request_code = _xml_message_bytes(requests[0], "request_base64_invalid")
    if request_bytes is None:
        return None, request_code
    response_bytes: bytes | None = None
    if responses:
        response_bytes, response_code = _xml_message_bytes(responses[0], "response_base64_invalid")
        if response_bytes is None:
            response_bytes = b""
            # Keep the request; the response bytes were not recovered.
            exchange = _pair_messages(index, "burp-xml", request_bytes, None, base_url, _child_text(item, "url"))
            return _with_extra(exchange, (response_code or "response_base64_invalid",)), None
    declared_text = _child_text(item, "status")
    declared = _status_value(declared_text)
    declared_present = declared_text not in (None, "")
    exchange = _pair_messages(index, "burp-xml", request_bytes, response_bytes, base_url, _child_text(item, "url"))
    if declared_present and declared is None:
        exchange = _with_extra(exchange, ("status_malformed",), clear_status=True)
    elif declared_present and declared != exchange.status_code:
        exchange = _with_extra(exchange, ("contradictory_status",), clear_status=True)
    elif declared_present and exchange.status_code is None and declared is not None and response_bytes is None:
        exchange = _with_status(exchange, declared)
    if exchange.method is None and not exchange.response_present:
        return None, exchange.diagnostics[0] if exchange.diagnostics else "item_malformed"
    return exchange, None


def _xml_message_bytes(node: ET.Element, invalid_code: str) -> tuple[bytes | None, str | None]:
    value = "".join(node.itertext())
    if node.attrib.get("base64", "").lower() == "true":
        try:
            return base64.b64decode(re.sub(r"\s", "", value), validate=True), None
        except (ValueError, TypeError):
            return None, invalid_code
    if "\x00" in value:
        return None, "nul_rejected"
    return value.encode("utf-8"), None


def _ingest_raw(data: bytes, response: bytes | None, base_url: str | None) -> IngestionReport:
    exchange = _pair_messages(0, "raw-http", data, response, base_url, None)
    if exchange.method is None and exchange.status_code is None and not exchange.response_present:
        code = exchange.diagnostics[0] if exchange.diagnostics else "unrecognized_message"
        if code == "unrecognized_message" and "unrecognized_message" in exchange.diagnostics:
            return IngestionReport("raw-http", (), (ParseDiagnostic(code, 0, "fatal"),), code)
    return IngestionReport("raw-http", (exchange,), ())


def _pair_messages(
    index: int,
    fmt: str,
    request: bytes,
    response: bytes | None,
    base_url: str | None,
    item_url: str | None,
) -> NormalizedExchange:
    request_parsed = _parse_message(request)
    diagnostics = list(request_parsed.diagnostics)
    response_parsed = _parse_message(response) if response is not None else None
    if response is None and request_parsed.kind == "response":
        response_parsed = request_parsed
        request_parsed = _Parsed(None, None, None, (), None, ())
        diagnostics = list(response_parsed.diagnostics)
    elif response_parsed is not None:
        diagnostics.extend(response_parsed.diagnostics)
    method = request_parsed.method if request_parsed.method in HTTP_METHODS else None
    if request_parsed.method and method is None:
        diagnostics.append("method_invalid")
    response_present = response_parsed is not None and response_parsed.kind == "response"
    if response_parsed is not None and response_parsed.kind != "response":
        diagnostics.append("unrecognized_message")
        response_present = False
    if response is None and request_parsed.kind == "request":
        diagnostics.append("response_missing")
    url, url_diagnostics = _observed_url(request_parsed.target, request_parsed.headers, base_url, item_url)
    diagnostics.extend(url_diagnostics)
    status = response_parsed.status_code if response_parsed and response_present else None
    version = None
    if response_parsed and response_parsed.version:
        version = response_parsed.version
    elif request_parsed.version:
        version = request_parsed.version
    return _exchange(
        index,
        fmt,
        version,
        method,
        request_parsed.target,
        url,
        request_parsed.headers,
        request_parsed.body_text,
        response_present,
        status,
        response_parsed.headers if response_parsed and response_present else (),
        response_parsed.body_text if response_parsed and response_present else None,
        diagnostics,
    )


@dataclass(frozen=True)
class _Parsed:
    kind: str | None
    version: str | None
    method: str | None
    headers: tuple[tuple[str, str], ...]
    target: str | None
    diagnostics: tuple[str, ...]
    body_text: str | None = None
    status_code: int | None = None


def _parse_message(raw: bytes) -> _Parsed:
    if len(raw) > MAX_EXCHANGE_BYTES:
        return _Parsed(None, None, None, (), None, ("exchange_too_large",), None)
    head, body, complete = _split_head(raw)
    diagnostics: list[str] = []
    if not complete:
        diagnostics.append("incomplete_message")
    if b"\x00" in head:
        return _Parsed(None, None, None, (), None, ("nul_rejected",), None)
    try:
        text = head.decode("utf-8")
    except UnicodeDecodeError:
        text = head.decode("iso-8859-1")
    lines = text.splitlines()
    if not lines or not lines[0].strip():
        return _Parsed(None, None, None, (), None, tuple(diagnostics + ["unrecognized_message"]), None)
    first = lines[0].strip()
    headers, header_diagnostics = _header_pairs(lines[1:])
    diagnostics.extend(header_diagnostics)
    kind: str | None = None
    version: str | None = None
    method: str | None = None
    target: str | None = None
    status: int | None = None
    request_match = _REQUEST_LINE.fullmatch(first)
    status_match = _STATUS_VERSION.fullmatch(first)
    if request_match and request_match.group(1).isupper():
        version_token = request_match.group(3).upper()
        if version_token in _SUPPORTED_VERSIONS:
            kind, version, method, target = "request", version_token, request_match.group(1), request_match.group(2)
        else:
            diagnostics.append("unsupported_http_version")
    elif status_match:
        version_token = status_match.group(1).upper()
        if version_token in _SUPPORTED_VERSIONS:
            kind, version, status = "response", version_token, int(status_match.group(2))
        else:
            diagnostics.append("unsupported_http_version")
    elif first.upper().startswith("HTTP/"):
        # A response export with an unusable status line. Keep the observed body
        # and leave the status unknown; do not read a number out of the line.
        diagnostics.append("status_malformed")
        kind = "response"
    elif "HTTP/" in first.upper():
        diagnostics.append("unsupported_http_version")
    else:
        diagnostics.append("unrecognized_message")
    if any(name.lower() == "transfer-encoding" for name, _ in headers):
        diagnostics.append("transfer_encoding_present")
    payload, payload_diagnostics = _decode_payload(body, headers, [])
    diagnostics.extend(payload_diagnostics)
    if "transfer_encoding_present" not in diagnostics and "ambiguous_header" not in diagnostics:
        _check_length(headers, len(body), diagnostics)
    return _Parsed(kind, version, method, headers, target, tuple(diagnostics), payload, status)


def _split_head(raw: bytes) -> tuple[bytes, bytes, bool]:
    candidates = [(raw.find(sep), sep) for sep in (b"\r\n\r\n", b"\n\n") if sep in raw]
    if not candidates:
        return raw, b"", False
    index, separator = min(candidates)
    return raw[:index], raw[index + len(separator) :], True


def _header_pairs(lines: list[str]) -> tuple[tuple[tuple[str, str], ...], list[str]]:
    pairs: list[tuple[str, str]] = []
    diagnostics: list[str] = []
    for line in lines:
        if not line:
            continue
        if line[0] in " \t":
            diagnostics.append("obsolete_line_folding")
            continue
        if ":" not in line:
            diagnostics.append("malformed_header")
            continue
        name, value = line.split(":", 1)
        name = name.strip()
        if not name or any(ord(char) < 33 or ord(char) > 126 for char in name):
            diagnostics.append("malformed_header")
            continue
        if len(pairs) >= 256:
            diagnostics.append("headers_limit")
            break
        pairs.append((name, value.strip()))
    return tuple(pairs), diagnostics


def _decode_payload(
    payload: bytes, headers: tuple[tuple[str, str], ...], diagnostics: list[str]
) -> tuple[str | None, list[str]]:
    notes = list(diagnostics)
    encoding = _single_header(headers, "content-encoding")
    if encoding is None and any(name.lower() == "content-encoding" for name, _ in headers):
        notes.append("content_encoding_unsupported")
        return None, notes
    decoded, code = _decompress(payload, encoding)
    if code:
        notes.append(code)
        return None, notes
    assert decoded is not None
    content_type = _single_header(headers, "content-type")
    if content_type is None and any(name.lower() == "content-type" for name, _ in headers):
        # Disagreeing types: do not pick a charset. Accept UTF-8 only when it is exact.
        try:
            return decoded.decode("utf-8"), notes
        except UnicodeDecodeError:
            notes.append("body_charset_undecoded")
            return None, notes
    text, text_code = _decode_text(decoded, content_type)
    if text_code:
        notes.append(text_code)
        return None, notes
    return text, notes


def _decompress(payload: bytes, encoding: str | None) -> tuple[bytes | None, str | None]:
    enc = (encoding or "identity").split(",")[0].strip().lower()
    if enc in {"", "identity"}:
        return payload, None
    if enc == "gzip":
        try:
            return gzip.decompress(payload), None
        except (OSError, EOFError, zlib.error):
            return None, "content_encoding_invalid"
    if enc == "deflate":
        try:
            return zlib.decompress(payload), None
        except zlib.error:
            try:
                return zlib.decompress(payload, -zlib.MAX_WBITS), None
            except zlib.error:
                return None, "content_encoding_invalid"
    if enc in {"br", "brotli"}:
        return None, "content_encoding_br_undecoded"
    return None, "content_encoding_unsupported"


def _decode_text(payload: bytes, content_type: str | None) -> tuple[str | None, str | None]:
    match = _CHARSET.search(content_type or "")
    name = match.group(1) if match else "utf-8"
    try:
        codec = codecs.lookup(name)
    except LookupError:
        return None, "charset_unknown"
    try:
        return str(codec.decode(payload)[0]), None
    except UnicodeError:
        return None, "body_charset_undecoded"


def _check_length(headers: tuple[tuple[str, str], ...], wire_length: int, diagnostics: list[str]) -> None:
    values = [value.strip() for name, value in headers if name.lower() == "content-length"]
    if len(values) != 1:
        return
    if not values[0].isdecimal() or int(values[0]) != wire_length:
        diagnostics.append("content_length_mismatch")


def _single_header(headers: tuple[tuple[str, str], ...], name: str) -> str | None:
    values = [value for header, value in headers if header.lower() == name]
    if len(values) == 1:
        return values[0]
    if values and len(set(values)) == 1:
        return values[0]
    return None


def _har_header_pairs(value: object) -> tuple[tuple[str, str], ...] | None:
    if value is None:
        return ()
    if not isinstance(value, list):
        return None
    pairs: list[tuple[str, str]] = []
    for row in value:
        if not isinstance(row, dict) or not isinstance(row.get("name"), str):
            return None
        raw = row.get("value", "")
        if not isinstance(raw, (str, int, float)):
            return None
        pairs.append((str(row["name"]), str(raw)))
        if len(pairs) > 256:
            return None
    return tuple(pairs)


def _needs_body_decode(entry: Any) -> bool:
    """True when a JSON-invalid HAR body still declares a content encoding to try."""
    response = entry.get("response") if isinstance(entry, dict) else None
    headers = response.get("headers") if isinstance(response, dict) else None
    if not isinstance(headers, list):
        return False
    for row in headers:
        if not isinstance(row, dict) or str(row.get("name", "")).lower() != "content-encoding":
            continue
        value = str(row.get("value", "")).split(",")[0].strip().lower()
        if value not in {"", "identity"}:
            return True
    return False


def _har_version(value: object, diagnostics: list[str]) -> str | None:
    if not isinstance(value, str) or not value.strip():
        return None
    token = value.strip().upper()
    if token in _SUPPORTED_VERSIONS:
        return token
    if token in _VERSION_ALIASES:
        diagnostics.append("http_version_alias")
        return _VERSION_ALIASES[token]
    diagnostics.append("unsupported_http_version")
    return None


def _status_value(value: object) -> int | None:
    if type(value) is int and 100 <= value <= 599:
        return value
    if isinstance(value, str) and value.isdigit() and 100 <= int(value) <= 599:
        return int(value)
    return None


def _observed_url(
    target: str | None,
    headers: tuple[tuple[str, str], ...],
    base_url: str | None,
    item_url: str | None,
) -> tuple[str | None, list[str]]:
    diagnostics: list[str] = []
    absolute = target if target and target.lower().startswith(("http://", "https://")) else None
    if absolute:
        try:
            parts = urlsplit(absolute)
        except ValueError:
            return None, ["url_invalid"]
        if parts.username or parts.password:
            return None, ["url_embedded_credentials"]
        if parts.scheme not in {"http", "https"} or not parts.hostname:
            return None, ["url_invalid"]
        if not _origin_agrees(parts.scheme, parts.netloc, headers, base_url, item_url, diagnostics):
            return None, diagnostics
        return absolute, diagnostics
    observed = item_url if item_url and item_url.lower().startswith(("http://", "https://")) else None
    if observed is None and base_url and target and target.startswith("/"):
        try:
            base = urlsplit(base_url)
        except ValueError:
            base = None
        if base and base.scheme in {"http", "https"} and base.hostname and not base.username:
            observed = f"{base.scheme}://{base.netloc}{target}"
    if observed is None:
        if target:
            diagnostics.append("scheme_unspecified")
        return None, diagnostics
    try:
        parts = urlsplit(observed)
    except ValueError:
        return None, ["url_invalid"]
    if parts.username or parts.password:
        return None, ["url_embedded_credentials"]
    if target and not _target_matches(parts, target):
        return None, ["contradictory_url"]
    if not _origin_agrees(parts.scheme, parts.netloc, headers, base_url, None, diagnostics):
        return None, diagnostics
    return observed, diagnostics


def _target_matches(parts: Any, target: str) -> bool:
    path, _, query = target.partition("?")
    if parts.path != path:
        return False
    return not query or parts.query == query


def _origin_agrees(
    scheme: str,
    netloc: str,
    headers: tuple[tuple[str, str], ...],
    base_url: str | None,
    item_url: str | None,
    diagnostics: list[str],
) -> bool:
    host = _single_header(headers, "host")
    if host and host.lower() != netloc.lower():
        diagnostics.append("contradictory_url")
        return False
    for candidate in (base_url, item_url):
        if not candidate:
            continue
        try:
            parsed = urlsplit(candidate)
        except ValueError:
            diagnostics.append("contradictory_url")
            return False
        if parsed.netloc and parsed.netloc.lower() != netloc.lower():
            diagnostics.append("contradictory_url")
            return False
        if parsed.scheme and parsed.scheme.lower() != scheme.lower():
            diagnostics.append("contradictory_url")
            return False
    return True


def _exchange(
    index: int,
    fmt: str,
    version: str | None,
    method: str | None,
    target: str | None,
    url: str | None,
    request_headers: tuple[tuple[str, str], ...],
    request_body: str | None,
    response_present: bool,
    status_code: int | None,
    response_headers: tuple[tuple[str, str], ...],
    response_body: str | None,
    diagnostics: list[str],
) -> NormalizedExchange:
    request_confident, request_notes = _confident_headers(request_headers)
    response_confident, response_notes = _confident_headers(response_headers)
    notes = list(diagnostics)
    notes.extend(request_notes)
    notes.extend(response_notes)
    if (
        response_present
        and status_code in _REDIRECTS
        and not any(name.lower() == "location" for name, _ in response_headers)
    ):
        notes.append("redirect_missing_location")
    unique = tuple(dict.fromkeys(notes))
    if "ambiguous_session" in unique:
        session_state = "ambiguous"
    elif any(name.lower() in _SESSION for name, _ in request_headers):
        session_state = "single"
    else:
        session_state = "absent"
    locations = tuple(value for name, value in response_headers if name.lower() == "location")
    return NormalizedExchange(
        index,
        fmt,
        version,
        method,
        target,
        url,
        request_headers,
        tuple(request_confident.items()),
        request_body,
        response_present,
        status_code,
        response_headers,
        tuple(response_confident.items()),
        response_body,
        locations,
        session_state,
        _confidence(unique),
        unique,
    )


def _confident_headers(headers: tuple[tuple[str, str], ...]) -> tuple[dict[str, str], list[str]]:
    grouped: dict[str, list[tuple[str, str]]] = {}
    for name, value in headers:
        grouped.setdefault(name.lower(), []).append((name, value))
    chosen: dict[str, str] = {}
    diagnostics: list[str] = []
    for name, items in grouped.items():
        values = {value for _, value in items}
        if len(items) > 1 and len(values) == 1:
            diagnostics.append("duplicate_header_identical")
            chosen[items[0][0]] = items[0][1]
            continue
        if len(values) > 1:
            diagnostics.append("ambiguous_header")
            if name in _SESSION:
                diagnostics.append("ambiguous_session")
            if name == "location":
                diagnostics.append("ambiguous_redirect")
            continue
        chosen[items[0][0]] = items[0][1]
    return chosen, diagnostics


def _confidence(diagnostics: tuple[str, ...]) -> str:
    if any(code in _AMBIGUOUS for code in diagnostics):
        return "ambiguous"
    if any(code in _PARTIAL for code in diagnostics):
        return "partial"
    return "observed"


def _with_extra(
    exchange: NormalizedExchange, extra: tuple[str, ...], *, clear_status: bool = False
) -> NormalizedExchange:
    diagnostics = tuple(dict.fromkeys(exchange.diagnostics + extra))
    return NormalizedExchange(
        exchange.index,
        exchange.origin_format,
        exchange.http_version,
        exchange.method,
        exchange.target,
        exchange.url,
        exchange.request_headers,
        exchange.confident_request_headers,
        exchange.request_body,
        exchange.response_present,
        None if clear_status else exchange.status_code,
        exchange.response_headers,
        exchange.confident_response_headers,
        exchange.response_body,
        exchange.locations,
        exchange.session_state,
        _confidence(diagnostics),
        diagnostics,
    )


def _with_status(exchange: NormalizedExchange, status: int) -> NormalizedExchange:
    return NormalizedExchange(
        exchange.index,
        exchange.origin_format,
        exchange.http_version,
        exchange.method,
        exchange.target,
        exchange.url,
        exchange.request_headers,
        exchange.confident_request_headers,
        exchange.request_body,
        exchange.response_present,
        status,
        exchange.response_headers,
        exchange.confident_response_headers,
        exchange.response_body,
        exchange.locations,
        exchange.session_state,
        exchange.confidence_cap,
        exchange.diagnostics,
    )


__all__ = [
    "IngestionReport",
    "NON_BLOCKING_DIAGNOSTICS",
    "NormalizedExchange",
    "ParseDiagnostic",
    "SCHEMA",
    "apply_confidence_cap",
    "assess_ingested_pair",
    "fallback_discovery_sources",
    "ingest_capture",
    "render_response",
]
