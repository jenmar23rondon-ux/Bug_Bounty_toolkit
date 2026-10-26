"""Common offline capture adapter for ``bbtk fuzz-plan`` (HAR, Burp XML, raw HTTP).

Design contract:
- No new HTTP parser: HAR goes through ``analysis.har_import.import_har`` unchanged, and
  Burp XML items / raw requests go through ``burp_import.parse_captured_exchanges`` and
  ``burp_import.captured_response`` (the same pairing rules used by case preparation).
- A request is only ever paired with the response of the same Burp item, or with a response
  file the user supplied explicitly for one raw request. Responses are never invented.
- Burp items are validated one at a time so independent bad items can be isolated
  (``partial`` mode). ``strict`` rejects the whole file on any bad item. Globally malformed
  XML, DTD/entity declarations, or ambiguous structure are file-fatal and never repaired.
- Raw HTTP carries no scheme, so an explicit ``origin`` is required; the Host header must
  agree with it. Origins are never silently rewritten.
- Nothing here opens sockets, resolves DNS, follows redirects, or reads XML-referenced files.
  Summaries carry only counts, enumerated reason codes, locators and SHA-256 digests.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import re
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit
import xml.etree.ElementTree as ET

from ..analysis.evidence_engine import CaptureSource, _parameter_names
from ..analysis.har_import import MAX_HAR_ENTRIES, HarImportResult, import_har
from ..burp_import import (
    MAX_EXCHANGE_BYTES,
    MAX_ITEM_BYTES,
    _decode_xml_message,
    _item_url,
    _local_name,
    captured_response,
    parse_captured_exchanges,
)
from ..core.private_files import read_private_input
from ..core.request_builder import parse_raw_http_request
from ..utils.exceptions import ToolkitError

CAPTURE_FORMATS = ("auto", "har", "burp-xml", "raw-http")
ADAPTER_VERSION = "1.0"

CAPTURE_FATAL_REASONS = (
    "format_unknown",
    "format_mismatch",
    "not_utf8",
    "nul_bytes",
    "xml_dtd_or_entity",
    "xml_malformed",
    "xml_no_items",
    "entries_over_limit",
    "no_valid_entries",
    "strict_entry_rejected",
    "response_without_raw_request",
    "raw_origin_required",
    "file_too_large",
)
CAPTURE_ENTRY_REASONS = (
    "item_messages_ambiguous",
    "request_missing",
    "request_base64_invalid",
    "response_base64_invalid",
    "request_incomplete",
    "request_line_invalid",
    "request_headers_ambiguous",
    "host_inconsistent",
    "origin_inconsistent",
    "item_url_invalid",
    "message_too_large",
    "response_incomplete",
    "response_headers_ambiguous",
    "response_encoding_unsupported",
    "response_length_mismatch",
    "request_invalid",
    "over_entry_limit",
)


class CaptureImportError(ValueError):
    """File-fatal capture problem; ``reason`` is enumerated and the message never echoes input."""

    def __init__(self, reason: str, entry_reason: str | None = None) -> None:
        assert reason in CAPTURE_FATAL_REASONS
        assert entry_reason is None or entry_reason in CAPTURE_ENTRY_REASONS
        detail = f" ({entry_reason})" if entry_reason else ""
        super().__init__(f"Capture rejected: {reason}{detail}")
        self.reason = reason
        self.entry_reason = entry_reason


@dataclass
class CaptureImportResult(HarImportResult):
    """HarImportResult-compatible result for non-HAR formats, with content-free provenance."""

    format: str = "burp-xml"
    file_sha256: str = ""
    response_file_sha256: str | None = None
    locators: list[str] = field(default_factory=list)
    paired_responses: int = 0
    requests_without_response: int = 0

    def reject(self, index: int, reason: str) -> None:
        assert reason in CAPTURE_ENTRY_REASONS
        self.rejected.append((index, reason))

    def summary(self) -> dict[str, Any]:
        base = super().summary()
        base["format"] = self.format
        base["provenance"] = {
            "adapter_version": ADAPTER_VERSION,
            "file_sha256": self.file_sha256,
            "response_file_sha256": self.response_file_sha256,
            "locators": list(self.locators),
            "paired_responses": self.paired_responses,
            "requests_without_response": self.requests_without_response,
        }
        return base


def detect_capture_format(data: bytes) -> str:
    """Classify bytes as har / burp-xml / raw-http from their leading syntax only."""
    head = data.lstrip(b"\xef\xbb\xbf \t\r\n")[:64]
    if head.startswith((b"{", b"[")):
        return "har"
    if head.startswith(b"<"):
        return "burp-xml"
    if re.match(rb"[A-Z]{1,16} \S+ HTTP/1\.[01]\r?\n", head + b"\n" if b"\n" not in head else head):
        return "raw-http"
    raise CaptureImportError("format_unknown")


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _message_reason(message: str) -> str:
    text = message.lower()
    if "exactly one request" in text:
        return "item_messages_ambiguous"
    if "base64" in text:
        return "request_base64_invalid"
    if "size limit" in text:
        return "message_too_large"
    if "request is incomplete" in text:
        return "request_incomplete"
    if "request line" in text:
        return "request_line_invalid"
    if "response is incomplete" in text:
        return "response_incomplete"
    if "duplicate response" in text:
        return "response_headers_ambiguous"
    if "decoded, uncompressed" in text:
        return "response_encoding_unsupported"
    if "content-length" in text:
        return "response_length_mismatch"
    if "inconsistent origin" in text:
        return "request_invalid"
    return "request_invalid"


def _precheck_request(raw: str, origin_netloc: str | None) -> str | None:
    """Cheap, parser-reusing classification for headers/host before the shared importer."""
    if "\r\n\r\n" not in raw and "\n\n" not in raw:
        return "request_incomplete"
    first = raw.splitlines()[0] if raw else ""
    if not re.fullmatch(r"[A-Z]{1,16} [^\s]+ HTTP/1\.[01]", first):
        return "request_line_invalid"
    try:
        # Syntax check only (a fixed non-routable base satisfies the Host requirement).
        parse_raw_http_request(raw, "https://capture.invalid")
    except (ValueError, ToolkitError) as exc:
        return "request_headers_ambiguous" if "duplicate" in str(exc).lower() else "request_invalid"
    head = raw.replace("\r\n", "\n").split("\n\n", 1)[0]
    hosts = [line.split(":", 1)[1].strip() for line in head.split("\n")[1:] if line.lower().startswith("host:")]
    if origin_netloc is not None and hosts and hosts[0].lower() != origin_netloc.lower():
        return "host_inconsistent"
    return None


def _source(exchange: Any, locator: str, fmt: str) -> tuple[CaptureSource, bool]:
    request = exchange.request
    url = request.prepared_url()
    body = request.body.decode("utf-8", "replace") if isinstance(request.body, bytes) else (request.body or "")
    req_headers = dict(request.headers)
    content_type = next((v for k, v in req_headers.items() if k.lower() == "content-type"), "")
    response = captured_response(exchange)
    resp_headers: dict[str, str] = {}
    status = None
    resp_body = ""
    if response is not None:
        resp_headers = {key.title(): value for key, value in response.headers.items()}
        status = response.status_code
        resp_body = response.body_text
    source = CaptureSource(
        "burp" if fmt == "burp-xml" else "raw-http",
        locator,
        url,
        request.method,
        req_headers,
        body,
        resp_headers,
        resp_body,
        status,
        None,
        _parameter_names(url, body, content_type),
        {"format": fmt, "response_bytes": len(resp_body), "response_paired": response is not None},
    )
    return source, response is not None


def _import_burp(
    data: bytes, *, strict: bool, allow_truncate: bool, max_entries: int, result: CaptureImportResult
) -> None:
    try:
        text = data.decode("utf-8-sig")
    except UnicodeError as exc:
        raise CaptureImportError("not_utf8") from exc
    if "\x00" in text:
        raise CaptureImportError("nul_bytes")
    if re.search(r"<!\s*(?:DOCTYPE|ENTITY)\b", text, re.I):
        raise CaptureImportError("xml_dtd_or_entity")
    try:
        root = ET.fromstring(text)
    except (ET.ParseError, ValueError, RecursionError) as exc:
        raise CaptureImportError("xml_malformed") from exc
    items = [node for node in root.iter() if _local_name(node.tag) == "item"]
    if not items:
        raise CaptureImportError("xml_no_items")
    result.entries_total = len(items)
    if len(items) > max_entries:
        if not allow_truncate:
            raise CaptureImportError("entries_over_limit")
        result.truncated = True
    seen: set[str] = set()
    for index, item in enumerate(items):
        if index >= max_entries:
            result.reject(index, "over_entry_limit")
            continue
        reason, source, paired = _burp_item(item, index)
        if reason is not None:
            if strict:
                raise CaptureImportError("strict_entry_rejected")
            result.reject(index, reason)
            continue
        assert source is not None
        _accept(result, source, paired, seen, ET.tostring(item))


def _burp_item(item: ET.Element, index: int) -> tuple[str | None, CaptureSource | None, bool]:
    requests = [child for child in item if _local_name(child.tag) == "request"]
    responses = [child for child in item if _local_name(child.tag) == "response"]
    if not requests:
        return "request_missing", None, False
    if len(requests) != 1 or len(responses) > 1:
        return "item_messages_ambiguous", None, False
    try:
        raw = _decode_xml_message(requests[0], strict=True)
    except ValueError:
        return "request_base64_invalid", None, False
    if responses:
        try:
            _decode_xml_message(responses[0], strict=True)
        except ValueError:
            return "response_base64_invalid", None, False
        if not "".join(responses[0].itertext()).strip():
            responses = []
    if len(raw.encode("utf-8")) > MAX_EXCHANGE_BYTES:
        return "message_too_large", None, False
    item_url = _item_url(item)
    if item_url is None:
        return "item_url_invalid", None, False
    reason = _precheck_request(raw, urlsplit(item_url).netloc)
    if reason is not None:
        return reason, None, False
    # Re-serialize exactly this item (with its own response only) and reuse the shared importer.
    single = ET.Element("items")
    clone = ET.SubElement(single, "item")
    for child in item:
        if _local_name(child.tag) == "response" and not responses:
            continue
        clone.append(child)
    try:
        exchanges = parse_captured_exchanges(ET.tostring(single))
    except ValueError as exc:
        message = str(exc)
        cause = str(exc.__cause__ or "")
        if "differs" in cause or "disagree" in cause or "overridden" in cause:
            return "origin_inconsistent", None, False
        return _message_reason(message + " " + cause), None, False
    if len(exchanges) != 1:
        return "item_messages_ambiguous", None, False
    source, paired = _source(exchanges[0], f"/items/item[{index}]", "burp-xml")
    return None, source, paired


def _accept(result: CaptureImportResult, source: CaptureSource, paired: bool, seen: set[str], key: bytes) -> None:
    fingerprint = _sha(key)
    if fingerprint in seen:
        result.duplicates += 1
    seen.add(fingerprint)
    result.accepted.append(source)
    result.locators.append(source.locator)
    if paired:
        result.paired_responses += 1
    else:
        result.requests_without_response += 1


def _import_raw(
    data: bytes, response_data: bytes | None, origin: str | None, result: CaptureImportResult, *, strict: bool
) -> None:
    if origin is None:
        raise CaptureImportError("raw_origin_required")
    try:
        text = data.decode("utf-8-sig")
    except UnicodeError as exc:
        raise CaptureImportError("not_utf8") from exc
    if "\x00" in text:
        raise CaptureImportError("nul_bytes")
    result.entries_total = 1
    netloc = urlsplit(origin).netloc
    reason = _precheck_request(text, netloc or None)
    exchange = None
    if reason is None:
        try:
            exchanges = parse_captured_exchanges(data, base_url=origin, response_data=response_data)
            exchange = exchanges[0]
        except ValueError as exc:
            cause = str(exc.__cause__ or "")
            reason = (
                "origin_inconsistent"
                if any(word in cause for word in ("differs", "disagree", "overridden"))
                else _message_reason(f"{exc} {cause}")
            )
            if reason == "request_invalid" and "must be an http" in str(exc).lower():
                raise CaptureImportError("raw_origin_required") from exc
    if reason is not None:
        result.reject(0, reason)
        raise CaptureImportError("strict_entry_rejected" if strict else "no_valid_entries", reason)
    assert exchange is not None
    source, paired = _source(exchange, "/raw/request[0]", "raw-http")
    _accept(result, source, paired, set(), data)


def load_capture_for_planning(
    path: Path,
    *,
    capture_format: str = "auto",
    response_path: Path | None = None,
    origin: str | None = None,
    strict: bool = False,
    allow_truncate: bool = False,
    max_entries: int = MAX_HAR_ENTRIES,
) -> HarImportResult:
    """Read one local capture offline and return accepted exchanges plus a safe summary.

    HAR input is delegated byte-for-byte to the existing resilient importer so its result
    (and therefore any plan built from it) is identical to the historical HAR-only path.
    """
    if capture_format not in CAPTURE_FORMATS:
        raise ValueError("Unsupported capture format.")
    if strict and allow_truncate:
        raise ValueError("strict and allow_truncate are mutually exclusive.")
    data = read_private_input(path, MAX_ITEM_BYTES)
    detected = detect_capture_format(data)
    fmt = detected if capture_format == "auto" else capture_format
    if fmt != detected:
        raise CaptureImportError("format_mismatch")
    if response_path is not None and fmt != "raw-http":
        raise CaptureImportError("response_without_raw_request")
    if fmt == "har":
        return import_har(
            data,
            strict=strict,
            max_bytes=MAX_ITEM_BYTES,
            max_message_bytes=MAX_EXCHANGE_BYTES,
            max_entries=max_entries,
            allow_truncate=allow_truncate,
        )
    result = CaptureImportResult("strict" if strict else "partial", 0, format=fmt, file_sha256=_sha(data))
    if fmt == "burp-xml":
        _import_burp(data, strict=strict, allow_truncate=allow_truncate, max_entries=max_entries, result=result)
    else:
        response_data = read_private_input(response_path, MAX_EXCHANGE_BYTES) if response_path else None
        if response_data is not None:
            result.response_file_sha256 = _sha(response_data)
        _import_raw(data, response_data, origin, result, strict=strict)
    if not result.accepted:
        raise CaptureImportError("no_valid_entries")
    return result


__all__ = [
    "ADAPTER_VERSION",
    "CAPTURE_ENTRY_REASONS",
    "CAPTURE_FATAL_REASONS",
    "CAPTURE_FORMATS",
    "CaptureImportError",
    "CaptureImportResult",
    "detect_capture_format",
    "load_capture_for_planning",
]
