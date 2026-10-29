"""Resilient offline HAR capture parsing with per-entry isolation and a structured summary.

Data-integrity contract:
- File-fatal problems (size, encoding, malformed or too-deep JSON, missing ``log.entries``,
  hard entry ceiling, no valid entry) always reject the whole file.
- Per-entry problems reject only that entry, with an enumerated reason code. Entries are
  never repaired, merged or re-paired: a request is only ever decoded together with the
  response object of the same HAR entry, and its locator keeps the original index.
- ``strict=True`` restores whole-file rejection when any entry is rejected or truncated.
- Nothing here performs network I/O, and no error or summary contains capture content:
  only indices, counts and reason codes.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass, field
import json
import re
from typing import Any
from urllib.parse import urlsplit

from ..access_control.comparison import parse_json
from ..idor_discovery import json_scalar_fields
from .evidence_engine import CaptureSource, har_entry_source

# Entries processed per file (unchanged historical discovery cap).
MAX_HAR_ENTRIES = 32
# Hard ceiling of entries a file may declare before it is rejected outright (memory bound).
MAX_HAR_ENTRIES_DECLARED = 4096
# Whole-document nesting guard applied before decoding (file-fatal).
MAX_FILE_JSON_DEPTH = 256
# Structural JSON depth of one HAR entry (bodies are strings and checked separately).
MAX_HAR_JSON_DEPTH = 32
# Depth accepted for JSON request/response bodies (matches json_scalar_fields' structure limit).
MAX_BODY_JSON_DEPTH = 16
MAX_ENTRY_HEADERS = 256
MAX_URL_CHARS = 8192
HTTP_METHODS = frozenset({"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "TRACE", "CONNECT"})

# Enumerated reason codes. Keep this list stable: tests and docs reference it.
FATAL_REASONS = (
    "file_too_large",
    "not_utf8",
    "json_invalid",
    "json_too_deep",
    "duplicate_json_keys",
    "log_entries_missing",
    "entries_empty",
    "entries_over_hard_limit",
    "no_valid_entries",
    "strict_entry_rejected",
    "entries_over_limit",
)
ENTRY_REASONS = (
    "entry_not_object",
    "duplicate_json_keys",
    "entry_too_deep",
    "request_missing",
    "response_missing",
    "request_body_malformed",
    "response_content_malformed",
    "unsupported_content_encoding",
    "response_base64_invalid",
    "method_invalid",
    "url_invalid",
    "url_embedded_credentials",
    "url_structural_limit",
    "headers_limit",
    "message_too_large",
    "body_json_too_deep",
    "body_json_invalid",
    "body_json_structure_limit",
    "object_reference_limit",
    "over_entry_limit",
)


class HarImportError(ValueError):
    """File-fatal HAR problem. ``reason`` is an enumerated code; the message never echoes input."""

    def __init__(self, reason: str) -> None:
        assert reason in FATAL_REASONS
        super().__init__(f"HAR capture rejected: {reason}")
        self.reason = reason


class _Ambiguous(dict[str, Any]):
    """Marks a JSON object that repeated a key; never repaired, only rejected."""


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    ambiguous = False
    for key, value in pairs:
        ambiguous = ambiguous or key in result
        result[key] = value
    return _Ambiguous(result) if ambiguous else result


_STRING = re.compile(r'"(?:[^"\\]|\\.)*"', re.S)


def json_depth(text: str) -> int:
    """Bracket nesting depth outside JSON strings, computed without recursion."""
    depth = deepest = 0
    for char in re.findall(r"[\[\]{}]", _STRING.sub("", text)):
        if char in "[{":
            depth += 1
            deepest = max(deepest, depth)
        else:
            depth -= 1
    return deepest


def _has_ambiguous(value: Any) -> bool:
    stack = [value]
    while stack:
        item = stack.pop()
        if isinstance(item, _Ambiguous):
            return True
        if isinstance(item, dict):
            stack.extend(item.values())
        elif isinstance(item, list):
            stack.extend(item)
    return False


@dataclass
class HarImportResult:
    """Accepted captures in original order plus a content-free summary."""

    mode: str
    entries_total: int
    accepted: list[CaptureSource] = field(default_factory=list)
    rejected: list[tuple[int, str]] = field(default_factory=list)
    truncated: bool = False
    duplicates: int = 0

    def reject(self, index: int, reason: str) -> None:
        assert reason in ENTRY_REASONS
        self.rejected.append((index, reason))

    def summary(self) -> dict[str, Any]:
        reasons: dict[str, int] = {}
        for _, reason in self.rejected:
            reasons[reason] = reasons.get(reason, 0) + 1
        return {
            "format": "har",
            "mode": self.mode,
            "entries_total": self.entries_total,
            "accepted": len(self.accepted),
            "rejected": len(self.rejected),
            "reasons": dict(sorted(reasons.items())),
            "rejected_entries": [{"index": index, "reason": reason} for index, reason in sorted(self.rejected)],
            "truncated": self.truncated,
            "duplicate_entries": self.duplicates,
        }


def _body_reason(body: str, headers: dict[str, str] | None, max_body_depth: int = MAX_BODY_JSON_DEPTH) -> str | None:
    content_type = next((v.lower() for k, v in (headers or {}).items() if k.lower() == "content-type"), "")
    if not body or ("json" not in content_type and not body.lstrip().startswith(("{", "["))):
        return None
    if json_depth(body) > max_body_depth:
        return "body_json_too_deep"
    try:
        document = parse_json(body)
    except (ValueError, RecursionError):
        return "body_json_invalid"
    try:
        json_scalar_fields(document, include_sensitive=True, max_depth=max_body_depth)
    except (ValueError, RecursionError):
        return "body_json_structure_limit"
    return None


def entry_reason(
    entry: Any, index: int, max_message_bytes: int, *, max_body_depth: int = MAX_BODY_JSON_DEPTH
) -> tuple[str | None, CaptureSource | None]:
    """Validate one entry in isolation. Returns (reason, None) or (None, source)."""
    if not isinstance(entry, dict):
        return "entry_not_object", None
    if _has_ambiguous(entry):
        return "duplicate_json_keys", None
    if json_depth(json.dumps(entry)) > MAX_HAR_JSON_DEPTH:
        return "entry_too_deep", None
    request, response = entry.get("request"), entry.get("response")
    if not isinstance(request, dict):
        return "request_missing", None
    if not isinstance(response, dict):
        return "response_missing", None
    post = request.get("postData", {})
    if not isinstance(post, dict) or not isinstance(post.get("text", ""), str):
        return "request_body_malformed", None
    content = response.get("content", {})
    if not isinstance(content, dict) or not isinstance(content.get("text", ""), str):
        return "response_content_malformed", None
    if content.get("encoding") not in (None, "base64"):
        return "unsupported_content_encoding", None
    if content.get("encoding") == "base64":
        try:
            base64.b64decode(content.get("text", ""), validate=True).decode("utf-8")
        except (ValueError, UnicodeError):
            return "response_base64_invalid", None
    for message in (request, response):
        headers = message.get("headers", [])
        if isinstance(headers, (list, dict)) and len(headers) > MAX_ENTRY_HEADERS:
            return "headers_limit", None
    source = har_entry_source(entry, index)
    if source is None:  # pragma: no cover - guarded by the checks above
        return "entry_not_object", None
    if source.method not in HTTP_METHODS:
        return "method_invalid", None
    if not source.url:
        return "url_invalid", None
    if len(source.url) > MAX_URL_CHARS or any(ord(char) < 32 for char in source.url):
        return "url_structural_limit", None
    try:
        parsed = urlsplit(source.url)
        hostname = parsed.hostname
        username, password = parsed.username, parsed.password
        parsed.port  # noqa: B018 - raises for malformed ports
    except ValueError:
        return "url_invalid", None
    if parsed.scheme not in {"http", "https"} or not hostname:
        return "url_invalid", None
    if username or password:
        return "url_embedded_credentials", None
    if any(len(body.encode()) > max_message_bytes for body in (source.request_body, source.response_body)):
        return "message_too_large", None
    for body, headers in (
        (source.request_body, source.request_headers),
        (source.response_body, source.response_headers),
    ):
        reason = _body_reason(body, headers, max_body_depth)
        if reason:
            return reason, None
    return None, source


def decode_har_document(text: str) -> Any:
    """``json.loads`` with last-wins semantics plus duplicate-key markers (values identical)."""
    return json.loads(text, object_pairs_hook=_pairs)


def has_duplicate_keys(value: Any) -> bool:
    """True when this object itself repeated a key (non-recursive)."""
    return isinstance(value, _Ambiguous)


def load_har_entries(data: bytes, *, max_bytes: int, reject_ambiguous_container: bool = True) -> list[Any]:
    """Apply the file-fatal checks shared by every HAR consumer and return ``log.entries``.

    Entries keep duplicate-key markers so per-entry validation (``entry_reason``) can isolate
    them. ``reject_ambiguous_container=False`` is only for descriptive classification of files a
    legacy importer already accepts; it never changes which entries are valid.
    """
    if len(data) > max_bytes:
        raise HarImportError("file_too_large")
    try:
        text = data.decode("utf-8-sig")
    except UnicodeError as exc:
        raise HarImportError("not_utf8") from exc
    if json_depth(text) > MAX_FILE_JSON_DEPTH:
        # Recursion/memory guard before decoding; deep but bounded entries are isolated per entry.
        raise HarImportError("json_too_deep")
    try:
        document = decode_har_document(text)
    except (ValueError, RecursionError) as exc:
        raise HarImportError("json_invalid") from exc
    log = document.get("log") if isinstance(document, dict) else None
    entries = log.get("entries") if isinstance(log, dict) else None
    if reject_ambiguous_container and (isinstance(document, _Ambiguous) or isinstance(log, _Ambiguous)):
        raise HarImportError("duplicate_json_keys")
    if not isinstance(entries, list):
        raise HarImportError("log_entries_missing")
    if not entries:
        raise HarImportError("entries_empty")
    if len(entries) > MAX_HAR_ENTRIES_DECLARED:
        raise HarImportError("entries_over_hard_limit")
    return entries


def entry_fingerprint(entry: Any) -> str:
    """Canonical serialization used for exact-duplicate detection (never stored or exported)."""
    return json.dumps(entry, sort_keys=True)


def import_har(
    data: bytes,
    *,
    strict: bool = False,
    max_bytes: int,
    max_message_bytes: int,
    max_entries: int = MAX_HAR_ENTRIES,
    allow_truncate: bool = False,
    max_body_depth: int = MAX_BODY_JSON_DEPTH,
) -> HarImportResult:
    """Parse HAR bytes offline. Raises HarImportError only for file-fatal problems.

    Over-count files stay file-fatal by default (historical fail-closed behaviour). Only with
    ``allow_truncate`` (never combined with ``strict``) are the first ``max_entries`` processed,
    the rest reported as ``over_entry_limit`` and ``truncated`` set.
    """
    if type(max_body_depth) is not int or not 1 <= max_body_depth <= 64:
        raise ValueError("HAR body depth must be between 1 and 64.")
    if strict and allow_truncate:
        raise ValueError("strict and allow_truncate are mutually exclusive.")
    entries = load_har_entries(data, max_bytes=max_bytes)
    result = HarImportResult("strict" if strict else "partial", len(entries))
    if len(entries) > max_entries:
        if not allow_truncate:
            raise HarImportError("entries_over_limit")
        result.truncated = True
    seen: set[str] = set()
    for index, entry in enumerate(entries):
        if index >= max_entries:
            result.reject(index, "over_entry_limit")
            continue
        reason, source = entry_reason(entry, index, max_message_bytes, max_body_depth=max_body_depth)
        if reason is not None:
            if strict:
                raise HarImportError("strict_entry_rejected")
            result.reject(index, reason)
            continue
        assert source is not None
        fingerprint = entry_fingerprint(entry)
        if fingerprint in seen:
            # Duplicates are kept (as before) with their own locator; only counted.
            result.duplicates += 1
        seen.add(fingerprint)
        result.accepted.append(source)
    if not result.accepted:
        raise HarImportError("no_valid_entries")
    return result
