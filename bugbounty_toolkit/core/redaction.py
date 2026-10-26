"""Destination-aware redaction for evidence, reports, console, and model inputs.

Private artifacts may retain values needed for authorized validation. Shareable
reports, console summaries, and model inputs must not carry synthetic canaries
or known secret shapes. Redaction is best-effort: unrecognized formats and novel
secret encodings remain residual risks — this module never claims absolute privacy.
"""

from __future__ import annotations

from enum import Enum
import hashlib
import json
import re
import time
from typing import Any, Mapping
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit


SENSITIVE_KEY = re.compile(
    r"password|passwd|passphrase|secret|token|api.?key|authorization|cookie|session|csrf|credential",
    re.I,
)
REDACTED = "[redacted]"
JWT_TOKEN = re.compile(r"(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*(?![A-Za-z0-9_-])")
# Excluding "<" bounds each failed attempt at the next tag, keeping unterminated inputs linear.
HTML_INPUT = re.compile(r"<input\b[^<>]{0,8192}>", re.I)
HTML_ATTRIBUTE = re.compile(r"\b([\w:-]+)\s*=\s*(?:\"([^\"]*)\"|'([^']*)'|([^\s>]+))", re.I)
HTML_VALUE = re.compile(r"\bvalue\s*=\s*(?:\"[^\"]*\"|'[^']*'|[^\s>]+)", re.I)

DEFAULT_MAX_CHARS = 2_000_000
DEFAULT_MAX_DEPTH = 64
DEFAULT_MAX_SECONDS = 2.0
_PATH_HINT = re.compile(
    r"(?i)(?:^|[\s\"'=])(?:/home/|/Users/|/var/|/tmp/|[A-Za-z]:\\|/workspace/|"
    r"registros/|inputs/|private/)[^\s\"'<>]{0,240}"
)
_SHA256_HEX = re.compile(r"\b[0-9a-f]{64}\b", re.I)
_PSEUDO_PREFIX = "bbtk-id-"

_API_KEY_PATTERNS = (
    re.compile(r"\bsk-[A-Za-z0-9_-]{12,}"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}"),
    re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}"),
    re.compile(r"(?i)\bBBTK[-_]CANARY[-_][A-Za-z0-9_-]+"),
    re.compile(r"(?i)\bCANARY[-_][A-Za-z0-9_-]{8,}"),
)
_COOKIE_PAIR = re.compile(r"(?i)\b((?:set-)?cookie)\s*[:=]\s*([^\r\n;]+)")
_AUTH_PAIR = re.compile(r"(?i)\b(authorization)\s*[:=]\s*([^\r\n]+)")
_SESSION_ID_VALUE = re.compile(r"(?i)\b(session[_-]?id|jsessionid|phpsessid|sid)\s*[:=]\s*[\"']?([A-Za-z0-9._-]{8,})")
_SECRET_KEYWORD = re.compile(r"(?i)password|passwd|secret|token|api[_-]?key|session[_-]?id")
_KV_SECRET = re.compile(
    r"""(?i)((?<![\w-])["']?(?:password|passwd|secret|[\w-]*token|api[_-]?key|session[_-]?id)["']?\s*[:=]\s*["']?)[^\s"'&<>,;}]+"""
)
_BEARER = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/-]+=*")
_HTTP_START = re.compile(r"^(?:[A-Z]{3,10}\s+\S+\s+HTTP/\d|(?:HTTP/\d\.\d\s+\d{3}))")
_SHAREABLE = frozenset(
    {
        "shareable_report",
        "console_summary",
        "model_input",
    }
)


class RedactionDestination(str, Enum):
    """Where the redacted value will be emitted."""

    PRIVATE_EVIDENCE = "private_evidence"
    MINIMIZED_ARTIFACT = "minimized_artifact"
    CONSOLE_SUMMARY = "console_summary"
    SHAREABLE_REPORT = "shareable_report"
    MODEL_INPUT = "model_input"


class RedactionLimitError(ValueError):
    """Raised when input exceeds configured size, depth, or time bounds."""


class RedactionResult:
    """Structured outcome for destination-aware redaction."""

    __slots__ = ("value", "truncated", "parse_errors", "destination", "elapsed_ms", "chars_in", "chars_out")

    def __init__(
        self,
        value: Any,
        *,
        truncated: bool,
        parse_errors: list[str],
        destination: RedactionDestination,
        elapsed_ms: float,
        chars_in: int,
        chars_out: int,
    ) -> None:
        self.value = value
        self.truncated = truncated
        self.parse_errors = parse_errors
        self.destination = destination
        self.elapsed_ms = elapsed_ms
        self.chars_in = chars_in
        self.chars_out = chars_out


def _safe_error(message: str) -> str:
    return message[:200]


def provenance_digest(content: bytes | str, *, algorithm: str = "sha256") -> str:
    """Hash content for provenance without retaining the plaintext."""
    raw = content.encode("utf-8", errors="replace") if isinstance(content, str) else content
    if algorithm != "sha256":
        raise ValueError(_safe_error("Unsupported provenance digest algorithm."))
    return hashlib.sha256(raw).hexdigest()


def pseudonymize_identifier(value: str, *, salt: str = "") -> str:
    """Stable opaque identifier distinct from the original secret/id."""
    digest = hashlib.sha256(f"{salt}\0{value}".encode("utf-8", errors="replace")).hexdigest()[:16]
    return f"{_PSEUDO_PREFIX}{digest}"


def detect_truncation(original_len: int, retained_len: int, *, claimed_complete: bool = True) -> dict[str, Any]:
    """Report whether truncation may invalidate an evidence claim."""
    truncated = retained_len < original_len
    return {
        "truncated": truncated,
        "original_chars": original_len,
        "retained_chars": retained_len,
        "validity_affected": bool(truncated and claimed_complete),
        "note": (
            "Truncation removed content that a completeness claim depended on."
            if truncated and claimed_complete
            else "No completeness claim is invalidated by this retention window."
            if truncated
            else "Content fully retained within the configured bound."
        ),
    }


def _looks_like_filesystem_path(value: str) -> bool:
    """True for absolute/local artifact paths; false for URL paths or query fragments."""
    if not value or any(ch.isspace() for ch in value) or "://" in value:
        return False
    lowered = value.replace("\\", "/").lower()
    return bool(
        lowered.startswith(("/home/", "/users/", "/var/", "/tmp/", "/workspace/", "registros/", "inputs/", "private/"))
        or (len(value) >= 3 and value[1:3] in (":\\", ":/"))
        or (lowered.endswith((".har", ".json", ".xml", ".txt", ".log")) and ("/" in value or "\\" in value))
    )


def _strip_local_paths(value: str) -> str:
    return _PATH_HINT.sub(" [path-redacted]", value)


def _apply_secret_shapes(value: str) -> str:
    value = JWT_TOKEN.sub(REDACTED, value)
    for pattern in _API_KEY_PATTERNS:
        value = pattern.sub(REDACTED, value)
    value = _BEARER.sub("Bearer [redacted]", value)
    value = _COOKIE_PAIR.sub(lambda m: f"{m.group(1)}: {REDACTED}", value)
    value = _AUTH_PAIR.sub(lambda m: f"{m.group(1)}: {REDACTED}", value)
    value = _SESSION_ID_VALUE.sub(lambda m: f"{m.group(1)}={REDACTED}", value)
    return value


def redact_jwts(value: str) -> str:
    """Replace compact JWT-like values before storing or sending imported text for review."""
    return JWT_TOKEN.sub(REDACTED, value)


def redact_html_secrets(value: str, redact_all_hidden: bool = False) -> str:
    """Redact values in HTML inputs whose name/id or type indicates a secret."""

    def replace_input(match: re.Match[str]) -> str:
        tag = match.group(0)
        attributes: dict[str, str] = {}
        for attribute in HTML_ATTRIBUTE.finditer(tag):
            attribute_name = attribute.group(1).lower()
            attribute_value = next((part for part in attribute.groups()[1:] if part is not None), "")
            attributes[attribute_name] = attribute_value
        field_name = f"{attributes.get('name', '')} {attributes.get('id', '')}"
        is_hidden = attributes.get("type", "").lower() == "hidden"
        if (
            attributes.get("type", "").lower() != "password"
            and not SENSITIVE_KEY.search(field_name)
            and not (redact_all_hidden and is_hidden)
        ):
            return tag
        return HTML_VALUE.sub('value="[redacted]"', tag)

    return HTML_INPUT.sub(replace_input, redact_jwts(value))


def redact_headers(headers: Mapping[str, str], *, destination: RedactionDestination | None = None) -> dict[str, str]:
    dest = destination or RedactionDestination.MINIMIZED_ARTIFACT
    out: dict[str, str] = {}
    allowlisted = {
        "content-type",
        "content-length",
        "accept",
        "accept-language",
        "accept-encoding",
        "user-agent",
        "host",
        "date",
        "server",
        "cache-control",
        "connection",
        "vary",
        "etag",
        "location",
    }
    for key, value in headers.items():
        name = str(key)
        if SENSITIVE_KEY.search(name):
            out[name] = REDACTED
            continue
        if dest.value in _SHAREABLE and name.lower() not in allowlisted:
            out[name] = REDACTED
            continue
        out[name] = redact_text(value, destination=dest) or ""
    return out


def redact_url(url: str, *, destination: RedactionDestination | None = None) -> str:
    dest = destination or RedactionDestination.MINIMIZED_ARTIFACT
    parsed = urlsplit(url)
    query = [
        (key, REDACTED if SENSITIVE_KEY.search(key) else value)
        for key, value in parse_qsl(parsed.query, keep_blank_values=True)
    ]
    netloc = parsed.netloc.rsplit("@", 1)[-1]
    if dest.value in _SHAREABLE:
        path_parts = []
        for segment in parsed.path.split("/"):
            if len(segment) >= 32 and re.fullmatch(r"[A-Za-z0-9._~+/-]+=*", segment or ""):
                path_parts.append(REDACTED)
            else:
                path_parts.append(segment)
        path = "/".join(path_parts)
    else:
        path = parsed.path
    safe = urlunsplit((parsed.scheme, netloc, path, urlencode(query), ""))
    if dest != RedactionDestination.PRIVATE_EVIDENCE:
        safe = _apply_secret_shapes(safe)
    return safe


def _redact_http_message(text: str, *, destination: RedactionDestination) -> str:
    lines = text.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    out: list[str] = []
    headers_done = False
    body_lines: list[str] = []
    for index, line in enumerate(lines):
        if not headers_done:
            if line == "":
                headers_done = True
                out.append(line)
                continue
            if index == 0 and _HTTP_START.match(line):
                parts = line.split(" ", 2)
                if len(parts) >= 2 and parts[0].isupper() and not parts[0].startswith("HTTP"):
                    target = parts[1]
                    if target.startswith(("http://", "https://")):
                        parts[1] = redact_url(target, destination=destination)
                    elif "?" in target:
                        path, _, query = target.partition("?")
                        pairs = [
                            (k, REDACTED if SENSITIVE_KEY.search(k) else v)
                            for k, v in parse_qsl(query, keep_blank_values=True)
                        ]
                        parts[1] = path + (("?" + urlencode(pairs)) if pairs else "")
                    out.append(" ".join(parts))
                else:
                    out.append(
                        _apply_secret_shapes(line) if destination != RedactionDestination.PRIVATE_EVIDENCE else line
                    )
                continue
            if ":" in line:
                name, _, value = line.partition(":")
                redacted = redact_headers({name.strip(): value.strip()}, destination=destination)
                out.append(f"{name.strip()}: {redacted[name.strip()]}")
                continue
            out.append(line)
        else:
            body_lines.append(line)
    body = "\n".join(body_lines)
    if body:
        out.append(redact_text(body, destination=destination) or "")
    return "\n".join(out)


def redact_data(
    value: Any,
    *,
    destination: RedactionDestination | None = None,
    _depth: int = 0,
    _deadline: float | None = None,
    _max_depth: int = DEFAULT_MAX_DEPTH,
    _errors: list[str] | None = None,
) -> Any:
    dest = destination or RedactionDestination.MINIMIZED_ARTIFACT
    errors = _errors if _errors is not None else []
    if _deadline is not None and time.monotonic() > _deadline:
        raise RedactionLimitError(_safe_error("Redaction time bound exceeded."))
    if _depth > _max_depth:
        errors.append("max_depth_exceeded")
        return REDACTED
    if isinstance(value, dict):
        result: dict[Any, Any] = {}
        for key, item in value.items():
            key_text = str(key)
            lowered = key_text.lower()
            if (
                lowered
                in {
                    "sha256",
                    "digest",
                    "content_sha256",
                    "bundle_sha256",
                    "provenance_hash",
                    "prompt_sha256",
                }
                and isinstance(item, str)
                and _SHA256_HEX.fullmatch(item)
            ):
                result[key] = item
                continue
            if (
                lowered in {"source_path", "path", "file_path", "local_path", "absolute_path"}
                and isinstance(item, str)
                and _looks_like_filesystem_path(item)
            ):
                if dest == RedactionDestination.PRIVATE_EVIDENCE:
                    result[key] = item
                elif dest == RedactionDestination.MINIMIZED_ARTIFACT:
                    result[key] = item.replace("\\", "/").rstrip("/").rsplit("/", 1)[-1] or REDACTED
                else:
                    result[key] = "[path-redacted]"
                continue
            if SENSITIVE_KEY.search(key_text):
                if dest == RedactionDestination.PRIVATE_EVIDENCE:
                    result[key] = redact_text(item, destination=dest) if isinstance(item, str) else item
                else:
                    result[key] = REDACTED
                continue
            result[key] = redact_data(
                item,
                destination=dest,
                _depth=_depth + 1,
                _deadline=_deadline,
                _max_depth=_max_depth,
                _errors=errors,
            )
        return result
    if isinstance(value, list):
        return [
            redact_data(
                item,
                destination=dest,
                _depth=_depth + 1,
                _deadline=_deadline,
                _max_depth=_max_depth,
                _errors=errors,
            )
            for item in value
        ]
    if isinstance(value, str):
        return redact_text(value, destination=dest) or ""
    return value


def redact_text(value: str | None, *, destination: RedactionDestination | None = None) -> str | None:
    if value is None:
        return None
    dest = destination or RedactionDestination.MINIMIZED_ARTIFACT
    if len(value) > DEFAULT_MAX_CHARS:
        head = value[:DEFAULT_MAX_CHARS]
        suffix = "\n[truncated: input exceeded redaction char bound]"
        return (redact_text(head, destination=dest) or "") + suffix

    try:
        parsed = json.loads(value)
    except (ValueError, TypeError):
        parsed = None
    except RecursionError:
        return REDACTED
    if isinstance(parsed, (dict, list)):
        try:
            return json.dumps(redact_data(parsed, destination=dest), ensure_ascii=True)
        except (TypeError, ValueError, RedactionLimitError):
            return REDACTED

    if "\n" in value and _HTTP_START.match(value.lstrip("\ufeff")):
        try:
            return _redact_http_message(value, destination=dest)
        except RedactionLimitError:
            return REDACTED

    if value.startswith(("http://", "https://")) and not any(char.isspace() for char in value):
        return redact_url(value, destination=dest)

    if "=" in value and "\n" not in value and not any(char in value for char in "<>{}"):
        pairs = parse_qsl(value, keep_blank_values=True)
        if pairs and any(SENSITIVE_KEY.search(key) for key, _ in pairs):
            encoded = urlencode([(key, REDACTED if SENSITIVE_KEY.search(key) else item) for key, item in pairs])
            if dest != RedactionDestination.PRIVATE_EVIDENCE:
                return _apply_secret_shapes(encoded)
            return encoded

    lowered = value.lower()
    if "<input" in lowered or "<html" in lowered or "<form" in lowered:
        html = redact_html_secrets(value, redact_all_hidden=dest != RedactionDestination.PRIVATE_EVIDENCE)
        if dest != RedactionDestination.PRIVATE_EVIDENCE:
            html = _apply_secret_shapes(html)
            if dest.value in _SHAREABLE:
                html = _strip_local_paths(html)
        return html

    text = value
    if dest == RedactionDestination.PRIVATE_EVIDENCE:
        return redact_jwts(text)

    text = _apply_secret_shapes(text)
    if _SECRET_KEYWORD.search(text):
        text = _KV_SECRET.sub(lambda match: match.group(1) + REDACTED, text)
    if dest.value in _SHAREABLE:
        text = _strip_local_paths(text)
        text = _apply_secret_shapes(text)
    return text


def scrub_model_output(value: str) -> tuple[str, bool]:
    """Prevent AI text from reintroducing redacted secrets into shareable surfaces."""
    cleaned = redact_text(value, destination=RedactionDestination.MODEL_INPUT) or ""
    return cleaned, cleaned != value


def redact_for(
    destination: RedactionDestination | str,
    value: Any,
    *,
    max_chars: int = DEFAULT_MAX_CHARS,
    max_depth: int = DEFAULT_MAX_DEPTH,
    max_seconds: float = DEFAULT_MAX_SECONDS,
) -> RedactionResult:
    """Apply destination policy with explicit bounds and truncation metadata."""
    dest = RedactionDestination(destination) if not isinstance(destination, RedactionDestination) else destination
    started = time.perf_counter()
    deadline = time.monotonic() + max_seconds
    errors: list[str] = []
    truncated = False
    if isinstance(value, str):
        chars_in = len(value)
    elif value is None:
        chars_in = 0
    else:
        chars_in = len(json.dumps(value, default=str))
    if chars_in > max_chars:
        truncated = True
        if isinstance(value, str):
            value = value[:max_chars]
        else:
            errors.append("input_exceeded_char_bound")
            value = {"_redaction": REDACTED, "truncated": True, "reason": "input_exceeded_char_bound"}
    try:
        redacted = redact_data(
            value,
            destination=dest,
            _deadline=deadline,
            _max_depth=max_depth,
            _errors=errors,
        )
    except RedactionLimitError as exc:
        errors.append(_safe_error(str(exc)))
        redacted = REDACTED
        truncated = True
    except (RecursionError, MemoryError):
        errors.append("parse_or_memory_limit")
        redacted = REDACTED
        truncated = True
    if isinstance(redacted, str):
        chars_out = len(redacted)
    else:
        chars_out = len(json.dumps(redacted, default=str))
    return RedactionResult(
        redacted,
        truncated=truncated or "max_depth_exceeded" in errors,
        parse_errors=errors,
        destination=dest,
        elapsed_ms=round((time.perf_counter() - started) * 1000, 3),
        chars_in=chars_in,
        chars_out=chars_out,
    )


UNRECOGNIZED_FORMATS = (
    "protobuf / msgpack / cbor binary bodies",
    "custom binary session tickets",
    "multipart MIME with nested encodings beyond text parts",
    "novel API key formats not matching known prefixes",
    "secrets split across multiple fields or encoded (base32/rot13/xor)",
    "images or PDFs embedding credentials as pixels/text",
    "WebSocket frames and HTTP/2 binary headers",
)
RESIDUAL_RISKS = (
    "Pattern and structure rules are best-effort; unknown secret shapes can pass.",
    "Private evidence destinations intentionally retain values for authorized validation — handle those files as secrets.",
    "Provenance hashes do not prove non-existence of secrets in the preimage.",
    "Adversarial text can attempt to reassemble redacted fragments; callers must not concatenate raw private fields into shareable outputs.",
    "Truncation markers indicate incomplete evidence; do not treat truncated shareable views as complete captures.",
)
