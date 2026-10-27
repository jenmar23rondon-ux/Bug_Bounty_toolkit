"""Offline information-disclosure indicator detection for stored HTTP responses.

This module separates three questions that are easy to conflate:

* **secret/sensitive-shape detection** — does the stored body contain something
  shaped like a credential, token, key, PII, stack trace, ...?
* **audience exposure** — who received the response (public, the owner, another
  actor, unknown)? Data shown to its own owner is usually intended.
* **unauthorized access** — whether the audience *should* have seen it. That is
  never decided here; it requires manual authorization validation.

Every result carries ``finding_confirmed = False``. Indicators are minimized: only
category, rule, location, length and a short salted fingerprint are emitted —
never the matched value, an excerpt, or the original body. The original body stays
in the caller's private storage; its SHA-256 is kept for provenance. Shape rules
reuse :mod:`bugbounty_toolkit.core.redaction` (JWT shape, sensitive key names,
provenance digest) instead of duplicating that secret detector. No network I/O and
no AI calls happen here; text in bodies (including prompt-injection attempts) is
treated as inert data.
"""

from __future__ import annotations

import base64
import binascii
from dataclasses import dataclass, field
import gzip
import hashlib
import json
import re
import time
from typing import Any, Mapping
import zlib

from bugbounty_toolkit.core.redaction import JWT_TOKEN, SENSITIVE_KEY, provenance_digest

ANALYSIS_VERSION = "information-disclosure-v1"
MAX_BODY_CHARS = 1_000_000
MAX_JSON_DEPTH = 32
MAX_INDICATORS = 200

STATES = (
    "not_observed",
    "indicator_detected",
    "insufficient_context",
    "access_control_validation_required",
    "public_or_intended_information",
    "invalid_evidence",
    "ready_for_manual_review",
)
CATEGORIES = (
    "credentials",
    "token",
    "private_key",
    "env_vars",
    "internal_config",
    "stack_trace",
    "pii",
    "private_file_ref",
    "debug_info",
)
AUDIENCES = ("public", "authenticated_self", "cross_actor", "unknown")
_SECRET_CATEGORIES = frozenset({"credentials", "token", "private_key", "env_vars"})

_PRIVATE_PEM = re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----([\s\S]{0,8192}?)-----END")
_PUBLIC_PEM = re.compile(r"-----BEGIN (?:CERTIFICATE|PUBLIC KEY|RSA PUBLIC KEY)-----")
_CANARY = re.compile(r"(?i)\bBBTK[-_]CANARY[-_][A-Za-z0-9_-]{6,}")
_VENDOR_KEY = re.compile(r"\b(?:sk_live_[A-Za-z0-9]{16,}|gh[pousr]_[A-Za-z0-9]{20,}|xox[baprs]-[A-Za-z0-9-]{10,})")
_ENV_LINE = re.compile(r"(?m)^\s*(?:export\s+)?([A-Z][A-Z0-9_]{2,64})\s*=\s*(\S{1,512})\s*$")
_ENV_SECRET_NAME = re.compile(r"PASSWORD|PASSWD|SECRET|TOKEN|API_?KEY|PRIVATE|CREDENTIAL")
_URL_CREDS = re.compile(r"\b[a-z][a-z0-9+.-]{1,20}://[^\s:/@\"']{1,64}:([^\s@/\"']{3,128})@[^\s\"']{1,255}", re.I)
_INTERNAL_HOST = re.compile(
    r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}"
    r"|[a-z0-9-]+\.(?:internal|corp|local)(?:\.[a-z0-9.-]+)?)\b",
    re.I,
)
_STACK = (
    re.compile(r"Traceback \(most recent call last\):"),
    re.compile(r"(?m)^\s+at [\w$.<>]+\([\w$.-]+\.(?:java|kt|scala|js|ts|cs):\d+\)"),
    re.compile(r"(?m)^\s+at .+ \(.+\.js:\d+:\d+\)"),
    re.compile(r"(?i)\bPHP (?:Fatal|Parse) error\b.+ on line \d+"),
    re.compile(r"(?m)^goroutine \d+ \[running\]:"),
)
_PRIVATE_FILE = re.compile(
    r"(?<![\w.-])(?:/var/backups/|/etc/(?:shadow|passwd)\b|/root/|/home/[\w.-]+/\.ssh/|[\w./-]+\.(?:sql|bak|dump|sqlite)(?:\.gz)?\b"
    r"|[\w./-]*\.git/config\b|[\w./-]*id_rsa\b)[^\s\"'<>]{0,200}"
)
_DEBUG_KEYS = frozenset({"debug", "debug_mode", "stacktrace", "stack_trace", "sql_query", "query_log", "xdebug"})
_PII_KEYS = {
    "ssn": "pii",
    "social_security_number": "pii",
    "national_id": "pii",
    "passport": "pii",
    "date_of_birth": "pii",
    "dob": "pii",
    "credit_card": "pii",
    "card_number": "pii",
    "iban": "pii",
}
_SSN = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
_PLACEHOLDER = re.compile(
    r"(?i)^(?:<[^>]{0,64}>|\{\{[^}]{0,64}\}\}|\$\{[^}]{0,64}\}|your[_-].*|.*[_-]here|changeme|change[_-]me|example.*|"
    r".*_example(?:_.*)?|sample.*|dummy.*|placeholder|redacted|\[redacted\]|null|none|true|false|test|password|secret|"
    r"\*+|x+|0+|\.+|-+)$"
)
_DOC_PATH = re.compile(r"(?i)/(?:docs?|documentation|api-docs|swagger|openapi|reference|guides?|examples?)(?:/|$|\.)")
_SUPPORTED_ENCODINGS = frozenset({"", "identity", "gzip", "deflate"})


@dataclass(frozen=True)
class Indicator:
    """One minimized indicator. Holds no matched value or excerpt."""

    category: str
    rule: str
    location: str
    value_length: int
    fingerprint: str
    suppressed_reason: str | None = None

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {
            "category": self.category,
            "rule": self.rule,
            "location": self.location,
            "value_length": self.value_length,
            "fingerprint": self.fingerprint,
        }
        if self.suppressed_reason:
            data["suppressed_reason"] = self.suppressed_reason
        return data


@dataclass
class DisclosureAssessment:
    response_id: str
    state: str
    audience: str
    body_sha256: str | None
    categories: list[str]
    indicators: list[Indicator]
    suppressed: list[Indicator]
    reasons: list[str]
    incomplete: bool
    elapsed_ms: float
    finding_confirmed: bool = False
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "analysis_version": ANALYSIS_VERSION,
            "response_id": self.response_id,
            "state": self.state,
            "finding_confirmed": False,
            "audience": self.audience,
            "body_sha256": self.body_sha256,
            "categories": list(self.categories),
            "indicators": [item.to_dict() for item in self.indicators],
            "suppressed": [item.to_dict() for item in self.suppressed],
            "reasons": list(self.reasons),
            "incomplete": self.incomplete,
            "dimensions": {
                "secret_shape_detected": any(item.category in _SECRET_CATEGORIES for item in self.indicators),
                "audience_exposure": self.audience,
                "unauthorized_access": "not_determined_requires_manual_validation",
            },
            "secret_values_included": False,
            "network_requests_sent": 0,
            "ai_requests_sent": 0,
        }


def _fingerprint(value: str, salt: str) -> str:
    # Salted and shortened so low-entropy values cannot be trivially reversed from shareable output.
    return hashlib.sha256(f"{ANALYSIS_VERSION}\0{salt}\0{value}".encode("utf-8", "replace")).hexdigest()[:12]


def _is_placeholder(value: str) -> bool:
    stripped = value.strip().strip("\"'")
    if len(stripped) < 6 or _PLACEHOLDER.match(stripped):
        return True
    return len(set(stripped.lower())) <= 2


class _Scanner:
    def __init__(self, salt: str, reflected: set[str], is_doc: bool) -> None:
        self.salt = salt
        self.reflected = reflected
        self.is_doc = is_doc
        self.found: list[Indicator] = []
        self.suppressed: list[Indicator] = []
        self._seen: set[tuple[str, str, str]] = set()

    def add(self, category: str, rule: str, location: str, value: str, *, check_placeholder: bool = True) -> None:
        key = (category, rule, _fingerprint(value, self.salt))
        if key in self._seen or len(self.found) + len(self.suppressed) >= MAX_INDICATORS:
            return
        self._seen.add(key)
        reason = None
        if value in self.reflected or any(len(item) >= 6 and item in value for item in self.reflected):
            reason = "reflected_from_request"
        elif check_placeholder and _is_placeholder(value):
            reason = "placeholder_value"
        elif check_placeholder and rule == "sensitive_key_value" and re.search(r"\s", value.strip()):
            reason = "descriptive_text_not_secret"
        elif self.is_doc:
            reason = "documentation_example"
        indicator = Indicator(category, rule, location, len(value), key[2], reason)
        (self.suppressed if reason else self.found).append(indicator)

    def scan_text(self, text: str, location: str) -> None:
        for match in _PRIVATE_PEM.finditer(text):
            self.add("private_key", "pem_private_key", location, match.group(1).strip(), check_placeholder=False)
        for match in JWT_TOKEN.finditer(text):
            self.add("token", "jwt_shape", location, match.group(0), check_placeholder=False)
        for match in _CANARY.finditer(text):
            self.add("token", "synthetic_canary", location, match.group(0), check_placeholder=False)
        for match in _VENDOR_KEY.finditer(text):
            self.add("credentials", "vendor_key_shape", location, match.group(0))
        for match in _URL_CREDS.finditer(text):
            self.add("internal_config", "url_embedded_credentials", location, match.group(1))
        for stack in _STACK:
            frame = stack.search(text)
            if frame:
                self.add("stack_trace", "stack_trace_frame", location, frame.group(0), check_placeholder=False)
                break
        for match in _PRIVATE_FILE.finditer(text):
            self.add("private_file_ref", "private_file_path", location, match.group(0), check_placeholder=False)
        env_lines = list(_ENV_LINE.finditer(text))
        if len(env_lines) >= 2:
            for match in env_lines:
                if _ENV_SECRET_NAME.search(match.group(1)):
                    self.add("env_vars", "dotenv_secret_assignment", f"{location}:{match.group(1)}", match.group(2))
        for match in _SSN.finditer(text):
            self.add("pii", "ssn_shape", location, match.group(0), check_placeholder=False)

    def scan_json(self, value: Any, path: str, depth: int) -> None:
        if depth > MAX_JSON_DEPTH:
            return
        if isinstance(value, dict):
            for raw_key, child in value.items():
                key = str(raw_key)
                child_path = f"{path}.{key}"
                lowered = key.lower()
                if isinstance(child, str):
                    if lowered in _PII_KEYS:
                        self.add("pii", "pii_field", child_path, child)
                    elif lowered in {"database_url", "db_url", "dsn", "connection_string"} or (
                        lowered.endswith(("_host", "_url")) and _INTERNAL_HOST.search(child)
                    ):
                        if _INTERNAL_HOST.search(child) or _URL_CREDS.search(child):
                            self.add("internal_config", "internal_endpoint_field", child_path, child)
                    elif SENSITIVE_KEY.search(key) and not lowered.endswith(("_type", "_expires", "_expiry", "_at")):
                        category = "token" if "token" in lowered or "session" in lowered else "credentials"
                        self.add(category, "sensitive_key_value", child_path, child)
                if lowered in _DEBUG_KEYS and child not in (False, None, "", 0, "false", "off"):
                    self.add(
                        "debug_info",
                        "debug_flag",
                        child_path,
                        json.dumps(child, sort_keys=True)[:256],
                        check_placeholder=False,
                    )
                self.scan_json(child, child_path, depth + 1)
        elif isinstance(value, list):
            for index, child in enumerate(value[:1000]):
                self.scan_json(child, f"{path}[{index}]", depth + 1)
        elif isinstance(value, str):
            self.scan_text(value, path)


def _decode_body(headers: Mapping[str, str], body: Any) -> tuple[str | None, str | None]:
    if not isinstance(body, str):
        return None, "body_missing_or_not_text"
    encoding = ""
    for name, value in headers.items():
        if str(name).lower() == "content-encoding":
            encoding = str(value).strip().lower()
    if encoding not in _SUPPORTED_ENCODINGS:
        return None, "unsupported_content_encoding"
    if encoding in {"gzip", "deflate"}:
        try:
            raw = base64.b64decode(body, validate=True)
            data = gzip.decompress(raw) if encoding == "gzip" else zlib.decompress(raw)
            if len(data) > MAX_BODY_CHARS:
                return None, "decoded_body_exceeds_limit"
            return data.decode("utf-8"), None
        except (binascii.Error, OSError, EOFError, zlib.error, UnicodeDecodeError):
            return None, "undecodable_compressed_body"
    if len(body) > MAX_BODY_CHARS:
        return None, "body_exceeds_limit"
    return body, None


def _reflected_values(request: Mapping[str, Any]) -> set[str]:
    values: set[str] = set()
    raw = request.get("body")
    texts = [raw] if isinstance(raw, str) else []
    query = request.get("query")
    if isinstance(query, str):
        texts.append(query)
    for text in texts:
        try:
            parsed = json.loads(text)
        except ValueError:
            parsed = None
        stack: list[Any] = [parsed] if parsed is not None else []
        while stack:
            item = stack.pop()
            if isinstance(item, dict):
                stack.extend(item.values())
            elif isinstance(item, list):
                stack.extend(item)
            elif isinstance(item, str) and len(item) >= 6:
                values.add(item)
        for part in re.split(r"[&=\s]", text):
            if len(part) >= 6:
                values.add(part)
    return values


def assess_disclosure(record: Mapping[str, Any], *, salt: str = "") -> DisclosureAssessment:
    """Assess one stored response record. Never raises on hostile content; never confirms."""
    started = time.perf_counter()
    response_id = str(record.get("id", "response"))[:128]
    audience = str(record.get("audience", "unknown"))
    if audience not in AUDIENCES:
        audience = "unknown"
    response = record.get("response")
    request = record.get("request") if isinstance(record.get("request"), Mapping) else {}
    assert isinstance(request, Mapping)

    def done(state: str, reasons: list[str], **kw: Any) -> DisclosureAssessment:
        return DisclosureAssessment(
            response_id=response_id,
            state=state,
            audience=audience,
            body_sha256=kw.get("sha"),
            categories=kw.get("categories", []),
            indicators=kw.get("indicators", []),
            suppressed=kw.get("suppressed", []),
            reasons=reasons,
            incomplete=kw.get("incomplete", False),
            elapsed_ms=round((time.perf_counter() - started) * 1000, 3),
        )

    if not isinstance(response, Mapping) or not isinstance(response.get("status"), int):
        return done("invalid_evidence", ["response_missing_or_without_status"])
    raw_headers = response.get("headers") or {}
    headers = {str(k): str(v) for k, v in raw_headers.items()} if isinstance(raw_headers, Mapping) else {}
    body_value = response.get("body")
    sha = provenance_digest(body_value) if isinstance(body_value, str) else None
    text, error = _decode_body(headers, body_value)
    if text is None:
        return done("invalid_evidence", [error or "invalid_body"], sha=sha)
    truncated = bool(response.get("truncated"))
    url = str(record.get("url", ""))
    scanner = _Scanner(salt or sha or "", _reflected_values(request), bool(_DOC_PATH.search(url)))
    content_type = headers.get("Content-Type", headers.get("content-type", "")).lower()
    parsed: Any = None
    if "json" in content_type or text.lstrip().startswith(("{", "[")):
        try:
            parsed = json.loads(text)
        except ValueError:
            parsed = None
    if parsed is not None:
        scanner.scan_json(parsed, "$", 0)
    else:
        scanner.scan_text(text, "body")
        if text.lstrip().startswith(("{", "[")):
            # Malformed/partial JSON: recover simple "key": "value" pairs as text evidence.
            for match in re.finditer(r'"([\w.-]{1,64})"\s*:\s*"([^"\\]{1,512})"', text):
                scanner.scan_json({match.group(1): match.group(2)}, "$~", 0)
    public_material = bool(_PUBLIC_PEM.search(text)) and not scanner.found
    indicators = scanner.found
    categories = sorted({item.category for item in indicators})
    reasons: list[str] = []
    kw: dict[str, Any] = {
        "sha": sha,
        "categories": categories,
        "indicators": indicators,
        "suppressed": scanner.suppressed,
        "incomplete": truncated,
    }
    if truncated:
        reasons.append("response_truncated")
    if not indicators:
        if truncated:
            return done("insufficient_context", reasons + ["no_indicator_in_partial_body"], **kw)
        if public_material:
            return done("public_or_intended_information", ["public_key_material_only"], **kw)
        if scanner.is_doc:
            return done("public_or_intended_information", ["documentation_examples_only"], **kw)
        return done("not_observed", reasons + ["no_sensitive_indicator"], **kw)
    secret = any(category in _SECRET_CATEGORIES for category in categories)
    if audience == "cross_actor":
        return done("access_control_validation_required", reasons + ["sensitive_data_for_other_actor"], **kw)
    if audience == "authenticated_self" and not secret:
        return done("public_or_intended_information", reasons + ["own_data_shown_to_owner"], **kw)
    if audience == "public" and secret and not truncated and response.get("status") == 200:
        return done("ready_for_manual_review", reasons + ["secret_shape_served_to_public_audience"], **kw)
    return done("indicator_detected", reasons + ["indicator_requires_context"], **kw)


def assess_batch(records: list[Mapping[str, Any]], *, salt: str = "") -> dict[str, Any]:
    """Assess many records; returns a minimized, shareable summary."""
    if not isinstance(records, list):
        raise ValueError("Disclosure input must contain a list of response records.")
    results = [
        assess_disclosure(item, salt=salt).to_dict() if isinstance(item, Mapping) else _invalid(i)
        for i, item in enumerate(records)
    ]
    counts: dict[str, int] = {state: 0 for state in STATES}
    for item in results:
        counts[item["state"]] += 1
    return {
        "analysis_version": ANALYSIS_VERSION,
        "finding_confirmed": False,
        "results": results,
        "state_counts": counts,
        "secret_values_included": False,
        "network_requests_sent": 0,
        "ai_requests_sent": 0,
        "note": "Indicators are leads for manual review; validity, activity or exploitability of any value is not asserted.",
    }


def _invalid(index: int) -> dict[str, Any]:
    return DisclosureAssessment(
        f"record-{index}", "invalid_evidence", "unknown", None, [], [], [], ["record_not_object"], False, 0.0
    ).to_dict()


def load_records(text: str) -> list[Mapping[str, Any]]:
    """Accept {"responses": [...]}, {"cases": [...]}, a list, or one record."""
    try:
        data = json.loads(text)
    except ValueError as exc:
        raise ValueError("Disclosure input must be JSON.") from exc
    if isinstance(data, dict):
        for key in ("responses", "cases"):
            if isinstance(data.get(key), list):
                return list(data[key])
        return [data]
    if isinstance(data, list):
        return data
    raise ValueError("Disclosure input must be a JSON object or list.")
