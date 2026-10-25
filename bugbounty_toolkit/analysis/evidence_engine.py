from __future__ import annotations

import base64
import csv
from dataclasses import asdict, dataclass
from datetime import datetime
import hashlib
import hmac
from html.parser import HTMLParser
import io
import json
from pathlib import Path
import re
import secrets
from typing import Any, Iterable
from urllib.parse import parse_qsl, urlsplit
import xml.etree.ElementTree as ET

from ..core.redaction import redact_html_secrets, redact_jwts, redact_text

MAX_INPUT_BYTES = 32 * 1024 * 1024
MAX_INPUT_FILES = 100
MAX_RECORDS = 10_000
MAX_CORRELATION_GROUPS = 2_000
_SENSITIVE_NAME = re.compile(
    r"password|passwd|secret|token|api.?key|authorization|cookie|session|csrf|credential", re.I
)
_RESOURCE_NAME = re.compile(r"(?:^id$|(?:^|[_-])(?:id|uid|uuid|user|account|resource)(?:$|[_-]))", re.I)
_RESOURCE_COLLECTIONS = {
    "account",
    "accounts",
    "address",
    "addresses",
    "basket",
    "baskets",
    "cart",
    "carts",
    "document",
    "documents",
    "file",
    "files",
    "item",
    "items",
    "order",
    "orders",
    "record",
    "records",
    "resource",
    "resources",
    "user",
    "users",
}
_STATIC_RESOURCE_SEGMENTS = {"all", "count", "create", "current", "list", "me", "metadata", "new", "search", "self"}
_UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f-]{27,}$", re.I)
_ABSOLUTE_URL = re.compile(r"https?://[^\s\"'<>]+", re.I)
_TIMESTAMP = re.compile(r"\b\d{4}-\d\d-\d\d[T ]\d\d:\d\d:\d\d(?:\.\d+)?(?:Z|[+-]\d\d:?\d\d)?\b")
_VOLATILE_KEYS = {"created_at", "updated_at", "timestamp", "request_id", "trace_id", "nonce"}
_TOOLKIT_TYPES = {
    "access-control",
    "xss",
    "sqli",
    "cors",
    "open-redirect",
    "ssrf",
    "csrf-audit",
    "apk-scan",
}


@dataclass(frozen=True)
class EvidenceProvenance:
    source_path: str
    locator: str


@dataclass(frozen=True)
class EvidenceRecord:
    evidence_id: str
    source_tools: tuple[str, ...]
    captured_at: str | None
    host: str | None
    endpoint: str | None
    method: str | None
    parameters: tuple[str, ...]
    status_code: int | None
    session_fingerprint: str | None
    resource_fingerprint: str | None
    response_fingerprint: str | None
    response_shape_fingerprint: str | None
    sensitivity: str
    validation_status: str
    technical_evidence: dict[str, object]
    provenance: tuple[EvidenceProvenance, ...]
    request_session_fingerprint: str | None = None
    response_session_fingerprint: str | None = None


@dataclass(frozen=True)
class _Source:
    tool: str
    locator: str
    url: str | None = None
    method: str | None = None
    request_headers: dict[str, str] | None = None
    request_body: str = ""
    response_headers: dict[str, str] | None = None
    response_body: str = ""
    status_code: int | None = None
    captured_at: str | None = None
    parameters: tuple[str, ...] = ()
    technical: dict[str, object] | None = None
    sensitivity_hint: bool = False


def _fingerprint(value: str, salt: bytes) -> str:
    return hmac.new(salt, value.encode("utf-8", errors="replace"), hashlib.sha256).hexdigest()[:24]


def _safe_time(value: object) -> str | None:
    if not isinstance(value, str) or len(value) > 80:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    return parsed.isoformat(timespec="seconds")


def _header_map(value: object) -> dict[str, str]:
    if isinstance(value, dict):
        return {str(key): str(item) for key, item in value.items() if isinstance(item, (str, int, float))}
    if isinstance(value, list):
        output: dict[str, str] = {}
        for row in value:
            if isinstance(row, dict) and isinstance(row.get("name"), str):
                output[row["name"]] = str(row.get("value", ""))
        return output
    return {}


def _status(value: object) -> int | None:
    if type(value) is int and 100 <= value <= 599:
        return value
    if isinstance(value, str) and value.isdigit() and 100 <= int(value) <= 599:
        return int(value)
    return None


def _parameter_names(url: str | None, body: str, content_type: str = "") -> tuple[str, ...]:
    names: set[str] = set()
    if url:
        try:
            names.update(name for name, _ in parse_qsl(urlsplit(url).query, keep_blank_values=True) if name)
        except ValueError:
            pass
    if body:
        try:
            parsed = json.loads(body)
        except (json.JSONDecodeError, RecursionError):
            parsed = None
        if isinstance(parsed, dict):
            names.update(str(name) for name in parsed if name)
        elif "application/x-www-form-urlencoded" in content_type.lower():
            names.update(name for name, _ in parse_qsl(body, keep_blank_values=True) if name)
    return tuple(sorted(names, key=str.casefold))


def _endpoint(url: str | None, headers: dict[str, str], salt: bytes) -> tuple[str | None, str | None, list[str]]:
    if not isinstance(url, str) or len(url) > 16_384:
        return None, None, []
    try:
        parsed = urlsplit(url)
        host = parsed.hostname
        port = parsed.port
        if not host:
            header_host = next((value.strip() for key, value in headers.items() if key.lower() == "host"), None)
            if header_host and any(character.isspace() or character in "/\\?#" for character in header_host):
                return None, None, []
            authority = urlsplit(f"//{header_host}") if header_host else None
            if authority is None or authority.hostname is None or authority.username or authority.password:
                return None, None, []
            host = authority.hostname
            port = authority.port
        if not host:
            return None, None, []
        host = host.rstrip(".").lower()
        if ":" in host and not host.startswith("["):
            host = f"[{host}]"
        if port:
            host = f"{host}:{port}"
        path = parsed.path or "/"
        resource_values: list[str] = []
        segments = []
        path_segments = path.split("/")
        for index, segment in enumerate(path_segments):
            follows_collection = index > 0 and path_segments[index - 1].lower() in _RESOURCE_COLLECTIONS
            dynamic = (
                segment.isdigit()
                or bool(_UUID.fullmatch(segment))
                or (len(segment) >= 24 and segment.isalnum())
                or (follows_collection and bool(segment) and segment.casefold() not in _STATIC_RESOURCE_SEGMENTS)
            )
            if dynamic:
                resource_values.append(segment)
                segments.append("{id}")
            else:
                segments.append(segment)
        for name, value in parse_qsl(parsed.query, keep_blank_values=True):
            if _RESOURCE_NAME.search(name) and value:
                resource_values.append(value)
        endpoint = "/".join(segments)
        if not endpoint.startswith("/"):
            endpoint = "/" + endpoint
        return host, endpoint, resource_values
    except (ValueError, UnicodeError):
        return None, None, []


def _session_values(headers: dict[str, str]) -> list[str]:
    values = []
    for name, value in headers.items():
        lowered = name.lower()
        if lowered in {"authorization", "proxy-authorization", "cookie", "set-cookie", "x-api-key"}:
            if value:
                values.append(f"{lowered}:{value}")
    return sorted(values)


def _directional_session_fingerprint(headers: dict[str, str], *, response: bool, salt: bytes) -> str | None:
    """Fingerprint cookie/session material separately for observed flow transitions."""
    cookie_names = {"set-cookie"} if response else {"cookie"}
    cookie_values: list[str] = []
    auth_values: list[str] = []
    for name, value in headers.items():
        lowered = name.lower()
        if lowered in cookie_names and value:
            first = value.split(";", 1)[0].strip()
            if "=" in first:
                key, item = first.split("=", 1)
                if key.strip() and item.strip():
                    cookie_values.append(f"cookie:{key.strip().casefold()}={item.strip()}")
        elif lowered in {"authorization", "proxy-authorization", "x-api-key"} and value:
            auth_values.append(f"{lowered}:{value.strip()}")
    # Cookie names/values provide a comparable Set-Cookie -> Cookie transition. If
    # no cookie was observed, retain opaque auth-header continuity as a fallback.
    material = sorted(cookie_values) if cookie_values else sorted(auth_values)
    if not material:
        return None
    fingerprint = _fingerprint("\n".join(material), salt)
    return f"hmac-sha256:{fingerprint}"


def _normalized_body(body: str) -> str:
    safe = redact_jwts(redact_text(body) or "")
    safe = redact_html_secrets(safe)
    safe = _TIMESTAMP.sub("<timestamp>", safe)
    try:
        value = json.loads(safe)
    except (json.JSONDecodeError, RecursionError):
        return safe

    def normalize(item: Any, key: str = "", depth: int = 0) -> Any:
        if depth > 20:
            return "<depth-limit>"
        if key.casefold() in _VOLATILE_KEYS:
            return "<volatile>"
        if isinstance(item, dict):
            return {str(child): normalize(value, str(child), depth + 1) for child, value in sorted(item.items())}
        if isinstance(item, list):
            return [normalize(value, "", depth + 1) for value in item[:1000]]
        return item

    return json.dumps(normalize(value), sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _shape(value: str) -> str:
    if not value:
        shape: object = {"kind": "empty"}
    else:
        try:
            parsed = json.loads(value)
        except (json.JSONDecodeError, RecursionError):
            parser = _ShapeParser()
            try:
                parser.feed(value[:1_000_000])
                parser.close()
            except (ValueError, AssertionError):
                pass
            shape = {"kind": "html" if parser.tags else "text", "tags": parser.tags[:2000]}
        else:

            def json_shape(item: Any, depth: int = 0) -> object:
                if depth > 20:
                    return "depth-limit"
                if isinstance(item, dict):
                    return {str(key): json_shape(child, depth + 1) for key, child in sorted(item.items())}
                if isinstance(item, list):
                    children = {json.dumps(json_shape(child, depth + 1), sort_keys=True) for child in item[:100]}
                    return {"array": sorted(children)[:100]}
                if item is None:
                    return "null"
                if isinstance(item, bool):
                    return "boolean"
                if isinstance(item, (int, float)):
                    return "number"
                return "string"

            shape = json_shape(parsed)
    return json.dumps(shape, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


class _ShapeParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.tags: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        names = ",".join(sorted(name.lower() for name, _ in attrs))
        self.tags.append(f"<{tag.lower()}:{names}>")

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.handle_starttag(tag, attrs)


def _record(source: _Source, path: Path, salt: bytes) -> EvidenceRecord:
    request_headers = source.request_headers or {}
    response_headers = source.response_headers or {}
    all_session_values = _session_values(request_headers) + _session_values(response_headers)
    host, endpoint, resource_values = _endpoint(source.url, request_headers, salt)
    query_parameters = _parameter_names(
        source.url,
        source.request_body,
        next((value for key, value in request_headers.items() if key.lower() == "content-type"), ""),
    )
    parameter_names = tuple(sorted(set(source.parameters) | set(query_parameters), key=str.casefold))
    for name, value in parse_qsl(urlsplit(source.url).query, keep_blank_values=True) if source.url else []:
        if _RESOURCE_NAME.search(name) and value and value not in resource_values:
            resource_values.append(value)
    session_fingerprint = _fingerprint("\n".join(sorted(all_session_values)), salt) if all_session_values else None
    request_session_fingerprint = _directional_session_fingerprint(request_headers, response=False, salt=salt)
    response_session_fingerprint = _directional_session_fingerprint(response_headers, response=True, salt=salt)
    resource_fingerprint = _fingerprint("\n".join(sorted(resource_values)), salt) if resource_values else None
    normalized = _normalized_body(source.response_body)
    response_fingerprint = _fingerprint(normalized, salt) if source.response_body else None
    shape = _shape(source.response_body)
    response_shape = _fingerprint(shape, salt) if source.response_body else None
    try:
        url_parts = urlsplit(source.url or "")
        url_contains_credentials = bool(url_parts.username or url_parts.password)
    except ValueError:
        url_contains_credentials = False
    sensitive = (
        source.sensitivity_hint
        or bool(all_session_values)
        or any(_SENSITIVE_NAME.search(name) for name in parameter_names)
        or url_contains_credentials
        or bool(re.search(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", source.response_body, re.I))
    )
    content_type = next(
        (
            value.split(";", 1)[0].strip().lower()[:80]
            for key, value in response_headers.items()
            if key.lower() == "content-type"
        ),
        "",
    )
    technical: dict[str, object] = {
        "content_type": content_type,
        "response_bytes": len(source.response_body.encode("utf-8", errors="replace")),
    }
    if response_fingerprint:
        technical["response_fingerprint"] = response_fingerprint
    if response_shape:
        technical["response_shape_fingerprint"] = response_shape
    if source.technical:
        for technical_key, technical_value in source.technical.items():
            if technical_key in {
                "classification",
                "finding_category",
                "severity",
                "template_id",
                "matcher_name",
                "line_length",
                "format",
                "response_length",
                "response_words",
                "response_lines",
                "extracted_result_count",
            }:
                if isinstance(technical_value, (str, int, float, bool)) or technical_value is None:
                    technical[technical_key] = technical_value
    normalized_method = source.method.upper()[:16] if isinstance(source.method, str) else None
    identity = {
        "host": host,
        "endpoint": endpoint,
        "method": normalized_method,
        "parameters": parameter_names,
        "status_code": source.status_code,
        "session": session_fingerprint,
        "request_session": request_session_fingerprint,
        "response_session": response_session_fingerprint,
        "resource": resource_fingerprint,
        "response": response_fingerprint,
        "technical": technical.get("classification"),
    }
    evidence_id = hashlib.sha256(json.dumps(identity, sort_keys=True, separators=(",", ":")).encode()).hexdigest()[:24]
    return EvidenceRecord(
        evidence_id=evidence_id,
        source_tools=(source.tool,),
        captured_at=_safe_time(source.captured_at),
        host=host,
        endpoint=endpoint,
        method=normalized_method,
        parameters=parameter_names,
        status_code=source.status_code,
        session_fingerprint=f"hmac-sha256:{session_fingerprint}" if session_fingerprint else None,
        request_session_fingerprint=request_session_fingerprint,
        response_session_fingerprint=response_session_fingerprint,
        resource_fingerprint=f"hmac-sha256:{resource_fingerprint}" if resource_fingerprint else None,
        response_fingerprint=f"hmac-sha256:{response_fingerprint}" if response_fingerprint else None,
        response_shape_fingerprint=f"hmac-sha256:{response_shape}" if response_shape else None,
        sensitivity="sensitive" if sensitive else "low",
        validation_status="parsed",
        technical_evidence=technical,
        provenance=(EvidenceProvenance(str(path.resolve()), source.locator[:300]),),
    )


def _parse_http_message(message: str) -> tuple[str | None, str | None, dict[str, str], str, int | None]:
    normalized = message.replace("\r\n", "\n").replace("\r", "\n")
    head, separator, body = normalized.partition("\n\n")
    lines = head.splitlines()
    if not lines:
        return None, None, {}, "", None
    request = re.fullmatch(r"([A-Za-z]{1,16})\s+(\S+)\s+HTTP/\d(?:\.\d)?", lines[0])
    response = re.match(r"HTTP/\d(?:\.\d)?\s+(\d{3})(?:\s|$)", lines[0])
    headers: dict[str, str] = {}
    for line in lines[1:1000]:
        if ":" in line and not line[:1].isspace():
            name, value = line.split(":", 1)
            headers[name.strip()] = value.strip()[:16_384]
    if request:
        return request.group(2), request.group(1).upper(), headers, body if separator else "", None
    if response:
        return None, None, headers, body if separator else "", int(response.group(1))
    return None, None, headers, body if separator else "", None


def _pair_record(
    path: Path,
    locator: str,
    request: str,
    response: str,
    url_hint: str | None,
    salt: bytes,
    captured_at: str | None = None,
) -> EvidenceRecord:
    target, method, request_headers, request_body, _ = _parse_http_message(request)
    _, _, response_headers, response_body, status_code = _parse_http_message(response)
    url = target if target and target.startswith(("http://", "https://")) else url_hint
    if url is None and target:
        url = target
    parameters = _parameter_names(
        url,
        request_body,
        next((value for key, value in request_headers.items() if key.lower() == "content-type"), ""),
    )
    return _record(
        _Source(
            "burp",
            locator,
            url,
            method,
            request_headers,
            request_body,
            response_headers,
            response_body,
            status_code,
            captured_at,
            parameters,
            {"format": "burp-http"},
        ),
        path,
        salt,
    )


def _xml_name(tag: object) -> str:
    return str(tag).rsplit("}", 1)[-1].lower()


def _burp_xml(path: Path, raw: bytes, salt: bytes) -> list[EvidenceRecord]:
    if re.search(rb"<!\s*(?:DOCTYPE|ENTITY)\b", raw, re.I):
        raise ValueError("Burp XML DTD/entity declarations are not supported.")
    try:
        root = ET.fromstring(raw)
    except (ET.ParseError, ValueError, RecursionError) as exc:
        raise ValueError("Burp XML is malformed or too deeply nested.") from exc
    records: list[EvidenceRecord] = []
    for index, item in enumerate((node for node in root.iter() if _xml_name(node.tag) == "item"), start=1):
        if len(records) >= MAX_RECORDS:
            raise ValueError(f"Input exceeds the {MAX_RECORDS}-record import limit.")
        fields: dict[str, str] = {}
        messages: dict[str, str] = {}
        for child in item.iter():
            name = _xml_name(child.tag)
            if name in {"url", "host", "protocol", "path", "port", "time"} and child.text:
                fields.setdefault(name, child.text.strip())
            elif name in {"request", "response"} and child.text:
                value = child.text.strip()
                if child.attrib.get("base64", "").lower() == "true":
                    try:
                        value = base64.b64decode("".join(value.split()), validate=True).decode(
                            "utf-8", errors="replace"
                        )
                    except (ValueError, TypeError):
                        continue
                messages.setdefault(name, value)
        url = fields.get("url")
        if not url and fields.get("host") and fields.get("path"):
            protocol = fields.get("protocol", "https")
            if protocol not in {"http", "https"}:
                continue
            port = fields.get("port", "")
            netloc = fields["host"] if not port else f"{fields['host']}:{port}"
            url = f"{protocol}://{netloc}{fields['path']}"
        if messages.get("request") or messages.get("response"):
            records.append(
                _pair_record(
                    path,
                    f"/item[{index}]",
                    messages.get("request", ""),
                    messages.get("response", ""),
                    url,
                    salt,
                    fields.get("time"),
                )
            )
        elif url:
            records.append(
                _record(
                    _Source("burp", f"/item[{index}]/url", url=url, technical={"format": "burp-sitemap"}), path, salt
                )
            )
    if not records:
        raise ValueError("Burp XML did not contain supported items or sitemap URLs.")
    return records


def _har(path: Path, data: Any, salt: bytes) -> list[EvidenceRecord]:
    log = data.get("log") if isinstance(data, dict) else None
    entries = log.get("entries") if isinstance(log, dict) else None
    if not isinstance(entries, list):
        raise ValueError("HAR input must contain log.entries.")
    if len(entries) > MAX_RECORDS:
        raise ValueError(f"HAR exceeds the {MAX_RECORDS}-entry import limit.")
    records = []
    for index, entry in enumerate(entries, start=1):
        if not isinstance(entry, dict):
            continue
        request, response = entry.get("request", {}), entry.get("response", {})
        if not isinstance(request, dict) or not isinstance(response, dict):
            continue
        request_headers = _header_map(request.get("headers"))
        response_headers = _header_map(response.get("headers"))
        cookies = request.get("cookies", [])
        if isinstance(cookies, list) and cookies:
            cookie_values = [f"{item.get('name')}={item.get('value')}" for item in cookies if isinstance(item, dict)]
            if cookie_values:
                request_headers["Cookie"] = "; ".join(cookie_values)
        response_cookies = response.get("cookies", [])
        if isinstance(response_cookies, list) and response_cookies:
            response_headers["Set-Cookie"] = "; ".join(
                f"{item.get('name')}={item.get('value')}" for item in response_cookies if isinstance(item, dict)
            )
        post_data = request.get("postData", {})
        body = post_data.get("text", "") if isinstance(post_data, dict) else ""
        if isinstance(post_data, dict) and isinstance(post_data.get("mimeType"), str):
            if not any(name.lower() == "content-type" for name in request_headers):
                request_headers["Content-Type"] = post_data["mimeType"]
        content = response.get("content", {})
        response_body = content.get("text", "") if isinstance(content, dict) else ""
        if isinstance(content, dict) and content.get("encoding") == "base64" and isinstance(response_body, str):
            try:
                response_body = base64.b64decode(response_body, validate=True).decode("utf-8", errors="replace")
            except (ValueError, TypeError):
                response_body = ""
        if not isinstance(body, str):
            body = ""
        if not isinstance(response_body, str):
            response_body = ""
        parameters = set(_parameter_names(request.get("url") if isinstance(request.get("url"), str) else None, body))
        query = request.get("queryString", [])
        if isinstance(query, list):
            parameters.update(str(row["name"]) for row in query if isinstance(row, dict) and row.get("name"))
        if isinstance(post_data, dict) and isinstance(post_data.get("params"), list):
            parameters.update(
                str(row["name"]) for row in post_data["params"] if isinstance(row, dict) and row.get("name")
            )
        technical = {
            "format": "har",
            "response_bytes": response_body.__len__(),
        }
        record = _record(
            _Source(
                "har",
                f"/log/entries[{index - 1}]",
                request.get("url") if isinstance(request.get("url"), str) else None,
                request.get("method") if isinstance(request.get("method"), str) else None,
                request_headers,
                body,
                response_headers,
                response_body,
                _status(response.get("status")),
                entry.get("startedDateTime") if isinstance(entry.get("startedDateTime"), str) else None,
                tuple(sorted(parameters)),
                technical,
            ),
            path,
            salt,
        )
        records.append(record)
    return records


def _ffuf(path: Path, data: Any, salt: bytes) -> list[EvidenceRecord]:
    rows = data.get("results") if isinstance(data, dict) else None
    if not isinstance(rows, list):
        raise ValueError("FFUF JSON input must contain a results array.")
    if len(rows) > MAX_RECORDS:
        raise ValueError(f"FFUF input exceeds the {MAX_RECORDS}-result import limit.")
    records = []
    for index, row in enumerate(rows, start=1):
        if not isinstance(row, dict):
            continue
        url = (
            row.get("url") or row.get("input", {}).get("FUZZ")
            if isinstance(row.get("input", {}), dict)
            else row.get("url")
        )
        if not isinstance(url, str):
            continue
        technical: dict[str, object] = {"format": "ffuf-json"}
        for key in ("length", "words", "lines"):
            value = row.get(key)
            if type(value) is int and 0 <= value <= 2**53:
                technical[f"response_{key}"] = value
        records.append(
            _record(
                _Source(
                    "ffuf",
                    f"/results[{index - 1}]",
                    url,
                    row.get("method") if isinstance(row.get("method"), str) else None,
                    status_code=_status(row.get("status")),
                    technical=technical,
                ),
                path,
                salt,
            )
        )
    return records


def _nuclei_row(path: Path, row: dict[str, Any], locator: str, salt: bytes) -> EvidenceRecord:
    info = row.get("info", {})
    if not isinstance(info, dict):
        info = {}
    technical: dict[str, object] = {"format": "nuclei-jsonl"}
    for key, value in (
        ("template_id", row.get("template-id", row.get("templateID"))),
        ("severity", info.get("severity")),
        ("matcher_name", row.get("matcher-name")),
    ):
        if isinstance(value, str) and len(value) <= 200:
            technical[key] = redact_text(value) or ""
    extracted = row.get("extracted-results", [])
    if isinstance(extracted, list):
        technical["extracted_result_count"] = min(len(extracted), 1000)
    return _record(
        _Source(
            "nuclei",
            locator,
            row.get("matched-at")
            if isinstance(row.get("matched-at"), str)
            else row.get("host")
            if isinstance(row.get("host"), str)
            else None,
            row.get("method") if isinstance(row.get("method"), str) else None,
            technical=technical,
            sensitivity_hint=bool(row.get("request") or row.get("response")),
        ),
        path,
        salt,
    )


def _nuclei_jsonl(path: Path, text: str, salt: bytes, single: Any = None) -> list[EvidenceRecord]:
    if single is not None:
        rows = single if isinstance(single, list) else [single]
        data_rows = [(index, row) for index, row in enumerate(rows, start=1) if isinstance(row, dict)]
    else:
        data_rows = []
        for line_number, line in enumerate(text.splitlines(), start=1):
            if not line.strip():
                continue
            try:
                row = json.loads(line)
            except (json.JSONDecodeError, RecursionError) as exc:
                raise ValueError(f"Nuclei JSONL has invalid JSON on line {line_number}.") from exc
            if isinstance(row, dict):
                data_rows.append((line_number, row))
    if len(data_rows) > MAX_RECORDS:
        raise ValueError(f"Nuclei input exceeds the {MAX_RECORDS}-finding import limit.")
    return [_nuclei_row(path, row, f"line:{line_number}", salt) for line_number, row in data_rows]


def _toolkit_json(path: Path, data: Any, salt: bytes) -> list[EvidenceRecord]:
    rows: list[tuple[str, dict[str, Any]]] = []
    if isinstance(data, dict):
        kind = data.get("type")
        if isinstance(kind, str) and kind in _TOOLKIT_TYPES:
            source_rows = data.get("steps" if kind == "access-control" else "results", [])
            if isinstance(source_rows, list):
                rows.extend(
                    (f"{kind}:{index}", {**row, "type": kind})
                    for index, row in enumerate(source_rows)
                    if isinstance(row, dict)
                )
            if not rows:
                rows.append((kind, data))
        elif isinstance(data.get("findings"), list):
            rows.extend(
                (f"findings:{index}", row) for index, row in enumerate(data["findings"]) if isinstance(row, dict)
            )
        else:
            raise ValueError("Toolkit JSON is not a recognized native evidence file or program report.")
    elif isinstance(data, list):
        rows.extend((f"items:{index}", row) for index, row in enumerate(data) if isinstance(row, dict))
    else:
        raise ValueError("Toolkit evidence JSON must contain an object or array.")
    if len(rows) > MAX_RECORDS:
        raise ValueError(f"Toolkit evidence exceeds the {MAX_RECORDS}-record import limit.")
    output = []
    for locator, row in rows:
        raw_type = row.get("type")
        row_type = raw_type[:80] if isinstance(raw_type, str) else "toolkit"
        url = next(
            (row[key] for key in ("url", "target", "endpoint", "request_url") if isinstance(row.get(key), str)), None
        )
        status = _status(row.get("status_code"))
        classification = row.get("classification")
        technical: dict[str, object] = {"format": "toolkit-json"}
        technical["finding_category"] = row_type if row_type in _TOOLKIT_TYPES else "toolkit"
        if isinstance(classification, str) and classification in {
            "candidate",
            "possible",
            "confirmed",
            "not_observed",
            "weak",
            "protected",
            "inconclusive",
            "error",
        }:
            technical["classification"] = classification
        if isinstance(row.get("context"), str) and row["context"] in {
            "html_text",
            "attribute",
            "url_attribute",
            "event_attribute",
            "script",
            "style",
            "comment",
        }:
            technical["classification"] = technical.get("classification", "observation")
        output.append(
            _record(
                _Source(
                    row_type[:80],
                    locator,
                    url,
                    row.get("method") if isinstance(row.get("method"), str) else None,
                    status_code=status,
                    parameters=tuple(str(item)[:200] for item in row.get("parameters", []) if isinstance(item, str))
                    if isinstance(row.get("parameters"), list)
                    else (),
                    technical=technical,
                    sensitivity_hint=any(_SENSITIVE_NAME.search(str(key)) for key in row),
                ),
                path,
                salt,
            )
        )
    return output


def _csv(path: Path, text: str, salt: bytes) -> list[EvidenceRecord]:
    try:
        reader = csv.DictReader(io.StringIO(text))
        fieldnames = {str(name).strip().lower() for name in (reader.fieldnames or [])}
        if not fieldnames:
            raise ValueError("CSV has no header row.")
        output = []
        for index, row in enumerate(reader, start=2):
            if index > MAX_RECORDS + 1:
                raise ValueError(f"CSV exceeds the {MAX_RECORDS}-row import limit.")
            values = {str(key).strip().lower(): value for key, value in row.items() if key is not None}
            url = next((values[key] for key in ("url", "matched-at", "target", "endpoint") if values.get(key)), None)
            method = next((values[key] for key in ("method", "http_method") if values.get(key)), None)
            status = next((_status(values[key]) for key in ("status", "status_code", "code") if values.get(key)), None)
            output.append(
                _record(
                    _Source("csv", f"row:{index}", url, method, status_code=status, technical={"format": "csv"}),
                    path,
                    salt,
                )
            )
        return output
    except csv.Error as exc:
        raise ValueError("CSV input is malformed.") from exc


def _documents(path: Path, text: str, kind: str, salt: bytes) -> list[EvidenceRecord]:
    output: list[EvidenceRecord] = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        if len(output) >= MAX_RECORDS:
            raise ValueError(f"Document exceeds the {MAX_RECORDS}-record import limit.")
        urls = _ABSOLUTE_URL.findall(line)
        candidates: Iterable[str | None] = (
            urls if urls else ([None] if line_number == 1 and not text.splitlines() else [])
        )
        for url in candidates:
            output.append(
                _record(
                    _Source(
                        "document",
                        f"line:{line_number}",
                        url,
                        technical={"format": kind, "line_length": len(line)},
                        sensitivity_hint=bool(_SENSITIVE_NAME.search(line)) or "@" in line,
                    ),
                    path,
                    salt,
                )
            )
    if not output:
        output.append(_record(_Source("document", "document", technical={"format": kind}), path, salt))
    return output


def _detect_format(path: Path, raw: bytes) -> str:
    suffix = path.suffix.lower()
    if suffix in {".html", ".htm"}:
        return "html"
    if suffix in {".md", ".markdown"}:
        return "markdown"
    if suffix == ".csv":
        return "csv"
    if suffix in {".har"}:
        return "har"
    if suffix in {".jsonl", ".ndjson"}:
        return "nuclei-jsonl"
    stripped = raw.lstrip()
    if stripped.startswith(b"<"):
        return "burp-xml"
    text_start = stripped[:200].decode("utf-8", errors="ignore")
    if re.match(r"(?:GET|POST|PUT|PATCH|DELETE|OPTIONS|HEAD)\s+\S+\s+HTTP/", text_start, re.I) or text_start.startswith(
        "HTTP/"
    ):
        return "http"
    try:
        data = json.loads(raw.decode("utf-8-sig"))
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError):
        return "text"
    if isinstance(data, list) and any(
        isinstance(row, dict) and any(key in row for key in ("template-id", "templateID", "matched-at")) for row in data
    ):
        return "nuclei-json"
    if isinstance(data, dict):
        if isinstance(data.get("log"), dict) and isinstance(data["log"].get("entries"), list):
            return "har"
        if data.get("type") in _TOOLKIT_TYPES or isinstance(data.get("findings"), list):
            return "toolkit-json"
        results = data.get("results")
        if isinstance(results, list) and (
            not results or any(isinstance(row, dict) and ("url" in row or "input" in row) for row in results)
        ):
            return "ffuf-json"
        if any(key in data for key in ("template-id", "templateID", "matched-at")):
            return "nuclei-json"
    return "text"


def _load_input(path: Path, format_name: str, salt: bytes) -> tuple[str, list[EvidenceRecord]]:
    try:
        with path.open("rb") as handle:
            raw = handle.read(MAX_INPUT_BYTES + 1)
    except OSError as exc:
        raise ValueError(f"Cannot read evidence input: {path.name}.") from exc
    if len(raw) > MAX_INPUT_BYTES:
        raise ValueError(f"Evidence input exceeds the {MAX_INPUT_BYTES}-byte limit: {path.name}.")
    detected = _detect_format(path, raw) if format_name == "auto" else format_name
    if detected == "burp-xml":
        records = _burp_xml(path, raw, salt)
    elif detected in {"nuclei-json", "nuclei-jsonl"}:
        try:
            text = raw.decode("utf-8-sig")
        except UnicodeDecodeError as exc:
            raise ValueError("Nuclei input must be UTF-8 text.") from exc
        if detected == "nuclei-json":
            try:
                parsed = json.loads(text)
            except (json.JSONDecodeError, RecursionError) as exc:
                raise ValueError("Nuclei JSON is malformed.") from exc
            records = _nuclei_jsonl(path, text, salt, parsed)
        else:
            records = _nuclei_jsonl(path, text, salt)
    elif detected in {"har", "ffuf-json", "toolkit-json"}:
        try:
            parsed = json.loads(raw.decode("utf-8-sig"))
        except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
            raise ValueError(f"{detected} input is not valid UTF-8 JSON.") from exc
        records = (
            _har(path, parsed, salt)
            if detected == "har"
            else _ffuf(path, parsed, salt)
            if detected == "ffuf-json"
            else _toolkit_json(path, parsed, salt)
        )
    else:
        try:
            text = raw.decode("utf-8-sig")
        except UnicodeDecodeError as exc:
            raise ValueError("Evidence input must be UTF-8 text or supported JSON/XML.") from exc
        if detected == "http":
            target, method, headers, body, status = _parse_http_message(text)
            if method:
                records = [
                    _record(
                        _Source(
                            "http-capture",
                            "message:1",
                            target,
                            method,
                            headers,
                            body,
                            technical={"format": "http-request"},
                        ),
                        path,
                        salt,
                    )
                ]
            elif status is not None or text.startswith("HTTP/"):
                records = [
                    _record(
                        _Source(
                            "http-capture",
                            "message:1",
                            response_headers=headers,
                            response_body=body,
                            status_code=status,
                            technical={"format": "http-response"},
                        ),
                        path,
                        salt,
                    )
                ]
            else:
                raise ValueError("Raw HTTP input is neither a recognized request nor response.")
        else:
            records = _csv(path, text, salt) if detected == "csv" else _documents(path, text, detected, salt)
    return detected, records


def _semantic_key(record: EvidenceRecord) -> tuple[object, ...]:
    return (
        record.host,
        record.endpoint,
        record.method,
        record.parameters,
        record.status_code,
        record.session_fingerprint,
        record.request_session_fingerprint,
        record.response_session_fingerprint,
        record.resource_fingerprint,
        record.response_fingerprint,
        record.technical_evidence.get("classification"),
        record.technical_evidence.get("finding_category"),
        record.technical_evidence.get("template_id"),
    )


def deduplicate(records: Iterable[EvidenceRecord]) -> list[EvidenceRecord]:
    """Merge semantically identical observations while retaining all source provenance."""
    merged: dict[tuple[object, ...], EvidenceRecord] = {}
    for record in records:
        key = _semantic_key(record)
        previous = merged.get(key)
        if previous is None:
            merged[key] = record
            continue
        merged[key] = EvidenceRecord(
            evidence_id=previous.evidence_id,
            source_tools=tuple(sorted(set(previous.source_tools) | set(record.source_tools))),
            captured_at=previous.captured_at or record.captured_at,
            host=previous.host,
            endpoint=previous.endpoint,
            method=previous.method,
            parameters=previous.parameters,
            status_code=previous.status_code,
            session_fingerprint=previous.session_fingerprint,
            request_session_fingerprint=previous.request_session_fingerprint,
            response_session_fingerprint=previous.response_session_fingerprint,
            resource_fingerprint=previous.resource_fingerprint,
            response_fingerprint=previous.response_fingerprint,
            response_shape_fingerprint=previous.response_shape_fingerprint,
            sensitivity=previous.sensitivity,
            validation_status=previous.validation_status,
            technical_evidence=previous.technical_evidence,
            provenance=tuple(dict.fromkeys((*previous.provenance, *record.provenance))),
        )
    return list(merged.values())


def correlate_evidence(records: Iterable[EvidenceRecord | dict[str, Any]]) -> list[dict[str, object]]:
    """Group endpoint-template observations; groups are descriptive, never findings."""
    groups: dict[tuple[object, ...], list[dict[str, Any]]] = {}
    for item in records:
        row = asdict(item) if isinstance(item, EvidenceRecord) else item
        host, endpoint, method = row.get("host"), row.get("endpoint"), row.get("method")
        if not all(isinstance(value, str) for value in (host, endpoint, method)):
            continue
        parameters = row.get("parameters", ())
        if not isinstance(parameters, (tuple, list)):
            parameters = ()
        bucket_key: tuple[object, ...] = (host, method, endpoint, tuple(sorted(str(value) for value in parameters)))
        groups.setdefault(bucket_key, []).append(row)
    correlated: list[dict[str, object]] = []
    for group_key, rows in groups.items():
        if len(rows) < 2:
            continue
        group_host, group_method, group_endpoint, group_parameters = group_key
        if (
            not isinstance(group_host, str)
            or not isinstance(group_method, str)
            or not isinstance(group_endpoint, str)
            or not isinstance(group_parameters, tuple)
        ):
            continue
        sessions = {
            row["session_fingerprint"]
            for row in rows
            if isinstance(row.get("session_fingerprint"), str) and row["session_fingerprint"]
        }
        resources = {
            row["resource_fingerprint"]
            for row in rows
            if isinstance(row.get("resource_fingerprint"), str) and row["resource_fingerprint"]
        }
        responses = {
            row["response_fingerprint"]
            for row in rows
            if isinstance(row.get("response_fingerprint"), str) and row["response_fingerprint"]
        }
        shapes = {
            row["response_shape_fingerprint"]
            for row in rows
            if isinstance(row.get("response_shape_fingerprint"), str) and row["response_shape_fingerprint"]
        }
        statuses = sorted({row["status_code"] for row in rows if type(row.get("status_code")) is int})
        correlated.append(
            {
                "host": group_host,
                "method": group_method,
                "endpoint_template": group_endpoint,
                "parameters": list(group_parameters),
                "evidence_ids": sorted(str(row.get("evidence_id", "")) for row in rows),
                "source_tools": sorted(
                    {
                        str(tool)
                        for row in rows
                        for tool in (
                            row.get("source_tools", [])
                            if isinstance(row.get("source_tools", []), (list, tuple))
                            else []
                        )
                    }
                ),
                "observation_count": len(rows),
                "distinct_sessions": len(sessions),
                "distinct_resources": len(resources),
                "response_variants": len(responses),
                "response_shape_variants": len(shapes),
                "status_codes": statuses,
                "interpretation": "correlation_only",
                "finding_claimed": False,
            }
        )
        if len(correlated) >= MAX_CORRELATION_GROUPS:
            break
    return correlated


def import_evidence(paths: list[Path], format_name: str = "auto") -> dict[str, object]:
    """Normalize supported local artifacts, deduplicate them and add descriptive correlations."""
    allowed = {
        "auto",
        "burp-xml",
        "har",
        "ffuf-json",
        "nuclei-json",
        "nuclei-jsonl",
        "toolkit-json",
        "http",
        "html",
        "markdown",
        "text",
        "csv",
    }
    if format_name not in allowed:
        raise ValueError("Unsupported evidence format.")
    if not paths or len(paths) > MAX_INPUT_FILES:
        raise ValueError(f"Provide between 1 and {MAX_INPUT_FILES} local evidence files.")
    salt = secrets.token_bytes(32)
    all_records: list[EvidenceRecord] = []
    inputs: list[dict[str, object]] = []
    for path in paths:
        detected, records = _load_input(path, format_name, salt)
        if len(all_records) + len(records) > MAX_RECORDS:
            raise ValueError(f"Combined inputs exceed the {MAX_RECORDS}-record import limit.")
        all_records.extend(records)
        inputs.append({"source_path": str(path.resolve()), "format": detected, "records_parsed": len(records)})
    unique = deduplicate(all_records)
    record_rows = json.loads(json.dumps([asdict(record) for record in unique]))
    correlations = correlate_evidence(unique)
    canonical = json.dumps(record_rows, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return {
        "schema_version": "1.1",
        "type": "unified-evidence-bundle",
        "bundle_id": hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:24],
        "created_at": datetime.now().astimezone().isoformat(timespec="seconds"),
        "inputs": inputs,
        "records": record_rows,
        "correlations": correlations,
        "summary": {
            "records_parsed": len(all_records),
            "records_unique": len(unique),
            "duplicates_merged": len(all_records) - len(unique),
            "correlation_groups": len(correlations),
        },
        "network_requests_sent": 0,
        "vulnerabilities_confirmed": 0,
    }


def correlations_from_bundle(path: Path) -> dict[str, object]:
    try:
        with path.open("rb") as handle:
            raw = handle.read(MAX_INPUT_BYTES + 1)
    except OSError as exc:
        raise ValueError(f"Cannot read evidence bundle: {path.name}.") from exc
    if len(raw) > MAX_INPUT_BYTES:
        raise ValueError(f"Evidence bundle exceeds the {MAX_INPUT_BYTES}-byte limit.")
    try:
        data = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise ValueError("Evidence bundle must contain valid UTF-8 JSON.") from exc
    if (
        not isinstance(data, dict)
        or data.get("type") != "unified-evidence-bundle"
        or not isinstance(data.get("records"), list)
    ):
        raise ValueError("Input is not a unified evidence bundle.")
    records = data["records"]
    if len(records) > MAX_RECORDS or any(not isinstance(row, dict) for row in records):
        raise ValueError("Evidence bundle records are malformed or exceed the import limit.")
    correlations = correlate_evidence(records)
    return {
        "schema_version": "1.0",
        "type": "evidence-correlations",
        "bundle_id": data.get("bundle_id"),
        "correlations": correlations,
        "summary": {"records": len(records), "correlation_groups": len(correlations)},
        "network_requests_sent": 0,
        "vulnerabilities_confirmed": 0,
    }
