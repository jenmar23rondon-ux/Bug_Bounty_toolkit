from __future__ import annotations

import base64
from dataclasses import dataclass
import re
from pathlib import Path
from urllib.parse import parse_qsl, urlsplit, urlunsplit
import xml.etree.ElementTree as ET

from .core.http_client import RequestSpec
from .core.redaction import redact_headers, redact_html_secrets, redact_jwts, redact_text, redact_url
from .core.request_builder import parse_raw_http_request

MAX_SITEMAP_BYTES = 100 * 1024 * 1024
MAX_REQUEST_BYTES = 8 * 1024 * 1024
MAX_ITEM_BYTES = 32 * 1024 * 1024
STATIC_EXTENSIONS = {
    ".avif",
    ".bmp",
    ".css",
    ".eot",
    ".gif",
    ".ico",
    ".jpeg",
    ".jpg",
    ".js",
    ".map",
    ".mjs",
    ".otf",
    ".png",
    ".svg",
    ".ttf",
    ".webp",
    ".woff",
    ".woff2",
}
JWT_PATTERN = re.compile(r"(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*(?![A-Za-z0-9_-])")


@dataclass(frozen=True)
class SitemapImport:
    routes: list[str]
    parameters: list[str]
    ignored_static: int
    ignored_items: int


@dataclass(frozen=True)
class BurpItem:
    html: str | None
    jwts: list[str]


def read_bounded(path: Path, limit: int, label: str) -> bytes:
    with path.open("rb") as handle:
        value = handle.read(limit + 1)
    if len(value) > limit:
        raise ValueError(f"{label} exceeds the {limit}-byte import limit.")
    return value


def _local_name(tag: object) -> str:
    return str(tag).rsplit("}", 1)[-1].lower()


def _child_text(node: ET.Element, name: str) -> str | None:
    for child in list(node):
        if _local_name(child.tag) == name:
            value = "".join(child.itertext()).strip()
            return value or None
    return None


def _decode_xml_message(node: ET.Element) -> str:
    value = "".join(node.itertext()).strip()
    if node.attrib.get("base64", "").lower() == "true":
        try:
            return base64.b64decode(value, validate=False).decode("utf-8", errors="replace")
        except (ValueError, TypeError) as exc:
            raise ValueError("Burp item contains an invalid base64 message.") from exc
    return value


def _item_url(item: ET.Element) -> str | None:
    direct = _child_text(item, "url")
    if direct:
        parsed = urlsplit(direct)
        return direct if parsed.scheme in {"http", "https"} and parsed.netloc else None
    protocol = _child_text(item, "protocol")
    host = _child_text(item, "host")
    path = _child_text(item, "path")
    if protocol not in {"http", "https"} or not host or not path:
        return None
    port = _child_text(item, "port")
    netloc = (
        host
        if not port or (protocol == "https" and port == "443") or (protocol == "http" and port == "80")
        else f"{host}:{port}"
    )
    return f"{protocol}://{netloc}{path if path.startswith('/') else '/' + path}"


def _route_for(url: str, base_url: str | None) -> str:
    parsed = urlsplit(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("Sitemap item did not contain an absolute HTTP URL.")
    safe_url = redact_url(url)
    safe = urlsplit(safe_url)
    route = urlunsplit(("", "", safe.path or "/", safe.query, ""))
    if base_url is None:
        return safe_url
    base = urlsplit(base_url)
    if base.scheme not in {"http", "https"} or not base.hostname:
        raise ValueError("--base-url must be an absolute HTTP or HTTPS URL.")
    same_origin = (parsed.scheme.lower(), parsed.netloc.lower()) == (base.scheme.lower(), base.netloc.lower())
    return route if same_origin else safe_url


def _form_parameter_names(message: str) -> list[str]:
    normalized = message.replace("\r\n", "\n")
    head, separator, body = normalized.partition("\n\n")
    if not separator:
        return []
    content_type = next(
        (
            line.split(":", 1)[1].strip().lower()
            for line in head.splitlines()[1:]
            if line.lower().startswith("content-type:")
        ),
        "",
    )
    if "application/x-www-form-urlencoded" not in content_type:
        return []
    return [name for name, _ in parse_qsl(body, keep_blank_values=True) if name]


def parse_sitemap(xml_bytes: bytes, base_url: str | None = None) -> SitemapImport:
    if len(xml_bytes) > MAX_SITEMAP_BYTES:
        raise ValueError(f"Burp sitemap exceeds the {MAX_SITEMAP_BYTES}-byte import limit.")
    if base_url is not None:
        base = urlsplit(base_url)
        if base.scheme not in {"http", "https"} or not base.hostname:
            raise ValueError("--base-url must be an absolute HTTP or HTTPS URL.")
    if re.search(rb"<!\s*(?:DOCTYPE|ENTITY)\b", xml_bytes, re.I):
        raise ValueError("Burp sitemap XML DTD/entity declarations are not supported.")
    try:
        root = ET.fromstring(xml_bytes)
    except (ET.ParseError, ValueError, RecursionError) as exc:
        raise ValueError("Burp sitemap XML is malformed; export the sitemap XML again and retry.") from exc

    routes: list[str] = []
    parameters: list[str] = []
    ignored_static = 0
    ignored_items = 0
    for item in root.iter():
        if _local_name(item.tag) != "item":
            continue
        try:
            url = _item_url(item)
            if url is None:
                ignored_items += 1
                continue
            parsed = urlsplit(url)
            if Path(parsed.path.lower()).suffix in STATIC_EXTENSIONS:
                ignored_static += 1
                continue
            routes.append(_route_for(url, base_url))
            parameters.extend(name for name, _ in parse_qsl(parsed.query, keep_blank_values=True) if name)
            request_node = next((node for node in item.iter() if _local_name(node.tag) == "request"), None)
            if request_node is not None:
                try:
                    parameters.extend(_form_parameter_names(_decode_xml_message(request_node)))
                except ValueError:
                    ignored_items += 1
        except (ValueError, TypeError, AttributeError):
            ignored_items += 1
    return SitemapImport(list(dict.fromkeys(routes)), list(dict.fromkeys(parameters)), ignored_static, ignored_items)


def normalize_raw_request(raw_bytes: bytes, base_url: str | None = None) -> str:
    if len(raw_bytes) > MAX_REQUEST_BYTES:
        raise ValueError(f"Burp request exceeds the {MAX_REQUEST_BYTES}-byte import limit.")
    try:
        raw = raw_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("Burp request must be exported as UTF-8 text.") from exc
    spec: RequestSpec = parse_raw_http_request(raw, base_url=base_url)
    safe_request_url = redact_url(spec.url)
    parsed = urlsplit(safe_request_url)
    target = urlunsplit(("", "", parsed.path or "/", parsed.query, ""))
    headers = dict(spec.headers)
    if not any(key.lower() == "host" for key in headers):
        headers["Host"] = parsed.netloc
    safe_headers = redact_headers(headers)
    if any("\r" in key or "\n" in key or "\r" in value or "\n" in value for key, value in safe_headers.items()):
        raise ValueError("Burp request contains invalid header line breaks.")
    body = spec.body.decode("utf-8", errors="replace") if isinstance(spec.body, bytes) else spec.body or ""
    safe_body = redact_jwts(redact_text(body) or "")
    header_text = "\r\n".join(f"{key}: {value}" for key, value in safe_headers.items())
    return f"{spec.method} {target} HTTP/1.1\r\n{header_text}\r\n\r\n{safe_body}"


def _parse_http_message(message: str) -> tuple[list[tuple[str, str]], str]:
    normalized = message.replace("\r\n", "\n")
    head, separator, body = normalized.partition("\n\n")
    if not separator:
        return [], ""
    headers: list[tuple[str, str]] = []
    for line in head.splitlines()[1:]:
        if ":" not in line or line[:1].isspace():
            continue
        name, value = line.split(":", 1)
        headers.append((name.strip(), value.strip()))
    return headers, body


def _messages_from_item(item_bytes: bytes) -> tuple[list[str], list[str]]:
    stripped = item_bytes.lstrip()
    if not stripped.startswith(b"<"):
        try:
            raw = item_bytes.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ValueError("Burp item must be UTF-8 text or a Burp XML export.") from exc
        if raw.startswith(("HTTP/", "GET ", "POST ", "PUT ", "PATCH ", "DELETE ", "OPTIONS ", "HEAD ")):
            return ([raw] if raw.startswith("HTTP/") else []), ([] if raw.startswith("HTTP/") else [raw])
        raise ValueError("Burp item is not a recognized HTTP capture or XML item export.")
    if re.search(rb"<!\s*(?:DOCTYPE|ENTITY)\b", item_bytes, re.I):
        raise ValueError("Burp item XML DTD/entity declarations are not supported.")
    try:
        root = ET.fromstring(item_bytes)
    except (ET.ParseError, ValueError, RecursionError) as exc:
        raise ValueError("Burp item XML is malformed; export the item again and retry.") from exc
    requests: list[str] = []
    responses: list[str] = []
    for node in root.iter():
        tag = _local_name(node.tag)
        if tag not in {"request", "response"}:
            continue
        value = _decode_xml_message(node)
        if not value:
            continue
        (requests if tag == "request" else responses).append(value)
    if not requests and not responses:
        raise ValueError("Burp XML item did not contain a request or response message.")
    return responses, requests


def extract_item_artifacts(item_bytes: bytes) -> BurpItem:
    if len(item_bytes) > MAX_ITEM_BYTES:
        raise ValueError(f"Burp item exceeds the {MAX_ITEM_BYTES}-byte import limit.")
    responses, requests = _messages_from_item(item_bytes)
    jwt_values: list[str] = []
    html_body: str | None = None
    for message in [*requests, *responses]:
        headers, body = _parse_http_message(message)
        for name, value in headers:
            if name.lower() in {"authorization", "proxy-authorization", "cookie", "set-cookie"}:
                jwt_values.extend(JWT_PATTERN.findall(value))
        if message in responses and body:
            content_type = next((value.lower() for name, value in headers if name.lower() == "content-type"), "")
            if "html" in content_type or re.search(r"<(?:!doctype\s+html|html|head|body)\b", body, re.I):
                html_body = redact_html_secrets(redact_jwts(redact_text(body) or ""))
    return BurpItem(html_body, list(dict.fromkeys(jwt_values)))


def safe_artifact_name(path: Path) -> str:
    name = re.sub(r"[^A-Za-z0-9_-]+", "-", path.stem).strip("-_")[:64]
    return name or "burp-item"
