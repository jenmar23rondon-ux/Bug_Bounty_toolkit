from __future__ import annotations

import base64
from dataclasses import dataclass
import os
import re
from pathlib import Path
import stat
from urllib.parse import parse_qsl, urlsplit, urlunsplit
import xml.etree.ElementTree as ET

from .core.http_client import RequestSpec, ResponseRecord
from .core.redaction import redact_headers, redact_html_secrets, redact_jwts, redact_text, redact_url
from .core.request_builder import parse_raw_http_request
from .core.target import normalize_url
from .utils.exceptions import ToolkitError

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


def _decode_xml_message(node: ET.Element, strict: bool = False) -> str:
    value = "".join(node.itertext())
    if not strict:
        value = value.strip()
    if node.attrib.get("base64", "").lower() == "true":
        try:
            encoded = re.sub(r"\s", "", value) if strict else value
            return base64.b64decode(encoded, validate=strict).decode("utf-8", errors="strict" if strict else "replace")
        except (ValueError, TypeError, UnicodeError) as exc:
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
    head, separator, body = message.partition("\r\n\r\n")
    if not separator:
        head, separator, body = message.partition("\n\n")
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


MAX_EXCHANGES = 32
MAX_EXCHANGE_BYTES = 1_000_000


@dataclass(frozen=True)
class CapturedExchange:
    """Private, lossless messages paired within one Burp item; never a report."""

    raw_request: str
    request: RequestSpec
    raw_response: str | None = None


def read_capture_file(path: Path, limit: int = MAX_ITEM_BYTES) -> bytes:
    """Read bounded regular local files without following links or blocking on FIFOs."""
    try:
        path = path.expanduser().absolute()
        if len(str(path)) > 4096 or any(part.is_symlink() for part in (path, *path.parents)):
            raise ValueError("Capture paths must be regular local files without symbolic links.")
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
        descriptor = os.open(path, flags)
        try:
            info = os.fstat(descriptor)
            if not stat.S_ISREG(info.st_mode):
                raise ValueError("Capture paths must name regular local files.")
            if info.st_size > limit:
                raise ValueError("Capture input exceeds its size limit.")
            with os.fdopen(descriptor, "rb") as source:
                descriptor = -1
                value = source.read(limit + 1)
        finally:
            if descriptor != -1:
                os.close(descriptor)
        if len(value) > limit:
            raise ValueError("Capture input exceeds its size limit.")
        return value
    except OSError as exc:
        raise ValueError("Cannot read the local capture file.") from exc


def captured_response(exchange: CapturedExchange) -> ResponseRecord | None:
    """Parse a complete bounded response, without interpreting it as live evidence."""
    raw = exchange.raw_response
    if raw is None:
        return None
    if len(raw.encode("utf-8")) > MAX_EXCHANGE_BYTES:
        raise ValueError("Captured response exceeds the comparison size limit.")
    first = raw.splitlines()[0] if raw else ""
    match = re.fullmatch(r"HTTP/1\.[01] ([1-5][0-9]{2})(?: [^\r\n]*)?", first)
    if match is None or ("\r\n\r\n" not in raw and "\n\n" not in raw):
        raise ValueError("Captured response is incomplete or is not supported HTTP/1.x.")
    pairs, body = _parse_http_message(raw)
    headers = {key.lower(): value for key, value in pairs}
    critical = {"content-length", "content-type", "content-encoding", "transfer-encoding"}
    if any(sum(key.lower() == name for key, _ in pairs) > 1 for name in critical):
        raise ValueError("Duplicate response framing/content headers are unsupported in discovery captures.")
    if headers.get("content-encoding", "identity").lower() != "identity" or "transfer-encoding" in headers:
        raise ValueError("Export decoded, uncompressed responses for offline JSON comparison.")
    size = len(body.encode("utf-8"))
    if "content-length" in headers:
        length = headers["content-length"]
        if not length.isdecimal() or int(length) != size:
            raise ValueError("Captured response Content-Length does not match the complete body.")
    return ResponseRecord(
        exchange.request,
        exchange.request.prepared_url(),
        int(match[1]),
        "",
        0,
        headers,
        body,
        size,
        set_cookies=tuple(value for name, value in pairs if name.lower() == "set-cookie"),
    )


def parse_captured_exchanges(
    data: bytes, base_url: str | None = None, response_data: bytes | None = None
) -> tuple[CapturedExchange, ...]:
    """Import raw HTTP or item-paired Burp XML for offline case preparation only."""
    if len(data) > MAX_ITEM_BYTES:
        raise ValueError("Capture input exceeds the Burp item size limit.")
    if base_url is not None:
        try:
            base = urlsplit(normalize_url(base_url))
        except ValueError as exc:
            raise ValueError("The captured base URL must be an HTTP(S) origin.") from exc
        if base.path not in {"", "/"} or base.query:
            raise ValueError("The captured base URL must not contain a path or query.")
    try:
        text = data.decode("utf-8-sig")
    except UnicodeError as exc:
        raise ValueError("Discovery captures must be UTF-8 HTTP or XML exports.") from exc
    if "\x00" in text:
        raise ValueError("NUL characters and non-UTF-8 XML are unsupported.")
    messages: list[tuple[str, str | None, str | None]] = []
    if text.lstrip().startswith("<"):
        if response_data is not None:
            raise ValueError("Separate responses are supported only with one raw request, not an XML history.")
        if re.search(r"<!\s*(?:DOCTYPE|ENTITY)\b", text, re.I):
            raise ValueError("Burp XML DTD/entity declarations are not supported.")
        try:
            root = ET.fromstring(text)
        except (ET.ParseError, ValueError, RecursionError) as exc:
            raise ValueError("Burp discovery XML is malformed.") from exc
        for item in root.iter():
            if _local_name(item.tag) != "item":
                continue
            requests = [child for child in item if _local_name(child.tag) == "request"]
            responses = [child for child in item if _local_name(child.tag) == "response"]
            if len(requests) != 1 or len(responses) > 1:
                raise ValueError("Each Burp item needs exactly one request and at most one paired response.")
            messages.append(
                (
                    _decode_xml_message(requests[0], strict=True),
                    _decode_xml_message(responses[0], strict=True) if responses else None,
                    _item_url(item),
                )
            )
            if len(messages) > MAX_EXCHANGES:
                raise ValueError("Capture exceeds the 32-item discovery limit; export a smaller selection.")
        if not messages:
            raise ValueError("Burp XML contains no paired request items.")
    else:
        try:
            response = response_data.decode("utf-8") if response_data is not None else None
        except UnicodeError as exc:
            raise ValueError("Captured response must be UTF-8 HTTP text.") from exc
        messages.append((text, response, None))

    exchanges: list[CapturedExchange] = []
    for raw, raw_response, item_url in messages:
        if len(raw.encode("utf-8")) > MAX_EXCHANGE_BYTES:
            raise ValueError("Captured request exceeds the comparison size limit.")
        if "\r\n\r\n" not in raw and "\n\n" not in raw:
            raise ValueError("Captured request is incomplete; export the complete HTTP message.")
        first = raw.splitlines()[0] if raw else ""
        if not re.fullmatch(r"[A-Z]{1,16} [^\s]+ HTTP/1\.[01]", first):
            raise ValueError("Discovery requires a complete HTTP/1.x request line.")
        try:
            origin = base_url
            if item_url is not None:
                item_parts = urlsplit(normalize_url(item_url))
                origin = f"{item_parts.scheme}://{item_parts.netloc}"
                if base_url and normalize_url(base_url).rstrip("/") != origin:
                    raise ValueError("The selected origin differs from the Burp item origin.")
            captured = parse_raw_http_request(raw)
            request = parse_raw_http_request(raw, origin)
            if urlsplit(captured.prepared_url()).netloc != urlsplit(request.prepared_url()).netloc:
                raise ValueError("Captured authority must not be overridden.")
            host = next((value for key, value in captured.headers.items() if key.lower() == "host"), None)
            if host is not None and host.lower() != urlsplit(request.prepared_url()).netloc.lower():
                raise ValueError("Captured Host and destination disagree.")
            if item_url is not None and request.prepared_url() != normalize_url(item_url):
                raise ValueError("Burp item URL and request target disagree.")
            for name, value in request.headers.items():
                if not re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]{1,80}", name) or any(
                    (ord(char) < 32 and char != "\t") or ord(char) > 255 for char in value
                ):
                    raise ValueError("Invalid captured header encoding.")
        except (ValueError, ToolkitError) as exc:
            raise ValueError("Unsupported capture request or inconsistent origin; inspect it locally.") from exc
        exchange = CapturedExchange(raw, request, raw_response)
        captured_response(exchange)
        exchanges.append(exchange)
    return tuple(exchanges)
