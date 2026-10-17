from __future__ import annotations

from urllib.parse import urljoin, urlparse

from .http_client import RequestSpec
from .target import normalize_url
from ..utils.exceptions import RequestBuildError


def build_request(
    url: str,
    method: str = "GET",
    headers: dict[str, str] | None = None,
    params: dict[str, str] | None = None,
    body: str | None = None,
) -> RequestSpec:
    return RequestSpec(
        method=method.upper(),
        url=normalize_url(url),
        headers=headers or {},
        params=params or {},
        body=body,
    )


def parse_raw_http_request(raw: str, base_url: str | None = None) -> RequestSpec:
    head, separator, body = raw.partition("\r\n\r\n")
    if not separator:
        head, _, body = raw.partition("\n\n")
    head = head.replace("\r\n", "\n")
    lines = [line for line in head.split("\n") if line.strip()]
    if not lines:
        raise RequestBuildError("Raw request is empty.")

    request_line = lines[0].split()
    if len(request_line) < 2:
        raise RequestBuildError("Raw request line must look like: GET /path HTTP/1.1")
    if len(request_line) != 3 or not request_line[2].startswith("HTTP/"):
        raise RequestBuildError("Expected an HTTP/1.x request line exported from Burp.")
    method, raw_target = request_line[0].upper(), request_line[1]

    headers: dict[str, str] = {}
    for line in lines[1:]:
        if ":" not in line:
            raise RequestBuildError("Invalid raw header syntax; expected Name: value. Inspect the capture locally.")
        key, value = line.split(":", 1)
        key = key.strip()
        if not key or any(existing.lower() == key.lower() for existing in headers):
            raise RequestBuildError("Empty or duplicate headers are not supported in raw requests.")
        headers[key] = value.strip()

    if raw_target.startswith(("http://", "https://")):
        url = raw_target
    else:
        host = next((value for key, value in headers.items() if key.lower() == "host"), None)
        if base_url:
            url = urljoin(normalize_url(base_url), raw_target)
            headers = {key: value for key, value in headers.items() if key.lower() != "host"}
        elif host:
            scheme = "https"
            url = f"{scheme}://{host}{raw_target}"
        else:
            raise RequestBuildError("Raw request needs a Host header or --base-url.")

    parsed = urlparse(url)
    if not parsed.hostname:
        raise RequestBuildError(f"Could not resolve host from raw request target: {raw_target}")

    headers = {key: value for key, value in headers.items() if key.lower() not in {"content-length", "transfer-encoding"}}
    return RequestSpec(method=method, url=normalize_url(url), headers=headers, body=body or None)
