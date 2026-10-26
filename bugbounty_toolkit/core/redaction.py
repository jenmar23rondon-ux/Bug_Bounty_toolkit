from __future__ import annotations

import json
import re
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit


SENSITIVE_KEY = re.compile(
    r"password|passwd|passphrase|secret|token|api.?key|authorization|cookie|session|csrf|credential", re.I
)
REDACTED = "[redacted]"
JWT_TOKEN = re.compile(r"(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*(?![A-Za-z0-9_-])")
HTML_INPUT = re.compile(r"<input\b[^>]*>", re.I)
HTML_ATTRIBUTE = re.compile(r"\b([\w:-]+)\s*=\s*(?:\"([^\"]*)\"|'([^']*)'|([^\s>]+))", re.I)
HTML_VALUE = re.compile(r"\bvalue\s*=\s*(?:\"[^\"]*\"|'[^']*'|[^\s>]+)", re.I)


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


def redact_headers(headers: dict[str, str]) -> dict[str, str]:
    return {
        key: REDACTED if SENSITIVE_KEY.search(key) else (redact_text(value) or "") for key, value in headers.items()
    }


def redact_url(url: str) -> str:
    parsed = urlsplit(url)
    query = [
        (key, REDACTED if SENSITIVE_KEY.search(key) else value)
        for key, value in parse_qsl(parsed.query, keep_blank_values=True)
    ]
    netloc = parsed.netloc.rsplit("@", 1)[-1]
    return urlunsplit((parsed.scheme, netloc, parsed.path, urlencode(query), ""))


def redact_data(value: Any) -> Any:
    if isinstance(value, dict):
        return {key: REDACTED if SENSITIVE_KEY.search(str(key)) else redact_data(item) for key, item in value.items()}
    if isinstance(value, list):
        return [redact_data(item) for item in value]
    if isinstance(value, str):
        if value.startswith(("http://", "https://")) and not any(char.isspace() for char in value):
            return redact_url(value)
        return redact_text(value)
    return value


_SECRET_KEYWORD = re.compile(r"(?i)password|passwd|secret|token|api[_-]?key|session[_-]?id")


def redact_text(value: str | None) -> str | None:
    if value is None:
        return None
    try:
        parsed = json.loads(value)
    except (ValueError, TypeError):
        parsed = None
    if isinstance(parsed, (dict, list)):
        return json.dumps(redact_data(parsed), ensure_ascii=True)
    if "=" in value and "\n" not in value and not any(char in value for char in "<>{}"):
        pairs = parse_qsl(value, keep_blank_values=True)
        if any(SENSITIVE_KEY.search(key) for key, _ in pairs):
            return urlencode([(key, REDACTED if SENSITIVE_KEY.search(key) else item) for key, item in pairs])
    value = re.sub(r"(?i)\bBearer\s+[A-Za-z0-9._~+/-]+=*", "Bearer [redacted]", value)
    if not _SECRET_KEYWORD.search(value):
        # Exact short-circuit: the pattern below cannot match without one of these literals, and
        # scanning it over large keyword-free bodies is quadratic.
        return value
    return re.sub(
        r"""(?i)(["']?(?:password|passwd|secret|[\w-]*token|api[_-]?key|session[_-]?id)["']?\s*[:=]\s*["']?)[^\s"'&<>,;}]+""",
        lambda match: match.group(1) + REDACTED,
        value,
    )
