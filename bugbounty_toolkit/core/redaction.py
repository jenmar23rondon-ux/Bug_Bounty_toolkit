from __future__ import annotations

import json
import re
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit


SENSITIVE_KEY = re.compile(r"password|passwd|passphrase|secret|token|api.?key|authorization|cookie|session|csrf|credential", re.I)
REDACTED = "[redacted]"


def redact_headers(headers: dict[str, str]) -> dict[str, str]:
    return {key: REDACTED if SENSITIVE_KEY.search(key) else redact_text(value) for key, value in headers.items()}


def redact_url(url: str) -> str:
    parsed = urlsplit(url)
    query = [(key, REDACTED if SENSITIVE_KEY.search(key) else value) for key, value in parse_qsl(parsed.query, keep_blank_values=True)]
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, urlencode(query), ""))


def redact_data(value):
    if isinstance(value, dict):
        return {key: REDACTED if SENSITIVE_KEY.search(str(key)) else redact_data(item) for key, item in value.items()}
    if isinstance(value, list):
        return [redact_data(item) for item in value]
    if isinstance(value, str):
        if value.startswith(("http://", "https://")) and not any(char.isspace() for char in value):
            return redact_url(value)
        return redact_text(value)
    return value


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
    return re.sub(
        r'''(?i)(["']?(?:password|passwd|secret|[\w-]*token|api[_-]?key|session[_-]?id)["']?\s*[:=]\s*["']?)[^\s"'&<>,;}]+''',
        lambda match: match.group(1) + REDACTED,
        value,
    )
