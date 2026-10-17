from __future__ import annotations

from http.cookies import SimpleCookie
import re


def parse_header_items(items: list[str] | None) -> dict[str, str]:
    headers: dict[str, str] = {}
    for item in items or []:
        if ":" in item:
            key, value = item.split(":", 1)
        elif "=" in item:
            key, value = item.split("=", 1)
        else:
            raise ValueError(f"Header must be 'Name: value' or 'Name=value': {item}")
        key = key.strip()
        if not re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+", key) or "\r" in value or "\n" in value:
            raise ValueError(f"Header name cannot be empty: {item}")
        headers = {existing: current for existing, current in headers.items() if existing.lower() != key.lower()}
        headers[key] = value.strip()
    return headers


def parse_cookie_items(items: list[str] | None) -> str | None:
    cookie = SimpleCookie()
    for item in items or []:
        if "=" not in item:
            raise ValueError(f"Cookie must be name=value: {item}")
        key, value = item.split("=", 1)
        cookie[key.strip()] = value.strip()
    if not cookie:
        return None
    return "; ".join(morsel.OutputString() for morsel in cookie.values())
