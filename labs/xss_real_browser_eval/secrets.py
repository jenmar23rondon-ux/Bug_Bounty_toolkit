"""Scan lab artifacts for secret-shaped strings. Synthetic ``bbtkxss`` markers are allowed."""

from __future__ import annotations

import re

_PATTERNS = (
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bsk-[A-Za-z0-9_-]{12,}"),
    re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]+"),
    re.compile(r"(?i)\blocalStorage\b"),
    re.compile(r"(?i)document\.cookie"),
    re.compile(r"(?i)\bset-cookie\b"),
    re.compile(r"(?i)\bauthorization\s*:"),
    re.compile(r"(?i)\bBBTK[-_]CANARY[-_]"),
)


def secret_leak_count(text: str) -> int:
    return sum(len(pattern.findall(text)) for pattern in _PATTERNS)
