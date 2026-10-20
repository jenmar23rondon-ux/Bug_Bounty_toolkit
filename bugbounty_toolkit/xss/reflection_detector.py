from __future__ import annotations

import html
from dataclasses import dataclass


@dataclass(frozen=True)
class ReflectionResult:
    marker: str
    payload: str
    reflected: bool
    reflected_unescaped: bool
    context: str | None = None


def detect_reflection(body: str, marker: str, payload: str, context_window: int = 80) -> ReflectionResult:
    decoded = html.unescape(body)
    reflected = marker in body or marker in decoded
    reflected_unescaped = payload in body
    context = None
    if reflected:
        index = decoded.find(marker)
        if index >= 0:
            start = max(0, index - context_window)
            end = min(len(decoded), index + len(marker) + context_window)
            context = decoded[start:end]
    return ReflectionResult(
        marker=marker,
        payload=payload,
        reflected=reflected,
        reflected_unescaped=reflected_unescaped,
        context=context,
    )
