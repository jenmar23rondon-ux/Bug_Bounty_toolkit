"""Offline Burp/HAR capture review recommendations for reflected XSS.

Produces *review recommendations* from already-captured HTTP exchanges. It never
issues new requests and never deduces a vulnerability from an isolated
reflection. Reuses ``classify_reflected_context`` and redaction helpers.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import asdict, dataclass
from typing import Any, Mapping, Sequence
from urllib.parse import parse_qs, urlsplit

from ..core.redaction import redact_text, redact_url
from .context_classifier import ReflectedAssessment, classify_reflected_context

_MARKERISH = re.compile(r"(bbtkxss[0-9a-f]{6,}|xss[_\-]?test|<[a-z0-9]+>|\"'|javascript:)", re.IGNORECASE)


@dataclass(frozen=True)
class CaptureReview:
    capture_ref: str
    route: str
    method: str
    parameters: list[str]
    content_type: str
    assessment: dict[str, object]
    recommendation: str
    finding_confirmed: bool = False
    requests_issued: int = 0

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def _parameters_from_url(url: str) -> list[str]:
    try:
        return sorted(parse_qs(urlsplit(url).query, keep_blank_values=True).keys())
    except Exception:
        return []


def _parameters_from_body(body: str, content_type: str) -> list[str]:
    media = content_type.split(";", 1)[0].strip().lower()
    if media in {"application/x-www-form-urlencoded", ""}:
        try:
            return sorted(parse_qs(body, keep_blank_values=True).keys())
        except Exception:
            return []
    return []


def _pick_marker(request_url: str, request_body: str, response_body: str) -> str | None:
    """Prefer a unique marker that already appears in both request and response."""
    candidates: list[str] = []
    for source in (request_url, request_body):
        candidates.extend(_MARKERISH.findall(source))
    for candidate in candidates:
        token: str = candidate if isinstance(candidate, str) else str(candidate)
        if token and token in response_body:
            return token
    # Fall back: any unique-looking token shared by request and response.
    for source in (request_url, request_body):
        for token in re.findall(r"[A-Za-z0-9_\-]{8,}", source):
            if token in response_body and token.lower() not in {"javascript", "text/html"}:
                return token
    return None


def review_capture(
    *,
    method: str,
    url: str,
    request_body: str = "",
    response_body: str,
    content_type: str = "text/html",
    truncated: bool = False,
    capture_id: str | None = None,
) -> CaptureReview:
    """Recommend a human review for one already-captured exchange. Offline only."""
    marker = _pick_marker(url, request_body, response_body)
    params = sorted(set(_parameters_from_url(url) + _parameters_from_body(request_body, content_type)))
    capture_ref = capture_id or hashlib.sha256(f"{method}|{url}|{len(response_body)}".encode()).hexdigest()[:16]

    if marker is None:
        assessment = ReflectedAssessment(
            reflected=False,
            context="not_reflected",
            decision="abstain_insufficient_context",
            escaped=False,
            transform=None,
            reason="No shared marker between request and response; cannot recommend a reflected-XSS review.",
            truncated=truncated,
        )
        recommendation = "No reviewable reflected-XSS signal in this capture; collect a marker-bearing probe first."
    else:
        assessment = classify_reflected_context(
            response_body,
            marker,
            marker,
            content_type,
            truncated=truncated,
        )
        if assessment.decision in {"candidate", "needs_browser_confirmation"}:
            recommendation = (
                "Manual review recommended: marker reflected in a potentially executable context. "
                "Do not treat this as a confirmed vulnerability; opt-in browser confirmation is separate."
            )
        elif assessment.decision == "escaped_safe":
            recommendation = "Marker reflected but appears escaped / non-HTML; low priority for XSS review."
        elif assessment.decision.startswith("abstain"):
            recommendation = f"Abstain: {assessment.reason}"
        else:
            recommendation = "No actionable reflected-XSS signal."

    return CaptureReview(
        capture_ref=capture_ref,
        route=redact_url(url) or url,
        method=method.upper(),
        parameters=params,
        content_type=content_type.split(";", 1)[0].strip().lower(),
        assessment=assessment.to_dict(),
        recommendation=redact_text(recommendation) or recommendation,
    )


def review_captures(exchanges: Sequence[Mapping[str, Any]]) -> list[dict[str, object]]:
    """Batch wrapper. Each item may carry method/url/request_body/response_body/content_type/truncated/id."""
    out: list[dict[str, object]] = []
    for item in exchanges:
        review = review_capture(
            method=str(item.get("method", "GET")),
            url=str(item["url"]),
            request_body=str(item.get("request_body", "")),
            response_body=str(item.get("response_body", "")),
            content_type=str(item.get("content_type", "text/html")),
            truncated=bool(item.get("truncated", False)),
            capture_id=str(item["id"]) if item.get("id") else None,
        )
        out.append(review.to_dict())
    return out
