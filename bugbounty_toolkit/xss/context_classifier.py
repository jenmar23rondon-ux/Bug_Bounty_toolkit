"""Offline reflected-XSS output-context classification for evidence quality.

This module is *additive*: it does not change the behavior of the existing
``XssParameterTester`` reflected pipeline (``reflection_detector`` +
``result_validator`` + ``analysis.html_context``). It provides a deeper,
deterministic, network-free analysis of *where* and *how* an innocuous marker is
reflected, so the investigator gets a better candidate/abstention decision
without ever auto-confirming a vulnerability.

Design rules honored here:
* Innocuous markers only; this module never builds exfiltration/callback payloads.
* Offline and side-effect free; it analyzes text that was already captured.
* It distinguishes *parsing* (marker located in the served bytes) from *rendering*
  (what a browser would do), and never claims execution from static text.
* Hostile/adversarial response bodies are treated strictly as data. Any embedded
  "instructions" are ignored and recorded as ``prompt_injection_ignored``.
* Every result carries ``finding_confirmed=False``.
"""

from __future__ import annotations

import html
import re
from dataclasses import asdict, dataclass, field

# Output contexts we recognize. ``unknown`` is a safe fallback.
CONTEXTS = (
    "not_reflected",
    "html_text",
    "html_comment",
    "html_attribute",
    "url_attribute",
    "event_attribute",
    "html_template",
    "js_string",
    "js_code",
    "css",
    "json",
    "non_html",
    "unknown",
)

# Candidate/abstention decisions. None of these confirm a vulnerability.
DECISIONS = (
    "not_reflected",
    "escaped_safe",
    "candidate",
    "needs_browser_confirmation",
    "abstain_truncated",
    "abstain_malformed",
    "abstain_insufficient_context",
)

_ESCAPED_LT = ("&lt;", "&#60;", "&#x3c;", "&#x3C;")
_ESCAPED_GT = ("&gt;", "&#62;", "&#x3e;", "&#x3E;")
_ESCAPED_DQ = ("&quot;", "&#34;", "&#x22;")
_ESCAPED_SQ = ("&#39;", "&#x27;", "&apos;")

_PROMPT_INJECTION = re.compile(
    r"(ignore (all |the )?previous|disregard (all |the )?(prior|previous)|"
    r"system prompt|you are now|new instructions|act as|do not follow)",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class ReflectedAssessment:
    reflected: bool
    context: str
    decision: str
    escaped: bool
    transform: str | None
    reason: str
    html_sniffable: bool = False
    prompt_injection_ignored: bool = False
    truncated: bool = False
    malformed_html: bool = False
    parse_note: str = (
        "Static analysis locates the marker in served bytes; it does not execute "
        "JavaScript or confirm XSS. Browser confirmation stays opt-in."
    )
    finding_confirmed: bool = False
    extra: dict[str, object] = field(default_factory=dict)

    def to_dict(self) -> dict[str, object]:
        data = asdict(self)
        return data


def _detect_transform(body: str, marker: str) -> tuple[bool, str | None]:
    """Return (present_verbatim, transform_label)."""
    if marker in body:
        return True, None
    low = marker.lower()
    if low != marker and low in body.lower() and low in body:
        return True, "case_changed"
    if marker.upper() in body and marker.upper() != marker:
        return True, "uppercased"
    if marker.lower() in body and marker.lower() != marker:
        return True, "lowercased"
    # URL-encoded reflection of the marker (e.g. inside a query echo).
    if re.sub(r"(.)", lambda m: "%%%02x" % ord(m.group(1)), marker).lower() in body.lower():
        return True, "url_encoded"
    return False, None


def _is_html_content_type(content_type: str) -> bool:
    media = content_type.split(";", 1)[0].strip().lower()
    return media in {"text/html", "application/xhtml+xml"}


def _is_sniffable_html(body: str, content_type: str) -> bool:
    """A non-HTML content type can still render as HTML if sniffed (no nosniff)."""
    media = content_type.split(";", 1)[0].strip().lower()
    if _is_html_content_type(content_type):
        return False
    if media in {"", "application/octet-stream"}:
        looks_html = bool(re.search(r"<\s*(html|body|script|img|svg|!doctype)", body, re.IGNORECASE))
        return looks_html
    return False


def _window(body: str, marker: str, before: int = 200, after: int = 120) -> str:
    index = body.find(marker)
    if index < 0:
        decoded = html.unescape(body)
        index = decoded.find(marker)
        if index < 0:
            return body[:before]
        body = decoded
    start = max(0, index - before)
    end = min(len(body), index + len(marker) + after)
    return body[start:end]


def _break_out_unescaped(window: str, marker: str) -> bool:
    """True if the raw marker neighbourhood still contains live '<'/'>' bytes."""
    idx = window.find(marker)
    if idx < 0:
        return False
    near = window[max(0, idx - 40) : idx + len(marker) + 40]
    return "<" in near or ">" in near


def _attr_quote_broken(window: str, marker: str) -> bool:
    idx = window.find(marker)
    if idx < 0:
        return False
    near = window[max(0, idx - 40) : idx + len(marker) + 40]
    return '"' in near or "'" in near or ">" in near


def _detect_malformed(body: str, content_type: str) -> bool:
    if not _is_html_content_type(content_type):
        return False
    opens = len(re.findall(r"<[a-zA-Z]", body))
    closes = len(re.findall(r"</[a-zA-Z]", body))
    selfclose = len(re.findall(r"/>", body))
    if opens == 0:
        return False
    # Grossly unbalanced tags, or an unterminated tag at EOF.
    if body.rstrip().endswith("<") or re.search(r"<[a-zA-Z][^>]*$", body):
        return True
    return opens > (closes + selfclose) * 3


def classify_reflected_context(
    body: str,
    marker: str,
    payload: str,
    content_type: str = "text/html",
    *,
    truncated: bool = False,
) -> ReflectedAssessment:
    """Classify the output context of an innocuous marker in a captured body.

    All parameters are already-captured values; nothing here performs I/O.
    """
    if not marker:
        raise ValueError("A nonempty marker is required.")

    prompt_injection = bool(_PROMPT_INJECTION.search(body))

    present, transform = _detect_transform(body, marker)
    if not present:
        return ReflectedAssessment(
            reflected=False,
            context="not_reflected",
            decision="not_reflected",
            escaped=False,
            transform=None,
            reason="The unique marker was not reflected in the captured response.",
            prompt_injection_ignored=prompt_injection,
            truncated=truncated,
        )

    html_ct = _is_html_content_type(content_type)
    sniffable = _is_sniffable_html(body, content_type)
    malformed = _detect_malformed(body, content_type)

    if truncated:
        return ReflectedAssessment(
            reflected=True,
            context="unknown",
            decision="abstain_truncated",
            escaped=False,
            transform=transform,
            reason="Response was truncated; the reflection context cannot be validated.",
            html_sniffable=sniffable,
            prompt_injection_ignored=prompt_injection,
            truncated=True,
            malformed_html=malformed,
        )

    window = _window(body, marker)

    # Non-HTML content that will not be sniffed as HTML is low risk for reflected XSS.
    if not html_ct and not sniffable:
        media = content_type.split(";", 1)[0].strip().lower()
        context = "json" if "json" in media else "non_html"
        return ReflectedAssessment(
            reflected=True,
            context=context,
            decision="escaped_safe",
            escaped=True,
            transform=transform,
            reason=(
                f"Marker reflected in a {context} response that is not served as HTML; "
                "no HTML/JS execution context without a content-type/sniffing issue."
            ),
            html_sniffable=False,
            prompt_injection_ignored=prompt_injection,
            malformed_html=malformed,
            extra={"media_type": media},
        )

    # Event handler attribute (on*="...MARKER...").
    if re.search(r"\son[a-z]+\s*=\s*[\"'][^\"']*" + re.escape(marker), window, re.IGNORECASE):
        return ReflectedAssessment(
            reflected=True,
            context="event_attribute",
            decision="needs_browser_confirmation",
            escaped=False,
            transform=transform,
            reason="Marker reflected inside an HTML event-handler attribute; browser confirmation required.",
            html_sniffable=sniffable,
            prompt_injection_ignored=prompt_injection,
            malformed_html=malformed,
        )

    # URL-bearing attribute (href/src/action/formaction).
    url_attr = re.search(
        r"\s(href|src|action|formaction)\s*=\s*(?:\"([^\"]*)\"|'([^']*)'|([^\s>]+))",
        window,
        re.IGNORECASE,
    )
    if url_attr and marker in "".join(g or "" for g in url_attr.groups()[1:]):
        value = next(g for g in url_attr.groups()[1:] if g is not None)
        dangerous = value.lower().lstrip().startswith(("javascript:", "data:text/html"))
        return ReflectedAssessment(
            reflected=True,
            context="url_attribute",
            decision="candidate" if dangerous else "escaped_safe",
            escaped=not dangerous,
            transform=transform,
            reason=(
                "Marker reflected in a URL attribute with a dangerous scheme."
                if dangerous
                else "Marker reflected in a URL attribute without a dangerous (javascript:/data:) scheme."
            ),
            html_sniffable=sniffable,
            prompt_injection_ignored=prompt_injection,
            malformed_html=malformed,
        )

    # Inside a <script> block.
    script_block = re.search(r"<script[^>]*>(.*?)</script>", body, re.IGNORECASE | re.DOTALL)
    if script_block and marker in script_block.group(1):
        frag = script_block.group(1)
        in_string = re.search(r"[\"'`][^\"'`]*" + re.escape(marker), frag)
        can_break = ("</script" in frag.lower() and "</script" in window.lower()) or (
            in_string is not None and re.search(r"[\"'`][^\"'`]*" + re.escape(marker) + r"[^\"'`]*[\"'`]", frag) is None
        )
        if in_string and not can_break:
            return ReflectedAssessment(
                reflected=True,
                context="js_string",
                decision="escaped_safe",
                escaped=True,
                transform=transform,
                reason="Marker reflected inside a closed JavaScript string literal; no observed break-out.",
                html_sniffable=sniffable,
                prompt_injection_ignored=prompt_injection,
                malformed_html=malformed,
            )
        return ReflectedAssessment(
            reflected=True,
            context="js_code" if not in_string else "js_string",
            decision="needs_browser_confirmation",
            escaped=False,
            transform=transform,
            reason="Marker reflected in a JavaScript context that may allow break-out; browser confirmation required.",
            html_sniffable=sniffable,
            prompt_injection_ignored=prompt_injection,
            malformed_html=malformed,
        )

    # Inside a <template> element.
    if re.search(r"<template[^>]*>.*?" + re.escape(marker), body, re.IGNORECASE | re.DOTALL):
        return ReflectedAssessment(
            reflected=True,
            context="html_template",
            decision="needs_browser_confirmation",
            escaped=False,
            transform=transform,
            reason="Marker reflected inside an HTML <template>; inert until cloned, browser confirmation required.",
            html_sniffable=sniffable,
            prompt_injection_ignored=prompt_injection,
            malformed_html=malformed,
        )

    # Inside a comment.
    if re.search(r"<!--(?:(?!-->).)*" + re.escape(marker), body, re.DOTALL):
        escaped = not _break_out_unescaped(window, marker)
        return ReflectedAssessment(
            reflected=True,
            context="html_comment",
            decision="escaped_safe" if escaped else "candidate",
            escaped=escaped,
            transform=transform,
            reason=(
                "Marker reflected inside an HTML comment without comment break-out."
                if escaped
                else "Marker reflected inside an HTML comment with raw '<'/'>' that may break the comment."
            ),
            html_sniffable=sniffable,
            prompt_injection_ignored=prompt_injection,
            malformed_html=malformed,
        )

    # Generic attribute value ("...MARKER...").
    attr = re.search(r"=\s*([\"'])[^\"']*" + re.escape(marker) + r"[^\"']*\1", window)
    attr_open = re.search(r"=\s*([\"'])[^\"']*" + re.escape(marker), window)
    if attr or attr_open:
        broke = _attr_quote_broken(window, marker)
        # If marker appears verbatim but quote/angle characters are still live nearby it may break out.
        payload_has_quote = any(ch in payload for ch in ('"', "'", ">"))
        escaped = not broke or transform in {"url_encoded"} or not payload_has_quote
        if any(esc in window for esc in _ESCAPED_DQ + _ESCAPED_SQ):
            escaped = True
        return ReflectedAssessment(
            reflected=True,
            context="html_attribute",
            decision="escaped_safe" if escaped else "candidate",
            escaped=escaped,
            transform=transform,
            reason=(
                "Marker reflected inside a quoted HTML attribute with quotes neutralized/encoded."
                if escaped
                else "Marker reflected inside a quoted HTML attribute with live quote/angle characters."
            ),
            html_sniffable=sniffable,
            prompt_injection_ignored=prompt_injection,
            malformed_html=malformed,
        )

    # HTML text node (default): decide on angle-bracket escaping.
    raw_has_angle = any(seq in window for seq in ("<" + marker, marker + ">", "</" + marker))
    escaped_angle = any(seq in window for seq in _ESCAPED_LT + _ESCAPED_GT)
    payload_has_angle = "<" in payload or ">" in payload
    if malformed and not raw_has_angle:
        return ReflectedAssessment(
            reflected=True,
            context="html_text",
            decision="abstain_malformed",
            escaped=False,
            transform=transform,
            reason="Marker reflected in HTML text but the document is malformed; abstaining from a verdict.",
            html_sniffable=sniffable,
            prompt_injection_ignored=prompt_injection,
            malformed_html=True,
        )
    if raw_has_angle and not escaped_angle:
        decision, escaped, reason = (
            "candidate",
            False,
            "Marker reflected in HTML text with live '<'/'>' adjacent; a tag break-out looks possible.",
        )
    elif payload_has_angle and escaped_angle:
        decision, escaped, reason = (
            "escaped_safe",
            True,
            "Marker reflected in HTML text with angle brackets HTML-entity encoded.",
        )
    elif not payload_has_angle:
        decision, escaped, reason = (
            "escaped_safe",
            True,
            "Innocuous marker reflected in HTML text without any tag-forming characters.",
        )
    else:
        decision, escaped, reason = (
            "needs_browser_confirmation",
            False,
            "Marker reflected in HTML text; escaping could not be determined statically.",
        )
    return ReflectedAssessment(
        reflected=True,
        context="html_text",
        decision=decision,
        escaped=escaped,
        transform=transform,
        reason=reason,
        html_sniffable=sniffable,
        prompt_injection_ignored=prompt_injection,
        malformed_html=malformed,
    )
