from __future__ import annotations

import secrets


def new_marker() -> str:
    return f"bbtkxss{secrets.token_hex(6)}"


def payloads_for_marker(marker: str) -> list[str]:
    return [
        marker,
        f"{marker}\"'",
        f"<{marker}>",
        f"\">{marker}<",
    ]
