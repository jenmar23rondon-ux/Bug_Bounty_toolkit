"""Synthetic tokens for this lab. They are not credentials."""

from __future__ import annotations

import re

CANARY = "BBTK_CANARY_IWE_STRESS01"
OWNER_TOKEN = "SYNTH_OWNER_TOKEN"
ACTOR_TOKEN = "SYNTH_ACTOR_TOKEN"

_PRIVATE = re.compile(
    r"SYNTH_OWNER_TOKEN|SYNTH_ACTOR_TOKEN|SYNTH_pw_[A-Za-z0-9]+|"
    r"SYNTH_[A-Za-z0-9-]+_(?:OWNER|ACTOR)|BBTK_CANARY_[A-Za-z0-9_-]+"
)


def leak_count(text: str) -> int:
    """Count synthetic secret shapes in shareable text. Zero is the only acceptable result."""
    return len(_PRIVATE.findall(text))
