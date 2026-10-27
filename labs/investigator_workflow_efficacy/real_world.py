"""Opt-in real-world protocol stub.

This module never opens a socket. CI must not import it. Running it without
``BBTK_IWE_REAL_WORLD=1`` refuses. Running it with the variable still refuses
to contact a target: this checkout has no authorized program list.
"""

from __future__ import annotations

import os
import sys


def main(argv: list[str] | None = None) -> int:
    del argv
    enabled = os.environ.get("BBTK_IWE_REAL_WORLD") == "1"
    if not enabled:
        print("real-world protocol is opt-in and private. Refusing to run. No requests were sent.")
        return 2
    print(
        "BBTK_IWE_REAL_WORLD=1 acknowledged. This repository copy still has no "
        "authorized target list, so no request will be sent. Follow "
        "labs/investigator_workflow_efficacy/real_world/PROTOCOL.md and keep "
        "raw notes outside the checkout. Publish anonymized aggregates only. "
        "finding_confirmed stays false."
    )
    return 2


if __name__ == "__main__":
    sys.exit(main())
