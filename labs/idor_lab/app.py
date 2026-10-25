"""Convenience entrypoint for the packaged loopback-only IDOR lab server."""

from __future__ import annotations

import sys
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]


def run() -> None:
    if str(REPOSITORY_ROOT) not in sys.path:
        sys.path.insert(0, str(REPOSITORY_ROOT))
    from bugbounty_toolkit.idor_lab_server import main

    main()


if __name__ == "__main__":
    run()
