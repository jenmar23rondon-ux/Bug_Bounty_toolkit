"""CLI: python -m labs.investigator_workflow_efficacy.run_lab"""

from __future__ import annotations

import sys

from .evaluate import main as evaluate_main


def main(argv: list[str] | None = None) -> int:
    return evaluate_main(argv)


if __name__ == "__main__":
    sys.exit(main())
