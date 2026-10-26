"""Generate a new private synthetic example bundle; print only safe counts."""

from __future__ import annotations

import json
from pathlib import Path
import sys

from bugbounty_toolkit.analysis.request_variation_plan import save_plan
from bugbounty_toolkit.core.private_files import atomic_private_write, local_path

from .fixtures import declaration, request


def create_example(directory: Path) -> dict[str, object]:
    directory = local_path(directory)
    directory.mkdir(mode=0o700, exist_ok=False)
    capture, config, scope = directory / "capture.http", directory / "resources.json", directory / "scope.txt"
    atomic_private_write(capture, request().encode())
    atomic_private_write(config, json.dumps(declaration(), indent=2).encode() + b"\n")
    atomic_private_write(scope, b"https://lab.test\n")
    return save_plan(capture, config, scope, directory / "plan.json")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("Usage: python -m labs.request_variation_eval.example NEW_PRIVATE_DIRECTORY")
    print(json.dumps(create_example(Path(sys.argv[1])), sort_keys=True))
