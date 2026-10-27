"""Generate a private synthetic example diff; print only safe counts."""

from __future__ import annotations

import json
from pathlib import Path
import sys

from bugbounty_toolkit.analysis.semantic_response_diff import diff_responses
from bugbounty_toolkit.core.private_files import atomic_private_write, local_path


def create_example(directory: Path) -> dict[str, object]:
    directory = local_path(directory)
    directory.mkdir(mode=0o700, exist_ok=False)
    left = {
        "status_code": 200,
        "headers": {"content-type": "application/json"},
        "body": '{"id":101,"owner":"alice","timestamp":"2024-01-01T00:00:00Z"}',
        "origin_ref": "example-left",
    }
    right = {
        "status_code": 200,
        "headers": {"content-type": "application/json"},
        "body": '{"id":101,"owner":"bob","timestamp":"2024-06-01T00:00:00Z"}',
        "origin_ref": "example-right",
    }
    result = diff_responses(left, right, ignore_volatile=["timestamp"])
    atomic_private_write(directory / "diff.json", json.dumps(result, indent=2, sort_keys=True).encode() + b"\n")
    return {
        "schema_version": result["schema_version"],
        "change_count": result["summary"]["change_count"],
        "authz_relevant_changes": result["summary"]["authz_relevant_changes"],
        "structural_equality": result["structural_equality"],
        "confirmed": False,
    }


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("Usage: python -m labs.semantic_response_diff_eval.example NEW_PRIVATE_DIRECTORY")
    print(json.dumps(create_example(Path(sys.argv[1])), sort_keys=True))
