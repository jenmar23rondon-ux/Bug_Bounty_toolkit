"""Write DEV and FINAL case files and their hash manifests.

Run this before the first FINAL evaluation. Do not edit FINAL after that run.
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from labs.idor_false_negative_recovery.corpus import document  # noqa: E402

def dumps(payload: dict) -> str:
    return json.dumps(payload, indent=2, sort_keys=True) + "\n"


def write_split(split: str) -> str:
    text = dumps(document(split))
    directory = HERE / split
    directory.mkdir(parents=True, exist_ok=True)
    target = directory / "cases.json"
    target.write_text(text, encoding="utf-8")
    digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
    (directory / "MANIFEST.sha256").write_text(f"{digest}  cases.json\n", encoding="utf-8")
    return digest


def main() -> None:
    for split in ("dev", "final"):
        digest = write_split(split)
        print(f"{split} {digest}")


if __name__ == "__main__":
    main()
