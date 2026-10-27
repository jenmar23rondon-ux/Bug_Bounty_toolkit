"""Write split JSON and hash manifests.

FINAL and STRESS manifests are the freeze point. Do not edit those cases after
the first FINAL or STRESS measurement.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from .corpus import document

LAB = Path(__file__).resolve().parent
SPLITS = ("dev", "final", "stress")


def dumps(payload: dict[str, object]) -> str:
    return json.dumps(payload, indent=2, sort_keys=True) + "\n"


def write_split(split: str) -> str:
    text = dumps(document(split))
    directory = LAB / split
    directory.mkdir(parents=True, exist_ok=True)
    target = directory / "cases.json"
    target.write_text(text, encoding="utf-8")
    digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
    (directory / "MANIFEST.sha256").write_text(f"{digest}  cases.json\n", encoding="utf-8")
    return digest


def main() -> None:
    for split in SPLITS:
        print(f"{split} {write_split(split)}")


if __name__ == "__main__":
    main()
