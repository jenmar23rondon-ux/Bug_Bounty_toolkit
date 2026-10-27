"""Write DEV/FINAL scenario files and the FINAL hash manifest.

Run this when the scenario specification changes, and before the first FINAL
metrics run. Do not re-freeze FINAL to match a disappointing measurement.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

from .spec import canonical_json

LAB = Path(__file__).resolve().parent


def write_splits() -> dict[str, str]:
    digests: dict[str, str] = {}
    for split in ("dev", "final"):
        text = canonical_json(split)
        directory = LAB / split
        directory.mkdir(exist_ok=True)
        target = directory / "scenarios.json"
        target.write_text(text, encoding="utf-8")
        digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
        digests[split] = digest
        if split == "final":
            (directory / "MANIFEST.sha256").write_text(f"{digest}  scenarios.json\n", encoding="utf-8")
    return digests


def main() -> int:
    for split, digest in write_splits().items():
        print(split, digest)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
