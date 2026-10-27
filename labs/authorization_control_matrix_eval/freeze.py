"""Write DEV/FINAL scenario files and hash manifests.

FINAL labels must be frozen before the first FINAL measurement. Re-run this only
when the scenario specification changes, never to make a failed FINAL score pass.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from .corpus import scenarios

HERE = Path(__file__).resolve().parent


def dump(split: str) -> str:
    payload = {
        "schema": "bbtk.authorization-control-matrix-scenarios/1",
        "split": split,
        "finding_confirmed": False,
        "scenarios": scenarios(split),
    }
    return json.dumps(payload, indent=2, sort_keys=True) + "\n"


def main() -> int:
    for split in ("dev", "final"):
        text = dump(split)
        out = HERE / split
        out.mkdir(exist_ok=True)
        (out / "scenarios.json").write_text(text, encoding="utf-8")
        digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
        (out / "MANIFEST.sha256").write_text(f"{digest}  scenarios.json\n", encoding="utf-8")
        print(f"{split} {digest} scenarios={text.count(chr(10))}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
