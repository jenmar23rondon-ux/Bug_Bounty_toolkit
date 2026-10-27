"""Write DEV/FINAL case files and hash manifests.

Run this before the first FINAL evaluation. The evaluator refuses a split whose
``cases.json`` does not match ``MANIFEST.sha256``.
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from labs.idor_pairing_precision_v4.corpus import cases_for  # noqa: E402

HERE = Path(__file__).resolve().parent


def dump(split: str) -> str:
    directory = HERE / split
    directory.mkdir(parents=True, exist_ok=True)
    document = {
        "schema": "bbtk.idor-pairing-precision-cases/1",
        "split": split,
        "label_policy": "Frozen synthetic expectations. Do not retune after MANIFEST.sha256 is committed.",
        "finding_confirmed": False,
        "cases": cases_for(split),
    }
    payload = json.dumps(document, indent=2, sort_keys=True) + "\n"
    path = directory / "cases.json"
    path.write_text(payload, encoding="utf-8")
    digest = hashlib.sha256(payload.encode()).hexdigest()
    (directory / "MANIFEST.sha256").write_text(f"{digest}  cases.json\n", encoding="utf-8")
    return digest


def main() -> None:
    for split in ("dev", "final"):
        print(split, dump(split))


if __name__ == "__main__":
    main()
