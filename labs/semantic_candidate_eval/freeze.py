"""Freeze DEV/FINAL labels and ledger digests: ``python -m labs.semantic_candidate_eval.freeze``.

Run only when the corpus specification changes; FINAL must not be re-frozen to
fit engine output.
"""

from __future__ import annotations

import hashlib
import json
import tempfile
from pathlib import Path

from .corpus import build_split

HERE = Path(__file__).resolve().parent


def frozen_text(split: str) -> str:
    with tempfile.TemporaryDirectory(prefix="bbtk-sem-freeze-") as tmp:
        manifest = build_split(split, Path(tmp))
    return json.dumps({**manifest, "frozen": True}, indent=2, sort_keys=True) + "\n"


def main() -> int:
    for split in ("dev", "final"):
        out = HERE / split
        out.mkdir(exist_ok=True)
        text = frozen_text(split)
        (out / "ground_truth.json").write_text(text, encoding="utf-8")
        digest = hashlib.sha256(text.encode()).hexdigest()
        (out / "MANIFEST.sha256").write_text(f"{digest}  ground_truth.json\n", encoding="utf-8")
        print(split, digest)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
