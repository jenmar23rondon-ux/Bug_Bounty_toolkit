"""CLI: ``python -m labs.semantic_candidate_eval.run_lab [--split dev|final|both] [--output F]``."""

from __future__ import annotations

import argparse
import json
import tempfile
from pathlib import Path

from .metrics import evaluate_split


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Semantic candidate correlation lab (synthetic only)")
    parser.add_argument("--split", choices=("dev", "final", "both"), default="both")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    splits = ("dev", "final") if args.split == "both" else (args.split,)
    result = {}
    for split in splits:
        with tempfile.TemporaryDirectory(prefix=f"bbtk-sem-{split}-") as tmp:
            result[split] = evaluate_split(split, Path(tmp))
    text = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(text, encoding="utf-8")
    else:
        print(text)
    bad = any(
        r["network_attempts"]
        or r["secret_leaks"]
        or r["invalid_refs_accepted"]
        or r["ledger_files_modified"]
        or r["auto_merges_or_confirmations"]
        or r["adversarial_false_merges"]
        for r in result.values()
    )
    return 1 if bad else 0


if __name__ == "__main__":
    raise SystemExit(main())
