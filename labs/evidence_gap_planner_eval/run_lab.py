"""CLI entry for the evidence-gap planner evaluation lab."""

from __future__ import annotations

import argparse
import json
import tempfile
from pathlib import Path

from .metrics import compare_splits, evaluate_split


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Evidence-gap planner offline evaluation (synthetic only)")
    parser.add_argument("--split", choices=("dev", "final", "both"), default="both")
    parser.add_argument("--output", type=Path, help="Write metrics JSON here")
    args = parser.parse_args(argv)
    with tempfile.TemporaryDirectory(prefix="bbtk-egp-") as tmp:
        root = Path(tmp)
        if args.split == "both":
            result = compare_splits(root / "dev", root / "final")
        else:
            result = evaluate_split(args.split, root / args.split)
    text = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(text, encoding="utf-8")
        print(f"[+] Metrics saved: {args.output}")
    else:
        print(text)
    final = result.get("final") or result
    if final.get("security", {}).get("network_requests_sent", 0) != 0:
        return 1
    if final.get("quality", {}).get("incompatible_recommendations", 0) != 0:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
