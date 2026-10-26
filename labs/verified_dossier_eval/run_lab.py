"""CLI entry for verified research dossier evaluation (synthetic, offline)."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from .metrics import compare_splits, evaluate_split


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Verified dossier claim-to-evidence eval (synthetic only)")
    parser.add_argument("--split", choices=("dev", "final", "both"), default="both")
    parser.add_argument("--output", type=Path, help="Write metrics JSON")
    parser.add_argument(
        "--work-root",
        type=Path,
        default=None,
        help="Optional persistent work root (default: sibling results/ under this package)",
    )
    args = parser.parse_args(argv)
    base = args.work_root or (Path(__file__).resolve().parent / "results" / "work")
    if args.split == "both":
        result = compare_splits(base / "dev", base / "final")
        final = result["final"]
    else:
        result = evaluate_split(args.split, base / args.split)
        final = result
    text = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(text, encoding="utf-8")
        print(f"[+] Metrics saved: {args.output}")
    else:
        print(text)
    if final.get("security", {}).get("network_requests_sent", 0) != 0:
        return 1
    if final.get("security", {}).get("auto_confirmations", 0) != 0:
        return 1
    if final.get("false_confirmations_accepted", 0) != 0:
        return 1
    if final.get("scenarios_passed", 0) != final.get("scenario_count", -1):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
