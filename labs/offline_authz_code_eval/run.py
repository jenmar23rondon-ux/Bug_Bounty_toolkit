"""CLI: ``python -m labs.offline_authz_code_eval.run [--output F]`` (offline, synthetic)."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from .evaluate import run


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Offline authorization code audit lab")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    metrics = run()
    stable = {k: v for k, v in metrics.items() if k not in {"elapsed_seconds", "peak_memory_kib"}}
    text = json.dumps(metrics if args.output is None else stable, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(text, encoding="utf-8")
    else:
        print(text)
    ok = (
        metrics["network_attempts"] == 0
        and metrics["target_code_executions"] == 0
        and metrics["finding_confirmed_true"] == 0
        and metrics["unauthorized_files_read"] == 0
    )
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
