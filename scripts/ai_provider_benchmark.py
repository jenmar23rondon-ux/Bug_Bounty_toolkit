#!/usr/bin/env python3
"""Reproducible local AI review benchmark.

Default: deterministic mock servers (no real model, no network beyond 127.0.0.1).
Optional live protocol on your own hardware, for example Qwen vs DeepSeek:

    python scripts/ai_provider_benchmark.py --live \
        --reviewer ollama=qwen2.5-coder:7b --reviewer ollama=deepseek-r1:8b --output qwen-vs-deepseek.json
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from bugbounty_toolkit.analysis.ai_review_eval import run_live_protocol, run_mock_evaluation  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--live", action="store_true", help="Use real local models instead of mocks")
    parser.add_argument("--reviewer", action="append", default=[], help="provider=model (max 2) for --live")
    parser.add_argument("--timeout", type=float, default=120.0)
    parser.add_argument("--repeats", type=int, default=1)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    if args.live:
        reviewers = []
        for item in args.reviewer:
            provider, sep, model = item.partition("=")
            if not sep:
                parser.error("--reviewer must be provider=model")
            reviewers.append((provider, model))
        result = run_live_protocol(reviewers, args.timeout, args.repeats)
    else:
        if args.reviewer:
            parser.error("--reviewer requires --live")
        result = run_mock_evaluation()
    text = json.dumps(result, indent=2, sort_keys=True)
    if args.output:
        if args.output.exists():
            parser.error(f"{args.output} exists; refusing to overwrite")
        args.output.write_text(text + "\n", encoding="utf-8")
    print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
