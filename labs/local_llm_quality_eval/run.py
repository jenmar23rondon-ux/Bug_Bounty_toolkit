"""CLI for the local LLM security-analysis quality evaluation.

Default (CI): deterministic loopback mocks with SIMULATED profiles; no GPU, no real model.
Live (opt-in, user's own GPU machine, models already installed):

    python -m labs.local_llm_quality_eval.run --live \\
        --qwen ollama=qwen2.5:7b-instruct-q4_K_M --deepseek ollama=deepseek-r1:8b \\
        --split final --repeats 3 --output labs/local_llm_quality_eval/results/real/rtx3060.json
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from labs.local_llm_quality_eval import corpus, harness  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--live", action="store_true", help="Opt-in: call already-installed local models on loopback")
    parser.add_argument("--qwen", help="provider=model for the Qwen slot (live only)")
    parser.add_argument("--deepseek", help="provider=model for the DeepSeek slot (live only)")
    parser.add_argument("--split", choices=("dev", "final"), default="final")
    parser.add_argument("--repeats", type=int, default=2)
    parser.add_argument("--timeout", type=float, default=120.0)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--verify-corpus", action="store_true", help="Only verify the frozen corpus manifest")
    args = parser.parse_args(argv)
    if args.verify_corpus:
        problems = corpus.verify()
        print(json.dumps({"corpus_ok": not problems, "problems": problems}, indent=2))
        return 1 if problems else 0
    if args.live:
        if not args.qwen or not args.deepseek:
            parser.error("--live requires --qwen and --deepseek (provider=model)")
        if args.split == "final":
            print("[i] FINAL is frozen: run it once; do not tune prompts on it.", file=sys.stderr)
        try:
            result = harness.run_live(args.qwen, args.deepseek, args.split, args.repeats, args.timeout)
        except (RuntimeError, ValueError) as exc:
            print(f"[!] {exc}", file=sys.stderr)
            return 2
    else:
        result = harness.run_mock(args.split, args.repeats)
    text = json.dumps(result, indent=1, sort_keys=True)
    if args.output:
        args.output.write_text(text + "\n", encoding="utf-8")
    else:
        print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
