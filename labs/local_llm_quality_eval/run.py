"""CLI for the local LLM security-analysis quality evaluation.

Default (CI): deterministic loopback mocks with SIMULATED profiles; no GPU, no real model.
Those scores are not Qwen or DeepSeek results.

Read-only inventory (no download, no scoring):

    python -m labs.local_llm_quality_eval.run --discover

Honest live-metric report when a GPU or model is absent:

    python -m labs.local_llm_quality_eval.run --not-measured \\
        --output labs/local_llm_quality_eval/results/real/not-measured.json

Live (opt-in, user's own GPU machine, models already installed, DEV then FINAL once):

    python -m labs.local_llm_quality_eval.run --live --split dev --repeats 3 --temperature 0 \\
        --qwen ollama=qwen2.5:7b-instruct-q4_K_M --deepseek ollama=deepseek-r1:8b
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from labs.local_llm_quality_eval import corpus, discovery, harness, metadata  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--live", action="store_true", help="Opt-in: call already-installed local models on loopback")
    parser.add_argument("--qwen", help="provider=model for the Qwen slot (live only)")
    parser.add_argument("--deepseek", help="provider=model for the DeepSeek slot (live only)")
    parser.add_argument("--split", choices=("dev", "final"), default="final")
    parser.add_argument("--repeats", type=int, default=2)
    parser.add_argument("--timeout", type=float, default=120.0)
    parser.add_argument("--temperature", type=float, default=0.0, help="Forwarded only on --live. Default 0.")
    parser.add_argument(
        "--seed",
        type=int,
        default=None,
        help="Recorded for reproducibility. The provider adapter does not apply a seed.",
    )
    parser.add_argument("--output", type=Path)
    parser.add_argument("--verify-corpus", action="store_true", help="Only verify the frozen corpus manifest")
    parser.add_argument(
        "--discover",
        action="store_true",
        help="Read-only GPU and local model inventory. Does not download models or score cases.",
    )
    parser.add_argument(
        "--not-measured",
        action="store_true",
        help="Write an honest NOT_MEASURED report for every live metric. Does not call a model.",
    )
    args = parser.parse_args(argv)
    modes = [args.verify_corpus, args.discover, args.not_measured, args.live]
    if sum(bool(mode) for mode in modes) > 1:
        parser.error("choose only one of --verify-corpus, --discover, --not-measured, --live")
    if args.verify_corpus:
        problems = corpus.verify()
        print(json.dumps({"corpus_ok": not problems, "problems": problems}, indent=2))
        return 1 if problems else 0
    if args.discover:
        result = discovery.discover()
    elif args.not_measured:
        try:
            result = metadata.build_not_measured_report(temperature=args.temperature, seed=args.seed)
        except (RuntimeError, ValueError) as exc:
            print(f"[!] {exc}", file=sys.stderr)
            return 2
    elif args.live:
        if not args.qwen or not args.deepseek:
            parser.error("--live requires --qwen and --deepseek (provider=model)")
        if args.split == "final":
            print("[i] FINAL is frozen: run it once; do not tune prompts on it.", file=sys.stderr)
        try:
            result = harness.run_live(
                args.qwen,
                args.deepseek,
                args.split,
                args.repeats,
                args.timeout,
                temperature=args.temperature,
                seed=args.seed,
            )
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
