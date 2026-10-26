"""Render results/*.json into results/RESULTS.md (per-family and per-scenario tables)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
KEYS = (
    "scenarios",
    "outcome_accuracy",
    "outcome_accuracy_ci95",
    "object_recall",
    "precision_at_1",
    "precision_at_3",
    "precision_at_5",
    "mrr",
    "ndcg_at_5",
    "precision_at_1_strict_resource_type",
    "pairing_precision",
    "pairing_recall",
    "forbidden_pairs_proposed",
    "eligibility_correct",
    "false_reviewable_cases",
    "false_reviewable_after_planner",
    "missed_eligible_cases",
    "pipeline_exceptions",
    "technical_errors_predicted",
    "correct_abstentions",
    "abstention_recall",
    "missing_control_recall",
    "next_step_precision_at_1",
    "next_step_precision_at_1_ci95",
    "redundant_proposals",
    "synthetic_manual_steps",
    "reference_correct_rate",
    "secret_leaks",
    "auto_confirmations",
    "network_attempts",
)


def _fmt(v: Any) -> str:
    return "—" if v is None else str(v)


def render(root: Path = HERE / "results") -> str:
    out = ["# irb-1.0 results (synthetic loopback lab — not real-world performance)\n"]
    for split in ("final", "stress", "dev"):
        p = root / f"{split}_metrics.json"
        if not p.is_file():
            continue
        d = json.loads(p.read_text(encoding="utf-8"))
        fams = d["by_family"]
        cols = ["overall", *fams]
        out.append(f"\n## {split.upper()} (manifest sha256 `{d['manifest_sha256'][:16]}…`)\n")
        out.append("| metric | " + " | ".join(cols) + " |")
        out.append("|---|" + "---|" * len(cols))
        for k in KEYS:
            vals = [d["overall"].get(k)] + [fams[f].get(k) for f in fams]
            out.append(f"| {k} | " + " | ".join(_fmt(v) for v in vals) + " |")
        out.append(f"\nLatency (ms, median/max): `{json.dumps(d['latency_ms'], sort_keys=True)}`  ")
        out.append(f"Peak traced memory: {d['peak_mem_kib_max']} KiB  ")
        out.append(f"Historical overlap: `{json.dumps(d['historical_overlap'], sort_keys=True)}`\n")
        out.append("| id | fam | tag | ideal | predicted | ok | codes | first step | top-1 type | proposals | notes |")
        out.append("|---|---|---|---|---|---|---|---|---|---|---|")
        for r in d["scenarios"]:
            top = (r.get("ranking") or {}).get("top1_type")
            notes = "; ".join([*r["info_loss"], *([r["exception"][:60]] if r["exception"] else [])])
            out.append(
                f"| {r['id']} | {r['family']} | {r['tag']} | {r['ideal_outcome']} | {r['predicted_outcome']} | "
                f"{'✓' if r['outcome_correct'] else '✗'} | {', '.join(r['eligibility_codes'])} | {r['first_step']} | "
                f"{_fmt(top)} | {r['proposals']} | {notes} |"
            )
    return "\n".join(out) + "\n"


def main() -> None:
    (HERE / "results" / "RESULTS.md").write_text(render(), encoding="utf-8")


if __name__ == "__main__":
    main()
