"""Offline measurement for handoff→case conversion reliability (adv-handoff-case-*).

Uses corpus ground-truth origin only. Network hard-blocked. No auto-approve / access-check.
"""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
CORPORA = {
    "adv-handoff-case-1.0": HERE / "frozen",
    "adv-handoff-case-dev": HERE / "dev",
}

# Reuse the adversarial harness helpers (same KEY/PROGRAM/shard/no_network).
sys.path.insert(0, str(HERE.parent))
from adversarial_idor_eval.evaluate import (  # noqa: E402
    KEY,
    PROGRAM,
    no_network,
    shard,
    _ratio,
)


def evaluate(corpus: str = "adv-handoff-case-1.0") -> dict:
    from bugbounty_toolkit.analysis import object_handoff as oh
    from bugbounty_toolkit.analysis import object_relationships as orel
    from bugbounty_toolkit.analysis.handoff_case_eligibility import classify_materialized_paths
    from bugbounty_toolkit.idor_discovery import discover_idor

    root = CORPORA[corpus]
    captures = root / "captures.har"
    gt = json.loads((root / "ground_truth.json").read_text(encoding="utf-8"))
    origin = gt["origin"]
    by_entry = {i: s for s in gt["scenarios"] for i in s["entries"]}

    with no_network() as attempts:
        work = Path(tempfile.mkdtemp(prefix="bbtk-hc-"))
        files, mapping, excluded = shard(captures, work)
        graph = orel.build_object_graph(PROGRAM, files, KEY, authorized=True)
        with tempfile.TemporaryDirectory() as tmp:
            handoff = oh.propose_object_handoff(
                graph,
                PROGRAM,
                KEY,
                verify_inputs=list(files),
                limit=64,
                materialize_dir=Path(tmp) / "pairs",
            )
            props = handoff["proposals"]
            pairs_dir = Path(tmp) / "pairs"
            rows = []
            for p in props:
                clf = classify_materialized_paths(pairs_dir, p["id"], base_url=origin).as_dict()
                owner = pairs_dir / f"{p['id']}-owner.http"
                actor = pairs_dir / f"{p['id']}-actor.http"
                ores = pairs_dir / f"{p['id']}-owner-response.http"
                ares = pairs_dir / f"{p['id']}-actor-response.http"
                cases = None
                error = None
                try:
                    d = discover_idor(
                        PROGRAM,
                        owner,
                        actor,
                        base_url=origin,
                        owner_response=ores if ores.is_file() else None,
                        actor_response=ares if ares.is_file() else None,
                        accounts_authorized=False,
                    )
                    cases = len(d.proposal.get("candidates", []))
                except Exception as exc:  # noqa: BLE001
                    error = f"{type(exc).__name__}: {str(exc)[:120]}"
                rows.append(
                    {
                        "proposal_id": p["id"],
                        "resource_type": p.get("resource_type"),
                        "cases": cases,
                        "error": error,
                        "classification": clf,
                        "provenance_origin": p.get("provenance_origin"),
                    }
                )

    eligible = [r for r in rows if (r["classification"] or {}).get("case_eligible")]
    technical = [r for r in rows if (r["classification"] or {}).get("technical_error")]
    legitimate = [r for r in rows if (r["classification"] or {}).get("legitimate_rejection")]
    correct_cases = sum(1 for r in eligible if r["cases"])
    return {
        "corpus_version": gt["corpus_version"],
        "origin": origin,
        "scenarios": len(gt["scenarios"]),
        "entries": len(by_entry),
        "proposals": len(rows),
        "case_eligible": len(eligible),
        "correct_cases": correct_cases,
        "yield_among_eligible": _ratio(correct_cases, len(eligible)),
        "yield_among_proposals": _ratio(sum(1 for r in rows if r["cases"]), len(rows)),
        "technical_errors": len(technical),
        "legitimate_rejections": len(legitimate),
        "conversion_fps": sum(1 for r in rows if r["cases"] and not (r["classification"] or {}).get("case_eligible")),
        "provenance_coverage": _ratio(sum(1 for r in rows if r.get("provenance_origin")), len(rows)),
        "network_connect_attempts": attempts["count"],
        "excluded_entries": excluded,
        "classification_codes": sorted(
            {(r["classification"] or {}).get("code") for r in rows if r.get("classification")}
        ),
        "rows": rows,
        "safety": {"network_connect_attempts": attempts["count"]},
        "note": "Proposals are needs_review only; nothing confirmed or executed.",
    }


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--corpus", choices=sorted(CORPORA), default="adv-handoff-case-1.0")
    ap.add_argument("--json", type=Path)
    a = ap.parse_args()
    res = evaluate(corpus=a.corpus)
    text = json.dumps(res, indent=1, sort_keys=True)
    if a.json:
        a.json.write_text(text + "\n", encoding="utf-8")
    print(text)


if __name__ == "__main__":
    raise SystemExit(main())
