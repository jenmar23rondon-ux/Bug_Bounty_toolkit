"""Offline ranking metrics for adv-ranking corpora (review relevance, not vulns).

Measurement only. Network hard-blocked. Never tunes rules.
"""

from __future__ import annotations

import argparse
import json
import math
import tempfile
from pathlib import Path
from typing import Any

from labs.adversarial_idor_eval.evaluate import (
    KEY,
    PROGRAM,
    ObjectTyper,
    _entry,
    _ratio,
    no_network,
    scenario_of_entry,
    shard,
    wilson,
)

HERE = Path(__file__).resolve().parent
CORPORA = {
    "adv-ranking-1.0": HERE / "frozen",
    "adv-ranking-dev": HERE / "dev",
}


def _dcg(rels: list[bool], k: int) -> float:
    return sum((1.0 if rel else 0.0) / math.log2(i + 2) for i, rel in enumerate(rels[:k]))


def evaluate_ranking(corpus: str = "adv-ranking-1.0", ks: tuple[int, ...] = (1, 3, 5, 10)) -> dict[str, Any]:
    from bugbounty_toolkit.analysis import object_relationships as orel

    root = CORPORA[corpus]
    captures = root / "captures.har"
    gt = json.loads((root / "ground_truth.json").read_text(encoding="utf-8"))
    with no_network() as attempts:
        work = Path(tempfile.mkdtemp(prefix="bbtk-rk-"))
        files, mapping, excluded = shard(captures, work)
        src_index = {orel._ref(KEY, "source", PROGRAM, f.read_bytes().hex()): fi for fi, f in enumerate(files)}

        def gentry(source_ref: str, locator: str) -> int:
            fi = src_index.get(source_ref)
            return mapping.get((fi, _entry(locator)), -1) if fi is not None else -1

        graph = orel.build_object_graph(PROGRAM, files, KEY, authorized=True)
        typer = ObjectTyper(
            orel, graph, json.loads(captures.read_text(encoding="utf-8")), gentry, scenario_of_entry(gt)
        )
        cands = orel.object_candidates(graph, PROGRAM, KEY, limit=100)["candidates"]
        pos = {(s["id"], t) for s in gt["scenarios"] for t in s["expected_pair_types"]}
        neg = {(s["id"], t) for s in gt["scenarios"] for t in s["forbidden_pair_types"]}
        amb = {(s["id"], t) for s in gt["scenarios"] for t in s["ambiguous_types"]}
        obs_entry: dict[str, list[int]] = {}
        for node in graph["observations"]:
            obs_entry[node["id"]] = [gentry(pv["source_ref"], str(pv["locator"])) for pv in node["provenance"]]
        by_entry = scenario_of_entry(gt)

        def cand_scen(c: dict) -> list[str]:
            ids = {by_entry.get(e, {}).get("id") for o in c.get("observation_refs", []) for e in obs_entry.get(o, [])}
            ids.discard(None)
            return sorted(ids)

        rows = []
        for c in cands:
            rt = typer.type_of(c["object_ref"], c["observation_refs"][0]) if c.get("observation_refs") else "?"
            rows.append(
                {
                    "resource_type": rt,
                    "exported_resource_type": c["resource_type"],
                    "scenarios": cand_scen(c),
                    "score": c.get("score"),
                    "order_reason": c.get("order_reason"),
                    "uncertainty": c.get("uncertainty"),
                }
            )
        disc_found = {(s, r["resource_type"]) for r in rows for s in r["scenarios"]}
        disc_rel = [any((s, r["resource_type"]) in pos for s in r["scenarios"]) for r in rows]
        depth = next((i for i, rel in enumerate(disc_rel, 1) if rel), None)
        ideal = sorted(disc_rel, reverse=True)
        result = {
            "corpus_version": gt["corpus_version"],
            "ranking_version": graph.get("ranking_version"),
            "scenarios": len(gt["scenarios"]),
            "entries": len(by_entry),
            "excluded_entries": excluded,
            "discovery_ranking": {
                "candidates": len(rows),
                "expected_objects": len(pos),
                "expected_found": len(pos & disc_found),
                "recall": _ratio(len(pos & disc_found), len(pos)),
                "recall_ci95": wilson(len(pos & disc_found), len(pos)),
                "precision_at_k": {str(k): _ratio(sum(disc_rel[:k]), min(k, len(disc_rel))) for k in ks},
                "mrr": (1.0 / depth) if depth else 0.0,
                "ndcg_at_k": {
                    str(k): (round(_dcg(disc_rel, k) / _dcg(ideal, k), 4) if _dcg(ideal, k) else None) for k in ks
                },
                "human_review_depth_to_first_relevant": depth,
                "relevant_still_available": len(pos & disc_found) == len(pos),
                "negative_in_top5": sorted(
                    {
                        f"{s}:{r['resource_type']}"
                        for r in rows[:5]
                        for s in r["scenarios"]
                        if (s, r["resource_type"]) in neg
                    }
                ),
                "ambiguous_surfaced": sorted(f"{s}:{t}" for s, t in amb & disc_found),
                "rows": rows,
                "note": "Scores prioritize human review; candidates are not confirmed findings.",
            },
            "safety": {"network_connect_attempts": attempts["count"]},
        }
    return result


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--corpus", choices=sorted(CORPORA), default="adv-ranking-1.0")
    ap.add_argument("--json", type=Path)
    a = ap.parse_args()
    res = evaluate_ranking(corpus=a.corpus)
    text = json.dumps(res, indent=1, sort_keys=True)
    if a.json:
        a.json.write_text(text + "\n", encoding="utf-8")
    print(text)


if __name__ == "__main__":
    main()
