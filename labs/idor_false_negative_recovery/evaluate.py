"""Score the frozen blocker-dependency-graph lab. Offline. No confirmation.

The evaluator refuses to run when cases.json differs from MANIFEST.sha256.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from labs.adversarial_idor_eval.evaluate import no_network  # noqa: E402

REVIEWABLE = frozenset({"reviewable", "safely_independent"})
ABSTAIN = frozenset({"inconclusive", "requires_manual_independence_review"})
SECRET = re.compile(r"BEGIN (?:RSA |OPENSSH )?PRIVATE KEY|AKIA[0-9A-Z]{16}|sk_live_[0-9A-Za-z]{8,}")


class FrozenCorpusError(RuntimeError):
    pass


def load_cases(split_dir: Path) -> dict[str, Any]:
    manifest = (split_dir / "MANIFEST.sha256").read_text(encoding="utf-8").split()
    data = (split_dir / "cases.json").read_bytes()
    if hashlib.sha256(data).hexdigest() != manifest[0]:
        raise FrozenCorpusError(f"{split_dir.name} cases.json differs from MANIFEST.sha256")
    loaded: dict[str, Any] = json.loads(data)
    return loaded


def _graph(case: dict[str, Any], *, reverse: bool = False) -> dict[str, Any]:
    from bugbounty_toolkit.analysis.blocker_dependency_graph import build_blocker_dependency_graph

    candidates = list(case["candidates"])
    evidence = list(case["evidence"])
    if reverse:
        candidates.reverse()
        evidence.reverse()
    return build_blocker_dependency_graph(candidates, evidence)


def _own_refs_ok(case: dict[str, Any], cid: str) -> bool:
    by_id = {row["evidence_id"]: row for row in case["evidence"]}
    cand = next(row for row in case["candidates"] if row["candidate_id"] == cid)
    return all(by_id.get(ref, {}).get("integrity", "missing") == "ok" for ref in cand["evidence_refs"])


def score_case(case: dict[str, Any], graph: dict[str, Any]) -> dict[str, Any]:
    got = {row["candidate_id"]: row for row in graph["candidates"]}
    expected = case["expected"]["by_candidate"]
    states_ok = all(got[cid]["effective_state"] == state for cid, state in expected.items())
    whole_ok = graph["whole_surface_blocks"] == case["expected"]["whole_surface"]
    order_ok = True
    if case.get("check_order"):
        other = _graph(case, reverse=True)
        order_ok = (
            other["candidates"] == graph["candidates"]
            and other["whole_surface_blocks"] == graph["whole_surface_blocks"]
        )
    confirmed = int(graph.get("finding_confirmed") is True) + sum(
        1 for row in graph["candidates"] if row.get("finding_confirmed")
    )
    return {
        "id": case["id"],
        "family": case["family"],
        "correct": bool(
            states_ok and whole_ok and order_ok and confirmed == 0 and graph.get("ledger_modified") is False
        ),
        "states_ok": states_ok,
        "whole_surface_ok": whole_ok,
        "order_ok": order_ok,
        "confirmed": confirmed,
        "got": {cid: got[cid]["effective_state"] for cid in expected},
        "reviewable_got": sorted(cid for cid, row in got.items() if row["reviewable"]),
        "manual": sum(1 for row in got.values() if row["effective_state"] == "requires_manual_independence_review"),
    }


def summarize(cases: list[dict[str, Any]], graphs: list[dict[str, Any]], rows: list[dict[str, Any]]) -> dict[str, Any]:
    eligible = []
    blocked_expected = []
    invalid_artifacts = 0
    invalid_detected = 0
    known_objects = 0
    known_objects_kept = 0
    abstain_expected = 0
    abstain_hit = 0
    propagated_predicted = 0
    propagated_correct = 0
    for case, graph in zip(cases, graphs):
        got = {row["candidate_id"]: row for row in graph["candidates"]}
        by_ev = {row["evidence_id"]: row for row in graph["artifacts"]}
        for cand in case["candidates"]:
            cid = cand["candidate_id"]
            exp = case["expected"]["by_candidate"][cid]
            pred = got[cid]["effective_state"]
            if exp in REVIEWABLE:
                eligible.append(pred in REVIEWABLE)
            else:
                blocked_expected.append(pred in REVIEWABLE)
            if exp in ABSTAIN:
                abstain_expected += 1
                abstain_hit += int(pred in ABSTAIN)
            own_ok = _own_refs_ok(case, cid)
            if own_ok and pred.startswith("blocked_"):
                propagated_predicted += 1
                propagated_correct += int(exp.startswith("blocked_"))
        for ev in case["evidence"]:
            reported = by_ev[ev["evidence_id"]]["integrity"]
            if ev["integrity"] in {"invalid", "missing", "out_of_program", "stale"}:
                invalid_artifacts += 1
                invalid_detected += int(reported == ev["integrity"])
            if ev.get("object_refs") is not None:
                known_objects += 1
                known_objects_kept += int(by_ev[ev["evidence_id"]]["object_refs_known"] is True)
            else:
                known_objects += 1
                known_objects_kept += int(by_ev[ev["evidence_id"]]["object_refs_known"] is False)
    fn = sum(1 for hit in eligible if not hit)
    false_rev = sum(1 for hit in blocked_expected if hit)
    n_eligible = len(eligible)

    def ratio(num: int, den: int) -> float | None:
        return round(num / den, 4) if den else None

    return {
        "cases": len(cases),
        "correct": sum(1 for row in rows if row["correct"]),
        "outcome_accuracy": ratio(sum(1 for row in rows if row["correct"]), len(rows)),
        "eligible_recall": ratio(n_eligible - fn, n_eligible),
        "fn_count": fn,
        "false_reviewable_count": false_rev,
        "correct_blockers": sum(1 for row in rows if row["states_ok"]),
        "correct_blockers_rate": ratio(sum(1 for row in rows if row["states_ok"]), len(rows)),
        "invalid_evidence_detection_rate": ratio(invalid_detected, invalid_artifacts),
        "abstention_rate": ratio(abstain_hit, abstain_expected),
        "provenance_completeness": ratio(known_objects_kept, known_objects),
        "integrity_propagation_precision": ratio(propagated_correct, propagated_predicted),
        "manual_effort_proxy": sum(row["manual"] for row in rows),
        "auto_confirmations": sum(row["confirmed"] for row in rows),
        "finding_confirmed": False,
        "ledger_modified": False,
    }


def secret_leaks(split_dir: Path) -> int:
    text = (split_dir / "cases.json").read_text(encoding="utf-8")
    return len(SECRET.findall(text))


def evaluate(split: str, root: Path = HERE) -> dict[str, Any]:
    split_dir = root / split
    with no_network() as attempts:
        document = load_cases(split_dir)
        graphs = [_graph(case) for case in document["cases"]]
        rows = [score_case(case, graph) for case, graph in zip(document["cases"], graphs)]
        metrics = summarize(document["cases"], graphs, rows)
        metrics["network_attempts"] = attempts["count"]
        metrics["external_requests"] = attempts["count"]
        metrics["secret_leaks"] = secret_leaks(split_dir)
    return {
        "schema_version": "bbtk-idor-fn-recovery-results/1",
        "split": split,
        "corpus_version": document["corpus_version"],
        "manifest_sha256": (split_dir / "MANIFEST.sha256").read_text(encoding="utf-8").split()[0],
        "finding_confirmed": False,
        "overall": metrics,
        "cases": rows,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--split", choices=("dev", "final"), default="dev")
    parser.add_argument("--json", type=Path)
    args = parser.parse_args(argv)
    result = evaluate(args.split)
    text = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(text, encoding="utf-8")
    print(json.dumps({"split": args.split, "overall": result["overall"]}, indent=2, sort_keys=True))
    overall = result["overall"]
    unsafe = overall["network_attempts"] or overall["auto_confirmations"] or overall["secret_leaks"]
    return 1 if unsafe or overall["correct"] != overall["cases"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
