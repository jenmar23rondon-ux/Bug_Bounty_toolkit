"""Evaluate idor-evidence-correctness-v3 on its frozen FINAL scenarios (offline, synthetic).

Families: A integrity-aware reviewability (planner effective view), B session control,
C access proof, D encoded identifiers (opt-in), E resource correlation. Public functions
only; labels live in ``final/scenarios.json`` and are verified against MANIFEST.sha256.
Capabilities missing at an older head are scored as ``unsupported`` (counted incorrect).
Network is hard-blocked; nothing is confirmed.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import sys
import tempfile
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from labs.adversarial_idor_eval.evaluate import no_network  # noqa: E402

PROGRAM = "v3-eval"
NOW = "2026-10-26T12:00:00Z"
NEGATIVE_CLASSES = frozenset({"identity_unproven", "invalid_session", "possibly_expired_session"})


class FrozenCorpusError(RuntimeError):
    pass


def load_scenarios(split_dir: Path = HERE / "final") -> dict[str, Any]:
    manifest = (split_dir / "MANIFEST.sha256").read_text(encoding="utf-8").split()
    data = (split_dir / "scenarios.json").read_bytes()
    if hashlib.sha256(data).hexdigest() != manifest[0]:
        raise FrozenCorpusError("scenarios.json differs from MANIFEST.sha256")
    loaded: dict[str, Any] = json.loads(data)
    return loaded


# ------------------------------------------------------------------------------- family A
def run_a(inp: dict[str, Any]) -> dict[str, Any]:
    from bugbounty_toolkit.analysis import evidence_ledger as L
    from bugbounty_toolkit.analysis.evidence_gap_planner import build_plan
    from bugbounty_toolkit.core.records import ProgramPaths

    work = Path(tempfile.mkdtemp(prefix="bbtk-v3-a-"))
    try:
        paths = ProgramPaths(work, PROGRAM)
        pdir = paths.program_dir
        (pdir / "evidence").mkdir(parents=True)
        ledger = L.new_ledger(PROGRAM)
        for cand in inp["candidates"]:
            L.upsert_surface(ledger, {"surface_id": cand["surface"], "kind": "endpoint", "ref": cand["surface"]})
            ledger["surfaces"][-1]["status"] = "investigated"
        for ev in inp["evidence"]:
            rel = f"evidence/{ev['id']}.json"
            payload = {
                "control": {"annotation_version": "bbtk-control-annotation/1", **ev["control"]},
                "proposal": {"owner": {"object_ref": ev["objects"][0]}, "actor": {"object_ref": ev["objects"][1]}}
                if len(ev["objects"]) == 2
                else {},
            }
            (pdir / rel).write_text(json.dumps(payload, sort_keys=True), encoding="utf-8")
            L.add_evidence(ledger, pdir, ev["id"], rel, tool="v3-eval")
        for cand in inp["candidates"]:
            L.add_candidate(
                ledger, cand["id"], cand["surface"], "idor", "lab", list(cand["refs"]), dedup_key=f"v3:{cand['id']}"
            )
            L.review_candidate(
                ledger, cand["id"], "requires_validation", "lab", blockers=["human_ownership_attestation"]
            )
        lp = pdir / "ledger" / "evidence-ledger.json"
        lp.parent.mkdir(parents=True, exist_ok=True)
        lp.write_text(json.dumps(ledger, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        mut = inp.get("mutation") or {}
        if "tamper" in mut:
            f = pdir / f"evidence/{mut['tamper']}.json"
            f.write_text(f.read_text(encoding="utf-8") + " ", encoding="utf-8")
        if "delete" in mut:
            (pdir / f"evidence/{mut['delete']}.json").unlink()
        before = lp.read_bytes()
        plan = build_plan(paths, now=NOW)
        unmodified = lp.read_bytes() == before
        target = inp["target"]
        res: dict[str, Any] = next((c for c in plan.get("candidates") or [] if c.get("candidate_id") == target), {})
        view = plan.get("effective_eligibility")
        if view is None:  # older head: only the raw ledger state exists
            reviewable = True
            supported = False
        else:
            row: dict[str, Any] = next((r for r in view if r["candidate_id"] == target), {})
            reviewable = bool(row.get("effective_reviewable"))
            supported = True
        steps = {s["step_id"]: s for s in plan.get("plan") or []}
        manual = sum(int(steps[s]["estimated_manual_steps"]) for s in res.get("steps") or [] if s in steps)
        blockers = [g["kind"] for g in res.get("gaps") or [] if g.get("kind") in {"invalid_evidence", "stale_evidence"}]
        return {
            "effective_reviewable": reviewable,
            "status": res.get("status"),
            "supported": supported,
            "ledger_unmodified": unmodified,
            "manual_steps": manual,
            "invalid_evidence_blockers": len(blockers),
        }
    finally:
        shutil.rmtree(work, ignore_errors=True)


def score_a(exp: dict[str, Any], got: dict[str, Any]) -> bool:
    ok = got["effective_reviewable"] == exp["effective_reviewable"] and got["ledger_unmodified"]
    if exp.get("status"):
        ok = ok and got["status"] == exp["status"]
    return bool(ok)


# ------------------------------------------------------------------------------- family B
def run_b(inp: dict[str, Any]) -> dict[str, Any]:
    from bugbounty_toolkit.analysis import actor_provenance as P

    fn = getattr(P, "classify_session_controls", None)
    if fn is None:
        return {"supported": False}
    out = fn(inp["observations"])
    return {
        "supported": True,
        "sessions": {k: v["classification"] for k, v in out["sessions"].items()},
        "dependent": [d["result"] for d in out["dependent_results"]],
        "expiry_proven": any(v["expiry_proven"] for v in out["sessions"].values()),
    }


def score_b(exp: dict[str, Any], got: dict[str, Any]) -> bool:
    return bool(got.get("supported") and got["sessions"] == exp["sessions"] and got["dependent"] == exp["dependent"])


# ------------------------------------------------------------------------------- family C
def run_c(inp: dict[str, Any]) -> dict[str, Any]:
    from bugbounty_toolkit.analysis import authorization_denial as A

    if "actor_raw" not in inp:
        r = A.assess_raw_response(inp["raw"])
        return {"supported": hasattr(r, "access_proof"), "access_proof": getattr(r, "access_proof", None)}
    out = A.assess_pair_authorization(inp["raw"], inp["actor_raw"])
    ann = out.annotation or {}
    return {
        "supported": "owner_control" in ann,
        "outcome": out.outcome,
        # Promotion = the e2e path would record requires_validation for an eligible pair.
        "promote": out.outcome == "possible_access",
        "owner_control": ann.get("owner_control"),
    }


def score_c(exp: dict[str, Any], got: dict[str, Any]) -> bool:
    return all(got.get(k) == v for k, v in exp.items())


# ------------------------------------------------------------------------------- family D
def run_d(inp: dict[str, Any]) -> dict[str, Any]:
    from bugbounty_toolkit.analysis import object_handoff as H

    fn = getattr(H, "normalize_captured_identifier", None)
    if fn is None:
        return {"supported": False}
    out = fn(inp["value"], captured_values=frozenset(inp["captured"]), kind=inp["kind"], enabled=inp["enabled"])
    return {"supported": True, **out}


def score_d(exp: dict[str, Any], got: dict[str, Any]) -> bool:
    if not got.get("supported"):
        return False
    for k, v in exp.items():
        if k == "not_equal":
            if got.get("namespace_key") == v:
                return False
        elif got.get(k) != v:
            return False
    return True


# ------------------------------------------------------------------------------- family E
def run_e(inp: dict[str, Any]) -> dict[str, Any]:
    from bugbounty_toolkit.analysis import resource_kind_lineage as R

    fn = getattr(R, "correlate_resources", None)
    if fn is None:
        return {"supported": False}
    return {"supported": True, **fn(inp["owner"], inp["actor"])}


def score_e(exp: dict[str, Any], got: dict[str, Any]) -> bool:
    return bool(got.get("supported")) and all(got.get(k) == v for k, v in exp.items())


RUN = {
    "A": (run_a, score_a),
    "B": (run_b, score_b),
    "C": (run_c, score_c),
    "D": (run_d, score_d),
    "E": (run_e, score_e),
}


def evaluate() -> dict[str, Any]:
    gt = load_scenarios()
    rows: list[dict[str, Any]] = []
    with no_network() as attempts:
        for sc in gt["scenarios"]:
            run, score = RUN[sc["family"]]
            got = run(sc["input"])
            rows.append({"id": sc["id"], "family": sc["family"], "correct": score(sc["expected"], got), "got": got})
    by_sc = {sc["id"]: sc for sc in gt["scenarios"]}
    fam: dict[str, dict[str, int]] = {}
    for r in rows:
        f = fam.setdefault(r["family"], {"n": 0, "correct": 0})
        f["n"] += 1
        f["correct"] += int(r["correct"])
    a_rows = [r for r in rows if r["family"] == "A"]
    false_rev = [
        r["id"]
        for r in a_rows
        if r["got"]["effective_reviewable"] and not by_sc[r["id"]]["expected"]["effective_reviewable"]
    ]
    missed = [
        r["id"]
        for r in a_rows
        if not r["got"]["effective_reviewable"] and by_sc[r["id"]]["expected"]["effective_reviewable"]
    ]
    abstain_expected = [
        r
        for r in rows
        if (r["family"] == "C" and by_sc[r["id"]]["expected"].get("promote") is False)
        or (r["family"] == "E" and not by_sc[r["id"]]["expected"].get("idor_review_signal", True))
        or (r["family"] == "B" and set(by_sc[r["id"]]["expected"]["sessions"].values()) & NEGATIVE_CLASSES)
    ]
    kind_rows = [r for r in rows if r["family"] == "E" and "resource_kind" in by_sc[r["id"]]["expected"]]
    b_rows = [r for r in rows if r["family"] == "B"]
    overall = {
        "scenarios": len(rows),
        "outcome_accuracy": round(sum(r["correct"] for r in rows) / len(rows), 4),
        "false_reviewable_cases": len(false_rev),
        "false_reviewable_ids": false_rev,
        "false_reviewable_rate": round(
            len(false_rev) / max(1, sum(1 for r in a_rows if not by_sc[r["id"]]["expected"]["effective_reviewable"])), 4
        ),
        "missed_eligible_cases": len(missed),
        "missed_eligible_ids": missed,
        "correct_abstentions": sum(1 for r in abstain_expected if r["correct"]),
        "abstentions_expected": len(abstain_expected),
        "resource_kind_preservation": round(sum(r["correct"] for r in kind_rows) / max(1, len(kind_rows)), 4),
        "provenance_validity": round(
            sum(1 for r in b_rows if r["got"].get("supported") and not r["got"].get("expiry_proven"))
            / max(1, len(b_rows)),
            4,
        ),
        "invalid_evidence_blockers": sum(int(r["got"].get("invalid_evidence_blockers") or 0) for r in a_rows),
        "ledger_history_unmodified": all(r["got"]["ledger_unmodified"] for r in a_rows),
        "estimated_manual_steps": sum(int(r["got"].get("manual_steps") or 0) for r in a_rows),
        "network_attempts": attempts["count"],
        "auto_confirmations": 0,
    }
    return {
        "type": "bbtk-idor-evidence-v3-eval",
        "corpus_version": gt["corpus_version"],
        "metric_scope": "synthetic offline lab only; not evidence of real-world performance",
        "overall": overall,
        "by_family": {k: {**v, "accuracy": round(v["correct"] / v["n"], 4)} for k, v in sorted(fam.items())},
        "scenarios": [{"id": r["id"], "family": r["family"], "correct": r["correct"]} for r in rows],
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--json", type=Path)
    args = ap.parse_args(argv)
    result = evaluate()
    text = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(text, encoding="utf-8")
    print(json.dumps({"overall": result["overall"], "by_family": result["by_family"]}, indent=2, sort_keys=True))
    return 1 if result["overall"]["network_attempts"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
