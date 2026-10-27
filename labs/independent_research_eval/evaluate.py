"""Run the real bbtk offline research pipeline on irb-1.0 and score it per stage and family.

Public interfaces only: ``run_e2e_research`` (capture → import → discovery → ranking →
handoff → eligibility → reviewable case → evidence ledger → report) and
``evidence_gap_planner.build_plan``. Stage latencies are measured in a separate timing
pass with the same public stage functions. Network is hard-blocked; nothing is confirmed.

The evaluator refuses to run if a split's files differ from its frozen MANIFEST.sha256.
"""

from __future__ import annotations

import argparse
import json
import shutil
import sys
import tempfile
import time
import tracemalloc
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from labs.adversarial_idor_eval.evaluate import KEY, no_network  # noqa: E402
from labs.independent_research_eval import metrics as M  # noqa: E402
from labs.independent_research_eval.build_corpus import ALT_ORIGIN, ORIGIN  # noqa: E402

PROGRAM = "irb-eval"
NOW = "2026-10-26T12:00:00Z"
EXPIRED = "2026-01-01T00:00:00Z"
ACTIVE = {"candidate", "requires_validation"}
SHAREABLE = ("e2e-report.json", "ranking.json", "handoff.json", "session.json")


class FrozenCorpusError(RuntimeError):
    pass


# ---------------------------------------------------------------------------- integrity
def manifest_mismatches(split_dir: Path) -> list[str]:
    """Files whose SHA-256 differs from MANIFEST.sha256, plus unlisted/missing files."""
    from bugbounty_toolkit.analysis.evidence_ledger import file_sha256

    manifest = split_dir / "MANIFEST.sha256"
    if not manifest.is_file():
        return ["MANIFEST.sha256 missing"]
    listed: dict[str, str] = {}
    for line in manifest.read_text(encoding="utf-8").splitlines():
        digest, _, rel = line.partition("  ")
        listed[rel] = digest
    bad = [rel for rel, d in listed.items() if not (split_dir / rel).is_file() or file_sha256(split_dir / rel) != d]
    present = {
        str(p.relative_to(split_dir)) for p in split_dir.rglob("*") if p.is_file() and p.name != "MANIFEST.sha256"
    }
    bad += sorted(f"unlisted:{p}" for p in present - set(listed))
    return sorted(bad)


def historical_overlap(split_dir: Path) -> dict[str, Any]:
    """Compare request URLs/markers with every historical lab capture (excluding this lab)."""
    ours = b"".join(p.read_bytes() for p in (split_dir / "captures").glob("*"))
    hist_files = [
        p
        for p in (ROOT / "labs").rglob("*")
        if p.is_file() and p.suffix in {".har", ".xml", ".http", ".json"} and HERE not in p.parents
    ]
    needles = [b"127.0.0.1:8177", b"127.0.0.1:8178", b'"/ib/', b"ib30-", b"irb-"]
    hits: dict[str, int] = {}
    for p in hist_files:
        data = p.read_bytes()
        for n in needles:
            if n in data:
                hits[n.decode()] = hits.get(n.decode(), 0) + 1
    # Exact-capture reuse: any historical file byte-identical to one of ours.
    our_hashes = {M_sha(p.read_bytes()) for p in (split_dir / "captures").glob("*")}
    identical = sum(1 for p in hist_files if M_sha(p.read_bytes()) in our_hashes)
    return {
        "historical_files_scanned": len(hist_files),
        "needle_hits": hits,
        "identical_files": identical,
        "our_bytes": len(ours),
        "overlap_free": not hits and identical == 0,
    }


def M_sha(data: bytes) -> str:  # noqa: N802 - small helper
    import hashlib

    return hashlib.sha256(data).hexdigest()


# ---------------------------------------------------------------------------- mutations (D)
def _program_dir(work: Path) -> Path:
    return work / PROGRAM


def _ledger_path(work: Path) -> Path:
    return _program_dir(work) / "ledger" / "evidence-ledger.json"


def _target_candidate(ledger: dict[str, Any]) -> dict[str, Any] | None:
    cands: list[dict[str, Any]] = [c for c in ledger.get("candidates") or [] if isinstance(c, dict)]
    active = [c for c in cands if c.get("state") in ACTIVE]
    pool = active or cands
    return pool[0] if pool else None


def _add_annotation(work: Path, ledger: dict[str, Any], eid: str, control: dict[str, Any]) -> None:
    from bugbounty_toolkit.analysis import evidence_ledger as L

    rel = f"evidence/{eid}.json"
    path = _program_dir(work) / rel
    path.write_text(
        json.dumps({"control": {"annotation_version": "bbtk-control-annotation/1", **control}}, sort_keys=True),
        encoding="utf-8",
    )
    L.add_evidence(ledger, _program_dir(work), eid, rel, tool="irb-annotation")
    cand = _target_candidate(ledger)
    if cand is not None:
        cand.setdefault("evidence_refs", []).append(eid)


def apply_mutation(work: Path, mutation: str | None) -> str | None:
    """Simulate a later edit of the ledger/evidence the pipeline produced. Returns error text."""
    if not mutation:
        return None
    lp = _ledger_path(work)
    if not lp.is_file():
        return "no_ledger"
    ledger = json.loads(lp.read_text(encoding="utf-8"))
    cand = _target_candidate(ledger)
    if cand is None:
        return "no_candidate"
    refs = list(cand.get("evidence_refs") or [])
    ev = {e["evidence_id"]: e for e in ledger.get("evidence") or []}
    first = _program_dir(work) / ev[refs[0]]["path"] if refs and refs[0] in ev else None
    if mutation == "tamper_evidence" and first is not None:
        first.write_text(first.read_text(encoding="utf-8") + " ", encoding="utf-8")
    elif mutation == "delete_evidence" and first is not None:
        first.unlink()
    elif mutation == "broken_ref":
        cand["evidence_refs"] = refs + ["ev-not-recorded-0001"]
    elif mutation == "duplicate_candidate":
        dup = json.loads(json.dumps(cand))
        dup["candidate_id"] = str(cand["candidate_id"]) + "-dup"
        ledger["candidates"].append(dup)
    elif mutation == "expired_annotation":
        _add_annotation(work, ledger, "ev-irb-expired", {"role": "owner_response", "expires_at": EXPIRED})
    elif mutation == "contradicting_control":
        _add_annotation(work, ledger, "ev-irb-neg", {"role": "negative_control", "contradicts_hypothesis": True})
    elif mutation in {"attest_all_controls", "attest_partial_controls"}:
        _add_annotation(
            work,
            ledger,
            "ev-irb-attest",
            {"role": "owner_response", "ownership": "attested", "distinct_accounts": "attested"},
        )
        if mutation == "attest_all_controls":
            _add_annotation(work, ledger, "ev-irb-negok", {"role": "negative_control", "contradicts_hypothesis": False})
    else:
        return f"unknown_or_inapplicable:{mutation}"
    lp.write_text(json.dumps(ledger, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return None


# ---------------------------------------------------------------------------- run
def _stage_timings(captures: list[Path]) -> dict[str, float]:
    from bugbounty_toolkit.analysis.object_handoff import propose_object_handoff
    from bugbounty_toolkit.analysis.object_relationships import build_object_graph, object_candidates

    t: dict[str, float] = {}
    tmp = Path(tempfile.mkdtemp(prefix="bbtk-irb-t-"))
    try:
        s = time.perf_counter()
        graph = build_object_graph(PROGRAM, captures, KEY, authorized=True)
        t["import_discovery_ms"] = (time.perf_counter() - s) * 1000
        s = time.perf_counter()
        object_candidates(graph, PROGRAM, KEY, limit=64)
        t["ranking_ms"] = (time.perf_counter() - s) * 1000
        s = time.perf_counter()
        propose_object_handoff(graph, PROGRAM, KEY, verify_inputs=captures, limit=64, materialize_dir=tmp)
        t["handoff_ms"] = (time.perf_counter() - s) * 1000
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    return {k: round(v, 2) for k, v in t.items()}


def run_scenario(split_dir: Path, sc: dict[str, Any], *, keep: Path | None = None) -> dict[str, Any]:
    from bugbounty_toolkit.analysis.evidence_gap_planner import build_plan, dumps_plan
    from bugbounty_toolkit.analysis.idor_e2e_research import run_e2e_research
    from bugbounty_toolkit.core.records import ProgramPaths

    captures = [split_dir / c for c in sc["captures"]]
    work = Path(tempfile.mkdtemp(prefix=f"bbtk-irb-{sc['id']}-"))
    pred: dict[str, Any] = {"id": sc["id"], "exception": None, "mutation_error": None}
    tracemalloc.start()
    started = time.perf_counter()
    with no_network() as attempts:
        try:
            try:
                pred["stage_ms"] = _stage_timings(captures)
            except Exception as exc:  # noqa: BLE001 - recorded as a stage error
                pred["stage_ms"] = {"error": type(exc).__name__}
            s = time.perf_counter()
            report = run_e2e_research(PROGRAM, captures, work, key=KEY, authorized=True, limit=64)
            pred["stage_ms"]["e2e_total_ms"] = round((time.perf_counter() - s) * 1000, 2)
            pred["mutation_error"] = apply_mutation(work, sc.get("post_pipeline_mutation"))
            s = time.perf_counter()
            plan = build_plan(ProgramPaths(work, PROGRAM), now=NOW)
            pred["stage_ms"]["planner_ms"] = round((time.perf_counter() - s) * 1000, 2)
            (work / "plan.json").write_text(dumps_plan(plan), encoding="utf-8")
            pred.update(_extract(work, report, plan, sc["labels"]))
        except Exception as exc:  # noqa: BLE001 - pipeline errors are measured, not hidden
            pred["exception"] = f"{type(exc).__name__}: {str(exc)[:200]}"
            pred.update(_empty())
    pred["elapsed_ms"] = round((time.perf_counter() - started) * 1000, 2)
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    pred["peak_mem_kib"] = round(peak / 1024, 1)
    pred["network_attempts"] = attempts["count"]
    pred["leak_scan"] = scan_leaks(work, sc["labels"].get("canaries") or [])
    if keep is not None:
        shutil.copytree(work, keep / sc["id"], dirs_exist_ok=True)
    shutil.rmtree(work, ignore_errors=True)
    return pred


def _empty() -> dict[str, Any]:
    return {
        "import": {},
        "ranked_types": [],
        "ranked_types_resolved": [],
        "ranked_types_exported_kind": [],
        "proposal_types": [],
        "classifications": [],
        "ledger_states": [],
        "effective_reviewable": [],
        "plan_statuses": [],
        "plan_controls": [],
        "first_step": "none",
        "plan_steps": 0,
        "plan_refs": {"valid": 0, "total": 0},
        "plan_manual_steps": 0,
        "confirmed": 0,
    }


def label_kind_refs(labels: dict[str, Any]) -> dict[str, str]:
    """Map the toolkit's keyed kind refs back to label nouns.

    The evaluator holds the lab HMAC key, so it pseudonymizes *label* nouns the same way the
    toolkit does (``kind-<hmac>`` for open-vocabulary nouns) instead of de-anonymizing output.
    """
    from urllib.parse import urlsplit

    from bugbounty_toolkit.analysis.object_relationships import _kind_ref, _ref

    nouns = {*labels["target_types"], *labels["ideal_pair_types"], *labels["forbidden_pair_types"]}
    out: dict[str, str] = {}
    for noun in nouns:
        for url in (ORIGIN, ALT_ORIGIN):
            u = urlsplit(url)
            origin = _ref(KEY, "origin", PROGRAM, u.scheme, u.hostname or "", u.port or 80)
            ref = _kind_ref(KEY, PROGRAM, origin, noun)
            if ref:
                out[ref] = noun
    return out


def _kind_name(value: Any, refs: dict[str, str]) -> str:
    text = str(value or "unknown")
    if text in refs:
        return refs[text]
    return text.removeprefix("kind:")


def _extract(work: Path, report: dict[str, Any], plan: dict[str, Any], labels: dict[str, Any]) -> dict[str, Any]:
    krefs = label_kind_refs(labels)
    handoff = json.loads((work / "handoff.json").read_text(encoding="utf-8"))
    ledger = json.loads(_ledger_path(work).read_text(encoding="utf-8")) if _ledger_path(work).is_file() else {}
    ev_ids = {e.get("evidence_id") for e in ledger.get("evidence") or []}
    steps = plan.get("plan") or []
    refs = [r for s in steps for r in s.get("evidence_refs") or []]
    active = [c for c in plan.get("candidates") or [] if not str(c.get("status", "")).startswith("closed_")]
    imp = report.get("capture_import") or {}
    confirmed = int(report.get("vulnerabilities_confirmed") or 0) + sum(
        1 for c in ledger.get("candidates") or [] if c.get("state") == "confirmed"
    )
    confirmed += sum(1 for s in steps if s.get("finding_confirmed") or s.get("execution_allowed"))
    kinds: dict[str, str] = {}
    for p in handoff.get("proposals") or []:
        kind = _kind_name(p.get("resource_kind"), krefs) if p.get("resource_kind") else ""
        for side in ("owner", "actor"):
            ref = (p.get(side) or {}).get("object_ref")
            if ref and kind:
                kinds.setdefault(str(ref), kind)
    ranking = report.get("ranking") or []
    return {
        "ranked_types_resolved": [
            str(r.get("resource_type"))
            if r.get("resource_type") not in (None, "unknown")
            else kinds.get(str(r.get("object_ref")), "unknown")
            for r in ranking
        ],
        "import": {k: imp.get(k) for k in ("entries_total", "accepted", "rejected", "reasons", "duplicate_entries")},
        "ranked_types": [str(r.get("resource_type")) for r in report.get("ranking") or []],
        # resource-kind-lineage-v1: what the exported ranking row ALONE says (resource_type, else the
        # keyed resource_kind pseudonymized like the labels). No handoff back-fill.
        "ranked_types_exported_kind": [
            str(r.get("resource_type"))
            if r.get("resource_type") not in (None, "unknown")
            else _kind_name(r.get("resource_kind"), krefs)
            if r.get("resource_kind")
            else "unknown"
            for r in report.get("ranking") or []
        ],
        "proposal_types": [
            _kind_name(p.get("resource_kind") or p.get("resource_type"), krefs) for p in handoff.get("proposals") or []
        ],
        "classifications": [
            {
                "code": c.get("code"),
                "case_eligible": bool(c.get("case_eligible")),
                "technical_error": bool(c.get("technical_error")),
            }
            for c in report.get("classifications") or []
        ],
        "ledger_states": [str(c.get("state")) for c in ledger.get("candidates") or []],
        # idor-evidence-correctness-v3: current reviewability from the planner's read-only
        # effective eligibility view (ledger history is never rewritten).
        "effective_reviewable": [bool(r.get("effective_reviewable")) for r in plan.get("effective_eligibility") or []],
        "plan_statuses": [str(c.get("status")) for c in active],
        "plan_controls": [c.get("controls") or {} for c in active],
        "first_step": str(steps[0]["step_type"]) if steps else "none",
        "plan_steps": len(steps),
        "plan_refs": {"valid": sum(1 for r in refs if r in ev_ids), "total": len(refs)},
        "plan_manual_steps": sum(int(s.get("estimated_manual_steps") or 0) for s in steps),
        "confirmed": confirmed,
    }


def scan_leaks(work: Path, canaries: list[str]) -> dict[str, Any]:
    """Count canary occurrences in shareable artifacts (private materialized pairs excluded)."""
    shareable = [work / n for n in (*SHAREABLE, "plan.json")] + list((_program_dir(work) / "ledger").glob("*.json"))
    shareable += list((_program_dir(work) / "evidence").glob("*.json"))
    leaks: dict[str, int] = {}
    private = 0
    for c in canaries:
        b = c.encode()
        for p in shareable:
            if p.is_file() and b in p.read_bytes():
                leaks[p.name] = leaks.get(p.name, 0) + 1
        for p in (work / "pairs").glob("*") if (work / "pairs").is_dir() else []:
            if b in p.read_bytes():
                private += 1
    return {"shareable_leaks": sum(leaks.values()), "by_artifact": leaks, "private_pair_occurrences": private}


# ---------------------------------------------------------------------------- scoring
def score(sc: dict[str, Any], pred: dict[str, Any]) -> dict[str, Any]:
    lab = sc["labels"]
    clf = pred["classifications"]
    technical = (
        any(c["technical_error"] for c in clf)
        or bool(pred["exception"])
        or bool((pred["import"] or {}).get("rejected"))
    )
    no_input = not (pred["import"] or {}).get("accepted")
    outcome = M.scenario_outcome(pred["plan_statuses"], technical=technical, no_input=no_input)
    ideal = lab["ideal_outcome"]
    raw_reviewable = any(s == "requires_validation" for s in pred["ledger_states"])
    eff = list(pred.get("effective_reviewable") or [])
    # Use the effective view when the planner emitted one row per ledger candidate; older heads
    # (no view) fall back to the raw ledger state so before/after stays comparable.
    reviewable = any(eff) if eff and len(eff) == len(pred["ledger_states"]) else raw_reviewable
    ranking = None
    if lab["target_types"]:
        rel = M.relevance_vector(pred["ranked_types_resolved"], lab["target_types"])
        strict = M.relevance_vector(pred["ranked_types"], lab["target_types"])
        ranking = {
            "strict_p@1": M.precision_at_k(strict, 1),
            "strict_recall": bool(sum(strict)),
            "kind_p@1": M.precision_at_k(
                M.relevance_vector(pred.get("ranked_types_exported_kind") or pred["ranked_types"], lab["target_types"]),
                1,
            ),
            "kind_recall": bool(
                sum(
                    M.relevance_vector(
                        pred.get("ranked_types_exported_kind") or pred["ranked_types"], lab["target_types"]
                    )
                )
            ),
            "recall": bool(sum(rel)),
            "p@1": M.precision_at_k(rel, 1),
            "p@3": round(M.precision_at_k(rel, 3), 4),
            "p@5": round(M.precision_at_k(rel, 5), 4),
            "rr": round(M.reciprocal_rank(rel), 4),
            "ndcg@5": round(M.ndcg_at_k(rel, 5), 4),
            "top1_type": pred["ranked_types_resolved"][0] if pred["ranked_types_resolved"] else None,
            "top1_strict_type": pred["ranked_types"][0] if pred["ranked_types"] else None,
        }
    pairing = M.pairing_counts(set(pred["proposal_types"]), lab["ideal_pair_types"], lab["forbidden_pair_types"])
    missing = None
    exp_missing = [m for m in lab["expected_missing_controls"] if m != "none"]
    if lab["ideal_reviewable"]:
        pm = {k for ctl in pred["plan_controls"] for k, v in ctl.items() if v != "present"}
        if exp_missing:
            missing = {"expected": len(exp_missing), "hit": len(set(exp_missing) & pm), "predicted": sorted(pm)}
        else:  # spec says nothing is missing; credit only if planner agrees for some candidate
            ok = any(all(v == "present" for v in ctl.values()) for ctl in pred["plan_controls"])
            missing = {"expected": 1, "hit": int(ok), "predicted": sorted(pm)}
    cap = lab.get("max_reasonable_proposals")
    redundant = max(0, len(pred["proposal_types"]) - cap) if cap is not None else 0
    info_loss = []
    if lab["target_types"] and ranking and ranking["recall"] and lab["ideal_pair_types"] and not pairing["tp"]:
        info_loss.append("target_ranked_but_not_paired")
    if pairing["tp"] and lab["ideal_reviewable"] and not reviewable:
        info_loss.append("paired_but_no_reviewable_case")
    imp = pred["import"] or {}
    if imp.get("entries_total") is not None and imp["entries_total"] < sc["exchanges"] and sc["format"] == "har":
        info_loss.append("entries_missing_at_import")
    return {
        "id": sc["id"],
        "family": sc["family"],
        "tag": sc["tag"],
        "ideal_outcome": ideal,
        "predicted_outcome": outcome,
        "outcome_correct": outcome == ideal,
        "outcome_correct_lenient": outcome == ideal or (ideal in M.ABSTAIN_LIKE and outcome in M.ABSTAIN_LIKE),
        "ideal_reviewable": lab["ideal_reviewable"],
        "predicted_reviewable": reviewable,
        "ledger_raw_reviewable": raw_reviewable,
        "eligibility_correct": any(c["case_eligible"] for c in clf) == lab["ideal_reviewable"],
        "eligibility_codes": sorted({str(c["code"]) for c in clf}),
        "ranking": ranking,
        "pairing": pairing,
        "proposal_types": sorted(set(pred["proposal_types"])),
        "proposals": len(pred["proposal_types"]),
        "missing_control": missing,
        "first_step": pred["first_step"],
        "next_step_correct": pred["first_step"] in lab["acceptable_first_steps"],
        "redundant_proposals": redundant,
        "manual_steps": pred["plan_manual_steps"] + (6 if reviewable else 0),
        "refs": pred["plan_refs"],
        "leaks": pred["leak_scan"]["shareable_leaks"],
        "confirmed": pred["confirmed"],
        "network_attempts": pred["network_attempts"],
        "exception": pred["exception"],
        "mutation_error": pred["mutation_error"],
        "info_loss": info_loss,
        "stage_ms": pred.get("stage_ms"),
        "peak_mem_kib": pred["peak_mem_kib"],
    }


def evaluate(split: str, root: Path = HERE, *, verify: bool = True) -> dict[str, Any]:
    split_dir = root / split
    if verify:
        bad = manifest_mismatches(split_dir)
        if bad:
            raise FrozenCorpusError(f"{split} corpus differs from MANIFEST.sha256: {bad[:5]}")
    gt = json.loads((split_dir / "ground_truth.json").read_text(encoding="utf-8"))
    rows = [score(sc, run_scenario(split_dir, sc)) for sc in gt["scenarios"]]
    lat = [r["stage_ms"] for r in rows if isinstance(r.get("stage_ms"), dict)]
    stage_keys = sorted({k for d in lat for k in d if k.endswith("_ms")})
    latency = {}
    for k in stage_keys:
        vals = sorted(float(d[k]) for d in lat if isinstance(d.get(k), (int, float)))
        if vals:
            latency[k] = {"median": vals[len(vals) // 2], "max": vals[-1]}
    manifest = (split_dir / "MANIFEST.sha256").read_bytes()
    return {
        "type": "bbtk-independent-research-benchmark",
        "corpus_version": gt["corpus_version"],
        "split": split,
        "manifest_sha256": M_sha(manifest),
        "label_source": gt["label_source"],
        "metric_scope": "synthetic loopback lab only; not evidence of real-world performance",
        "historical_overlap": historical_overlap(split_dir),
        "overall": M.summarize(rows),
        "by_family": M.by_family(rows),
        "latency_ms": latency,
        "peak_mem_kib_max": max((r["peak_mem_kib"] for r in rows), default=0),
        "scenarios": rows,
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--split", choices=("dev", "final", "stress"), default="dev")
    ap.add_argument("--json", type=Path)
    args = ap.parse_args(argv)
    result = evaluate(args.split)
    text = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(text, encoding="utf-8")
    print(json.dumps({"split": args.split, "overall": result["overall"]}, indent=2, sort_keys=True))
    o = result["overall"]
    return 1 if (o["network_attempts"] or o["auto_confirmations"] or o["secret_leaks"]) else 0


if __name__ == "__main__":
    raise SystemExit(main())
