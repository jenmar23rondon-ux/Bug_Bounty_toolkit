"""Before/after metrics: exact-key dedup baseline vs semantic correlation.

Synthetic corpora only; figures do not measure real-world productivity.
Predicted duplicate = ``similarity_band == "strong"``. The frozen FINAL labels
are verified against their SHA-256 manifest before any scoring.
"""

from __future__ import annotations

import hashlib
import json
import socket
import time
import tracemalloc
from pathlib import Path
from typing import Any

from bugbounty_toolkit.analysis.candidate_similarity import correlate_ledger, exact_key_duplicates
from bugbounty_toolkit.analysis.evidence_ledger import load_ledger

from .corpus import build_split
from .freeze import HERE, frozen_text

FIXED_KEY = b"semantic-candidate-lab-fixed-key"


class FrozenCorpusError(RuntimeError):
    pass


def verify_frozen(split: str) -> dict[str, Any]:
    """Rebuild the split and check it matches the committed labels + manifest digest."""
    stored = (HERE / split / "ground_truth.json").read_text(encoding="utf-8")
    want = (HERE / split / "MANIFEST.sha256").read_text(encoding="utf-8").split()[0]
    if hashlib.sha256(stored.encode()).hexdigest() != want:
        raise FrozenCorpusError(f"{split}: ground_truth.json does not match MANIFEST.sha256")
    if frozen_text(split) != stored:
        raise FrozenCorpusError(f"{split}: corpus generator output differs from frozen labels")
    data: dict[str, Any] = json.loads(stored)
    return data


def _pairs(rows: list[list[str]]) -> set[tuple[str, str]]:
    return {(min(a, b), max(a, b)) for a, b in rows}


def _prf(counts: list[int], negatives: int) -> dict[str, float | int]:
    tp, fp, fn = counts
    prec = tp / (tp + fp) if tp + fp else 1.0
    rec = tp / (tp + fn) if tp + fn else 1.0
    f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0.0
    return {
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "precision": round(prec, 4),
        "recall": round(rec, 4),
        "f1": round(f1, 4),
        "false_merge_rate": round(fp / negatives, 4) if negatives else 0.0,
        "false_negative_rate": round(fn / (tp + fn), 4) if tp + fn else 0.0,
    }


def evaluate_split(split: str, root: Path, *, frozen: dict[str, Any] | None = None) -> dict[str, Any]:
    truth = frozen if frozen is not None else verify_frozen(split)
    manifest = build_split(split, root)
    if [s["programs"] for s in manifest["scenarios"]] != [s["programs"] for s in truth["scenarios"]]:
        raise FrozenCorpusError("built ledgers differ from frozen digests")
    attempts = {"n": 0}
    real_connect = socket.socket.connect

    def guard(self: socket.socket, *a: Any, **k: Any) -> None:
        attempts["n"] += 1
        raise OSError("network disabled in lab")

    socket.socket.connect = guard  # type: ignore[method-assign,assignment]
    tracemalloc.start()
    totals = {"sem": [0, 0, 0], "base": [0, 0, 0], "base_surface": [0, 0, 0]}
    negatives = 0
    adversarial_false_merges = 0
    invalid_refs_accepted = 0
    leaks = 0
    ledger_changed = 0
    auto_actions = 0
    p1_hits = p1_total = 0
    reuse_valid = reuse_total = reuse_expected_found = reuse_expected = 0
    latencies: list[float] = []
    per_family: dict[str, dict[str, Any]] = {}
    scenarios_out: list[dict[str, Any]] = []
    canary = truth["canary"]
    try:
        for spec in truth["scenarios"]:
            progs = [p["program"] for p in spec["programs"]]
            ledgers = [(load_ledger(root / p / "ledger" / "evidence-ledger.json"), root / p) for p in progs]
            before = [
                hashlib.sha256((root / p / "ledger" / "evidence-ledger.json").read_bytes()).hexdigest() for p in progs
            ]
            gold = _pairs(spec["duplicate_pairs"])
            row: dict[str, Any] = {"scenario": spec["scenario"], "family": spec["family"]}
            for idx, (ledger, pdir) in enumerate(ledgers):
                t0 = time.perf_counter()
                report = correlate_ledger(
                    ledger,
                    program_dir=pdir,
                    key=FIXED_KEY,
                    now=truth["scenarios"] and "2026-10-26T12:00:00Z",
                    extra_ledgers=[x for j, x in enumerate(ledgers) if j != idx],
                )
                latencies.append((time.perf_counter() - t0) * 1000)
                ids = sorted(str(c["candidate_id"]) for c in ledger["candidates"])
                all_pairs = {(a, b) for i, a in enumerate(ids) for b in ids[i + 1 :]}
                pred = {
                    (min(p["candidate_a"], p["candidate_b"]), max(p["candidate_a"], p["candidate_b"]))
                    for p in report["pairs"]
                    if p["similarity_band"] == "strong"
                }
                base = exact_key_duplicates(ledger)
                base_surface = exact_key_duplicates(ledger, use_dedup_key=False)
                # Cross-program "pairs": the ledger rule never sees them; semantic must not either.
                for name, got in (("sem", pred), ("base", base), ("base_surface", base_surface)):
                    tp, fp, fn = len(got & gold), len(got - gold), len(gold & all_pairs - got)
                    totals[name][0] += tp
                    totals[name][1] += fp
                    totals[name][2] += fn
                    fam = per_family.setdefault(
                        spec["family"], {"sem": [0, 0, 0], "base": [0, 0, 0], "base_surface": [0, 0, 0], "neg": 0}
                    )
                    fam[name][0] += tp
                    fam[name][1] += fp
                    fam[name][2] += fn
                    row[f"{name}_pred"] = sorted(map(list, got))
                negs = len(all_pairs - gold)
                negatives += negs
                per_family[spec["family"]]["neg"] += negs
                if spec["adversarial"]:
                    adversarial_false_merges += len(pred - gold)
                    for g in report["groups"]:
                        if any((a, b) not in gold for i, a in enumerate(g["members"]) for b in g["members"][i + 1 :]):
                            adversarial_false_merges += 1
                rows = {str(e["evidence_id"]): e for e in ledger["evidence"]}
                bad = {r for c in ledger["candidates"] for r in c["evidence_refs"] if r not in rows}
                for eid, ev in rows.items():
                    path = pdir / ev["path"]
                    if not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != ev["sha256"]:
                        bad.add(eid)
                    if ev.get("surface_fingerprint") != "fp-v1":
                        bad.add(eid)
                for p in report["pairs"]:
                    invalid_refs_accepted += len(set(p["supporting_evidence_refs"]) & bad)
                    if p["merge_performed"] or p["finding_confirmed"]:
                        auto_actions += 1
                blob = json.dumps(report)
                if canary in blob or "/api/" in blob or "/v2/" in blob or "session=" in blob:
                    leaks += 1
                for cid in ids:
                    true_n = {b if a == cid else a for a, b in gold if cid in (a, b)}
                    if not true_n:
                        continue
                    p1_total += 1
                    top = report["neighbours"].get(cid) or []
                    if top and top[0]["candidate"] in true_n:
                        p1_hits += 1
                exp = {tuple(x) for x in spec["expected_reuse"]}
                reuse_expected += len(exp)
                got_reuse = {(r["target_candidate"], r["reuse_kind"]) for r in report["reuse_recommendations"]}
                reuse_total += len(got_reuse)
                reuse_valid += len(got_reuse & exp)
                reuse_expected_found += len(exp & got_reuse)
                row.setdefault("bands", {}).update(
                    {f"{p['candidate_a']}|{p['candidate_b']}": p["similarity_band"] for p in report["pairs"]}
                )
                row["cross_program_pairs_skipped"] = (
                    row.get("cross_program_pairs_skipped", 0) + report["cross_program_pairs_skipped"]
                )
            after = [
                hashlib.sha256((root / p / "ledger" / "evidence-ledger.json").read_bytes()).hexdigest() for p in progs
            ]
            ledger_changed += sum(1 for x, y in zip(before, after) if x != y)
            row["gold"] = sorted(map(list, gold))
            scenarios_out.append(row)
        _cur, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
        socket.socket.connect = real_connect  # type: ignore[method-assign]
    lat = sorted(latencies)
    return {
        "split": split,
        "synthetic": True,
        "scenario_count": len(truth["scenarios"]),
        "manifest_verified": True,
        "baseline_exact_key": _prf(totals["base"], negatives),
        "baseline_surface_category": _prf(totals["base_surface"], negatives),
        "semantic": _prf(totals["sem"], negatives),
        "negative_pairs": negatives,
        "adversarial_false_merges": adversarial_false_merges,
        "neighbour_precision_at_1": round(p1_hits / p1_total, 4) if p1_total else 1.0,
        "redundant_candidates_identified": totals["sem"][0],
        "reuse": {
            "recommendations": reuse_total,
            "valid": reuse_valid,
            "precision": round(reuse_valid / reuse_total, 4) if reuse_total else 1.0,
            "expected": reuse_expected,
            "recall": round(reuse_expected_found / reuse_expected, 4) if reuse_expected else 1.0,
        },
        "invalid_refs_accepted": invalid_refs_accepted,
        "secret_leaks": leaks,
        "network_attempts": attempts["n"],
        "ledger_files_modified": ledger_changed,
        "auto_merges_or_confirmations": auto_actions,
        "latency_ms": {"median": round(lat[len(lat) // 2], 3), "max": round(lat[-1], 3)},
        "peak_tracemalloc_bytes": peak,
        "per_family": {
            k: {
                "semantic": _prf(v["sem"], v["neg"]),
                "baseline": _prf(v["base"], v["neg"]),
                "baseline_surface_category": _prf(v["base_surface"], v["neg"]),
            }
            for k, v in sorted(per_family.items())
        },
        "scenarios": scenarios_out,
    }
