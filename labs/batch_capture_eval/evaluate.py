"""Offline evaluation of bounded batch capture ingestion vs. the monolithic importer.

Run: ``python -m labs.batch_capture_eval.evaluate [--freeze] [--split dev|final|all] [--bench]``.
The corpus manifest (``manifest.json``) is frozen with SHA-256 digests and verified before any
metric is computed. All metrics are on synthetic fixtures only.
"""

from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import random
import socket
import sys
import tempfile
import time
import tracemalloc
from typing import Any

from bugbounty_toolkit.analysis import batch_capture_pipeline as bcp
from bugbounty_toolkit.analysis import evidence_engine
from labs.batch_capture_eval.fixtures import CANARY, SPLITS, Scenario, entry, har, oversize_file, scenarios

MANIFEST = Path(__file__).with_name("manifest.json")
LIMITS = bcp.CampaignLimits(
    max_files_per_batch=4,
    max_bytes_per_batch=16 * 1024 * 1024,
    max_records_per_batch=5_000,
    max_total_files=500,
    max_total_bytes=512 * 1024 * 1024,
    max_total_records=50_000,
)


def corpus_manifest() -> dict[str, Any]:
    out: dict[str, Any] = {"schema": "bbtk.batch-capture-eval-corpus/1", "splits": {}}
    for split in SPLITS:
        out["splits"][split] = {
            sc.name: {rel: hashlib.sha256(data).hexdigest() for rel, data in sorted(sc.files.items())}
            for sc in scenarios(split)
        }
    out["corpus_sha256"] = hashlib.sha256(json.dumps(out["splits"], sort_keys=True).encode()).hexdigest()
    return out


def verify_frozen() -> str:
    frozen = json.loads(MANIFEST.read_text())
    current = corpus_manifest()
    if frozen != current:
        raise SystemExit("Frozen corpus manifest mismatch: fixtures changed after freezing.")
    return str(current["corpus_sha256"])


def _write(root: Path, files: dict[str, bytes]) -> None:
    for rel, data in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        path.write_bytes(data)
        os.chmod(path, 0o600)


def _bundles(state: Path) -> list[dict[str, Any]]:
    folder = state / "batches"
    return [json.loads(p.read_text()) for p in sorted(folder.glob("*.json"))] if folder.exists() else []


def _rel(root: Path, source_path: str) -> str:
    return str(Path(source_path).relative_to(root.resolve()))


def _locator_metrics(sc: Scenario, root: Path, bundles: list[dict[str, Any]]) -> dict[str, int]:
    seen: Counter[tuple[str, str]] = Counter()
    mixed = 0
    for bundle in bundles:
        labels_by_session: dict[str, set[str]] = {}
        for record in bundle["records"]:
            labels = set()
            for prov in record["provenance"]:
                rel = _rel(root, prov["source_path"])
                seen[(rel, prov["locator"])] += 1
                label = sc.valid.get(rel, {}).get(prov["locator"])
                if label:
                    labels.add(label)
            mixed += len(labels) > 1
            fp = record.get("request_session_fingerprint")
            if fp:
                labels_by_session.setdefault(fp, set()).update(labels)
        mixed += sum(len(v) > 1 for v in labels_by_session.values())
    expected = {(rel, loc) for rel, locs in sc.valid.items() for loc in locs}
    return {
        "valid_expected": len(expected),
        "valid_preserved": len(expected & set(seen)),
        "lost_records": len(expected - set(seen)),
        "locators_duplicated": sum(1 for k, v in seen.items() if k in expected and v > 1),
        "mixed_sessions": mixed,
    }


def projection(root: Path, bundles: list[dict[str, Any]]) -> list[str]:
    """Salt-independent view of records (fingerprints are salted per import and excluded)."""
    rows = []
    for bundle in bundles:
        for r in bundle["records"]:
            prov = sorted((_rel(root, p["source_path"]), p["locator"]) for p in r["provenance"])
            rows.append(json.dumps([r["host"], r["endpoint"], r["method"], r["status_code"], r["parameters"], prov]))
    return sorted(rows)


def _monolith(sc: Scenario, root: Path) -> dict[str, Any]:
    paths = [root / rel for rel in sorted(sc.files)]
    tracemalloc.start()
    started = time.perf_counter()
    try:
        bundle = evidence_engine.import_evidence(paths, "auto", "partial")
        error = None
    except (ValueError, RecursionError) as exc:
        bundle, error = None, type(exc).__name__
    elapsed = time.perf_counter() - started
    peak = tracemalloc.get_traced_memory()[1]
    tracemalloc.stop()
    out: dict[str, Any] = {
        "ok": bundle is not None,
        "error": error,
        "seconds": round(elapsed, 4),
        "peak_kib": peak // 1024,
    }
    out.update(_locator_metrics(sc, root, [bundle] if bundle else []))
    out["projection"] = projection(root, [bundle]) if bundle else None
    return out


def _batched(sc: Scenario, root: Path, state: Path, limits: bcp.CampaignLimits = LIMITS) -> dict[str, Any]:
    names = sorted(sc.files)
    if sc.expect.get("shuffle"):
        random.Random(5).shuffle(names)
    tracemalloc.start()
    started = time.perf_counter()
    plan = bcp.plan_campaign(root, names, program="lab-batch", limits=limits)
    summary = bcp.run_campaign(plan, state)
    elapsed = time.perf_counter() - started
    peak = tracemalloc.get_traced_memory()[1]
    tracemalloc.stop()
    bundles = _bundles(state)
    out: dict[str, Any] = {
        "status": summary["status"],
        "seconds": round(elapsed, 4),
        "peak_kib": peak // 1024,
        "batches": summary["batches_total"],
        "files_by_state": summary["files_by_state"],
        "har_rejections_by_reason": summary["har_rejections_by_reason"],
        "cross_batch_duplicate_har_entries": summary["cross_batch_duplicate_har_entries"],
        "cross_file_duplicate_har_entries": summary["cross_file_duplicate_har_entries"],
        "duplicate_files": summary["files_by_state"]["duplicate_file"],
        "duplicate_entries": summary["har_entries"]["duplicate_entries"],
        "burp_items_not_emitted": summary["burp_items_not_emitted"],
        "records_unique": sum(len(b["records"]) for b in bundles),
        "warnings": summary["warnings"],
    }
    out.update(_locator_metrics(sc, root, bundles))
    out["projection"] = projection(root, bundles)
    rejected_ok = 0
    expected_rejects = sum(len(v) for v in sc.rejected.values())
    for bundle in bundles:
        for row in bundle["inputs"]:
            rel = _rel(root, row["source_path"])
            got = {r["index"]: r["reason"] for r in row.get("capture_import", {}).get("rejected_entries", [])}
            rejected_ok += sum(1 for i, reason in sc.rejected.get(rel, {}).items() if got.get(i) == reason)
    out["rejects_expected"] = expected_rejects + len(sc.rejected_files)
    out["rejects_reported"] = rejected_ok + sum(
        1 for e in summary["file_errors"] if any(e["ref"] == _ref(r) for r in sc.rejected_files)
    )
    out["leaks"] = _leaks(state, summary)
    checks = {
        "duplicate_entries_min": lambda v: out["duplicate_entries"] >= v,
        "cross_file_duplicate_har_entries": lambda v: out["cross_file_duplicate_har_entries"] == v,
        "duplicate_files": lambda v: out["duplicate_files"] == v,
        "burp_items_not_emitted": lambda v: out["burp_items_not_emitted"] == v,
    }
    out["expectations_failed"] = sorted(k for k, v in sc.expect.items() if k in checks and not checks[k](v))
    out["partial_marked_complete"] = int(summary["complete"] and summary["status"] != "complete")
    return out


def _ref(relpath: str) -> str:
    from bugbounty_toolkit.analysis.har_provenance import path_ref

    return path_ref(relpath)


def _leaks(state: Path, summary: dict[str, Any]) -> int:
    texts = [json.dumps(summary)] + [p.read_text(errors="replace") for p in state.rglob("*") if p.is_file()]
    return sum(CANARY in t for t in texts)


def _run_split(split: str, tmp: Path) -> dict[str, Any]:
    results: dict[str, Any] = {}
    for sc in scenarios(split):
        root = tmp / split / sc.name / "in"
        _write(root, sc.files)
        mono = _monolith(sc, root)
        batch = _batched(sc, root, tmp / split / sc.name / "state")
        mp, bp = mono.pop("projection"), batch.pop("projection")
        batch["equivalent_to_monolith"] = None if mp is None else mp == bp
        results[sc.name] = {"monolith": mono, "batched": batch}
    return results


def _resilience(tmp: Path) -> dict[str, Any]:
    """Interruption, resume, file change, altered output, limits. Expectations are fixed here."""
    out: dict[str, Any] = {}
    root = tmp / "res" / "in"
    sc = Scenario("resume", "final")
    for f in range(8):
        sc.add_har(f"p{f}.har", [entry(f"/res/{f}/{i}", session="alice", n=i) for i in range(5)], ["alice"] * 5)
    _write(root, sc.files)
    small = bcp.CampaignLimits(2, 16 * 1024 * 1024, 5_000, 100, 64 * 1024 * 1024, 50_000)
    plan = bcp.plan_campaign(root, sorted(sc.files), program="lab-batch", limits=small)
    state = tmp / "res" / "state"
    first = bcp.run_campaign(plan, state, max_batches=2)
    second = bcp.run_campaign(plan, state)
    third = bcp.run_campaign(plan, state)
    out["interrupted_status"] = first["status"]
    out["resumed_status"] = second["status"]
    out["resume_reused"] = second["resume"]["reused"]
    out["resume_executed"] = second["resume"]["executed"]
    out["rerun_executed"] = third["resume"]["executed"]
    out["resume_reuse_pct"] = round(100 * second["resume"]["reused"] / plan.batches.__len__(), 1)
    # Altered output -> detected and only that batch re-run.
    victim = sorted((state / "batches").glob("*.json"))[0]
    victim.write_bytes(victim.read_bytes().replace(b'"records"', b'"recordz"', 1))
    altered = bcp.run_campaign(plan, state)
    out["altered_output_reprocessed"] = altered["resume"]["reprocessed_output_altered"]
    out["altered_executed"] = altered["resume"]["executed"]
    # Changed file -> refused by default; with consent only its batch re-runs.
    (root / "p5.har").write_bytes(har([entry("/res/changed", session="alice", n=1)]))
    try:
        bcp.run_campaign(bcp.plan_campaign(root, sorted(sc.files), program="lab-batch", limits=small), state)
        out["changed_file_refused"] = False
    except bcp.CampaignError as exc:
        out["changed_file_refused"] = exc.reason == "source_changed"
    changed = bcp.run_campaign(
        bcp.plan_campaign(root, sorted(sc.files), program="lab-batch", limits=small), state, allow_source_changes=True
    )
    out["changed_executed"] = changed["resume"]["executed"]
    out["changed_status"] = changed["status"]
    # Different program / limits -> refused.
    try:
        bcp.run_campaign(bcp.plan_campaign(root, sorted(sc.files), program="other", limits=small), state)
        out["program_mismatch_refused"] = False
    except bcp.CampaignError as exc:
        out["program_mismatch_refused"] = exc.reason == "campaign_mismatch"
    # Campaign total exhausted.
    tight = bcp.CampaignLimits(2, 16 * 1024 * 1024, 15, 100, 64 * 1024 * 1024, 15)
    total = bcp.run_campaign(
        bcp.plan_campaign(root, sorted(sc.files), program="lab-batch", limits=tight), tmp / "res" / "s2"
    )
    out["total_limit_status"] = total["status"]
    out["total_limit_records"] = total["records_parsed"]
    # Per-batch record limit.
    per = bcp.CampaignLimits(2, 16 * 1024 * 1024, 6, 100, 64 * 1024 * 1024, 50_000)
    pb = bcp.run_campaign(
        bcp.plan_campaign(root, sorted(sc.files), program="lab-batch", limits=per), tmp / "res" / "s3"
    )
    out["batch_limit_status"] = pb["status"]
    out["batch_limit_failed"] = pb["batches_by_state"]["failed"]
    # Oversize single file keeps the existing 32 MiB file limit.
    big_root = tmp / "res" / "big"
    _write(big_root, {"huge.har": oversize_file(), "ok.har": sc.files["p0.har"]})
    big = bcp.run_campaign(
        bcp.plan_campaign(big_root, ["huge.har", "ok.har"], program="lab-batch", limits=small), tmp / "res" / "s4"
    )
    out["oversize_status"] = big["status"]
    out["oversize_omitted"] = big["files_by_state"]["omitted_file_limit"]
    # Symlinked / external input refused.
    (root / "link.har").symlink_to(root / "p0.har")
    for name, rel in (("symlink_refused", "link.har"), ("external_refused", "../outside.har")):
        try:
            bcp.plan_campaign(root, [rel], program="lab-batch", limits=small)
            out[name] = False
        except (bcp.CampaignError, ValueError):
            out[name] = True
    return out


def _bench(tmp: Path) -> list[dict[str, Any]]:
    rows = []
    for files in (10, 50, 100, 200):
        sc = Scenario(f"bench-{files}", "bench")
        for f in range(files):
            sc.add_har(f"b{f:04d}.har", [entry(f"/b/{f}/{i}", session="alice", n=i) for i in range(30)], ["alice"] * 30)
        root = tmp / "bench" / str(files) / "in"
        _write(root, sc.files)
        mono = _monolith(sc, root)
        mono.pop("projection")
        lim = bcp.CampaignLimits(10, 16 * 1024 * 1024, 5_000, 500, 512 * 1024 * 1024, 50_000)
        batch = _batched(sc, root, tmp / "bench" / str(files) / "state", lim)
        batch.pop("projection")
        rows.append(
            {
                "files": files,
                "entries": files * 30,
                "monolith_ok": mono["ok"],
                "monolith_error": mono["error"],
                "monolith_s": mono["seconds"],
                "monolith_peak_kib": mono["peak_kib"],
                "monolith_preserved": mono["valid_preserved"],
                "batched_status": batch["status"],
                "batched_s": batch["seconds"],
                "batched_peak_kib": batch["peak_kib"],
                "batched_preserved": batch["valid_preserved"],
                "batches": batch["batches"],
            }
        )
    return rows


def evaluate(split: str = "all", bench: bool = False) -> dict[str, Any]:
    corpus = verify_frozen()
    network: list[str] = []
    real = socket.socket.connect

    def guard(self: socket.socket, address: Any) -> None:
        network.append(str(address))
        raise OSError("network disabled in evaluation")

    socket.socket.connect = guard  # type: ignore[method-assign,assignment]
    try:
        with tempfile.TemporaryDirectory(prefix="bbtk-batch-eval-") as name:
            tmp = Path(name).resolve()
            os.chmod(tmp, 0o700)
            report: dict[str, Any] = {"corpus_sha256": corpus, "synthetic_only": True, "splits": {}}
            for s in SPLITS if split == "all" else (split,):
                report["splits"][s] = _run_split(s, tmp)
            report["resilience"] = _resilience(tmp)
            if bench:
                report["benchmark"] = _bench(tmp)
    finally:
        socket.socket.connect = real  # type: ignore[method-assign]
    report["network_attempts"] = len(network)
    totals: Counter[str] = Counter()
    for results in report["splits"].values():
        for row in results.values():
            b = row["batched"]
            for key in (
                "valid_expected",
                "valid_preserved",
                "lost_records",
                "mixed_sessions",
                "locators_duplicated",
                "rejects_expected",
                "rejects_reported",
                "leaks",
                "partial_marked_complete",
            ):
                totals[key] += b[key]
            totals["monolith_valid_preserved"] += row["monolith"]["valid_preserved"]
            totals["monolith_failed_imports"] += not row["monolith"]["ok"]
            totals["equivalence_checked"] += b["equivalent_to_monolith"] is not None
            totals["equivalent_to_monolith"] += bool(b["equivalent_to_monolith"])
            totals["expectations_failed"] += len(b["expectations_failed"])
    report["totals"] = dict(totals)
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--freeze", action="store_true")
    parser.add_argument("--split", default="all", choices=("all", *SPLITS))
    parser.add_argument("--bench", action="store_true")
    args = parser.parse_args(argv)
    if args.freeze:
        if MANIFEST.exists():
            raise SystemExit("Corpus already frozen; refusing to overwrite manifest.json.")
        MANIFEST.write_text(json.dumps(corpus_manifest(), indent=2, sort_keys=True) + "\n")
        return 0
    json.dump(evaluate(args.split, args.bench), sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
