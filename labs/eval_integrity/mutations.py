"""Seeded, reversible mutations applied ONLY to temporary copies (or in-memory reports).

Each operator must make a validator fail. ``run_suite`` returns detection metrics; it never
touches the frozen corpora (a snapshot is taken before and after to prove it).
"""

from __future__ import annotations

import copy
import hashlib
import json
import random
import shutil
import tempfile
import time
import tracemalloc
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any
from unittest import mock

from bugbounty_toolkit.analysis import evidence_ledger as ledger_mod
from bugbounty_toolkit.analysis import object_relationships as orel
from labs.eval_integrity import pipeline
from labs.eval_integrity.build_fixture import CANARIES
from labs.eval_integrity.corpus_integrity import (
    MANIFEST,
    CorpusSpec,
    Issue,
    audit,
    check_independence,
    sha256_bytes,
    snapshot,
)
from labs.eval_integrity.registry import INDEPENDENT_PAIRS, PINS, specs

HERE = Path(__file__).resolve().parent
E2E = HERE / "frozen_e2e"
EXPECTED = HERE / "expected_contract.json"


@dataclass(frozen=True)
class Outcome:
    mutation: str
    family: str
    detected: bool
    codes: tuple[str, ...]
    legacy_detected: bool | None = None


# ----------------------------------------------------------------- helpers


def _rewrite_manifest(root: Path) -> None:
    """Coordinated tampering: recompute the manifest so only pins/regeneration can notice."""
    names = sorted(p.name for p in root.iterdir() if p.is_file() and p.name != MANIFEST)
    text = "".join(f"{sha256_bytes((root / n).read_bytes())}  {n}\n" for n in names)
    (root / MANIFEST).write_text(text, encoding="utf-8")


def _edit_json(path: Path, fn: Callable[[Any], None]) -> None:
    data = json.loads(path.read_text(encoding="utf-8"))
    fn(data)
    path.write_text(json.dumps(data, indent=1, sort_keys=True) + "\n", encoding="utf-8")


def legacy_checks(root: Path, builder: Callable[[Path], None]) -> bool:
    """Exact logic of the pre-fix tests (manifest-vs-bytes + regenerate-in-place). True = detected."""
    try:
        for line in (root / MANIFEST).read_text(encoding="utf-8").strip().splitlines():
            digest, name = line.split("  ")
            if hashlib.sha256((root / name).read_bytes()).hexdigest() != digest:
                return True
        builder(root)  # the old test regenerated INTO the corpus, then compared to its own output
        for line in (root / MANIFEST).read_text(encoding="utf-8").strip().splitlines():
            digest, name = line.split("  ")
            if hashlib.sha256((root / name).read_bytes()).hexdigest() != digest:
                return True
    except (OSError, ValueError):
        return True
    return False


# ----------------------------------------------------------------- corpus mutations

CorpusMutation = Callable[[Path], None]


def _flip_capture_byte(root: Path) -> None:
    data = bytearray((root / "captures.har").read_bytes())
    pos = data.index(b"127.0.0.1") + 2
    data[pos] = ord("8") if data[pos] != ord("8") else ord("9")
    (root / "captures.har").write_bytes(bytes(data))


def _relabel_gt_coordinated(root: Path) -> None:
    def fn(gt: Any) -> None:
        gt["scenarios"][0]["expected_pair_types"] = ["mutated_label"]

    _edit_json(root / "ground_truth.json", fn)
    _rewrite_manifest(root)


def _alter_manifest(root: Path) -> None:
    text = (root / MANIFEST).read_text(encoding="utf-8")
    (root / MANIFEST).write_text(("0" if text[0] != "0" else "1") + text[1:], encoding="utf-8")


def _remove_file(root: Path) -> None:
    (root / "ground_truth.json").unlink()


def _add_file(root: Path) -> None:
    (root / "extra.json").write_text("{}\n", encoding="utf-8")


def _drop_entry_coordinated(root: Path) -> None:
    def fn(har: Any) -> None:
        har["log"]["entries"].pop()

    _edit_json(root / "captures.har", fn)
    _rewrite_manifest(root)


def _add_scenario_coordinated(root: Path) -> None:
    def fn(gt: Any) -> None:
        extra = copy.deepcopy(gt["scenarios"][0])
        extra["id"] = "Z99"
        extra["entries"] = []
        gt["scenarios"].append(extra)

    _edit_json(root / "ground_truth.json", fn)
    _rewrite_manifest(root)


def _missing_ref_coordinated(root: Path) -> None:
    def fn(gt: Any) -> None:
        gt["scenarios"][0]["entries"].append(100000)

    _edit_json(root / "ground_truth.json", fn)
    _rewrite_manifest(root)


def _hash_change_coordinated(root: Path) -> None:
    """Re-serialize the capture with a different whitespace layout (same JSON, new bytes/hash)."""
    data = json.loads((root / "captures.har").read_text(encoding="utf-8"))
    (root / "captures.har").write_text(json.dumps(data, sort_keys=True) + "\n", encoding="utf-8")
    _rewrite_manifest(root)


CORPUS_MUTATIONS: dict[str, CorpusMutation] = {
    "capture_byte_flip": _flip_capture_byte,
    "ground_truth_label_changed_with_manifest": _relabel_gt_coordinated,
    "manifest_line_altered": _alter_manifest,
    "file_removed": _remove_file,
    "file_added": _add_file,
    "entry_deleted_with_manifest": _drop_entry_coordinated,
    "scenario_added_with_manifest": _add_scenario_coordinated,
    "missing_entry_reference_with_manifest": _missing_ref_coordinated,
    "hash_changed_same_semantics": _hash_change_coordinated,
}


def _drifting_builder(builder: Callable[[Path], None]) -> Callable[[Path], None]:
    def wrapped(out: Path) -> None:
        builder(out)

        def fn(gt: Any) -> None:
            gt["scenarios"][-1]["description"] += " (generator drift)"

        _edit_json(out / "ground_truth.json", fn)
        _rewrite_manifest(out)

    return wrapped


@contextmanager
def _temp_copy(spec: CorpusSpec) -> Iterator[CorpusSpec]:
    tmp = Path(tempfile.mkdtemp(prefix="bbtk-mut-"))
    try:
        dst = tmp / spec.name
        shutil.copytree(spec.root, dst, ignore=shutil.ignore_patterns("__pycache__"))
        yield replace(spec, root=dst)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def corpus_outcomes(all_specs: list[CorpusSpec]) -> list[Outcome]:
    out: list[Outcome] = []
    for spec in all_specs:
        for name, mutate in CORPUS_MUTATIONS.items():
            with _temp_copy(spec) as copy_spec:
                mutate(copy_spec.root)
                issues = audit([copy_spec], pins={spec.name: PINS[spec.name]})
            with _temp_copy(spec) as legacy_spec:
                mutate(legacy_spec.root)
                legacy = legacy_checks(legacy_spec.root, spec.builder)
            out.append(_outcome(f"{spec.name}:{name}", "corpus", issues, legacy))
        # Generator drift: corpus untouched, builder silently changed.
        drift = replace(spec, builder=_drifting_builder(spec.builder))
        issues = audit([drift], pins={spec.name: PINS[spec.name]})
        with _temp_copy(spec) as legacy_spec:
            legacy = legacy_checks(legacy_spec.root, drift.builder)
        out.append(_outcome(f"{spec.name}:generator_drift", "corpus", issues, legacy))
    # Improper sharing between supposedly independent sets.
    by_name = {s.name: s for s in all_specs}
    for left, right in INDEPENDENT_PAIRS:
        with _temp_copy(by_name[left]) as a, _temp_copy(by_name[right]) as b:
            src_gt = json.loads((a.root / "ground_truth.json").read_text(encoding="utf-8"))
            src_har = json.loads((a.root / "captures.har").read_text(encoding="utf-8"))

            def fn_gt(gt: Any, leaked: Any = src_gt["scenarios"][0], origin: Any = src_gt["origin"]) -> None:
                gt["scenarios"].append(leaked)
                gt["origin"] = origin

            def fn_har(har: Any, leaked: Any = src_har["log"]["entries"][0]) -> None:
                har["log"]["entries"].append(leaked)

            _edit_json(b.root / "ground_truth.json", fn_gt)
            _edit_json(b.root / "captures.har", fn_har)
            _rewrite_manifest(b.root)
            issues = check_independence(a.root, b.root, left, right)
        # The pre-fix suite only compared adv-ranking-1.0's origin against adv-1.0/adv-1.1.
        legacy = left == "adv-ranking-1.0" and right in {"adv-1.0", "adv-1.1"}
        out.append(_outcome(f"{left}~{right}:scenario_shared", "independence", issues, legacy))
    return out


def _outcome(name: str, family: str, issues: list[Issue], legacy: bool | None) -> Outcome:
    return Outcome(name, family, bool(issues), tuple(sorted({i.code for i in issues})), legacy)


# ----------------------------------------------------------------- pipeline mutations


def _e2e_copy_mutation(fn: Callable[[Any, Any], None]) -> Callable[[], list[Issue]]:
    def run() -> list[Issue]:
        tmp = Path(tempfile.mkdtemp(prefix="bbtk-e2e-mut-"))
        try:
            shutil.copytree(E2E, tmp / "c")
            har = json.loads((tmp / "c" / "captures.har").read_text(encoding="utf-8"))
            gt = json.loads((tmp / "c" / "ground_truth.json").read_text(encoding="utf-8"))
            fn(har, gt)
            (tmp / "c" / "captures.har").write_text(json.dumps(har, indent=1, sort_keys=True) + "\n", encoding="utf-8")
            (tmp / "c" / "ground_truth.json").write_text(
                json.dumps(gt, indent=1, sort_keys=True) + "\n", encoding="utf-8"
            )
            report = pipeline.run_pipeline(tmp / "c", tmp / "w")
            return pipeline.check_contract(report, tmp / "c", _expected())
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    return run


def _report_mutation(fn: Callable[[dict[str, Any]], None]) -> Callable[[], list[Issue]]:
    def run() -> list[Issue]:
        tmp = Path(tempfile.mkdtemp(prefix="bbtk-e2e-mut-"))
        try:
            report = pipeline.run_pipeline(E2E, tmp)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
        fn(report)
        return pipeline.check_contract(report, E2E, _expected())

    return run


def _patched_run(target: str, replacement: Callable[..., Any]) -> Callable[[], list[Issue]]:
    def run() -> list[Issue]:
        tmp = Path(tempfile.mkdtemp(prefix="bbtk-e2e-mut-"))
        try:
            with mock.patch(target, replacement):
                report = pipeline.run_pipeline(E2E, tmp)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
        return pipeline.check_contract(report, E2E, _expected())

    return run


def _expected() -> dict[str, Any]:
    data: dict[str, Any] = json.loads(EXPECTED.read_text(encoding="utf-8"))
    return data


def _reorder(har: Any, _gt: Any) -> None:
    har["log"]["entries"].reverse()


def _duplicate(har: Any, _gt: Any) -> None:
    har["log"]["entries"].append(copy.deepcopy(har["log"]["entries"][0]))


def _incomplete(har: Any, _gt: Any) -> None:
    del har["log"]["entries"][1]["request"]["url"]


def _gt_manipulated(_har: Any, gt: Any) -> None:
    gt["scenarios"][0]["entries"] = [0]
    gt["scenarios"][2]["entries"] = [1, 3, 4]


def _swap_responses(har: Any, _gt: Any) -> None:
    e = har["log"]["entries"]
    e[0]["response"], e[3]["response"] = e[3]["response"], e[0]["response"]


def _missing_observation(report: dict[str, Any]) -> None:
    report["proposals"][0]["owner"]["observation_ref"] = "observation-missing"


def _cross_pair(report: dict[str, Any]) -> None:
    a, b = report["proposals"][0], report["proposals"][1]
    a["actor"], b["actor"] = b["actor"], a["actor"]
    a["actor_entry_sha256"], b["actor_entry_sha256"] = b["actor_entry_sha256"], a["actor_entry_sha256"]


def _no_evidence(report: dict[str, Any]) -> None:
    report["ledger"]["candidates"][0]["evidence_refs"] = []


def _auto_confirm(report: dict[str, Any]) -> None:
    report["ledger"]["candidates"][0]["state"] = "confirmed"


def _broken_report_ref(report: dict[str, Any]) -> None:
    report["ledger"]["candidates"][0]["evidence_refs"] = ["ev-does-not-exist"]


def _response_mismatch(report: dict[str, Any]) -> None:
    report["proposals"][0]["owner_entry_sha256"] = "0" * 64


def _network(report: dict[str, Any]) -> None:
    report["network_connect_attempts"] = 1


_real_json_fields = orel._json_fields
_real_candidates = orel.object_candidates


def _parser_drops_fields(body: str, headers: dict[str, str] | None) -> dict[str, Any]:
    fields = _real_json_fields(body, headers)
    return {k: v for k, v in fields.items() if not k.endswith("_id")}


def _score_bumped(*args: Any, **kwargs: Any) -> dict[str, Any]:
    result: dict[str, Any] = _real_candidates(*args, **kwargs)
    if result["candidates"]:
        result["candidates"][-1]["score"] += 5
    return result


def _ledger_engine_auto_confirm() -> list[Issue]:
    """Seed an auto-confirmation directly in a real ledger; the ledger validator must refuse it."""
    ledger = ledger_mod.new_ledger("p")
    ledger_mod.upsert_surface(ledger, {"surface_id": "s1", "kind": "endpoint", "ref": "/x", "status": "investigated"})
    ledger["evidence"].append({"evidence_id": "e1", "path": "evidence/a.json", "sha256": "0" * 64, "provenance": {}})
    ledger_mod.add_candidate(ledger, "c1", "s1", "idor", "alice", ["e1"])
    ledger["candidates"][0]["state"] = "confirmed"
    ledger["candidates"][0]["review"] = {"reviewer": "bbtk", "method": "heuristic", "basis": "heuristic"}
    result = ledger_mod.validate_ledger(ledger)
    return [Issue(i["code"], "ledger", i["ref"]) for i in result["issues"] if i["severity"] == "error"]


def _nondeterminism() -> list[Issue]:
    rng = random.Random()

    def noisy(corpus: Path, work: Path) -> dict[str, Any]:
        report = pipeline.run_pipeline(corpus, work)
        report["ranking"][0]["score"] += rng.randint(1, 10**9)
        return report

    _, same = pipeline.run_twice(E2E, noisy)
    return [] if same else [Issue("nondeterministic", "e2e", "canonical_digest")]


PIPELINE_MUTATIONS: dict[str, Callable[[], list[Issue]]] = {
    "captures_reordered": _e2e_copy_mutation(_reorder),
    "duplicate_capture": _e2e_copy_mutation(_duplicate),
    "incomplete_capture": _e2e_copy_mutation(_incomplete),
    "ground_truth_manipulated": _e2e_copy_mutation(_gt_manipulated),
    "responses_swapped_between_scenarios": _e2e_copy_mutation(_swap_responses),
    "missing_observation_reference": _report_mutation(_missing_observation),
    "cross_scenario_pairing": _report_mutation(_cross_pair),
    "candidate_without_evidence": _report_mutation(_no_evidence),
    "auto_confirmation_in_report": _report_mutation(_auto_confirm),
    "report_broken_reference": _report_mutation(_broken_report_ref),
    "request_response_digest_mismatch": _report_mutation(_response_mismatch),
    "network_attempt_recorded": _report_mutation(_network),
    "parser_result_changed": _patched_run(
        "bugbounty_toolkit.analysis.object_relationships._json_fields", _parser_drops_fields
    ),
    "ranking_score_modified": _patched_run("labs.eval_integrity.pipeline.object_candidates", _score_bumped),
    "ledger_auto_confirmation": _ledger_engine_auto_confirm,
    "nondeterministic_run": _nondeterminism,
}


def pipeline_outcomes() -> list[Outcome]:
    return [_outcome(name, "pipeline", fn(), None) for name, fn in PIPELINE_MUTATIONS.items()]


# ----------------------------------------------------------------- suite


def run_suite() -> dict[str, Any]:
    labs_root = HERE.parent
    before = snapshot(labs_root)
    tracemalloc.start()
    started = time.perf_counter()
    all_specs = specs()
    baseline_issues = audit(all_specs, pins=PINS, independent_pairs=INDEPENDENT_PAIRS)
    corpus = corpus_outcomes(all_specs)
    pipe = pipeline_outcomes()
    report, deterministic = pipeline.run_twice(E2E)
    clean = pipeline.check_contract(report, E2E, _expected())
    elapsed = time.perf_counter() - started
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    after = snapshot(labs_root)
    rows = corpus + pipe
    corpus_rows = [r for r in rows if r.family in {"corpus", "independence"}]
    legacy_rows = [r for r in corpus_rows if r.legacy_detected is not None]
    canary_hits = [c for c in CANARIES if c in json.dumps(report)]
    return {
        "type": "bbtk-eval-integrity-metrics",
        "clean_baseline": {
            "corpus_issues": [i.as_dict() for i in baseline_issues],
            "e2e_contract_issues": [i.as_dict() for i in clean],
            "deterministic": deterministic,
            "stages": report["stages"],
            "capture_import": {k: report["capture_import"][k] for k in ("entries_total", "accepted", "rejected")},
            "eligible_rejections": sum(1 for e in report["eligibility"] if e["status"] == "insufficient_evidence"),
            "reviewable_proposals": len(report["proposals"]),
            "false_confirmations": report["vulnerabilities_confirmed"]
            + sum(1 for c in report["ledger"]["candidates"] if c["state"] == "confirmed"),
            "network_connect_attempts": report["network_connect_attempts"],
            "secret_canaries_leaked": len(canary_hits),
        },
        "seeded_defects": {"detected": sum(r.detected for r in rows), "total": len(rows)},
        "corpus_mutations": {"detected": sum(r.detected for r in corpus_rows), "total": len(corpus_rows)},
        "pipeline_mutations": {"detected": sum(r.detected for r in pipe), "total": len(pipe)},
        "legacy_corpus_checks": {
            "detected": sum(bool(r.legacy_detected) for r in legacy_rows),
            "total": len(legacy_rows),
            "note": "Pre-fix test logic (manifest-vs-bytes + regenerate-in-place) on the same temp mutations.",
        },
        "undetected": [r.mutation for r in rows if not r.detected],
        "rows": [
            {
                "mutation": r.mutation,
                "family": r.family,
                "detected": r.detected,
                "codes": list(r.codes),
                "legacy_detected": r.legacy_detected,
            }
            for r in rows
        ],
        "frozen_untouched": before == after,
        "elapsed_seconds": round(elapsed, 2),
        "peak_traced_memory_mib": round(peak / 2**20, 1),
    }


def main() -> None:  # pragma: no cover - CLI wrapper
    import argparse

    ap = argparse.ArgumentParser(description="Seeded-mutation integrity suite (temp copies only).")
    ap.add_argument("--json", type=Path)
    args = ap.parse_args()
    result = run_suite()
    text = json.dumps(result, indent=1, sort_keys=True)
    if args.json:
        args.json.write_text(text + "\n", encoding="utf-8")
    print(text)


if __name__ == "__main__":  # pragma: no cover
    main()
