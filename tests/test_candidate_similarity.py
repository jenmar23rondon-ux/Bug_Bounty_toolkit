from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path

import tempfile
import unittest
from unittest import mock

from bugbounty_toolkit.analysis import candidate_similarity as cs
from bugbounty_toolkit.analysis.evidence_gap_planner import build_plan
from bugbounty_toolkit.analysis.evidence_ledger import load_ledger
from bugbounty_toolkit.core.records import ProgramPaths
from labs.semantic_candidate_eval import metrics as lab_metrics
from labs.semantic_candidate_eval.corpus import CANARY, NOW, build_split

KEY = b"k" * 32


def _program(tmp_path: Path, split: str, scenario: str) -> Path:
    manifest = build_split(split, tmp_path)
    spec = next(s for s in manifest["scenarios"] if s["scenario"] == scenario)
    return tmp_path / spec["programs"][0]["program"]


def _bands(report: dict[str, object]) -> dict[str, str]:
    return {f"{p['candidate_a']}|{p['candidate_b']}": p["similarity_band"] for p in report["pairs"]}  # type: ignore[attr-defined,index]


def test_true_duplicate_is_strong_but_never_merged(tmp_path: Path) -> None:
    pdir = _program(tmp_path, "dev", "true_duplicate")
    report = cs.correlate_program(pdir, key=KEY, now=NOW)
    (pair,) = report["pairs"]
    assert pair["similarity_band"] == "strong"
    assert pair["duplicate_hypothesis"] == "probable_same_issue"
    assert pair["human_review_required"] is True
    assert pair["merge_performed"] is False and pair["finding_confirmed"] is False
    assert report["groups"] == [
        {"members": ["c1", "c2"], "basis": "all_pairs_strong", "human_review_required": True, "merge_performed": False}
    ]


def test_adversarial_negatives_not_strong(tmp_path: Path) -> None:
    for scenario, band in (
        ("same_path_diff_vuln", "distinct"),
        ("same_id_diff_namespace", "distinct"),
        ("different_role", "distinct"),
        ("rejected_and_new", "possible"),
        ("stale_evidence", "insufficient_evidence"),
    ):
        report = cs.correlate_program(_program(tmp_path / scenario, "dev", scenario), key=KEY, now=NOW)
        assert [p["similarity_band"] for p in report["pairs"]] == [band], scenario


def test_same_literal_id_different_namespace_explained(tmp_path: Path) -> None:
    report = cs.correlate_program(_program(tmp_path, "dev", "same_id_diff_namespace"), key=KEY, now=NOW)
    assert "same_literal_id_different_namespace" in report["pairs"][0]["conflicting_signals"]


def test_ledger_and_dedup_key_untouched(tmp_path: Path) -> None:
    pdir = _program(tmp_path, "final", "multi_candidate_group")
    path = pdir / "ledger" / "evidence-ledger.json"
    before = hashlib.sha256(path.read_bytes()).hexdigest()
    ledger = load_ledger(path)
    snapshot = copy.deepcopy(ledger)
    report = cs.correlate_ledger(ledger, program_dir=pdir, key=KEY, now=NOW)
    assert ledger == snapshot
    assert hashlib.sha256(path.read_bytes()).hexdigest() == before
    assert report["ledger_modified"] is False and report["dedup_key_modified"] is False
    assert report["groups"][0]["members"] == ["g1", "g2", "g3", "g4"]


def test_invalid_refs_never_support(tmp_path: Path) -> None:
    report = cs.correlate_program(_program(tmp_path, "final", "stale_or_invalid_evidence"), key=KEY, now=NOW)
    assert {p["similarity_band"] for p in report["pairs"]} == {"insufficient_evidence"}
    for pair in report["pairs"]:
        assert not set(pair["supporting_evidence_refs"]) & {"e-stale", "e-tamp", "e-missing"}
    missing = {m for p in report["pairs"] for m in p["missing_information"]}
    assert "invalid_evidence_ref:m-broken:e-missing" in missing
    assert "invalid_evidence_ref:m-tamp:e-tamp" in missing
    assert "stale_evidence_ref:m-stale:e-stale" in missing


def test_no_program_dir_trusts_nothing(tmp_path: Path) -> None:
    pdir = _program(tmp_path, "dev", "true_duplicate")
    ledger = load_ledger(pdir / "ledger" / "evidence-ledger.json")
    report = cs.correlate_ledger(ledger, program_dir=None, key=KEY)
    assert report["pairs"][0]["similarity_band"] == "insufficient_evidence"


def test_cross_program_skipped_by_default_and_never_compared(tmp_path: Path) -> None:
    manifest = build_split("dev", tmp_path)
    spec = next(s for s in manifest["scenarios"] if s["scenario"] == "cross_program")
    a, b = (tmp_path / p["program"] for p in spec["programs"])
    la, lb = (load_ledger(d / "ledger" / "evidence-ledger.json") for d in (a, b))
    default = cs.correlate_ledger(la, program_dir=a, key=KEY, extra_ledgers=[(lb, b)])
    assert default["pairs"] == [] and default["cross_program_pairs_skipped"] == 1
    opted = cs.correlate_ledger(la, program_dir=a, key=KEY, extra_ledgers=[(lb, b)], include_cross_program=True)
    assert [p["similarity_band"] for p in opted["pairs"]] == ["not_comparable_cross_program"]


def test_report_never_exports_literals(tmp_path: Path) -> None:
    for split in ("dev", "final"):
        root = tmp_path / split
        manifest = build_split(split, root)
        for spec in manifest["scenarios"]:
            for prog in spec["programs"]:
                blob = json.dumps(cs.correlate_program(root / prog["program"], key=KEY, now=NOW))
                assert CANARY not in blob and "/api/" not in blob and "session=" not in blob


def test_session_ambiguity_blocks_strong(tmp_path: Path) -> None:
    report = cs.correlate_program(_program(tmp_path, "final", "ambiguous_sessions"), key=KEY, now=NOW)
    pair = report["pairs"][0]
    assert pair["similarity_band"] == "possible"
    assert any(m.startswith("session_ambiguous:") for m in pair["missing_information"])


def test_shared_resource_capped(tmp_path: Path) -> None:
    report = cs.correlate_program(_program(tmp_path, "final", "legitimately_shared"), key=KEY, now=NOW)
    pair = report["pairs"][0]
    assert pair["similarity_band"] == "weak"
    assert "legitimate_access_documented" in pair["conflicting_signals"]


def test_non_clique_component_not_grouped() -> None:
    groups, review = cs._groups(["a", "b", "c"], {("a", "b"), ("b", "c")})
    assert groups == [] and review == [["a", "b", "c"]]


def test_reuse_is_recommendation_only(tmp_path: Path) -> None:
    report = cs.correlate_program(_program(tmp_path, "final", "same_request_diff_times"), key=KEY, now=NOW)
    kinds = {(r["target_candidate"], r["reuse_kind"]) for r in report["reuse_recommendations"]}
    assert ("t-tue", "reuse_ownership_attestation") in kinds
    assert all(r["copy_performed"] is False and r["ledger_modified"] is False for r in report["reuse_recommendations"])


def test_planner_context_is_read_only(tmp_path: Path) -> None:
    pdir = _program(tmp_path, "final", "true_duplicate")
    paths = ProgramPaths(root=tmp_path, program=pdir.name)
    plan = build_plan(paths, now=NOW)
    frozen = json.dumps(plan, sort_keys=True)
    ctx = cs.planner_context(plan, cs.correlate_program(pdir, key=KEY, now=NOW))
    assert json.dumps(plan, sort_keys=True) == frozen
    assert ctx["planner_modified"] is False and ctx["scores_modified"] is False
    assert ctx["candidates"]["dup-2"]["reuse"][0]["reuse_kind"] == "reuse_negative_control"


def test_too_many_candidates_not_truncated(tmp_path: Path) -> None:
    with mock.patch.object(cs, "MAX_CANDIDATES", 2):
        report = cs.correlate_program(_program(tmp_path, "dev", "group_of_three"), key=KEY)
    assert report["status"] == "too_many_candidates" and report["pairs"] == []


def test_normalize_path() -> None:
    assert cs.normalize_path("/API/Orders/123?x=1") == "/api/orders/{}"
    assert cs.normalize_path("/a/8d1f3c2a-0000-4000-8000-00000000abcd/{id}") == "/a/{}/{}"
    assert cs.normalize_path("https://h.example/x/:id/") == "/x/{}"


def test_no_ai_or_network_imports() -> None:
    src = Path(cs.__file__).read_text(encoding="utf-8")
    for banned in ("ai_providers", "ai_backend", "requests", "urllib", "httpx", "socket"):
        assert f"import {banned}" not in src and f".{banned} import" not in src


def test_lab_final_acceptance(tmp_path: Path) -> None:
    result = lab_metrics.evaluate_split("final", tmp_path)
    assert result["adversarial_false_merges"] == 0
    assert result["semantic"]["fp"] == 0
    assert result["semantic"]["f1"] > result["baseline_surface_category"]["f1"]
    assert result["semantic"]["f1"] > result["baseline_exact_key"]["f1"]
    for k in ("invalid_refs_accepted", "secret_leaks", "network_attempts", "ledger_files_modified"):
        assert result[k] == 0
    assert result["auto_merges_or_confirmations"] == 0


def test_lab_metrics_reproducible(tmp_path: Path) -> None:
    a = lab_metrics.evaluate_split("dev", tmp_path / "a")
    b = lab_metrics.evaluate_split("dev", tmp_path / "b")
    for r in (a, b):
        r.pop("latency_ms")
        r.pop("peak_tracemalloc_bytes")
    assert a == b


def test_tampered_frozen_labels_detected(tmp_path: Path) -> None:
    truth = lab_metrics.verify_frozen("final")
    truth["scenarios"][0]["duplicate_pairs"] = []
    real = lab_metrics.build_split

    def mutated(split: str, root: Path) -> dict[str, object]:
        m = real(split, root)
        m["scenarios"][0]["programs"][0]["ledger_sha256"] = "0" * 64  # type: ignore[index]
        return m

    with mock.patch.object(lab_metrics, "build_split", mutated):
        try:
            lab_metrics.evaluate_split("final", tmp_path, frozen=truth)
        except lab_metrics.FrozenCorpusError:
            pass
        else:
            raise AssertionError("mutated corpus accepted")
    with mock.patch.object(lab_metrics, "frozen_text", lambda split: "{}"):
        try:
            lab_metrics.verify_frozen("final")
        except lab_metrics.FrozenCorpusError:
            pass
        else:
            raise AssertionError("mutated generator accepted")


class CandidateSimilarityTests(unittest.TestCase):
    pass


def _wrap(fn: object) -> object:
    def method(self: unittest.TestCase) -> None:
        with tempfile.TemporaryDirectory(prefix="bbtk-sem-test-") as tmp:
            if fn.__code__.co_argcount:  # type: ignore[attr-defined]
                fn(Path(tmp))  # type: ignore[operator]
            else:
                fn()  # type: ignore[operator]

    return method


for _name in [
    "test_true_duplicate_is_strong_but_never_merged",
    "test_adversarial_negatives_not_strong",
    "test_same_literal_id_different_namespace_explained",
    "test_ledger_and_dedup_key_untouched",
    "test_invalid_refs_never_support",
    "test_no_program_dir_trusts_nothing",
    "test_cross_program_skipped_by_default_and_never_compared",
    "test_report_never_exports_literals",
    "test_session_ambiguity_blocks_strong",
    "test_shared_resource_capped",
    "test_non_clique_component_not_grouped",
    "test_reuse_is_recommendation_only",
    "test_planner_context_is_read_only",
    "test_too_many_candidates_not_truncated",
    "test_normalize_path",
    "test_no_ai_or_network_imports",
    "test_lab_final_acceptance",
    "test_lab_metrics_reproducible",
    "test_tampered_frozen_labels_detected",
]:
    setattr(CandidateSimilarityTests, _name, _wrap(globals()[_name]))
    del globals()[_name]
