"""Authored DEV and FINAL cases for the blocker dependency graph.

Labels are the spec of each family. They are not derived from a previous graph run.
FINAL is frozen by MANIFEST.sha256 before the first FINAL evaluation.
"""

from __future__ import annotations

from typing import Any

# Shared evidence shapes. Object refs are synthetic. No credentials.
_OK = "ok"
_BAD = "invalid"
_STALE = "stale"


def _ev(
    eid: str,
    integrity: str,
    objects: list[str] | None,
    *,
    depends_on: list[str] | None = None,
    namespace: str | None = None,
    bundle_id: str | None = None,
) -> dict[str, Any]:
    row: dict[str, Any] = {"evidence_id": eid, "integrity": integrity, "object_refs": objects}
    if depends_on:
        row["depends_on"] = depends_on
    if namespace:
        row["namespace"] = namespace
    if bundle_id:
        row["bundle_id"] = bundle_id
    return row


def _cand(
    cid: str,
    surface: str,
    refs: list[str],
    state: str,
    *,
    missing: list[str] | None = None,
    conflict: bool = False,
    duplicate_of: str | None = None,
) -> dict[str, Any]:
    row: dict[str, Any] = {
        "candidate_id": cid,
        "surface_id": surface,
        "evidence_refs": refs,
        "original_state": state,
    }
    if missing:
        row["missing_mandatory_controls"] = missing
    if conflict:
        row["conflict"] = True
    if duplicate_of:
        row["semantic_duplicate_of"] = duplicate_of
    return row


def _case(
    cid: str,
    family: int,
    description: str,
    candidates: list[dict[str, Any]],
    evidence: list[dict[str, Any]],
    expected: dict[str, str],
    *,
    whole_surface: list[str] | None = None,
    check_order: bool = False,
) -> dict[str, Any]:
    reviewable = sorted(k for k, v in expected.items() if v in {"reviewable", "safely_independent"})
    return {
        "id": cid,
        "family": family,
        "description": description,
        "candidates": candidates,
        "evidence": evidence,
        "check_order": check_order,
        "expected": {
            "by_candidate": expected,
            "whole_surface": whole_surface or [],
            "reviewable_ids": reviewable,
        },
    }


def final_cases() -> list[dict[str, Any]]:
    """Fifteen held-out families. One case each. Do not retune after the manifest is frozen."""
    return [
        _case(
            "FN-F01",
            1,
            "Corrupt shared evidence invalidates every candidate that cites it",
            [
                _cand("c1", "s1", ["e-shared"], "requires_validation"),
                _cand("c2", "s1", ["e-shared"], "requires_validation"),
            ],
            [_ev("e-shared", _BAD, ["obj:shared"])],
            {"c1": "blocked_invalid_evidence", "c2": "blocked_invalid_evidence"},
            whole_surface=["s1"],
        ),
        _case(
            "FN-F02",
            2,
            "Unrelated corrupt evidence must not poison an independent candidate",
            [
                _cand("c-good", "s1", ["e-good"], "requires_validation"),
                _cand("c-bad", "s2", ["e-bad"], "requires_validation"),
            ],
            [_ev("e-good", _OK, ["obj:a"]), _ev("e-bad", _BAD, ["obj:z"])],
            {"c-bad": "blocked_invalid_evidence", "c-good": "reviewable"},
        ),
        _case(
            "FN-F03",
            3,
            "Same endpoint, different objects: only the dependent candidate is blocked",
            [
                _cand("c1", "s1", ["e1"], "requires_validation"),
                _cand("c2", "s1", ["e2"], "requires_validation"),
            ],
            [_ev("e1", _OK, ["o1", "o2"]), _ev("e2", _BAD, ["o5", "o6"])],
            {"c1": "safely_independent", "c2": "blocked_invalid_evidence"},
        ),
        _case(
            "FN-F04",
            4,
            "Same raw id in different namespaces is not the same object",
            [
                _cand("c-orders", "s1", ["e-orders"], "requires_validation"),
                _cand("c-users", "s1", ["e-users"], "requires_validation"),
            ],
            [
                _ev("e-orders", _BAD, ["1"], namespace="orders"),
                _ev("e-users", _OK, ["1"], namespace="users"),
            ],
            {"c-orders": "blocked_invalid_evidence", "c-users": "safely_independent"},
        ),
        _case(
            "FN-F05",
            5,
            "Two independent complete controls stay reviewable",
            [_cand("c1", "s1", ["e-owner", "e-actor"], "requires_validation")],
            [_ev("e-owner", _OK, ["o1"]), _ev("e-actor", _OK, ["o2"])],
            {"c1": "reviewable"},
        ),
        _case(
            "FN-F06",
            6,
            "Missing mandatory control is not reviewable",
            [_cand("c1", "s1", ["e1"], "requires_validation", missing=["negative_control"])],
            [_ev("e1", _OK, ["o1", "o2"])],
            {"c1": "blocked_missing_control"},
        ),
        _case(
            "FN-F07",
            7,
            "Invalid evidence ref blocks that candidate",
            [_cand("c1", "s1", ["e-missing"], "requires_validation")],
            [],
            {"c1": "blocked_invalid_evidence"},
        ),
        _case(
            "FN-F08",
            8,
            "Stale file blocks its candidate and not a disjoint neighbour",
            [
                _cand("c1", "s1", ["e-stale"], "requires_validation"),
                _cand("c2", "s1", ["e-fresh"], "requires_validation"),
            ],
            [_ev("e-stale", _STALE, ["o1"]), _ev("e-fresh", _OK, ["o9"])],
            {"c1": "blocked_stale_evidence", "c2": "safely_independent"},
        ),
        _case(
            "FN-F09",
            9,
            "Intact shared provenance does not block either candidate",
            [
                _cand("c1", "s1", ["e1"], "requires_validation"),
                _cand("c2", "s1", ["e2"], "requires_validation"),
            ],
            [
                _ev("e1", _OK, ["o1"], bundle_id="bundle-intact"),
                _ev("e2", _OK, ["o2"], bundle_id="bundle-intact"),
            ],
            {"c1": "reviewable", "c2": "reviewable"},
        ),
        _case(
            "FN-F10",
            10,
            "Conflict between two otherwise valid observations stays inconclusive",
            [_cand("c1", "s1", ["e1", "e2"], "requires_validation", conflict=True)],
            [_ev("e1", _OK, ["o1"]), _ev("e2", _OK, ["o1"])],
            {"c1": "inconclusive"},
        ),
        _case(
            "FN-F11",
            11,
            "Transitive dependency through a third artifact blocks only the dependent candidate",
            [
                _cand("c1", "s1", ["e1"], "requires_validation"),
                _cand("c2", "s1", ["e2"], "requires_validation"),
            ],
            [
                _ev("e1", _OK, ["o1"], depends_on=["e3"]),
                _ev("e2", _OK, ["o2"]),
                _ev("e3", _BAD, ["o9"]),
            ],
            {"c1": "blocked_invalid_evidence", "c2": "safely_independent"},
        ),
        _case(
            "FN-F12",
            12,
            "Adjacent valid candidate next to a blocked one stays independent",
            [
                _cand("c-blocked", "s1", ["e-bad"], "requires_validation"),
                _cand("c-next", "s1", ["e-next"], "requires_validation"),
            ],
            [_ev("e-bad", _BAD, ["left-a"]), _ev("e-next", _OK, ["right-b"])],
            {"c-blocked": "blocked_invalid_evidence", "c-next": "safely_independent"},
        ),
        _case(
            "FN-F13",
            13,
            "Import order does not change the overlay",
            [
                _cand("c1", "s1", ["e1"], "requires_validation"),
                _cand("c2", "s1", ["e2"], "requires_validation"),
            ],
            [_ev("e1", _OK, ["o1"]), _ev("e2", _BAD, ["o8"])],
            {"c1": "safely_independent", "c2": "blocked_invalid_evidence"},
            check_order=True,
        ),
        _case(
            "FN-F14",
            14,
            "Semantic duplicate is not a second reviewable candidate",
            [
                _cand("c1", "s1", ["e1"], "requires_validation"),
                _cand("c2", "s1", ["e1"], "requires_validation", duplicate_of="c1"),
            ],
            [_ev("e1", _OK, ["o1", "o2"])],
            {"c1": "reviewable", "c2": "inconclusive"},
        ),
        _case(
            "FN-F15",
            15,
            "Incomplete missing-response case is not reviewable and is not confirmed",
            [_cand("c1", "s1", ["e1"], "candidate", missing=["actor_response"])],
            [_ev("e1", _OK, ["o1"])],
            {"c1": "blocked_missing_control"},
        ),
    ]


def dev_cases() -> list[dict[str, Any]]:
    """DEV-only cases, including the ambiguous-object fail-closed rule. Not used to edit FINAL."""
    return [
        _case(
            "FN-D01",
            3,
            "DEV: disjoint sibling of a tampered artifact",
            [
                _cand("c1", "sd", ["ed1"], "requires_validation"),
                _cand("c2", "sd", ["ed2"], "requires_validation"),
            ],
            [_ev("ed1", _OK, ["da", "db"]), _ev("ed2", _BAD, ["dx"])],
            {"c1": "safely_independent", "c2": "blocked_invalid_evidence"},
        ),
        _case(
            "FN-D02",
            0,
            "DEV: unknown object identity on a bad artifact is not proven independence",
            [
                _cand("c1", "sd", ["ed1"], "requires_validation"),
                _cand("c2", "sd", ["ed2"], "requires_validation"),
            ],
            [_ev("ed1", _OK, ["da"]), _ev("ed2", _BAD, None)],
            {"c1": "requires_manual_independence_review", "c2": "blocked_invalid_evidence"},
            whole_surface=["sd"],
        ),
        _case(
            "FN-D03",
            6,
            "DEV: missing control",
            [_cand("c1", "sd", ["ed1"], "requires_validation", missing=["owner_response"])],
            [_ev("ed1", _OK, ["da"])],
            {"c1": "blocked_missing_control"},
        ),
        _case(
            "FN-D04",
            10,
            "DEV: conflict stays inconclusive",
            [_cand("c1", "sd", ["ed1", "ed2"], "requires_validation", conflict=True)],
            [_ev("ed1", _OK, ["da"]), _ev("ed2", _OK, ["db"])],
            {"c1": "inconclusive"},
            check_order=True,
        ),
        _case(
            "FN-D05",
            4,
            "DEV: namespace split",
            [
                _cand("c-a", "sd", ["ea"], "requires_validation"),
                _cand("c-b", "sd", ["eb"], "requires_validation"),
            ],
            [_ev("ea", _BAD, ["9"], namespace="ns-a"), _ev("eb", _OK, ["9"], namespace="ns-b")],
            {"c-a": "blocked_invalid_evidence", "c-b": "safely_independent"},
        ),
        _case(
            "FN-D06",
            1,
            "DEV: shared bad artifact is a whole-surface block",
            [
                _cand("c1", "sd", ["esh"], "requires_validation"),
                _cand("c2", "sd", ["esh"], "requires_validation"),
            ],
            [_ev("esh", _BAD, ["same"])],
            {"c1": "blocked_invalid_evidence", "c2": "blocked_invalid_evidence"},
            whole_surface=["sd"],
        ),
    ]


def document(split: str) -> dict[str, Any]:
    cases = dev_cases() if split == "dev" else final_cases()
    return {
        "schema_version": "bbtk-idor-fn-recovery-lab/1",
        "corpus_version": "idor-fn-recovery-1.0",
        "split": split,
        "label_source": "authored from the blocker-dependency-graph spec before the first FINAL run",
        "finding_confirmed": False,
        "cases": cases,
    }
