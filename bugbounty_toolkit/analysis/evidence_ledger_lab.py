"""Synthetic, offline validation lab for the evidence ledger.

Every scenario builds a throwaway program directory under a temporary folder,
writes synthetic evidence JSON, and checks that the validator raises exactly the
expected issue codes. No network, no target, no test execution.
"""

from __future__ import annotations

import copy
import json
import tempfile
import time
from pathlib import Path
from typing import Any, Callable

from ..core.records import ProgramPaths, RecordStore
from .evidence_graph import EvidenceGraphStore
from .evidence_ledger import (
    LedgerError,
    add_candidate,
    add_evidence,
    import_native_evidence,
    new_ledger,
    review_candidate,
    upsert_surface,
    validate_ledger,
)
from .investigation_memory import InvestigationMemory

PROGRAM = "ledger-lab"
Scenario = Callable[[dict[str, Any], Path], object]


def _write(program_dir: Path, rel: str, data: object) -> None:
    target = program_dir / rel
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(data, sort_keys=True), encoding="utf-8")


def _base(program_dir: Path) -> dict[str, Any]:
    """Two surfaces covered, one pending, one blocked, one out of scope; one true and one false candidate."""
    ledger = new_ledger(PROGRAM)
    upsert_surface(
        ledger,
        {
            "surface_id": "s-orders",
            "kind": "endpoint",
            "ref": "GET /api/orders/{id}",
            "status": "investigated",
            "fingerprint": "rev-a",
            "investigation_id": "inv-1",
        },
    )
    upsert_surface(
        ledger, {"surface_id": "s-profile", "kind": "endpoint", "ref": "GET /api/profile", "status": "reviewed"}
    )
    upsert_surface(
        ledger,
        {
            "surface_id": "s-export",
            "kind": "endpoint",
            "ref": "POST /api/export",
            "status": "pending",
            "blocker": "second synthetic account not provisioned",
        },
    )
    upsert_surface(
        ledger,
        {
            "surface_id": "s-admin",
            "kind": "workflow",
            "ref": "admin approval flow",
            "status": "blocked",
            "blocker": "requires role not granted in lab",
        },
    )
    upsert_surface(
        ledger,
        {
            "surface_id": "s-cdn",
            "kind": "asset",
            "ref": "static CDN",
            "status": "out_of_scope",
            "reason": "excluded by program scope",
        },
    )
    _write(program_dir, "evidence/orders-cross-read.json", {"type": "access-control", "synthetic": True})
    _write(program_dir, "evidence/profile-reflect.json", {"type": "xss", "synthetic": True})
    add_evidence(
        ledger,
        program_dir,
        "ev-orders",
        "evidence/orders-cross-read.json",
        tool="access-check",
        surface_fingerprint="rev-a",
        investigation_id="inv-1",
        graph_node_ids=["node-orders"],
    )
    add_evidence(ledger, program_dir, "ev-profile", "evidence/profile-reflect.json", tool="xss")
    add_candidate(ledger, "c-true", "s-orders", "idor", "researcher-a", ["ev-orders"])
    review_candidate(ledger, "c-true", "requires_validation", "reviewer-b", blockers=["replay with fresh owner"])
    review_candidate(
        ledger,
        "c-true",
        "confirmed",
        "reviewer-b",
        method="human_lab_reproduction",
        basis="owner private field returned to actor in synthetic lab replay",
        human_attestation=True,
    )
    add_candidate(ledger, "c-false", "s-profile", "xss", "researcher-a", ["ev-profile"])
    review_candidate(
        ledger,
        "c-false",
        "rejected",
        "reviewer-b",
        rejection_reason="false_positive",
        rejection_detail="value reflected inside JSON string, HTML-encoded",
    )
    return ledger


def _mut(fn: Scenario) -> Scenario:
    return fn


SCENARIOS: list[tuple[str, set[str], Scenario]] = [
    ("valid_baseline", set(), _mut(lambda led, d: None)),
    (
        "candidate_without_evidence",
        {"evidence_incomplete"},
        _mut(
            lambda led, d: led["candidates"].append(
                {
                    "candidate_id": "c-noev",
                    "surface_id": "s-profile",
                    "category": "csrf",
                    "state": "requires_validation",
                    "evidence_refs": [],
                    "raised_by": "researcher-a",
                    "blockers": ["need form submit"],
                }
            )
        ),
    ),
    (
        "confirmed_without_evidence",
        {"evidence_incomplete"},
        _mut(
            lambda led, d: led["candidates"].append(
                {
                    "candidate_id": "c-conf-noev",
                    "surface_id": "s-profile",
                    "category": "sqli",
                    "state": "confirmed",
                    "evidence_refs": [],
                    "raised_by": "researcher-a",
                    "review": {
                        "reviewer": "reviewer-b",
                        "method": "human_manual",
                        "basis": "looked right",
                        "reviewed_at": "2026-10-25T00:00:00Z",
                    },
                }
            )
        ),
    ),
    (
        "auto_confirm_heuristic",
        {"auto_confirmation_blocked"},
        _mut(lambda led, d: led["candidates"][0]["review"].update({"method": "heuristic", "basis": "pattern_match"})),
    ),
    (
        "auto_confirm_tool_reviewer",
        {"auto_confirmation_blocked"},
        _mut(lambda led, d: led["candidates"][0]["review"].update({"reviewer": "ollama"})),
    ),
    (
        "self_review",
        {"review_not_independent"},
        _mut(lambda led, d: led["candidates"][0]["review"].update({"reviewer": "researcher-a"})),
    ),
    (
        "duplicate_candidate",
        {"duplicate_candidate"},
        _mut(
            lambda led, d: led["candidates"].append(
                {
                    "candidate_id": "c-dup",
                    "surface_id": "s-orders",
                    "category": "IDOR",
                    "state": "candidate",
                    "evidence_refs": ["ev-orders"],
                    "raised_by": "researcher-c",
                }
            )
        ),
    ),
    (
        "duplicate_rejected_ok",
        set(),
        _mut(
            lambda led, d: led["candidates"].append(
                {
                    "candidate_id": "c-dup",
                    "surface_id": "s-orders",
                    "category": "IDOR",
                    "state": "rejected",
                    "evidence_refs": ["ev-orders"],
                    "raised_by": "researcher-c",
                    "duplicate_of": "c-true",
                    "rejection": {"reason": "duplicate", "detail": "same object reference as c-true"},
                }
            )
        ),
    ),
    (
        "broken_evidence_ref",
        {"broken_evidence_ref"},
        _mut(lambda led, d: led["candidates"][1]["evidence_refs"].append("ev-ghost")),
    ),
    (
        "broken_surface_ref",
        {"broken_surface_ref"},
        _mut(lambda led, d: led["candidates"][1].update({"surface_id": "s-ghost"})),
    ),
    (
        "broken_graph_ref",
        {"broken_graph_ref"},
        _mut(lambda led, d: led["evidence"][0]["provenance"]["graph_node_ids"].append("node-ghost")),
    ),
    (
        "broken_investigation_ref",
        {"broken_investigation_ref"},
        _mut(lambda led, d: led["surfaces"][0].update({"investigation_id": "inv-ghost"})),
    ),
    (
        "broken_duplicate_ref",
        {"broken_duplicate_ref"},
        _mut(
            lambda led, d: led["candidates"][1].update(
                {"duplicate_of": "c-ghost", "rejection": {"reason": "duplicate", "detail": "dup"}}
            )
        ),
    ),
    ("blocked_surface_without_blocker", {"blocker_missing"}, _mut(lambda led, d: led["surfaces"][3].pop("blocker"))),
    (
        "rejected_without_reason",
        {"rejection_reason_missing"},
        _mut(lambda led, d: led["candidates"][1].pop("rejection")),
    ),
    (
        "candidate_on_out_of_scope",
        {"state_incompatible"},
        _mut(
            lambda led, d: led["candidates"].append(
                {
                    "candidate_id": "c-oos",
                    "surface_id": "s-cdn",
                    "category": "takeover",
                    "state": "candidate",
                    "evidence_refs": ["ev-profile"],
                    "raised_by": "researcher-a",
                }
            )
        ),
    ),
    (
        "confirmed_on_pending_surface",
        {"state_incompatible"},
        _mut(lambda led, d: led["candidates"][0].update({"surface_id": "s-export"})),
    ),
    (
        "code_change_invalidates",
        {"evidence_invalidated_by_change"},
        _mut(lambda led, d: led["surfaces"][0].update({"fingerprint": "rev-b"})),
    ),
    (
        "evidence_tampered",
        {"evidence_digest_mismatch", "evidence_incomplete"},
        _mut(lambda led, d: (d / "evidence/orders-cross-read.json").write_text("{}", encoding="utf-8")),
    ),
    (
        "evidence_deleted",
        {"evidence_missing", "evidence_incomplete"},
        _mut(lambda led, d: (d / "evidence/orders-cross-read.json").unlink()),
    ),
    (
        "unsafe_evidence_path",
        {"evidence_path_unsafe"},
        _mut(lambda led, d: led["evidence"][1].update({"path": "../../etc/passwd"})),
    ),
    (
        "unknown_schema_version",
        {"schema_version_unsupported"},
        _mut(lambda led, d: led.update({"schema_version": "bbtk-evidence-ledger/99"})),
    ),
    ("unknown_field", {"unknown_field"}, _mut(lambda led, d: led["candidates"][0].update({"auto_verdict": "yes"}))),
    ("invalid_state", {"invalid_enum"}, _mut(lambda led, d: led["candidates"][1].update({"state": "VULNERABLE"}))),
    (
        "requires_validation_without_blocker",
        {"blocker_missing"},
        _mut(
            lambda led, d: (
                led["candidates"][1].update({"state": "requires_validation", "rejection": None})
                or led["candidates"][1].pop("rejection")
            )
        ),
    ),
    (
        "broken_finding_ref",
        {"broken_finding_ref"},
        _mut(lambda led, d: led["candidates"][0].update({"finding_id": "F-ghost"})),
    ),
]


def _prepare_program(root: Path) -> Path:
    paths = ProgramPaths(root, PROGRAM)
    store = RecordStore(paths)
    try:
        EvidenceGraphStore(store)
        store.connection.execute(
            "insert into graph_nodes(node_id,node_type,epistemic_state,attributes_json,provenance_json,observed_at)"
            " values('node-orders','HTTPRequest','observed','{}','{}','2026-10-25T00:00:00Z')"
        )
        store.connection.commit()
        InvestigationMemory(store).save_snapshot(
            "inv-1", "bundle-1", "evidence/snapshot.json", {"triage": {"status": "ok"}}
        )
    finally:
        store.close()
    return paths.program_dir


def _api_guards(program_dir: Path) -> dict[str, bool]:
    """Every guarded call must raise; True means the guard held."""
    results: dict[str, bool] = {}
    checks: dict[str, Callable[[dict[str, Any]], object]] = {
        "confirm_without_attestation": lambda led: review_candidate(
            led, "c-new", "confirmed", "reviewer-b", method="human_manual", basis="x"
        ),
        "candidate_straight_to_confirmed": lambda led: review_candidate(
            led, "c-new", "confirmed", "reviewer-b", method="human_manual", basis="x", human_attestation=True
        ),
        "automatic_reviewer": lambda led: review_candidate(led, "c-new", "requires_validation", "bbtk", blockers=["x"]),
        "heuristic_method": lambda led: (
            review_candidate(led, "c-new", "requires_validation", "reviewer-b", blockers=["x"]),
            review_candidate(
                led, "c-new", "confirmed", "reviewer-b", method="heuristic", basis="x", human_attestation=True
            ),
        ),
        "reject_without_reason": lambda led: review_candidate(led, "c-new", "rejected", "reviewer-b"),
    }
    for name, call in checks.items():
        ledger = _base(program_dir)
        add_candidate(ledger, "c-new", "s-profile", "csrf", "researcher-a", ["ev-profile"])
        try:
            call(ledger)
            results[name] = False
        except LedgerError:
            results[name] = True
    return results


def _baseline_findings(program_dir: Path) -> int:
    """Before: the existing findings table accepts every lab record; count how many it refuses."""
    store = RecordStore(ProgramPaths(program_dir.parent, PROGRAM))
    refused = 0
    try:
        for name, expected, _ in SCENARIOS:
            if not expected:
                continue
            try:
                store.add_finding(f"lab-{name}", name, "lab", "info", "lab.invalid", "synthetic", None)
            except Exception:  # noqa: BLE001 - measuring the baseline, any refusal counts
                refused += 1
        store.connection.execute("delete from findings where id like 'lab-%'")
        store.connection.commit()
    finally:
        store.close()
    return refused


def run_evidence_ledger_lab() -> dict[str, Any]:
    started = time.perf_counter()
    rows: list[dict[str, Any]] = []
    false_confirmations = 0
    with tempfile.TemporaryDirectory(prefix="bbtk-ledger-lab-") as tmp:
        for name, expected, mutate in SCENARIOS:
            root = Path(tmp) / name
            program_dir = _prepare_program(root)
            ledger = _base(program_dir)
            mutate(ledger, program_dir)
            result = validate_ledger(copy.deepcopy(ledger), program_dir=program_dir)
            codes = {i["code"] for i in result["issues"] if i["severity"] == "error"}
            warnings = {i["code"] for i in result["issues"] if i["severity"] == "warning"}
            detected = expected <= (codes | warnings) if expected else result["valid"]
            if expected and result["valid"] and any(c.get("state") == "confirmed" for c in ledger["candidates"]):
                false_confirmations += 1
            rows.append(
                {
                    "scenario": name,
                    "expected": sorted(expected),
                    "errors": sorted(codes),
                    "warnings": sorted(warnings),
                    "valid": result["valid"],
                    "passed": detected,
                    "coverage": result["summary"].get("surface_status"),
                    "coverage_ratio": result["summary"].get("coverage_ratio"),
                }
            )
        guard_dir = _prepare_program(Path(tmp) / "guards")
        guards = _api_guards(guard_dir)
        _write(
            guard_dir,
            "evidence/legacy-vulnerable.json",
            {
                "type": "access-control",
                "classification": "VULNERABLE",
                "steps": [{"step": "cross_read", "status_code": 200}],
            },
        )
        ledger = _base(guard_dir)
        imported = import_native_evidence(
            ledger, guard_dir, "evidence/legacy-vulnerable.json", "s-orders", raised_by="researcher-a"
        )
        state = next(c["state"] for c in ledger["candidates"] if c["candidate_id"] == imported["candidate_id"])
        baseline_refused = _baseline_findings(guard_dir)
    invalid = [r for r in rows if r["expected"]]

    def caught(codes: set[str]) -> tuple[int, int]:
        subset = [r for r in invalid if set(r["expected"]) & codes]
        return sum(r["passed"] for r in subset), len(subset)

    base = rows[0]
    metrics = {
        "scenarios": len(rows),
        "scenarios_passed": sum(r["passed"] for r in rows),
        "invalid_records_rejected": f"{sum(not r['valid'] for r in invalid)}/{len(invalid)}",
        "candidates_without_evidence_caught": "%d/%d" % caught({"evidence_incomplete"}),
        "broken_refs_found": "%d/%d"
        % caught(
            {
                "broken_evidence_ref",
                "broken_surface_ref",
                "broken_graph_ref",
                "broken_investigation_ref",
                "broken_duplicate_ref",
                "broken_finding_ref",
            }
        ),
        "duplicates_caught": "%d/%d" % caught({"duplicate_candidate"}),
        "valid_duplicate_rejection_accepted": next(
            r["valid"] for r in rows if r["scenario"] == "duplicate_rejected_ok"
        ),
        "auto_confirmations_blocked": "%d/%d" % caught({"auto_confirmation_blocked", "review_not_independent"}),
        "stale_evidence_caught": "%d/%d"
        % caught({"evidence_invalidated_by_change", "evidence_digest_mismatch", "evidence_missing"}),
        "coverage_recorded": base["coverage"],
        "coverage_ratio": base["coverage_ratio"],
        "api_guards_held": f"{sum(guards.values())}/{len(guards)}",
        "legacy_vulnerable_import_state": state,
        "false_confirmations": false_confirmations + (state == "confirmed") + (len(guards) - sum(guards.values())),
        "baseline_findings_table_refused": f"{baseline_refused}/{len(invalid)}",
        "network_requests_sent": 0,
        "processing_ms": round((time.perf_counter() - started) * 1000, 1),
    }
    return {
        "type": "evidence-ledger-lab",
        "synthetic": True,
        "metrics": metrics,
        "scenarios": rows,
        "api_guards": guards,
        "human_gate": "No candidate is confirmed without an independent human reviewer.",
    }
