"""End-to-end contract run over public interfaces on main (offline, synthetic, review-only).

capture -> import -> object discovery -> ranking -> handoff -> eligibility -> reviewable
proposal -> Evidence Ledger -> structured report. Nothing here confirms a finding, executes a
case, or contacts the network: sockets are hard-blocked for the duration of the run.

PR #34 (IDOR case reliability) is not on main; its eligibility module is NOT used. The
eligibility stage uses the handoff ``status`` contract available on main and records the
pending contract explicitly in ``pending_contracts``.
"""

from __future__ import annotations

import hashlib
import json
import re
import shutil
import tempfile
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

from bugbounty_toolkit.analysis import evidence_ledger as ledger_mod
from bugbounty_toolkit.analysis.object_handoff import propose_object_handoff
from bugbounty_toolkit.analysis.object_relationships import build_object_graph, object_candidates
from bugbounty_toolkit.core.records import ProgramPaths, RecordStore
from bugbounty_toolkit.reporting.json_report import build_program_report
from labs.adversarial_idor_eval.evaluate import no_network
from labs.eval_integrity.corpus_integrity import Issue

PROGRAM = "e2e-contract"
KEY = b"e2e-contract-synthetic-key-32byt"
REVIEWER = "lab-reviewer"
STAGES = (
    "import",
    "object_discovery",
    "ranking",
    "handoff",
    "eligibility",
    "reviewable_proposal",
    "evidence_ledger",
    "structured_report",
)
PENDING_CONTRACTS = ("idor-case-eligibility (PR #34, not merged): eligibility measured via object-handoff status only",)
_VOLATILE = re.compile(r"(_at|captured_at|updated_at|created_at|records_path|path)$")


def entry_digest(entry: Mapping[str, Any]) -> str:
    canon = json.dumps({"request": entry.get("request"), "response": entry.get("response")}, sort_keys=True)
    return hashlib.sha256(canon.encode()).hexdigest()


def _index(locator: str) -> int:
    match = re.fullmatch(r"/log/entries\[(\d+)\]", locator)
    return int(match.group(1)) if match else -1


def run_pipeline(corpus: Path, workdir: Path) -> dict[str, Any]:
    """Run every stage on ``corpus/captures.har`` inside ``workdir``. Returns a structured report."""
    captures = corpus / "captures.har"
    har = json.loads(captures.read_text(encoding="utf-8"))
    stages: dict[str, str] = {}
    errors: list[str] = []
    with no_network() as attempts:
        graph = build_object_graph(PROGRAM, [captures], KEY, authorized=True)
        stages["import"] = "ok"
        stages["object_discovery"] = "ok"
        ranked = object_candidates(graph, PROGRAM, KEY, limit=100)["candidates"]
        stages["ranking"] = "ok"
        handoff = propose_object_handoff(graph, PROGRAM, KEY, verify_inputs=[captures], limit=20)
        stages["handoff"] = "ok"
        eligibility = []
        for cand in ranked:
            doc = propose_object_handoff(graph, PROGRAM, KEY, candidate=cand["object_ref"], limit=20)
            eligibility.append(
                {
                    "object_ref": cand["object_ref"],
                    "status": doc["status"],
                    "proposals": doc["total_proposals"],
                    "executed": False,
                }
            )
        stages["eligibility"] = "ok"
        proposals = handoff["proposals"]
        stages["reviewable_proposal"] = "ok" if proposals else "none"

        program_dir = ProgramPaths(workdir, PROGRAM).program_dir
        store = RecordStore(ProgramPaths(workdir, PROGRAM))
        try:
            (program_dir / "evidence").mkdir(parents=True, exist_ok=True)
            ledger = ledger_mod.new_ledger(PROGRAM)
            for proposal in proposals:
                pid = proposal["id"]
                rel = f"evidence/{pid}.json"
                (program_dir / rel).write_text(json.dumps(proposal, sort_keys=True), encoding="utf-8")
                ledger_mod.upsert_surface(
                    ledger,
                    {
                        "surface_id": proposal["endpoint_ref"],
                        "kind": "endpoint",
                        "ref": str(proposal["endpoint_hint"]["path_template"]),
                        "status": "investigated",
                    },
                )
                ledger_mod.add_evidence(ledger, program_dir, f"ev-{pid}", rel, tool="object-handoff")
                ledger_mod.add_candidate(
                    ledger, f"cand-{pid}", proposal["endpoint_ref"], "idor", REVIEWER, [f"ev-{pid}"]
                )
            ledger_path = program_dir / "ledger" / "evidence-ledger.json"
            validation = ledger_mod.save_ledger(ledger_path, ledger, program_dir=program_dir)
            stages["evidence_ledger"] = "ok"
            program_report = build_program_report(store)
            stages["structured_report"] = "ok"
        finally:
            store.close()

    entries = har["log"]["entries"]
    report: dict[str, Any] = {
        "type": "bbtk-e2e-contract-report",
        "program": PROGRAM,
        "stages": stages,
        "stage_order": list(STAGES),
        "errors": errors,
        "pending_contracts": list(PENDING_CONTRACTS),
        "capture_import": graph["capture_import"],
        "sources": graph["sources"],
        "origin_refs": sorted({n["origin_ref"] for n in graph["nodes"] if n.get("type") == "Endpoint"}),
        "observations": sorted(
            (
                {
                    "id": o["id"],
                    "locators": sorted(str(p["locator"]) for p in o["provenance"]),
                    "source_refs": sorted({str(p["source_ref"]) for p in o["provenance"]}),
                }
                for o in graph["observations"]
            ),
            key=lambda row: row["id"],
        ),
        "ranking": [
            {
                "object_ref": c["object_ref"],
                "resource_type": c["resource_type"],
                "score": c["score"],
                "confirmed": c["confirmed"],
            }
            for c in ranked
        ],
        "eligibility": eligibility,
        "proposals": [
            {
                "id": p["id"],
                "resource_type": p["resource_type"],
                "score": p["score"],
                "confirmed": p["confirmed"],
                "case_executable": p["case_executable"],
                "researcher_review_required": p["researcher_review_required"],
                "owner": {k: p["owner"][k] for k in ("object_ref", "observation_ref", "source_ref", "locator")},
                "actor": {k: p["actor"][k] for k in ("object_ref", "observation_ref", "source_ref", "locator")},
                "owner_entry_sha256": entry_digest(entries[_index(p["owner"]["locator"])])
                if 0 <= _index(p["owner"]["locator"]) < len(entries)
                else None,
                "actor_entry_sha256": entry_digest(entries[_index(p["actor"]["locator"])])
                if 0 <= _index(p["actor"]["locator"]) < len(entries)
                else None,
            }
            for p in proposals
        ],
        "ledger": {
            "valid": validation["valid"],
            "candidates": [
                {"candidate_id": c["candidate_id"], "state": c["state"], "evidence_refs": c["evidence_refs"]}
                for c in ledger["candidates"]
            ],
            "evidence": [{"evidence_id": e["evidence_id"], "sha256": e["sha256"]} for e in ledger["evidence"]],
        },
        "program_report_ledger": program_report.get("evidence_ledger"),
        "network_connect_attempts": attempts["count"],
        "network_requests_sent": int(handoff["network_requests_sent"]) + int(graph["network_requests_sent"]),
        "vulnerabilities_confirmed": int(handoff["vulnerabilities_confirmed"]),
    }
    return report


def canonical_digest(report: Mapping[str, Any]) -> str:
    def strip(value: Any) -> Any:
        if isinstance(value, dict):
            return {k: strip(v) for k, v in sorted(value.items()) if not _VOLATILE.search(k)}
        if isinstance(value, list):
            return [strip(v) for v in value]
        return value

    return hashlib.sha256(json.dumps(strip(report), sort_keys=True).encode()).hexdigest()


def contract_view(report: Mapping[str, Any]) -> dict[str, Any]:
    """Small, human-readable projection pinned in ``expected_contract.json``."""
    ci = report["capture_import"]
    return {
        "stages": dict(report["stages"]),
        "capture_import": {k: ci[k] for k in ("entries_total", "accepted", "rejected", "duplicate_entries", "reasons")},
        "ranking": [[r["resource_type"], r["score"]] for r in report["ranking"]],
        "eligibility": sorted([e["status"], e["proposals"]] for e in report["eligibility"]),
        "proposals": sorted(
            [p["resource_type"], p["score"], p["owner"]["locator"], p["actor"]["locator"]] for p in report["proposals"]
        ),
        "ledger_states": sorted(c["state"] for c in report["ledger"]["candidates"]),
        "origin_count": len(report["origin_refs"]),
        "source_refs": sorted(s["id"] for s in report["sources"]),
    }


def check_contract(report: Mapping[str, Any], corpus: Path, expected: Mapping[str, Any] | None) -> list[Issue]:
    """Invariants (always) + pinned contract (when ``expected`` is given)."""
    name = "e2e"
    issues: list[Issue] = []
    gt = json.loads((corpus / "ground_truth.json").read_text(encoding="utf-8"))
    entries = json.loads((corpus / "captures.har").read_text(encoding="utf-8"))["log"]["entries"]
    scenario_of = {i: s["id"] for s in gt["scenarios"] for i in s["entries"]}
    by_id = {s["id"]: s for s in gt["scenarios"]}
    for stage in STAGES:
        if report["stages"].get(stage) not in {"ok", "none"}:
            issues.append(Issue("stage_incomplete", name, stage))
    if report["network_connect_attempts"] or report["network_requests_sent"]:
        issues.append(Issue("network_activity", name, str(report["network_connect_attempts"])))
    if report["vulnerabilities_confirmed"]:
        issues.append(Issue("auto_confirmation", name, "handoff"))
    if any(r["confirmed"] for r in report["ranking"]) or any(p["confirmed"] for p in report["proposals"]):
        issues.append(Issue("auto_confirmation", name, "candidate"))
    if any(p["case_executable"] or not p["researcher_review_required"] for p in report["proposals"]):
        issues.append(Issue("review_gate_bypassed", name, "proposal"))
    if any(e.get("executed") for e in report["eligibility"]):
        issues.append(Issue("forced_execution", name, "eligibility"))
    if len(report["origin_refs"]) != 1:
        issues.append(Issue("origin_not_preserved", name, str(len(report["origin_refs"]))))
    source_ids = {s["id"] for s in report["sources"]}
    obs = {o["id"]: o for o in report["observations"]}
    for p in report["proposals"]:
        scen = set()
        for role in ("owner", "actor"):
            side = p[role]
            idx = _index(side["locator"])
            if side["source_ref"] not in source_ids:
                issues.append(Issue("broken_source_ref", name, p["id"]))
            o = obs.get(side["observation_ref"])
            if o is None:
                issues.append(Issue("candidate_without_evidence", name, p["id"]))
            elif side["locator"] not in o["locators"]:
                issues.append(Issue("provenance_mismatch", name, p["id"]))
            if not 0 <= idx < len(entries) or entry_digest(entries[idx]) != p[f"{role}_entry_sha256"]:
                issues.append(Issue("request_response_mismatch", name, f"{p['id']}:{role}"))
            scen.add(scenario_of.get(idx))
        if len(scen) != 1 or None in scen:
            issues.append(Issue("cross_scenario_pairing", name, p["id"]))
        else:
            sid = next(iter(s for s in scen if s is not None))
            if p["resource_type"] not in by_id[sid]["expected_pair_types"]:
                issues.append(Issue("unexpected_pair_type", name, f"{sid}:{p['resource_type']}"))
    ev = {e["evidence_id"] for e in report["ledger"]["evidence"]}
    for c in report["ledger"]["candidates"]:
        if c["state"] == "confirmed":
            issues.append(Issue("auto_confirmation", name, c["candidate_id"]))
        if not c["evidence_refs"] or any(r not in ev for r in c["evidence_refs"]):
            issues.append(Issue("broken_report_ref", name, c["candidate_id"]))
    if not report["ledger"]["valid"] or not (report.get("program_report_ledger") or {}).get("valid"):
        issues.append(Issue("ledger_invalid", name, "evidence_ledger"))
    if expected is not None:
        actual = contract_view(report)
        for key in sorted(set(expected) | set(actual)):
            if expected.get(key) != actual.get(key):
                issues.append(Issue("contract_drift", name, key))
    return issues


def run_twice(
    corpus: Path, runner: Callable[[Path, Path], dict[str, Any]] = run_pipeline
) -> tuple[dict[str, Any], bool]:
    """Run in two fresh temp dirs; return the first report and whether canonical digests match."""
    digests = []
    first: dict[str, Any] = {}
    for _ in range(2):
        tmp = Path(tempfile.mkdtemp(prefix="bbtk-e2e-"))
        try:
            report = runner(corpus, tmp)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
        digests.append(canonical_digest(report))
        first = first or report
    return first, digests[0] == digests[1]
