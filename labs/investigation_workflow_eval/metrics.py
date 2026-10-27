"""Metrics for the review-only investigation workflow lab (synthetic, offline)."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path
from typing import Any

from bugbounty_toolkit.analysis.investigation_workflow import (
    DONE_STATES,
    build_workflow,
    explain_workflow,
    validate_workflow,
)

from .corpus import SCENARIOS, Scenario, _complete, write_artifact


def naive_baseline(root: Path, case: dict[str, Any]) -> dict[str, str]:
    """'Before' behaviour: no workflow engine; any present artifact is trusted (no hashes/refs/cycles)."""
    out: dict[str, str] = {}
    for stage in case["artifacts"]:
        try:
            body = json.loads((root / case["artifacts"][stage]["path"]).read_text())
        except (OSError, ValueError):
            out[stage] = "completed_by_evidence"
            continue
        out[stage] = (
            "blocked"
            if body.get("outcome") in {"contradicted", "permission_missing", "rejected"}
            else ("completed_by_evidence")
        )
    return out


def _run(sc: Scenario, root: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    case = sc.build(root)
    wf = build_workflow(
        root,
        case["artifacts"],
        gap_plan=case.get("gap_plan"),
        candidate_id="c1",
        graph=case.get("graph"),
        task_budget=case.get("task_budget"),
    )
    return case, wf


def evaluate() -> dict[str, Any]:
    m: dict[str, Any] = {
        "scenarios": 0,
        "states_correct": 0,
        "states_expected": 0,
        "stop_conditions_correct": 0,
        "dependencies_respected": 0,
        "invalid_stages_detected": 0,
        "invalid_stages_expected": 0,
        "inconsistent_states": 0,
        "baseline_states_correct": 0,
        "baseline_invalid_detected": 0,
        "executions": 0,
        "commands_emitted": 0,
        "auto_confirmations": 0,
        "network_requests_sent": 0,
    }
    per: dict[str, Any] = {}
    for sc in SCENARIOS:
        with tempfile.TemporaryDirectory(prefix="bbtk-iwf-") as tmp:
            root = Path(tmp)
            case, wf = _run(sc, root)
            base = naive_baseline(root, case)
        st = {t["stage"]: t["status"] for t in wf["tasks"]}
        m["scenarios"] += 1
        ok = sum(st.get(k) == v for k, v in sc.expect_status.items())
        m["states_expected"] += len(sc.expect_status)
        m["states_correct"] += ok
        m["baseline_states_correct"] += sum(base.get(k, "pending") == v for k, v in sc.expect_status.items())
        stops_ok = sc.expect_stops <= set(wf["stop_conditions"]) and wf["documental_complete"] == sc.expect_complete
        m["stop_conditions_correct"] += int(stops_ok)
        problems = validate_workflow(wf)
        m["dependencies_respected"] += int(not any("dependency" in p for p in problems))
        m["inconsistent_states"] += len(problems)
        inv = [k for k, v in sc.expect_status.items() if v == "invalidated"]
        m["invalid_stages_expected"] += len(inv)
        m["invalid_stages_detected"] += sum(st.get(k) == "invalidated" for k in inv)
        m["baseline_invalid_detected"] += sum(base.get(k) == "invalidated" for k in inv)
        for k in ("executions", "commands_emitted", "auto_confirmations", "network_requests_sent"):
            m[k] += wf[k]
        per[sc.name] = {"ok": ok == len(sc.expect_status) and stops_ok, "stops": wf["stop_conditions"]}
    m.update(_resume_metrics())
    m.update(_ai_metrics())
    m["synthetic_manual_steps"] = sum(1 for _ in SCENARIOS)  # one human review touchpoint per scenario
    return {"metrics": m, "scenarios": per}


def _resume_metrics() -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="bbtk-iwf-") as tmp:
        root = Path(tmp)
        case = _complete(root)
        first = build_workflow(root, case["artifacts"], gap_plan=case["gap_plan"], candidate_id="c1")
        second = build_workflow(root, case["artifacts"], gap_plan=case["gap_plan"], candidate_id="c1", prior=first)
        dup = build_workflow(root, case["artifacts"], gap_plan=case["gap_plan"], candidate_id="c1", prior=second)
        arts = dict(case["artifacts"])
        arts["discovery"] = write_artifact(root, "discovery", evidence_refs=["ev-2"])
        changed = build_workflow(root, arts, gap_plan=case["gap_plan"], candidate_id="c1", prior=first)
        # resume of an incomplete workflow with no new evidence
        partial = {k: v for k, v in case["artifacts"].items() if k != "human_review"}
        p1 = build_workflow(root, partial, gap_plan=case["gap_plan"], candidate_id="c1")
        p2 = build_workflow(root, partial, gap_plan=case["gap_plan"], candidate_id="c1", prior=p1)
    resumes_ok = int(second["state_digest"] == first["state_digest"]) + int(
        dup["state_digest"] == first["state_digest"]
    )
    return {
        "resumes_correct": resumes_ok,
        "resumes_total": 2,
        "redundant_tasks": second["resume"]["reevaluated_tasks"] + dup["resume"]["reevaluated_tasks"],
        "reused_tasks_on_resume": second["resume"]["reused_tasks"],
        "change_invalidations_detected": changed["resume"]["invalidated_by_change"],
        "no_new_evidence_stop": "no_new_evidence" in p2["stop_conditions"],
    }


def _ai_metrics() -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="bbtk-iwf-") as tmp:
        root = Path(tmp)
        case = _complete(root)
        wf = build_workflow(root, case["artifacts"], gap_plan=case["gap_plan"], candidate_id="c1")

    def bad_model(_: dict[str, Any]) -> object:
        return {
            "sections": [
                {"text": "Ranking is grounded in ev-1.", "task_refs": ["wf-ranking"], "evidence_refs": ["ev-1"]},
                {"text": "Next, task wf-exploit.", "task_refs": ["wf-exploit"], "evidence_refs": []},
                {"text": "Cites ev-404.", "task_refs": ["wf-ranking"], "evidence_refs": ["ev-404"]},
                {"text": "I approve this action.", "task_refs": ["wf-human_review"], "evidence_refs": []},
                {"text": "Run sqlmap now.", "task_refs": ["wf-discovery"], "evidence_refs": []},
                {"text": "x", "task_refs": ["wf-ranking"], "status": "completed_by_evidence"},
            ]
        }

    before = json.dumps(wf, sort_keys=True)
    exp = explain_workflow(wf, bad_model)
    return {
        "ai_inventions_accepted": len(exp["accepted_sections"]) - 1,
        "ai_sections_rejected": exp["rejected_sections"],
        "unauthorized_modifications": int(exp["state_changed"] or json.dumps(wf, sort_keys=True) != before),
        "workflow_without_ai_ok": wf["documental_complete"] and all(t["status"] in DONE_STATES for t in wf["tasks"]),
    }
