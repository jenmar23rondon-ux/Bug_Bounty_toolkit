"""Synthetic scenarios for the review-only investigation workflow lab (offline only)."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from bugbounty_toolkit.analysis.evidence_gap_planner import PLAN_SCHEMA_VERSION
from bugbounty_toolkit.analysis.investigation_workflow import DEFAULT_GRAPH

STAGES = list(DEFAULT_GRAPH)
HUMAN = "reviewer:analyst-1"


def write_artifact(root: Path, stage: str, **content: Any) -> dict[str, str]:
    body = {"stage": stage, "outcome": "ok", "evidence_refs": ["ev-1"], **content}
    if stage == "evidence_import":
        body.setdefault("evidence_ids", ["ev-1", "ev-2"])
        body.setdefault("bundle_id", "bundle-a")
        body["evidence_refs"] = []
    if DEFAULT_GRAPH[stage][1]:
        body.setdefault("reviewer", HUMAN)
    data = json.dumps(body, sort_keys=True).encode()
    path = root / "artifacts" / f"{stage}.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return {"path": f"artifacts/{stage}.json", "sha256": hashlib.sha256(data).hexdigest()}


def gap_plan(steps: list[dict[str, Any]] | None = None, blocked: bool = False) -> dict[str, Any]:
    return {
        "schema_version": PLAN_SCHEMA_VERSION,
        "program": "lab",
        "status": "ok",
        "network_requests_sent": 0,
        "executions": 0,
        "auto_confirmations": 0,
        "ai_used": False,
        "candidates": [{"candidate_id": "c1", "status": "blocked" if blocked else "ready", "steps": []}],
        "plan": steps or [],
    }


def gap_step(req: str) -> dict[str, Any]:
    return {
        "candidate_id": "c1",
        "step_id": f"s-{req}",
        "step_type": "identify_missing_negative_control",
        "priority": "high",
        "reason_code": "gap",
        "evidence_refs": ["ev-1"],
        "missing_requirement": req,
        "expected_information_gain": "high",
        "estimated_manual_steps": 1,
        "prerequisites": [],
        "blocking_conditions": [],
        "requires_human_review": True,
        "execution_allowed": False,
        "finding_confirmed": False,
        "also_applies_to": [],
    }


@dataclass
class Scenario:
    name: str
    build: Callable[[Path], dict[str, Any]]
    expect_status: dict[str, str] = field(default_factory=dict)
    expect_stops: set[str] = field(default_factory=set)
    expect_complete: bool = False


def _all(root: Path, skip: tuple[str, ...] = (), **over: dict[str, Any]) -> dict[str, Any]:
    return {s: write_artifact(root, s, **over.get(s, {})) for s in STAGES if s not in skip and s != "missing_evidence"}


def _complete(root: Path) -> dict[str, Any]:
    return {"artifacts": _all(root), "gap_plan": gap_plan()}


def _incomplete(root: Path) -> dict[str, Any]:
    return {"artifacts": _all(root, skip=("object_handoff", "eligibility_check")), "gap_plan": gap_plan()}


def _false_positive(root: Path) -> dict[str, Any]:
    return {"artifacts": _all(root, control_review={"outcome": "contradicted"}), "gap_plan": gap_plan()}


def _blocked(root: Path) -> dict[str, Any]:
    return {"artifacts": _all(root, eligibility_check={"outcome": "permission_missing"}), "gap_plan": gap_plan()}


def _invalid_evidence(root: Path) -> dict[str, Any]:
    return {"artifacts": _all(root, discovery={"evidence_refs": ["ev-999"]}), "gap_plan": gap_plan()}


def _dossier_rejected(root: Path) -> dict[str, Any]:
    return {"artifacts": _all(root, dossier_verification={"outcome": "rejected"}), "gap_plan": gap_plan()}


def _file_changed(root: Path) -> dict[str, Any]:
    arts = _all(root)
    (root / "artifacts" / "ranking.json").write_text('{"stage":"ranking","outcome":"ok","tampered":1}')
    return {"artifacts": arts, "gap_plan": gap_plan()}


def _review_pending(root: Path) -> dict[str, Any]:
    return {"artifacts": _all(root, skip=("human_review",)), "gap_plan": gap_plan()}


def _gaps_open(root: Path) -> dict[str, Any]:
    return {"artifacts": _all(root), "gap_plan": gap_plan([gap_step("negative_control")])}


def _circular(root: Path) -> dict[str, Any]:
    g = dict(DEFAULT_GRAPH)
    g["discovery"] = (("integrity_validation", "ranking"), False)
    return {"artifacts": _all(root), "gap_plan": gap_plan(), "graph": g}


def _ai_reviewer(root: Path) -> dict[str, Any]:
    return {"artifacts": _all(root, human_review={"reviewer": "ollama:llama3"}), "gap_plan": gap_plan()}


def _approval_outside(root: Path) -> dict[str, Any]:
    return {"artifacts": _all(root, ranking={"outcome": "approved"}), "gap_plan": gap_plan()}


def _budget(root: Path) -> dict[str, Any]:
    return {"artifacts": _all(root), "gap_plan": gap_plan(), "task_budget": 4}


SCENARIOS: list[Scenario] = [
    Scenario(
        "complete", _complete, {"report_preparation": "completed_by_evidence"}, {"documental_tasks_complete"}, True
    ),
    Scenario("incomplete", _incomplete, {"object_handoff": "ready_for_review", "eligibility_check": "pending"}, set()),
    Scenario(
        "false_positive",
        _false_positive,
        {"control_review": "blocked", "missing_evidence": "blocked"},
        {"candidate_contradicted"},
    ),
    Scenario("blocked", _blocked, {"eligibility_check": "blocked"}, {"permissions_missing"}),
    Scenario("invalid_evidence", _invalid_evidence, {"discovery": "invalidated"}, {"invalid_reference"}),
    Scenario("dossier_rejected", _dossier_rejected, {"dossier_verification": "blocked"}, {"dossier_rejected"}),
    Scenario(
        "file_changed", _file_changed, {"ranking": "invalidated", "object_handoff": "blocked"}, {"invalid_reference"}
    ),
    Scenario("review_pending", _review_pending, {"human_review": "requires_human_review"}, set()),
    Scenario("gaps_open", _gaps_open, {"missing_evidence": "blocked"}, {"missing_evidence"}),
    Scenario("circular", _circular, {"discovery": "blocked", "ranking": "blocked"}, {"circular_dependency"}),
    Scenario("ai_reviewer", _ai_reviewer, {"human_review": "requires_human_review"}, set()),
    Scenario("approval_outside_review", _approval_outside, {"ranking": "invalidated"}, {"invalid_reference"}),
    Scenario("task_budget", _budget, {"object_handoff": "pending"}, {"task_budget_exhausted"}),
]
