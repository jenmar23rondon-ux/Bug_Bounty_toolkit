"""Offline-first orchestration for the existing evidence and skill workflows."""

from __future__ import annotations

import re
from pathlib import Path
from typing import TypedDict

from .access_assessment import assess_access_control
from .ai_backend import AICallLog, AISelection
from .hypotheses import SECOND_OPINION, analyze_hypotheses
from .ollama_review import DEFAULT_OLLAMA_MODEL
from .prioritization import prioritize_hypotheses
from .skill_router import load_hypotheses_result, route_hypotheses

_PROGRAM = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,79}$")


class InvestigationStage(TypedDict):
    status: str
    detail: str


class InvestigationResult(TypedDict):
    type: str
    schema_version: str
    notice: str
    program: str
    mode: str
    status: str
    stages: dict[str, InvestigationStage]
    correlation_summary: dict[str, object]
    hypotheses: dict[str, object]
    access_control_assessment: dict[str, object] | None
    routing: dict[str, object]
    prioritization: dict[str, object]
    human_approval_required: bool
    execution_performed: bool
    target_requests_sent: int


def _group_statuses(groups: object) -> dict[str, int]:
    counts: dict[str, int] = {}
    if isinstance(groups, list):
        for group in groups:
            if isinstance(group, dict) and isinstance(group.get("status"), str):
                status = group["status"]
                counts[status] = counts.get(status, 0) + 1
    return dict(sorted(counts.items()))


def investigate_evidence(
    program: str,
    evidence_path: Path,
    max_tests: int = 100,
    model: str = DEFAULT_OLLAMA_MODEL,
    timeout: float = 120.0,
    offline: bool = False,
    dry_run: bool = False,
    case_file: Path | None = None,
    access_evidence: Path | None = None,
    selection: AISelection | None = None,
) -> InvestigationResult:
    """Join correlation, optional local hypotheses, routing and triage without executing a check."""
    if not _PROGRAM.fullmatch(program):
        raise ValueError("A valid program name is required.")
    if type(max_tests) is not int or max_tests <= 0:
        raise ValueError("--max-tests must be a positive integer.")
    if (case_file is None) != (access_evidence is None):
        raise ValueError("--case-file and --access-evidence must be supplied together.")

    use_ollama = not (offline or dry_run)
    hypotheses_result = analyze_hypotheses(
        evidence_path,
        model=model,
        timeout=timeout,
        dry_run=not use_ollama,
        selection=selection if use_ollama else None,
    )
    validated_result, reviewed = load_hypotheses_result(hypotheses_result)
    groups = hypotheses_result.get("groups")
    group_rows = groups if isinstance(groups, list) else []
    observation_count = sum(
        int(packet.get("observation_count", 0))
        for group in group_rows
        if isinstance(group, dict)
        and isinstance((packet := group.get("minimized_packet")), dict)
        and type(packet.get("observation_count")) is int
    )
    correlation_summary: dict[str, object] = {
        "bundle_id": hypotheses_result.get("bundle_id", "unknown"),
        "groups": len(group_rows),
        "observations_in_minimized_groups": observation_count,
    }

    route_log = AICallLog()
    try:
        routing = route_hypotheses(
            validated_result,
            reviewed,
            program,
            max_tests,
            model=model,
            timeout=timeout,
            use_ollama=use_ollama,
            selection=selection if use_ollama else None,
            log=route_log,
        )
        routing_status = "plan_ready" if routing.get("plan") else "no_reviewed_hypotheses"
    except ValueError as exc:
        if "exceeding --max-tests" not in str(exc):
            raise
        routing = {
            "selected": [],
            "missing_inputs": [str(exc)],
            "plan": [],
        }
        routing_status = "deferred_over_budget"
    routing["status"] = routing_status
    routing["ai_backend"] = route_log.summary()

    prioritization = prioritize_hypotheses(validated_result, reviewed, program, max_tests)
    access_assessment = (
        assess_access_control(case_file, access_evidence)
        if case_file is not None and access_evidence is not None
        else None
    )
    mode = (
        "dry_run"
        if dry_run
        else "offline"
        if offline
        else "local_ollama"
        if selection is None
        else f"local_{selection.provider}"
    )
    hypothesis_statuses = _group_statuses(groups)
    stages = {
        "correlate": InvestigationStage(
            status="complete",
            detail=f"Recomputed {len(group_rows)} descriptive groups; these are not findings.",
        ),
        "hypothesize": InvestigationStage(
            status="model_reviewed" if hypothesis_statuses.get("reviewed", 0) else "no_reviewed_hypotheses",
            detail=f"Group review states: {hypothesis_statuses or {'none': 0}}.",
        ),
        "access_assessment": InvestigationStage(
            status=str(access_assessment.get("classification", "unknown"))
            if access_assessment is not None
            else "not_requested",
            detail="Deterministic ownership predicates only; HTTP status and model opinion cannot confirm access.",
        ),
        "route": InvestigationStage(status=routing_status, detail="Validated registered-skill plan; never executed."),
        "prioritize": InvestigationStage(
            status=str(prioritization.get("status", "unknown")),
            detail="Priority, model confidence and demonstrated severity remain separate.",
        ),
    }
    return InvestigationResult(
        type="ai-investigation",
        schema_version="1.0",
        notice=SECOND_OPINION,
        program=program,
        mode=mode,
        status="review_required" if reviewed or access_assessment is not None else "insufficient_evidence",
        stages=stages,
        correlation_summary=correlation_summary,
        hypotheses=hypotheses_result,
        access_control_assessment=access_assessment,
        routing=routing,
        prioritization=prioritization,
        human_approval_required=True,
        execution_performed=False,
        target_requests_sent=0,
    )
