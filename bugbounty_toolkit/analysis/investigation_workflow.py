"""Review-only investigation workflow engine.

Builds a deterministic, **non-executable** task graph over the existing
investigation stages. The engine never runs tools, never emits scan commands,
never changes scope, permissions or Evidence Ledger state and never confirms a
vulnerability. Every node carries ``execution_allowed: False``.

Inputs are verifiable artifacts (hash-pinned JSON files under a root
directory), the Evidence-Gap Planner output (``evidence_gap_planner.build_plan``)
and, optionally, an Investigation Memory record and a previous workflow
result for resumption. An optional AI explainer may only describe an already
computed workflow; it never controls state.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path, PurePosixPath
from typing import Any

from .evidence_gap_planner import validate_plan

WORKFLOW_SCHEMA_VERSION = "bbtk-investigation-workflow/1"
MAX_ARTIFACT_BYTES = 2 * 1024 * 1024

STATES = (
    "pending",
    "ready_for_review",
    "blocked",
    "completed_by_evidence",
    "requires_human_review",
    "invalidated",
    "not_applicable",
)
DONE_STATES = frozenset({"completed_by_evidence", "not_applicable"})

# stage -> (prerequisites, reviewer_required)
DEFAULT_GRAPH: dict[str, tuple[tuple[str, ...], bool]] = {
    "evidence_import": ((), False),
    "integrity_validation": (("evidence_import",), False),
    "discovery": (("integrity_validation",), False),
    "ranking": (("discovery",), False),
    "object_handoff": (("ranking",), False),
    "eligibility_check": (("object_handoff",), False),
    "control_review": (("eligibility_check",), True),
    "missing_evidence": (("control_review",), False),
    "human_review": (("missing_evidence",), True),
    "dossier_verification": (("human_review",), False),
    "report_preparation": (("dossier_verification",), True),
}

# Artifact outcome -> (status, reason_code, stop_code)
_OUTCOMES: dict[str, tuple[str, str, str | None]] = {
    "ok": ("completed_by_evidence", "artifact_verified", None),
    "approved": ("completed_by_evidence", "human_decision_recorded", None),
    "not_applicable": ("not_applicable", "artifact_not_applicable", None),
    "contradicted": ("blocked", "candidate_contradicted", "candidate_contradicted"),
    "permission_missing": ("blocked", "permission_missing", "permissions_missing"),
    "insufficient_control": ("blocked", "insufficient_control", "insufficient_control"),
    "rejected": ("blocked", "artifact_rejected", "dossier_rejected"),
}
_HUMAN_ONLY_OUTCOMES = frozenset({"approved"})
_REF = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_AI_REVIEWER = re.compile(r"^(ai|model|llm|ollama|lmstudio|bot)\b", re.IGNORECASE)
_FORBIDDEN_AI = re.compile(
    r"\b(approve[sd]?|authori[sz]e[sd]?|confirm(ed|s)?|mark(ed)? (as )?complete[d]?|execute[sd]?|run |"
    r"curl|sqlmap|nmap|ffuf|nuclei|burp|scan(ning)?)\b",
    re.IGNORECASE,
)


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _safe_rel(value: object) -> str | None:
    if not isinstance(value, str) or not value or "\\" in value or len(value) > 240:
        return None
    p = PurePosixPath(value)
    if p.is_absolute() or any(part in {"", ".", ".."} for part in p.parts):
        return None
    return p.as_posix()


def _refs(value: object) -> tuple[list[str], bool]:
    """Return sanitized refs and whether any ref was malformed."""
    if not isinstance(value, list):
        return [], value is not None
    good = sorted({str(v) for v in value if isinstance(v, str) and _REF.fullmatch(v)})
    return good, len(good) != len({str(v) for v in value})


def find_cycles(graph: Mapping[str, tuple[Sequence[str], bool]]) -> set[str]:
    """Return every stage that sits on (or depends on an unknown/circular) prerequisite cycle."""
    color: dict[str, int] = {}
    on_cycle: set[str] = set()
    stack: list[str] = []

    def visit(node: str) -> None:
        color[node] = 1
        stack.append(node)
        for dep in graph.get(node, ((), False))[0]:
            if dep not in graph:
                continue
            if color.get(dep) == 1:
                on_cycle.update(stack[stack.index(dep) :])
            elif color.get(dep) is None:
                visit(dep)
        stack.pop()
        color[node] = 2

    for n in sorted(graph):
        if n not in color:
            visit(n)
    return on_cycle


def _topo(graph: Mapping[str, tuple[Sequence[str], bool]], skip: set[str]) -> list[str]:
    order: list[str] = []
    seen: set[str] = set()

    def visit(node: str) -> None:
        if node in seen or node in skip or node not in graph:
            return
        seen.add(node)
        for dep in sorted(graph[node][0]):
            visit(dep)
        order.append(node)

    for n in graph:  # declaration order is deterministic
        visit(n)
    return order


def _load_artifact(root: Path, spec: object) -> tuple[dict[str, Any] | None, str | None, str | None, str]:
    """Return (content, actual_sha, rel_path, problem_code)."""
    if not isinstance(spec, Mapping):
        return None, None, None, "artifact_spec_invalid"
    rel = _safe_rel(spec.get("path"))
    expected = spec.get("sha256")
    if rel is None:
        return None, None, None, "artifact_path_unsafe"
    path = root / rel
    try:
        resolved = path.resolve()
        resolved.relative_to(root.resolve())
    except (OSError, ValueError):
        return None, None, rel, "artifact_path_unsafe"
    if not resolved.is_file():
        return None, None, rel, "artifact_missing"
    if resolved.stat().st_size > MAX_ARTIFACT_BYTES:
        return None, None, rel, "artifact_too_large"
    actual = _sha256(resolved)
    if not isinstance(expected, str) or expected.lower() != actual:
        return None, actual, rel, "artifact_hash_mismatch"
    try:
        content = json.loads(resolved.read_text(encoding="utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None, actual, rel, "artifact_unparseable"
    if not isinstance(content, dict):
        return None, actual, rel, "artifact_unparseable"
    return content, actual, rel, ""


def _node(stage: str, prereqs: Sequence[str], reviewer: bool) -> dict[str, Any]:
    return {
        "task_id": f"wf-{stage}",
        "stage": stage,
        "prerequisites": [f"wf-{p}" for p in prereqs],
        "evidence_refs": [],
        "status": "pending",
        "missing_requirements": [],
        "reason_codes": [],
        "source_artifacts": [],
        "reviewer_required": reviewer,
        "blocked_reason": None,
        "completion_basis": None,
        "execution_allowed": False,
        "finding_confirmed": False,
    }


def build_workflow(
    root: Path,
    artifacts: Mapping[str, object],
    *,
    gap_plan: Mapping[str, Any] | None = None,
    candidate_id: str | None = None,
    memory: Mapping[str, Any] | None = None,
    prior: Mapping[str, Any] | None = None,
    graph: Mapping[str, tuple[Sequence[str], bool]] | None = None,
    task_budget: int | None = None,
) -> dict[str, Any]:
    """Compute the review-only workflow state. Read-only, offline, deterministic, no AI."""
    g: Mapping[str, tuple[Sequence[str], bool]] = graph if graph is not None else DEFAULT_GRAPH
    cycles = find_cycles(g)
    nodes: dict[str, dict[str, Any]] = {s: _node(s, g[s][0], g[s][1]) for s in g}
    stops: set[str] = set()
    hashes: dict[str, str] = {}
    known_evidence: set[str] | None = None
    bundle_id: str | None = None
    prior_hashes: Mapping[str, Any] = (prior or {}).get("artifact_hashes") or {}
    prior_status: dict[str, str] = {
        str(t.get("stage")): str(t.get("status")) for t in (prior or {}).get("tasks") or [] if isinstance(t, dict)
    }
    counters = {"reused_tasks": 0, "reevaluated_tasks": 0, "invalidated_by_change": 0, "evaluated_tasks": 0}

    for stage in sorted(cycles):
        n = nodes[stage]
        n.update(status="blocked", blocked_reason="circular_dependency")
        n["reason_codes"].append("circular_dependency")
        stops.add("circular_dependency")
    for stage, (prereqs, _) in g.items():
        if any(p not in g for p in prereqs) and stage not in cycles:
            n = nodes[stage]
            n.update(status="blocked", blocked_reason="unknown_prerequisite")
            n["reason_codes"].append("unknown_prerequisite")
            stops.add("invalid_reference")

    for stage in _topo(g, cycles):
        n = nodes[stage]
        if n["status"] == "blocked":
            continue
        prereqs, reviewer = g[stage]
        pstat = [nodes[p]["status"] for p in prereqs]
        if any(s in {"blocked", "invalidated"} for s in pstat):
            n.update(status="blocked", blocked_reason="prerequisite_blocked")
            n["reason_codes"].append("prerequisite_blocked")
            continue
        if any(s not in DONE_STATES for s in pstat):
            n["reason_codes"].append("awaiting_prerequisites")
            continue
        if task_budget is not None and counters["evaluated_tasks"] >= task_budget:
            n["reason_codes"].append("task_budget_exhausted")
            stops.add("task_budget_exhausted")
            continue
        counters["evaluated_tasks"] += 1

        if stage == "missing_evidence" and stage not in artifacts:
            _apply_gap_plan(n, gap_plan, candidate_id, stops)
            continue

        spec = artifacts.get(stage)
        if spec is None:
            n["status"] = "requires_human_review" if reviewer else "ready_for_review"
            n["reason_codes"].append("artifact_not_provided")
            n["missing_requirements"].append(f"artifact:{stage}")
            continue
        content, actual, rel, problem = _load_artifact(root, spec)
        if rel:
            n["source_artifacts"].append(rel)
        if actual:
            hashes[stage] = actual
            if stage in prior_hashes:
                if prior_hashes[stage] == actual:
                    counters["reused_tasks"] += 1
                else:
                    counters["reevaluated_tasks"] += 1
                    if prior_status.get(stage) in DONE_STATES:
                        counters["invalidated_by_change"] += 1
                        n["reason_codes"].append("artifact_changed_since_prior")
        if problem:
            status = "invalidated" if problem in {"artifact_hash_mismatch", "artifact_unparseable"} else "blocked"
            n.update(status=status, blocked_reason=problem)
            n["reason_codes"].append(problem)
            stops.add("invalid_reference")
            continue
        assert content is not None
        refs, malformed = _refs(content.get("evidence_refs"))
        if stage == "evidence_import":
            ids, bad = _refs(content.get("evidence_ids"))
            known_evidence = set(ids)
            bid = content.get("bundle_id")
            bundle_id = bid if isinstance(bid, str) and _REF.fullmatch(bid) else None
            malformed = malformed or bad
        unknown = sorted(set(refs) - (known_evidence or set())) if stage != "evidence_import" else []
        n["evidence_refs"] = refs
        if content.get("stage") != stage:
            n.update(status="invalidated", blocked_reason="artifact_stage_mismatch")
            n["reason_codes"].append("artifact_stage_mismatch")
            stops.add("invalid_reference")
            continue
        if malformed or unknown:
            n.update(status="invalidated", blocked_reason="invalid_evidence_reference")
            n["reason_codes"].append("invalid_evidence_reference")
            n["missing_requirements"].extend(f"evidence:{u}" for u in unknown)
            stops.add("invalid_reference")
            continue
        outcome = str(content.get("outcome"))
        if outcome not in _OUTCOMES:
            n.update(status="invalidated", blocked_reason="unknown_outcome")
            n["reason_codes"].append("unknown_outcome")
            stops.add("invalid_reference")
            continue
        if reviewer and outcome in {"ok", "approved"}:
            who = content.get("reviewer")
            if not isinstance(who, str) or not who.strip() or _AI_REVIEWER.match(who.strip()):
                n["status"] = "requires_human_review"
                n["reason_codes"].append("human_reviewer_missing")
                n["missing_requirements"].append("human_reviewer")
                continue
        elif outcome in _HUMAN_ONLY_OUTCOMES:
            n.update(status="invalidated", blocked_reason="approval_outside_review_stage")
            n["reason_codes"].append("approval_outside_review_stage")
            stops.add("invalid_reference")
            continue
        status, reason, stop = _OUTCOMES[outcome]
        n["status"] = status
        n["reason_codes"].append(reason)
        if status == "blocked":
            n["blocked_reason"] = reason
        else:
            n["completion_basis"] = f"artifact_sha256:{actual}"
        if stop:
            stops.add(stop)

    tasks = [nodes[s] for s in g]
    for t in tasks:
        t["reason_codes"] = sorted(set(t["reason_codes"]))
        t["missing_requirements"] = sorted(set(t["missing_requirements"]))
    statuses = [t["status"] for t in tasks]
    documental_complete = all(s in DONE_STATES for s in statuses)
    actionable = [t["task_id"] for t in tasks if t["status"] in {"ready_for_review", "requires_human_review"}]
    if documental_complete:
        stops.add("documental_tasks_complete")
    elif not actionable and "task_budget_exhausted" not in stops:
        stops.add("no_informative_action")
    changed = prior is not None and (
        dict(prior_hashes) != hashes or any(prior_status.get(t["stage"]) != t["status"] for t in tasks)
    )
    if prior is not None and not changed and not documental_complete:
        stops.add("no_new_evidence")

    memory_info = _memory_check(memory, bundle_id, nodes)
    state_digest = hashlib.sha256(
        json.dumps([(t["task_id"], t["status"]) for t in tasks] + sorted(hashes.items()), sort_keys=True).encode()
    ).hexdigest()
    return {
        "schema_version": WORKFLOW_SCHEMA_VERSION,
        "mode": "review_only",
        "deterministic": True,
        "ai_used": False,
        "network_requests_sent": 0,
        "executions": 0,
        "commands_emitted": 0,
        "auto_confirmations": 0,
        "ledger_modified": False,
        "scope_modified": False,
        "finding_confirmed": False,
        "documental_complete": documental_complete,
        "absence_of_vulnerability_inferred": False,
        "bundle_id": bundle_id,
        "candidate_id": candidate_id,
        "tasks": tasks,
        "next_reviewable_tasks": actionable,
        "stop_conditions": sorted(stops),
        "should_stop": bool(stops - {"task_budget_exhausted"}) and not actionable or documental_complete,
        "artifact_hashes": dict(sorted(hashes.items())),
        "resume": {**counters, "resumed": prior is not None},
        "memory": memory_info,
        "state_digest": state_digest,
    }


def _apply_gap_plan(
    n: dict[str, Any], plan: Mapping[str, Any] | None, candidate_id: str | None, stops: set[str]
) -> None:
    """Reuse the Evidence-Gap Planner result; never recompute or reprioritize it."""
    if plan is None:
        n["status"] = "ready_for_review"
        n["reason_codes"].append("evidence_gap_plan_not_provided")
        n["missing_requirements"].append("evidence_gap_plan")
        return
    if validate_plan(plan) or plan.get("status") != "ok":
        n.update(status="invalidated", blocked_reason="evidence_gap_plan_invalid")
        n["reason_codes"].append("evidence_gap_plan_invalid")
        stops.add("invalid_reference")
        return
    steps = [
        s
        for s in plan.get("plan") or []
        if isinstance(s, dict)
        and (
            candidate_id is None
            or s.get("candidate_id") == candidate_id
            or candidate_id in (s.get("also_applies_to") or [])
        )
    ]
    cand = [
        c
        for c in plan.get("candidates") or []
        if isinstance(c, dict) and (candidate_id is None or c.get("candidate_id") == candidate_id)
    ]
    n["source_artifacts"].append("evidence_gap_plan")
    if any(c.get("status") == "blocked" for c in cand):
        n.update(status="blocked", blocked_reason="evidence_gap_planner_blocked")
        n["reason_codes"].append("evidence_gap_planner_blocked")
        stops.add("permissions_missing")
        return
    if steps:
        n.update(status="blocked", blocked_reason="evidence_gaps_open")
        n["reason_codes"].append("evidence_gaps_open")
        n["missing_requirements"].extend(str(s.get("missing_requirement")) for s in steps)
        n["evidence_refs"] = sorted({str(r) for s in steps for r in s.get("evidence_refs") or []})
        stops.add("missing_evidence")
        return
    n["status"] = "completed_by_evidence"
    n["reason_codes"].append("evidence_gap_plan_no_open_gaps")
    n["completion_basis"] = "evidence_gap_plan:no_open_gaps"


def _memory_check(
    memory: Mapping[str, Any] | None, bundle_id: str | None, nodes: Mapping[str, Mapping[str, Any]]
) -> dict[str, Any]:
    """Investigation Memory is advisory: reused only with the same bundle and matching verified state."""
    if memory is None:
        return {"used": False, "reason": "not_provided", "inconsistent_stages": []}
    if not bundle_id or memory.get("bundle_id") != bundle_id:
        return {"used": False, "reason": "bundle_mismatch", "inconsistent_stages": []}
    stages = memory.get("stages") if isinstance(memory.get("stages"), dict) else {}
    assert isinstance(stages, dict)
    bad = sorted(s for s, st in stages.items() if s in nodes and nodes[s]["status"] != st)
    return {"used": not bad, "reason": "consistent" if not bad else "state_mismatch", "inconsistent_stages": bad}


def memory_stages(workflow: Mapping[str, Any]) -> dict[str, dict[str, str]]:
    """Stage summary compatible with ``InvestigationMemory.save_snapshot`` (<=20 stages)."""
    return {str(t["stage"]): {"status": str(t["status"])} for t in workflow.get("tasks") or []}


def minimized_view(workflow: Mapping[str, Any]) -> dict[str, Any]:
    """Data minimized for an optional AI explainer: ids, stages, states, reason codes only."""
    return {
        "tasks": [
            {k: t[k] for k in ("task_id", "stage", "status", "reason_codes", "evidence_refs")}
            for t in workflow.get("tasks") or []
        ],
        "stop_conditions": list(workflow.get("stop_conditions") or []),
    }


def explain_workflow(
    workflow: Mapping[str, Any], explainer: Callable[[dict[str, Any]], object] | None
) -> dict[str, Any]:
    """Ask an optional local model to *describe* a computed workflow.

    The explainer receives only ``minimized_view`` and must return
    ``{"sections": [{"text": str, "task_refs": [...], "evidence_refs": [...]}]}``.
    Sections citing unknown tasks/evidence or proposing actions/approvals are
    discarded. The workflow itself is never modified.
    """
    result: dict[str, Any] = {"ai_used": False, "accepted_sections": [], "rejected_sections": 0, "state_changed": False}
    if explainer is None:
        return result
    before = json.dumps(workflow, sort_keys=True, default=str)
    try:
        raw = explainer(minimized_view(workflow))
    except Exception:  # noqa: BLE001 - explainer is optional and untrusted
        result["error"] = "explainer_failed"
        return result
    result["ai_used"] = True
    tasks = {str(t["task_id"]) for t in workflow.get("tasks") or []}
    evidence = {str(r) for t in workflow.get("tasks") or [] for r in t.get("evidence_refs") or []}
    sections = raw.get("sections") if isinstance(raw, dict) else None
    for sec in sections if isinstance(sections, list) else []:
        if not isinstance(sec, dict) or not isinstance(sec.get("text"), str):
            result["rejected_sections"] += 1
            continue
        trefs, ered = sec.get("task_refs") or [], sec.get("evidence_refs") or []
        ok = (
            isinstance(trefs, list)
            and isinstance(ered, list)
            and bool(trefs)
            and all(isinstance(r, str) and r in tasks for r in trefs)
            and all(isinstance(r, str) and r in evidence for r in ered)
            and not _FORBIDDEN_AI.search(sec["text"])
            and not any(k in sec for k in ("status", "new_tasks", "execution_allowed", "approve", "priority"))
        )
        if ok:
            result["accepted_sections"].append(
                {"text": sec["text"][:2000], "task_refs": sorted(trefs), "evidence_refs": sorted(ered)}
            )
        else:
            result["rejected_sections"] += 1
    result["state_changed"] = json.dumps(workflow, sort_keys=True, default=str) != before
    return result


def validate_workflow(workflow: Mapping[str, Any]) -> list[str]:
    """Contract check; empty list means the workflow honours the review-only invariants."""
    problems: list[str] = []
    if workflow.get("schema_version") != WORKFLOW_SCHEMA_VERSION:
        problems.append("schema_version")
    for key in ("network_requests_sent", "executions", "commands_emitted", "auto_confirmations"):
        if workflow.get(key) != 0:
            problems.append(f"nonzero:{key}")
    for key in ("finding_confirmed", "ledger_modified", "scope_modified", "ai_used"):
        if workflow.get(key) is not False:
            problems.append(f"flag:{key}")
    ids = {t.get("task_id") for t in workflow.get("tasks") or []}
    for t in workflow.get("tasks") or []:
        if t.get("execution_allowed") is not False or t.get("finding_confirmed") is not False:
            problems.append(f"{t.get('task_id')}:unsafe_flags")
        if t.get("status") not in STATES:
            problems.append(f"{t.get('task_id')}:status")
        if any(p not in ids for p in t.get("prerequisites") or []):
            problems.append(f"{t.get('task_id')}:unknown_prerequisite")
    by_id = {t.get("task_id"): t for t in workflow.get("tasks") or []}
    for t in workflow.get("tasks") or []:
        if t.get("status") in DONE_STATES and any(
            by_id.get(p, {}).get("status") not in DONE_STATES for p in t.get("prerequisites") or []
        ):
            problems.append(f"{t.get('task_id')}:dependency_violated")
    return problems
