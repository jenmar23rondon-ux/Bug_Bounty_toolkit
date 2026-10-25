"""Deterministic research triage kept separate from confidence and severity."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .skill_router import SKILL_REGISTRY, load_hypotheses_file

_CATEGORY_TO_SKILL = {
    "access_control": "bugbounty-access-control",
    "xss": "bugbounty-xss",
    "sqli": "bugbounty-sqli",
    "cors": "bugbounty-cors",
    "open_redirect": "bugbounty-open-redirect",
    "jwt": "bugbounty-jwt",
}
_POTENTIAL_IMPACT = {
    "access_control": "high",
    "sqli": "high",
    "jwt": "high",
    "xss": "medium",
    "cors": "medium",
    "info_disclosure": "medium",
    "open_redirect": "low",
    "unknown": "unknown",
}
_IMPACT_POINTS = {"high": 20, "medium": 12, "low": 5, "unknown": 0}


def _risk(kind: str, budget_cost: int) -> tuple[str, int]:
    if kind == "offline":
        return "low", 0
    if budget_cost >= 4:
        return "high", 10
    return "medium", 5


def _score(hypothesis: dict[str, Any], impact: str, budget_cost: int, risk_penalty: int) -> int:
    supporting = len(hypothesis["evidence_for"])
    contradictory = len(hypothesis["evidence_against"])
    missing_controls = len(hypothesis["missing_controls"])
    evidence_points = min(supporting, 3) * 10
    controls_points = max(0, 10 - min(missing_controls, 5) * 2)
    impact_points = _IMPACT_POINTS[impact]
    contradiction_penalty = min(contradictory, 3) * 5
    cost_penalty = min(budget_cost * 2, 12)
    return max(
        0,
        min(
            100,
            evidence_points + controls_points + impact_points - contradiction_penalty - cost_penalty - risk_penalty,
        ),
    )


def _priority(score: int) -> str:
    if score >= 60:
        return "P1"
    if score >= 35:
        return "P2"
    if score > 0:
        return "P3"
    return "hold"


def prioritize_hypotheses(
    data: dict[str, Any], hypotheses: list[tuple[str, dict[str, Any]]], program: str, max_tests: int
) -> dict[str, object]:
    """Rank research steps deterministically without asserting impact or validating a finding."""
    if not program or len(program) > 80:
        raise ValueError("A valid program name is required.")
    if type(max_tests) is not int or max_tests <= 0:
        raise ValueError("--max-tests must be a positive integer.")

    groups = data.get("groups")
    total_groups = len(groups) if isinstance(groups, list) else len(hypotheses)
    ranked: list[dict[str, Any]] = []
    for group_id, hypothesis in hypotheses:
        category = hypothesis["category"]
        skill_name = _CATEGORY_TO_SKILL.get(category, "bugbounty-executor")
        skill = SKILL_REGISTRY[skill_name]
        impact = _POTENTIAL_IMPACT[category]
        operational_risk, risk_penalty = _risk(skill.kind, skill.budget_cost)
        score = _score(hypothesis, impact, skill.budget_cost, risk_penalty)
        confidence = hypothesis["confidence"]
        summary = " ".join(hypothesis["summary"].split())[:300]
        ranked.append(
            {
                "group_id": group_id,
                "category": category,
                "summary": summary,
                "skill": skill_name,
                "research_priority": _priority(score),
                "priority_score": score,
                "hypothesis_confidence": {
                    "value": confidence,
                    "source": "hypothesis; not independently verified",
                },
                "potential_impact": {
                    "band": impact,
                    "basis": "category heuristic only; impact has not been demonstrated",
                },
                "demonstrated_severity": "not_assessed",
                "evidence_quality": {
                    "supporting_records": len(hypothesis["evidence_for"]),
                    "contradictory_records": len(hypothesis["evidence_against"]),
                    "missing_controls": list(hypothesis["missing_controls"]),
                    "repeatability": "multiple_records_need_independence_review"
                    if len(hypothesis["evidence_for"]) > 1
                    else "single_or_no_supporting_record",
                },
                "check_cost": {
                    "estimated_request_units": skill.budget_cost,
                    "operational_risk": operational_risk,
                    "estimate_note": "Registry estimate only; the selected command enforces its own request budget.",
                },
                "scope_status": "not_verified" if skill.kind == "http" else "not_applicable_to_offline_step",
                "human_approval_required": True,
            }
        )

    ranked.sort(key=lambda item: (-int(item["priority_score"]), str(item["group_id"])))
    remaining = max_tests
    plan: list[dict[str, object]] = []
    for index, item in enumerate(ranked, start=1):
        skill = SKILL_REGISTRY[str(item["skill"])]
        cost = skill.budget_cost
        within_budget = cost <= remaining
        if within_budget:
            remaining -= cost
        else:
            item["research_priority"] = "deferred"
        item["budget_status"] = "within_budget" if within_budget else "deferred_over_budget"
        item["execution_status"] = "not_started_requires_human_approval"
        plan.append(
            {
                "step": index,
                "group_id": item["group_id"],
                "skill": skill.name,
                "command_template": skill.commands[0].format(program=program),
                "kind": skill.kind,
                "estimated_request_units": cost,
                "why": f"Priority score {item['priority_score']}; {item['potential_impact']['basis']}.",
                "status": item["budget_status"],
                "approval_required": True,
                "scope_status": item["scope_status"],
            }
        )

    skipped = max(0, total_groups - len(hypotheses))
    missing_inputs = [
        "Verify program authorization, target scope, exclusions and automation policy before any HTTP check."
    ]
    if skipped:
        missing_inputs.append(f"{skipped} group(s) had no valid reviewed hypothesis and were not prioritized.")
    for item in ranked:
        if item["scope_status"] == "not_verified":
            missing_inputs.append(f"{item['skill']}: verify the exact endpoint is in scope before execution.")
    if not hypotheses:
        missing_inputs.append(
            "No valid reviewed hypotheses were available; inspect the evidence and model-review status."
        )

    return {
        "type": "investigation-prioritization",
        "schema_version": "1.0",
        "notice": "Research priority, hypothesis confidence and demonstrated severity are separate; this is not confirmation.",
        "program": program,
        "status": "review_required" if hypotheses else "insufficient_input",
        "max_tests": max_tests,
        "estimated_budget_remaining": remaining,
        "scope_validated": False,
        "human_approval_required": True,
        "network_requests_sent": 0,
        "ollama_calls": 0,
        "unreviewed_groups": skipped,
        "missing_inputs": list(dict.fromkeys(missing_inputs)),
        "items": ranked,
        "plan": plan,
    }


def prioritize_hypotheses_file(path: Path, program: str, max_tests: int) -> dict[str, object]:
    """Read saved hypotheses and create a local-only, approval-gated triage plan."""
    data, hypotheses = load_hypotheses_file(path)
    return prioritize_hypotheses(data, hypotheses, program, max_tests)


def write_prioritization_report(result: dict[str, object], path: Path, force: bool = False) -> Path:
    """Write a JSON triage report, refusing replacement unless the caller opts in."""
    path.parent.mkdir(parents=True, exist_ok=True)
    if force:
        path.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    else:
        with path.open("x", encoding="utf-8") as output:
            output.write(json.dumps(result, indent=2, sort_keys=True) + "\n")
    return path
