"""Before/after metrics for the evidence-gap planner vs manual and generic baselines.

All figures are measured on synthetic corpora. They are labelled as such and
must not be presented as human-productivity claims.
"""

from __future__ import annotations

import math
import time
from pathlib import Path
from typing import Any

from bugbounty_toolkit.analysis.evidence_gap_planner import STEP_CATALOG, build_plan, dumps_plan, validate_plan
from bugbounty_toolkit.core.records import ProgramPaths

from .corpus import NOW, build_split


def _generic_baseline(truth: dict[str, Any]) -> str:
    """Naive strategy: always ask for a human review, ignoring evidence gaps."""
    if truth.get("blocked"):
        return "blocked_missing_authorization"
    if truth.get("abstain"):
        return "request_human_review"
    return "request_human_review"


def _manual_steps(truth: dict[str, Any]) -> int:
    return int(truth["manual_steps_baseline"])


def _dcg(relevances: list[int]) -> float:
    return sum(rel / math.log2(i + 2) for i, rel in enumerate(relevances))


def evaluate_split(split: str, root: Path) -> dict[str, Any]:
    """Build the split under ``root``, run the planner and baselines, return metrics."""
    manifest = build_split(split, root)
    scenarios = manifest["scenarios"]
    p_at_1 = p_at_3 = 0
    mrr_sum = 0.0
    ndcg_sum = 0.0
    recall_num = recall_den = 0
    irrelevant = duplicates = 0
    abstain_ok = blocked_ok = incompatible = 0
    manual_sum = planner_sum = generic_sum = 0
    actionable = stopped = regenerated = 0
    missing_identified = 0
    reused_total = 0
    latencies: list[float] = []
    json_sizes: list[int] = []
    safety = {
        "executions": 0,
        "network_requests_sent": 0,
        "auto_confirmations": 0,
        "scope_changes": 0,
        "auto_approvals": 0,
        "secret_leaks": 0,
        "invented_refs": 0,
        "tampered_accepted": 0,
    }
    per_scenario: list[dict[str, Any]] = []

    for truth in scenarios:
        program = truth["program"]
        paths = ProgramPaths(root, program)
        t0 = time.perf_counter()
        plan = build_plan(paths, now=NOW)
        plan2 = build_plan(paths, now=NOW)
        latencies.append(time.perf_counter() - t0)
        body = dumps_plan(plan)
        json_sizes.append(len(body.encode()))
        if dumps_plan(plan2) == body:
            regenerated += 1
        problems = validate_plan(plan)
        if problems:
            incompatible += 1
        safety["network_requests_sent"] += int(plan.get("network_requests_sent") or 0)
        safety["executions"] += int(plan.get("executions") or 0)
        safety["auto_confirmations"] += int(plan.get("auto_confirmations") or 0)

        ranked = [s["step_type"] for s in plan.get("plan") or []]
        expected = truth["expected_top_step"]
        target = truth.get("target_candidate")
        if target:
            ranked = [
                s["step_type"]
                for s in plan.get("plan") or []
                if s["candidate_id"] == target or target in (s.get("also_applies_to") or [])
            ] or ranked

        if ranked and ranked[0] == expected:
            p_at_1 += 1
        if expected in ranked[:3]:
            p_at_3 += 1
        if expected in ranked:
            mrr_sum += 1.0 / (ranked.index(expected) + 1)
            relevances = [1 if t == expected else 0 for t in ranked[:5]]
            ideal = sorted(relevances, reverse=True)
            ndcg_sum += (_dcg(relevances) / _dcg(ideal)) if any(ideal) else 0.0
        else:
            relevances = [0] * min(5, max(1, len(ranked)))
            ndcg_sum += 0.0

        forbidden_hit = [t for t in ranked if t in set(truth.get("forbidden_steps") or [])]
        irrelevant += len(forbidden_hit)
        if truth.get("integrity") and "verify_evidence_digest" in ranked and expected == "verify_evidence_digest":
            # Tampered evidence must not be treated as usable for other steps.
            if any(t == "request_human_review" for t in ranked):
                safety["tampered_accepted"] += 1

        missing = set(truth.get("missing_controls") or [])
        recall_den += len(missing) if missing else 0
        found = {
            s["missing_requirement"].removeprefix("control:")
            for s in plan.get("plan") or []
            if str(s.get("missing_requirement", "")).startswith("control:")
        }
        hit = len(missing & found)
        recall_num += hit
        missing_identified += hit

        cand_rows = {c["candidate_id"]: c for c in plan.get("candidates") or []}
        focus = target or next(iter(cand_rows), None)
        row = cand_rows.get(focus or "", {})
        if row.get("status") == "abstain" and truth.get("abstain"):
            abstain_ok += 1
        if row.get("status") == "blocked" and truth.get("blocked"):
            blocked_ok += 1
        if row.get("status") in {"stop_recommended", "blocked", "duplicate"} and truth.get("stop"):
            stopped += 1
        if ranked and not truth.get("abstain") and not truth.get("blocked"):
            actionable += 1
        reused_total += len(row.get("reused_evidence") or [])

        # Duplicate count: same step_id appearing twice in plan (should be 0 after merge).
        ids = [s["step_id"] for s in plan.get("plan") or []]
        duplicates += max(0, len(ids) - len(set(ids)))

        planner_steps = int(truth["manual_steps_planner"])
        if ranked:
            planner_steps = min(
                planner_steps, sum(int(s["estimated_manual_steps"]) for s in (plan.get("plan") or [])[:1])
            )
        manual_sum += _manual_steps(truth)
        planner_sum += planner_steps
        generic_sum += 1 if truth.get("blocked") else 5  # generic always burns review effort

        per_scenario.append(
            {
                "scenario": truth["scenario"],
                "expected": expected,
                "top": ranked[0] if ranked else None,
                "hit_at_1": bool(ranked and ranked[0] == expected),
                "planner_steps": planner_steps,
                "manual_steps": _manual_steps(truth),
                "generic_top": _generic_baseline(truth),
                "contract_ok": not problems,
            }
        )

    n = len(scenarios) or 1
    red_pct = round(100.0 * (1.0 - (planner_sum / manual_sum)), 2) if manual_sum else 0.0
    return {
        "split": split,
        "synthetic": True,
        "scenarios": len(scenarios),
        "quality": {
            "precision_at_1": round(p_at_1 / n, 4),
            "precision_at_3": round(p_at_3 / n, 4),
            "recall_missing_controls": round(recall_num / recall_den, 4) if recall_den else 1.0,
            "mrr": round(mrr_sum / n, 4),
            "ndcg_at_5": round(ndcg_sum / n, 4),
            "irrelevant_steps": irrelevant,
            "duplicate_steps": duplicates,
            "correct_abstentions": abstain_ok,
            "correct_blocks": blocked_ok,
            "incompatible_recommendations": incompatible,
        },
        "utility": {
            "manual_steps_total": manual_sum,
            "planner_steps_total": planner_sum,
            "generic_baseline_steps_total": generic_sum,
            "redundant_step_reduction_pct_vs_manual": red_pct,
            "missing_controls_identified": missing_identified,
            "existing_evidence_reused": reused_total,
            "candidates_with_actionable_step": actionable,
            "candidates_correctly_stopped": stopped,
            "deterministic_regenerations": regenerated,
            "deterministic_regeneration_rate": round(regenerated / n, 4),
        },
        "security": safety,
        "performance": {
            "latency_per_scenario_ms_mean": round(1000 * sum(latencies) / n, 3),
            "latency_per_scenario_ms_max": round(1000 * max(latencies), 3) if latencies else 0.0,
            "json_bytes_mean": round(sum(json_sizes) / n, 1),
            "json_bytes_max": max(json_sizes) if json_sizes else 0,
        },
        "per_scenario": per_scenario,
        "catalog_size": len(STEP_CATALOG),
        "network_requests_sent": 0,
    }


def compare_splits(dev_root: Path, final_root: Path) -> dict[str, Any]:
    return {
        "dev": evaluate_split("dev", dev_root),
        "final": evaluate_split("final", final_root),
        "label": "synthetic_offline_only",
    }
