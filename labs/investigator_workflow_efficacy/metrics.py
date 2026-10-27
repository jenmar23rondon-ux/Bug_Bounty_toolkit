"""Compare arm dispositions to pre-declared lab labels. Does not retune labels."""

from __future__ import annotations

import json
from typing import Any

NOT_MEASURED: dict[str, str] = {
    "human_minutes": "No human investigator was timed. Scripted wall-clock is not researcher time.",
    "human_manual_actions": "Scripted action counts are a checklist replay, not observed human clicks.",
    "human_researcher_errors": "No human reviewer participated.",
    "human_dossier_quality": "The checklist score is paperwork completeness, not a human quality judgment.",
    "human_time_to_first_reviewable": "No human clock was started.",
    "human_time_to_complete_report": "No human clock was started.",
    "field_bug_bounty_efficacy": "Disposable fixture only. Do not cite these rows as program results.",
    "browser_dom_execution": "Chromium was not launched. DOM rows use static source text only.",
    "real_world_program": "The opt-in real-world protocol was not executed.",
}

PRIOR_KNOWLEDGE_BIAS = (
    "The same change set declared the lab behavior, the labels, the manual checklist, "
    "and the bbtk adapter. The adapter follows public function contracts and was not "
    "refit after the FINAL split ran. This is not a blinded study."
)

MANUAL_TOOLS = (
    "checklist",
    "http",
    "checklist",
    "editor",
    "checklist",
    "checklist",
    "checklist",
)
BBTK_TOOLS = (
    "checklist",
    "http",
    "hash",
    "bbtk-module",
    "checklist",
    "dossier",
    "workflow",
    "redaction",
    "checklist",
)


def tool_switches(tools: tuple[str, ...]) -> int:
    previous = ""
    switches = 0
    for tool in tools:
        if previous and tool != previous:
            switches += 1
        previous = tool
    return switches


def score_arm(cases: list[dict[str, Any]], rows: list[dict[str, Any]]) -> dict[str, Any]:
    by_id = {row["case_id"]: row for row in rows}
    tp = fp = fn = tn = conservative = over_reject = correct = 0
    confirmed = 0
    missing = 0
    incomplete = 0
    checklist_total = 0
    mismatches: list[dict[str, str]] = []
    for case in cases:
        row = by_id[str(case["id"])]
        truth = str(case["truth"])
        got = str(row["disposition"])
        if row.get("finding_confirmed"):
            confirmed += 1
        missing += int(row.get("missing_evidence") or 0)
        incomplete += int(row.get("incomplete_repro") or 0)
        checklist_total += int(row.get("checklist") or 0)
        if got == truth:
            correct += 1
        else:
            mismatches.append({"id": str(case["id"]), "truth": truth, "got": got, "reason": str(row.get("reason"))})
        if truth == "review" and got == "review":
            tp += 1
        elif got == "review" and truth != "review":
            fp += 1
        elif truth == "review" and got != "review":
            fn += 1
        else:
            tn += 1
            if truth == "reject" and got == "abstain":
                conservative += 1
            elif truth == "abstain" and got == "reject":
                over_reject += 1
    total = len(cases) or 1
    return {
        "cases": len(cases),
        "correct": correct,
        "accuracy": round(correct / total, 3),
        "valid_found": tp,
        "fp_accepted": fp,
        "fn": fn,
        "tn": tn,
        "conservative_abstain": conservative,
        "over_reject": over_reject,
        "candidates_reviewed": len(rows),
        "finding_confirmed_true": confirmed,
        "missing_evidence": missing,
        "incomplete_repro": incomplete,
        "dossier_checklist_mean": round(checklist_total / total, 3),
        "mismatches": mismatches,
    }


def arm_envelope(
    name: str,
    scored: dict[str, Any],
    *,
    wall_clock_seconds: float,
    seconds_to_first_review: float | None,
    seconds_to_report: float,
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    tools = MANUAL_TOOLS if name == "manual" else BBTK_TOOLS
    cases = int(scored["cases"])
    payload = {
        "arm": name,
        "scripted_actions": len(tools) * cases,
        "scripted_tool_switches": tool_switches(tools) * cases,
        "distinct_tools": len(set(tools)),
        "scripted_wall_clock_seconds": round(wall_clock_seconds, 6),
        "scripted_seconds_to_first_reviewable": None
        if seconds_to_first_review is None
        else round(seconds_to_first_review, 6),
        "scripted_seconds_to_report_draft": round(seconds_to_report, 6),
        **scored,
    }
    if extra:
        payload.update(extra)
    return payload


def comparison_markdown(report: dict[str, Any]) -> str:
    lines = [
        "# Manual vs bbtk on the disposable investigator lab",
        "",
        "Fixture results only. Human timing is NOT_MEASURED.",
        "",
        "| Split | Arm | Cases | Correct | Valid found | FP accepted | FN | Conservative abstain | Over-reject | Actions | Tool switches | External | Secret leaks | finding_confirmed true | Checklist mean |",
        "| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |",
    ]
    for split, payload in report["splits"].items():
        for arm_name in ("manual", "bbtk"):
            arm = payload[arm_name]
            lines.append(
                "| {split} | {arm} | {cases} | {correct} | {valid} | {fp} | {fn} | {cons} | {over} | {actions} | {switches} | {ext} | {leaks} | {confirmed} | {checklist} |".format(
                    split=split,
                    arm=arm_name,
                    cases=arm["cases"],
                    correct=arm["correct"],
                    valid=arm["valid_found"],
                    fp=arm["fp_accepted"],
                    fn=arm["fn"],
                    cons=arm["conservative_abstain"],
                    over=arm["over_reject"],
                    actions=arm["scripted_actions"],
                    switches=arm["scripted_tool_switches"],
                    ext=payload["external_requests"],
                    leaks=payload["secret_leaks"],
                    confirmed=arm["finding_confirmed_true"],
                    checklist=arm["dossier_checklist_mean"],
                )
            )
    lines.extend(
        [
            "",
            "## NOT_MEASURED",
            "",
            "| Item | Reason |",
            "| --- | --- |",
        ]
    )
    for key, reason in NOT_MEASURED.items():
        lines.append(f"| {key} | {reason} |")
    lines.append("")
    return "\n".join(lines)


def dumps(payload: dict[str, Any]) -> str:
    return json.dumps(payload, indent=2, sort_keys=True) + "\n"
