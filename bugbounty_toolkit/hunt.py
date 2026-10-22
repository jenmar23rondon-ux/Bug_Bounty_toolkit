from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from html import escape
import json
from pathlib import Path
from typing import Any

from .core.redaction import redact_url


MODULE_ORDER = ("cors-check", "ssrf-check", "csrf-audit", "open-redirect", "xss", "sqli", "access-check")
_SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}
_FINDING_SEVERITY = {
    "candidate": "high",
    "confirmed": "high",
    "VULNERABLE": "high",
    "possible": "medium",
    "reflected": "medium",
    "possible_csrf": "medium",
    "DÉBIL": "low",
    "DEBIL": "low",
    "weak": "low",
}


@dataclass(frozen=True)
class HuntTask:
    task_id: str
    module: str
    argv: tuple[str, ...]
    estimated_requests: int
    minimum_requests: int
    request_quantum: int
    parameters: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.module not in MODULE_ORDER:
            raise ValueError(f"Unsupported hunt module: {self.module}")
        if not self.task_id or min(self.estimated_requests, self.minimum_requests, self.request_quantum) <= 0:
            raise ValueError("Hunt task budgets must be positive.")
        if self.minimum_requests > self.estimated_requests:
            raise ValueError("Hunt task minimum cannot exceed its estimated request count.")


def parse_module_selection(only: str | None, skip: str | None) -> tuple[str, ...]:
    def parse(value: str | None, flag: str) -> set[str]:
        if value is None:
            return set()
        names = {part.strip().lower() for part in value.split(",") if part.strip()}
        if not names:
            raise ValueError(f"{flag} must name at least one module.")
        unknown = names - set(MODULE_ORDER)
        if unknown:
            raise ValueError(f"Unknown {flag} module(s): {', '.join(sorted(unknown))}.")
        return names

    selected = parse(only, "--only")
    excluded = parse(skip, "--skip")
    return tuple(name for name in MODULE_ORDER if (not selected or name in selected) and name not in excluded)


def _next_quota(task: HuntTask, allocated: int) -> int:
    if allocated == 0:
        return task.minimum_requests
    if allocated >= task.estimated_requests:
        return 0
    return min(task.request_quantum, task.estimated_requests - allocated)


def allocate_request_budgets(tasks: list[HuntTask], max_tests: int) -> dict[str, int]:
    if type(max_tests) is not int or max_tests <= 0:
        raise ValueError("Global hunt budget must be a positive integer.")
    allocations = {task.task_id: 0 for task in tasks}
    remaining = max_tests
    for task in tasks:
        if remaining >= task.minimum_requests:
            allocations[task.task_id] = task.minimum_requests
            remaining -= task.minimum_requests

    while remaining:
        changed = False
        for task in tasks:
            quota = _next_quota(task, allocations[task.task_id])
            if quota and quota <= remaining:
                allocations[task.task_id] += quota
                remaining -= quota
                changed = True
        if not changed:
            break
    return allocations


def redistribute_unused_budget(
    tasks: list[HuntTask], allocations: dict[str, int], start_index: int, unused: int
) -> int:
    """Offer unused quota to later tasks without exceeding any estimate."""
    remaining = max(0, unused)
    while remaining:
        changed = False
        for task in tasks[start_index:]:
            quota = _next_quota(task, allocations[task.task_id])
            if quota and quota <= remaining:
                allocations[task.task_id] += quota
                remaining -= quota
                changed = True
        if not changed:
            break
    return remaining


def plan_fingerprint(payload: dict[str, Any]) -> str:
    import hashlib

    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def summarize_module(module: str, task_results: list[dict[str, Any]]) -> dict[str, Any]:
    evidence_data: list[dict[str, Any]] = []
    evidence_paths: list[str] = []
    statuses = [str(item.get("status", "error")) for item in task_results]
    for item in task_results:
        for raw_path in item.get("evidence_paths", []):
            if not isinstance(raw_path, str):
                continue
            evidence_paths.append(raw_path)
            try:
                value = json.loads(Path(raw_path).read_text(encoding="utf-8"))
            except (OSError, ValueError):
                continue
            if isinstance(value, dict):
                evidence_data.append(value)

    if any(status == "cancelled" for status in statuses):
        status = "cancelled"
    elif any(status == "rate_limited" for status in statuses):
        status = "rate_limited"
    elif any(status == "error" for status in statuses):
        status = "error"
    elif statuses and all(value == "skipped" for value in statuses):
        status = "skipped"
    elif statuses and all(value == "validated" for value in statuses):
        status = "validated"
    else:
        status = "completed"

    labels: Counter[str] = Counter()
    ai_reviews: list[dict[str, Any] | str] = []
    stop_reasons: list[str] = []
    reasons = [str(item["reason"]) for item in task_results if isinstance(item.get("reason"), str)]
    reasons.extend(
        f"error: {item['error_type']}"
        for item in task_results
        if isinstance(item.get("error_type"), str) and not isinstance(item.get("reason"), str)
    )
    inputs_not_tested = sum(
        item["inputs_not_tested"]
        for item in task_results
        if type(item.get("inputs_not_tested")) is int and item["inputs_not_tested"] > 0
    )
    requests_attempted = 0
    for data in evidence_data:
        topic = data.get("type")
        rows = data.get("steps" if topic == "access-control" else "results", [])
        if isinstance(rows, list):
            labels.update(
                row["classification"]
                for row in rows
                if isinstance(row, dict) and isinstance(row.get("classification"), str)
            )
            requests_attempted += len(rows)
        if isinstance(data.get("classification"), str):
            labels[data["classification"]] += 1
        if isinstance(data.get("requests_attempted"), int):
            requests_attempted += max(0, data["requests_attempted"] - (len(rows) if isinstance(rows, list) else 0))
        reason = data.get("stop_reason")
        if isinstance(reason, str):
            stop_reasons.append(reason)
        ai_review = data.get("ai_review")
        if isinstance(ai_review, (dict, str)):
            if isinstance(ai_review, str):
                ai_reviews.append(ai_review)
            elif ai_review.get("status") == "skipped":
                ai_reviews.append({"status": "skipped", "reason": "no_candidate_or_possible_finding"})
            elif ai_review.get("status") == "available":
                assessment = ai_review.get("assessment", {})
                decision = assessment.get("decision") if isinstance(assessment, dict) else None
                reason = (
                    assessment.get("summary", ai_review.get("reason"))
                    if isinstance(assessment, dict)
                    else ai_review.get("reason")
                )
                ai_reviews.append(
                    {
                        "status": "available",
                        "decision": decision
                        if decision in {"candidate", "not_observed", "inconclusive"}
                        else "inconclusive",
                        "reason": reason[:1200] if isinstance(reason, str) else "No reason was returned.",
                        "not_confirmation": True,
                    }
                )
            else:
                ai_reviews.append("unavailable")

    if labels["confirmed"]:
        toolkit_verdict = "confirmed"
    elif labels["candidate"] or labels["VULNERABLE"]:
        toolkit_verdict = "candidate"
    elif labels["possible"]:
        toolkit_verdict = "possible"
    elif labels["DÉBIL"] or labels["DEBIL"] or labels["weak"]:
        toolkit_verdict = "weak"
    elif status in {"skipped", "validated", "error"}:
        toolkit_verdict = status
    else:
        toolkit_verdict = "no_candidate_observed"

    return {
        "module": module,
        "status": status,
        "toolkit_verdict": toolkit_verdict,
        "classification_counts": dict(sorted(labels.items())),
        "requests_attempted": requests_attempted,
        "inputs_not_tested": inputs_not_tested,
        "stop_reasons": sorted(set(stop_reasons)),
        "reasons": reasons,
        "evidence_paths": list(dict.fromkeys(evidence_paths)),
        "ai_reviews": ai_reviews,
    }


def collect_findings(module_summaries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for summary in module_summaries:
        module = summary["module"]
        for raw_path in summary.get("evidence_paths", []):
            try:
                evidence = json.loads(Path(raw_path).read_text(encoding="utf-8"))
            except (OSError, ValueError):
                continue
            if not isinstance(evidence, dict):
                continue
            topic = evidence.get("type")
            if topic == "access-control":
                rows = []
                if evidence.get("classification") in {"candidate", "possible"}:
                    rows.append(evidence)
                if evidence.get("anonymous_classification") == "anonymous_access":
                    rows.append({"classification": "candidate", "finding_kind": "anonymous_access"})
                matrix = evidence.get("matrix", [])
                if isinstance(matrix, list):
                    rows.extend(
                        row
                        for row in matrix
                        if isinstance(row, dict) and row.get("classification") in {"candidate", "possible"}
                    )
            else:
                rows = evidence.get("results", [])
                if topic == "csrf-audit" and evidence.get("classification") in {"possible_csrf", "weak"}:
                    rows = [
                        {
                            "classification": evidence["classification"],
                            "status_code": evidence.get("status_code"),
                        }
                    ]
            if not isinstance(rows, list):
                continue
            for row in rows:
                if not isinstance(row, dict):
                    continue
                classification = row.get("classification")
                if not isinstance(classification, str):
                    continue
                severity = _FINDING_SEVERITY.get(classification)
                if severity is None:
                    continue
                target = row.get("route") or row.get("url") or evidence.get("url") or evidence.get("target")
                ai_review = evidence.get("ai_review")
                ai_review_data = ai_review if isinstance(ai_review, dict) else {}
                ai_assessment = ai_review_data.get("assessment", {})
                ai_decision = ai_assessment.get("decision") if isinstance(ai_assessment, dict) else None
                if ai_decision not in {"candidate", "not_observed", "inconclusive"}:
                    ai_decision = None
                ai_reason = (
                    ai_assessment.get("summary", ai_review_data.get("reason"))
                    if isinstance(ai_assessment, dict)
                    else None
                )
                findings.append(
                    {
                        "module": module,
                        "type": str(row.get("finding_kind") or topic or module),
                        "severity": severity,
                        "classification": classification,
                        "target": redact_url(target) if isinstance(target, str) else None,
                        "parameter": row.get("parameter") if isinstance(row.get("parameter"), str) else None,
                        "status_code": row.get("status_code") if type(row.get("status_code")) is int else None,
                        "ai_decision": ai_decision,
                        "ai_reason": ai_reason[:1200] if isinstance(ai_reason, str) else None,
                        "evidence_path": raw_path,
                    }
                )
    findings.sort(
        key=lambda row: (
            _SEVERITY_ORDER.get(row["severity"], 99),
            str(row["type"]).lower(),
            str(row["module"]).lower(),
            str(row.get("target") or "").lower(),
        )
    )
    return findings


def render_hunt_html(report: dict[str, Any], destination: Path) -> Path:
    modules = report.get("modules", [])
    findings = report.get("findings", [])
    module_rows = "\n".join(
        "<tr>"
        + "".join(
            f"<td>{escape(str(module.get(key, '-')))}</td>"
            for key in ("module", "status", "toolkit_verdict", "requests_attempted")
        )
        + f"<td>{escape(_ai_review_text(module.get('ai_reviews', [])))}</td>"
        + f"<td>{escape(', '.join(module.get('evidence_paths', [])) or '-')}</td></tr>"
        for module in modules
        if isinstance(module, dict)
    )
    finding_rows = "\n".join(
        "<tr>"
        + "".join(
            f"<td>{escape(str(finding.get(key) if finding.get(key) is not None else '-'))}</td>"
            for key in (
                "severity",
                "type",
                "module",
                "classification",
                "target",
                "parameter",
                "status_code",
                "ai_decision",
                "ai_reason",
            )
        )
        + "</tr>"
        for finding in findings
        if isinstance(finding, dict)
    )
    html = f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Bug Bounty Hunt Report</title>
  <style>
    body {{ font-family: Arial, sans-serif; margin: 24px; color: #17202a; max-width: 1200px; }}
    table {{ border-collapse: collapse; width: 100%; margin: 16px 0 28px; }}
    th, td {{ border: 1px solid #d9e2ec; padding: 8px; text-align: left; font-size: 14px; overflow-wrap: anywhere; }}
    th {{ background: #f0f4f8; }}
  </style>
</head>
<body>
  <h1>Bug Bounty Hunt Report</h1>
  <p><strong>Program:</strong> {escape(str(report.get("program", "-")))}</p>
  <p><strong>Base URL:</strong> {escape(str(report.get("base_url", "-")))}</p>
  <p><strong>Status:</strong> {escape(str(report.get("status", "-")))}</p>
  <p><strong>Requests:</strong> {escape(str(report.get("budget", {}).get("requests_started", 0)))} / {escape(str(report.get("budget", {}).get("max_tests", 0)))}</p>
  <p>AI assessments are a secondary opinion and never confirm a vulnerability.</p>
  <h2>Module Verdicts</h2>
  <table><thead><tr><th>Module</th><th>Status</th><th>Toolkit verdict</th><th>Requests</th><th>AI second opinion</th><th>Evidence</th></tr></thead>
  <tbody>{module_rows or '<tr><td colspan="6">No modules were selected.</td></tr>'}</tbody></table>
  <h2>Findings, ordered by severity and type</h2>
  <table><thead><tr><th>Severity</th><th>Type</th><th>Module</th><th>Classification</th><th>Target</th><th>Parameter</th><th>Status</th><th>AI decision</th><th>AI reason</th></tr></thead>
  <tbody>{finding_rows or '<tr><td colspan="9">No candidate findings.</td></tr>'}</tbody></table>
</body>
</html>
"""
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(html, encoding="utf-8")
    return destination


def _ai_review_text(reviews: object) -> str:
    if not isinstance(reviews, list) or not reviews:
        return "-"
    summaries: list[str] = []
    for review in reviews:
        if isinstance(review, str):
            summaries.append(review)
        elif isinstance(review, dict):
            status = review.get("status", "unavailable")
            if status == "available":
                summaries.append(
                    f"{review.get('decision', 'inconclusive')}: {review.get('reason', 'No reason returned.')}"
                )
            else:
                summaries.append(str(status))
    return " | ".join(summaries) or "-"
