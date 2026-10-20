from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ..core.redaction import redact_data


def _cell(value: Any) -> str:
    if value is None:
        text = "-"
    elif isinstance(value, (dict, list)):
        text = json.dumps(redact_data(value), ensure_ascii=True, sort_keys=True)
    else:
        text = str(redact_data(value))
    return text.replace("|", "\\|").replace("\r", " ").replace("\n", " ")


def render_evidence_review(data: dict[str, Any], destination: Path) -> Path:
    """Write a redacted Markdown review draft from native JSON evidence; never submits it."""
    safe = redact_data(data)
    if not isinstance(safe, dict):
        raise ValueError("Evidence must be a JSON object.")
    lines = [
        "# Security Finding Review Draft",
        "",
        "> Draft only. Manually verify scope, impact, reproduction and evidence before submission. Nothing is sent to a platform.",
        "",
        "## Observed Result",
        "",
        f"- Type: {_cell(safe.get('type'))}",
        f"- Mode: {_cell(safe.get('mode'))}",
        f"- Target: {_cell(safe.get('url') or safe.get('target'))}",
        f"- Classification: {_cell(safe.get('classification'))}",
        f"- Confirmed by tool: {_cell(safe.get('confirmed'))}",
        f"- Requests attempted: {_cell(safe.get('requests_attempted'))}",
        f"- Stop reason: {_cell(safe.get('stop_reason'))}",
        "",
        "## A/B Comparison Evidence",
        "",
    ]
    steps = safe.get("steps")
    if isinstance(steps, list) and steps:
        fields = (
            "step",
            "account",
            "status_code",
            "duration_ms",
            "application_success",
            "owner_resource_match",
            "actor_resource_match",
            "owner_private_match",
            "actor_private_match",
            "transport_error",
        )
        lines.append("| " + " | ".join(fields) + " |")
        lines.append("| " + " | ".join("---" for _ in fields) + " |")
        for item in steps:
            if not isinstance(item, dict):
                continue
            lines.append("| " + " | ".join(_cell(item.get(field)) for field in fields) + " |")
        lines.append("")
    else:
        lines.extend(["No structured A/B step records were present in this evidence file.", ""])

    results = safe.get("results")
    if isinstance(results, list) and results:
        lines.extend(
            ["## Probe Results", "", "| Probe | Status | Classification | Confirmed |", "| --- | --- | --- | --- |"]
        )
        for item in results:
            if isinstance(item, dict):
                probe = item.get("probe_offset", item.get("payload", item.get("origin", "-")))
                lines.append(
                    "| "
                    + " | ".join(
                        _cell(value)
                        for value in (probe, item.get("status_code"), item.get("classification"), item.get("confirmed"))
                    )
                    + " |"
                )
        lines.append("")

    lines.extend(
        [
            "## Researcher Review",
            "",
            "- Confirm the program policy, affected asset and authorization are still valid.",
            "- Validate the controls and distinguish a candidate from a confirmed impact.",
            "- Remove any remaining sensitive data and add concise reproduction and remediation details.",
            "- This draft is local evidence only; the toolkit does not submit HackerOne reports.",
            "",
        ]
    )
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text("\n".join(lines), encoding="utf-8")
    return destination
