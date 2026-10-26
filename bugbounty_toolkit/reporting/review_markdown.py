from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ..core.redaction import RedactionDestination, redact_data
from .finding_report import build_evidence_finding_report, render_evidence_report_markdown


def _shareable(value: object) -> object:
    return redact_data(value, destination=RedactionDestination.SHAREABLE_REPORT)


def _cell(value: Any) -> str:
    if value is None:
        text = "-"
    elif isinstance(value, (dict, list)):
        text = json.dumps(_shareable(value), ensure_ascii=True, sort_keys=True)
    else:
        text = str(_shareable(value))
    return text.replace("|", "\\|").replace("\r", " ").replace("\n", " ")


def render_evidence_review(
    data: dict[str, Any], destination: Path, program: str = "Información pendiente", source_name: str | None = None
) -> Path:
    """Write a professional, redacted report draft from supplied JSON evidence."""
    report = build_evidence_finding_report(
        data,
        program=program,
        source_name=source_name or destination.stem,
    )
    safe = _shareable(data)
    if not isinstance(safe, dict):
        raise ValueError("Evidence must be a JSON object.")
    lines = [render_evidence_report_markdown(report), "## Observed Result", ""]
    for key in ("type", "mode", "url", "target", "classification", "confirmed", "requests_attempted", "stop_reason"):
        lines.append(f"- {key}: {_cell(safe.get(key))}")
    lines.extend(["", "## A/B Comparison Evidence", ""])
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
        lines.extend(["| " + " | ".join(fields) + " |", "| " + " | ".join("---" for _ in fields) + " |"])
        for item in steps:
            if isinstance(item, dict):
                lines.append("| " + " | ".join(_cell(item.get(field)) for field in fields) + " |")
    else:
        lines.append("No structured A/B step records were present in this evidence file.")
    results = safe.get("results")
    if isinstance(results, list) and results:
        lines.extend(
            ["", "## Probe Results", "", "| Probe | Status | Classification | Confirmed |", "| --- | --- | --- | --- |"]
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
    lines.extend(
        [
            "",
            "## Researcher Review",
            "",
            "- Confirm the program policy, affected asset and authorization are still valid.",
            "- Verify the controls and distinguish a candidate from technically validated behavior.",
            "- Supply missing reproduction, impact and severity evidence without inferring it from an HTTP status.",
            "- This draft is local evidence only; the toolkit does not submit HackerOne reports.",
            "",
        ]
    )
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text("\n".join(lines), encoding="utf-8")
    return destination
