"""Offline capture inventory for human review, reusing the evidence importer."""

from __future__ import annotations

import hashlib
from html import escape
from pathlib import Path
from typing import Any, cast

from ..analysis.evidence_engine import MAX_INPUT_BYTES, MAX_INPUT_FILES, import_evidence
from ..analysis.har_provenance import path_ref
from ..core.private_files import read_private_input


def render_capture_dossier_markdown(dossier: dict[str, Any]) -> str:
    """Render the same intake inventory for a human, without loading captures."""

    def text(value: object) -> str:
        safe = escape(str(value)).replace("\n", " ").replace("\r", " ")
        for char in ("\\", "`", "*", "_", "[", "]", "|", "#"):
            safe = safe.replace(char, "\\" + char)
        return safe

    summary = dossier["summary"]
    lines = [
        "# Capture intake dossier",
        "",
        "Human review required. Finding confirmed: false.",
        "",
        f"Observations: {summary['records_unique']}; duplicates merged: {summary['duplicates_merged']}.",
        "",
    ]
    controls = {
        "ownership_and_sharing": "Verify resource ownership and legitimate sharing.",
        "distinct_actor_authorization": "Verify distinct actor sessions and their authorization context.",
        "negative_control": "Compare a known denied request under valid owner controls.",
    }
    for row in dossier["observations"]:
        lines.extend(
            [
                f"## Evidence {text(row['evidence_ref'])}",
                "",
                f"Captured HTTP status: {text(row['http_status'])}. Classification: inconclusive.",
                "The capture alone does not establish ownership or unauthorized access.",
                "",
            ]
        )
        for source in row["provenance"]:
            lines.append(
                f"- Source {text(source['source_ref'])}, locator {text(source['locator'])}; SHA-256 {text(source['source_sha256'])}."
            )
        lines.extend(["", "Controls to review:", ""])
        lines.extend("- " + controls[control] for control in row["missing_controls"])
        lines.append("")
    lines.extend(["## Limitations", ""])
    lines.extend("- " + text(value) for value in dossier["limitations"])
    return "\n".join(lines) + "\n"


def build_capture_dossier(paths: list[Path], format_name: str = "auto") -> dict[str, Any]:
    """Deduplicate a bounded import and retain content-free source locators.

    This is an intake dossier. Ownership, authorization, impact and execution
    cannot be established by normalized capture fingerprints alone.
    """
    if not paths or len(paths) > MAX_INPUT_FILES:
        raise ValueError("Capture dossier input count exceeds the importer limit.")
    digests = {
        str(path.resolve()): hashlib.sha256(read_private_input(path, MAX_INPUT_BYTES)).hexdigest() for path in paths
    }
    bundle = cast(dict[str, Any], import_evidence(paths, format_name, "partial"))
    if any(
        hashlib.sha256(read_private_input(path, MAX_INPUT_BYTES)).hexdigest() != digests[str(path.resolve())]
        for path in paths
    ):
        raise ValueError("Capture changed during dossier import.")
    observations = []
    for row in bundle["records"]:
        observations.append(
            {
                "evidence_ref": row["evidence_id"],
                "status": "inconclusive",
                "reason": "capture_observation_requires_human_context",
                "http_status": row["status_code"],
                "provenance": [
                    {
                        "source_ref": path_ref(prov["source_path"]),
                        "source_sha256": digests[prov["source_path"]],
                        "locator": prov["locator"],
                    }
                    for prov in row["provenance"]
                ],
                "missing_controls": ["ownership_and_sharing", "distinct_actor_authorization", "negative_control"],
            }
        )
    return {
        "schema": "bbtk.capture-review-dossier/1",
        "status": "intake_requires_human_review",
        "notice": "Review captured observations and controls before drafting vulnerability claims.",
        "summary": bundle["summary"],
        "capture_origin": bundle.get("capture_origin"),
        "observations": observations,
        "limitations": [
            "No ownership or authorization inferred from HTTP status or fingerprints.",
            "No automatic ledger entries; verified claim dossiers require ledger evidence.",
        ],
        "finding_confirmed": False,
        "ledger_mutated": False,
        "network_requests_sent": 0,
    }
