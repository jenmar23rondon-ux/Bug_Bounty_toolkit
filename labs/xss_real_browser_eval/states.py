"""Map browser observations onto the lab's explicit state labels.

Uses ``evidence_record`` for execution, CSP, sanitization, sinks, and browser
failure. ``reflection_observed`` is layered on top when the HTTP body contains
the marker and nothing stronger was observed. Execution is never inferred from
a sink. ``finding_confirmed`` is forced false.
"""

from __future__ import annotations

from typing import Any

from bugbounty_toolkit.xss.evidence_record import (
    DomObservation,
    assert_minimized,
    build_browser_evidence,
    classify_dom_state,
)

LAB_STATES = (
    "reflection_observed",
    "source_observed",
    "sink_reached",
    "execution_observed",
    "execution_blocked",
    "sanitized",
    "inconclusive_browser_error",
    "inconclusive",
)

# Evidence-record vocabulary for the minimized record. Reflection is not a DOM state.
DOM_RESULT_FOR_LAB = {
    "reflection_observed": "inconclusive",
    "source_observed": "source_observed",
    "sink_reached": "sink_reached",
    "execution_observed": "execution_observed",
    "execution_blocked": "execution_blocked_csp",
    "sanitized": "sanitization_applied",
    "inconclusive_browser_error": "inconclusive_browser_error",
    "inconclusive": "inconclusive",
}

REQUIRED_ROW_FIELDS = (
    "scenario_id",
    "letter",
    "name",
    "navigation_url",
    "origin",
    "status",
    "content_type",
    "source_observed",
    "sink_reached",
    "sinks",
    "marker_execution",
    "csp_error",
    "browser_error",
    "runtime_ms",
    "allowed_requests",
    "blocked_requests",
    "external_requests",
    "state",
    "finding_confirmed",
    "measurement",
)


def lab_state(observation: DomObservation, *, reflected: bool) -> str:
    """Most specific defensible label. Browser failure wins over partial signals."""
    if observation.browser_failed:
        return "inconclusive_browser_error"
    if observation.marker_executed:
        return "execution_observed"
    if observation.csp_blocked:
        return "execution_blocked"
    if observation.sanitized:
        return "sanitized"
    if observation.sinks:
        return "sink_reached"
    if reflected:
        return "reflection_observed"
    if observation.source_observed:
        return "source_observed"
    return "inconclusive"


def seal(row: dict[str, Any]) -> dict[str, Any]:
    if row.get("finding_confirmed") is True or row.get("confirmed") is True:
        raise RuntimeError("refusing to emit a confirmed finding")
    row["finding_confirmed"] = False
    row["confirmed"] = False
    return row


def evidence_for(
    *,
    case_id: str,
    lab_label: str,
    observation: DomObservation,
    csp_header: str | None,
    technical_errors: list[str],
) -> dict[str, Any]:
    """Minimized DOM evidence. The lab label is hashed for provenance and stored on the row."""
    dom_state = classify_dom_state(observation)
    evidence = build_browser_evidence(
        case_id=case_id,
        context="xss_real_browser_lab",
        execution_result=dom_state,
        observed_source="url" if observation.source_observed else None,
        observed_sink=observation.sinks[0] if observation.sinks else None,
        csp_header=csp_header,
        technical_errors=technical_errors,
        capture_refs=[case_id],
        capture_bytes={
            "observation": (
                f"lab={lab_label};executed={observation.marker_executed};sinks={','.join(observation.sinks)}"
            )
        },
    )
    payload = evidence.to_dict()
    assert_minimized(payload)
    if payload.get("finding_confirmed") is not False:
        raise RuntimeError("evidence record confirmed a finding")
    return payload
