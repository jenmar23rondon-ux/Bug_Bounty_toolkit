from __future__ import annotations

import json
from pathlib import Path
from typing import Any

MAX_CASE_BYTES = 2_000_000
_CHECK_FIELDS = ("owner_resource", "actor_resource", "owner_marker", "actor_marker")


def _read_json(path: Path, label: str) -> Any:
    try:
        with path.open("rb") as source:
            raw = source.read(MAX_CASE_BYTES + 1)
        if len(raw) > MAX_CASE_BYTES:
            raise ValueError(f"{label} exceeds the {MAX_CASE_BYTES}-byte limit.")
        return json.loads(raw.decode("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise ValueError(f"{label} must be readable UTF-8 JSON.") from exc


def _insufficient(reason: str) -> dict[str, object]:
    return {
        "type": "access-control-assessment",
        "classification": "insufficient_evidence",
        "controls_classification": "insufficient_evidence",
        "reason": reason,
        "confirmed": False,
        "status_code_used": False,
        "model_opinion_used": False,
    }


def assess_access_control(case_path: Path, evidence_path: Path | None) -> dict[str, object]:
    """Classify supplied A/B evidence from explicit ownership predicates, never status alone."""
    case = _read_json(case_path, "Access case")
    if not isinstance(case, dict):
        return _insufficient("The case is not a JSON object.")
    checks = case.get("checks")
    if (
        case.get("accounts_authorized") is not True
        or not isinstance(checks, dict)
        or any(checks.get(key) in (None, "") for key in _CHECK_FIELDS)
    ):
        return _insufficient("The case lacks authorized-account or owner/actor resource-marker declarations.")
    if case.get("resource_private") is not True:
        return _insufficient("The case does not attest that this is a private resource.")
    if case.get("expected_cross_access") != "deny":
        return _insufficient("The case does not declare cross-account access as denied.")
    if evidence_path is None:
        return _insufficient("No native access-check evidence was supplied; unified fingerprints do not map ownership.")

    evidence = _read_json(evidence_path, "Access-check evidence")
    if not isinstance(evidence, dict) or evidence.get("type") != "access-control" or evidence.get("mode") != "read":
        return _insufficient("Evidence must be a native read-mode access-check result.")
    steps = evidence.get("steps")
    if not isinstance(steps, list):
        return _insufficient("Evidence has no access-check steps.")
    by_name = {step.get("step"): step for step in steps if isinstance(step, dict) and isinstance(step.get("step"), str)}
    owner = by_name.get("owner_control")
    actor = by_name.get("actor_control")
    if evidence.get("controls_valid") is not True or not isinstance(owner, dict) or not isinstance(actor, dict):
        return _insufficient(
            "Both own-resource controls must be present and valid before a cross result is interpreted."
        )
    own_controls_valid = all(
        row.get("application_success") is True
        and row.get("resource_match") is True
        and row.get("private_match") is True
        for row in (owner, actor)
    )
    if not own_controls_valid:
        return _insufficient("Owner and actor controls do not both prove access to their declared private resources.")
    cross = by_name.get("cross_read")
    if not isinstance(cross, dict):
        return {
            "type": "access-control-assessment",
            "classification": "insufficient_evidence",
            "controls_classification": "legitimate_access",
            "reason": "Both own-resource controls passed, but no crossed read was recorded.",
            "confirmed": False,
            "status_code_used": False,
            "model_opinion_used": False,
        }

    resource_match = cross.get("owner_resource_match")
    private_match = cross.get("owner_private_match")
    application_success = cross.get("application_success")
    if type(resource_match) is not bool or type(private_match) is not bool or type(application_success) is not bool:
        return _insufficient(
            "Crossed evidence is missing owner-resource, private-marker or application-success predicates."
        )
    if resource_match and private_match and application_success:
        classification = "possible_unauthorized_access"
        reason = "The actor response matched the owner's declared resource and private marker; manual verification remains required."
    elif application_success is False and not resource_match and not private_match:
        classification = "denied"
        reason = "Application-level success was false and no owner resource or private marker was observed."
    else:
        classification = "insufficient_evidence"
        reason = "The crossed response does not establish either private-data access or an application-level denial."
    return {
        "type": "access-control-assessment",
        "classification": classification,
        "controls_classification": "legitimate_access",
        "reason": reason,
        "confirmed": False,
        "status_code_used": False,
        "model_opinion_used": False,
    }
