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
    evidence = _read_json(evidence_path, "Access-check evidence") if evidence_path is not None else None
    return assess_access_control_data(case, evidence)


def assess_access_control_data(case: object, evidence: object | None) -> dict[str, object]:
    """Classify supplied BOLA/BFLA evidence from explicit predicates, never status or model opinion."""
    if not isinstance(case, dict):
        return _insufficient("The case is not a JSON object.")
    if case.get("type") == "function-access-case":
        return _assess_function_matrix(case, evidence)
    if isinstance(evidence, dict) and evidence.get("mode") == "account-matrix":
        return _assess_account_matrix(case, evidence)
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
    if evidence is None:
        return _insufficient("No native access-check evidence was supplied; unified fingerprints do not map ownership.")
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
        "category": "BOLA",
        "classification": classification,
        "controls_classification": "legitimate_access",
        "reason": reason,
        "confirmed": False,
        "status_code_used": False,
        "model_opinion_used": False,
    }


def _assessment(
    category: str,
    classification: str,
    reason: str,
    controls: str,
    checks: list[dict[str, object]],
) -> dict[str, object]:
    return {
        "type": "access-control-assessment",
        "category": category,
        "classification": classification,
        "controls_classification": controls,
        "reason": reason,
        "checks": checks,
        "confirmed": False,
        "status_code_used": False,
        "model_opinion_used": False,
    }


def _assess_account_matrix(case: dict[str, Any], evidence: dict[str, Any]) -> dict[str, object]:
    checks = case.get("checks")
    if (
        case.get("accounts_authorized") is not True
        or case.get("resource_private") is not True
        or case.get("expected_cross_access") != "deny"
        or not isinstance(checks, dict)
        or any(checks.get(key) in (None, "") for key in _CHECK_FIELDS)
    ):
        return _insufficient(
            "The BOLA matrix case lacks authorized accounts, private resource or explicit deny declarations."
        )
    if evidence.get("type") != "access-control" or evidence.get("controls_valid") is not True:
        return _insufficient("The native account matrix did not validate all own-resource controls.")
    accounts: dict[str, tuple[object, object]] = {
        "owner": (checks["owner_resource"], checks["owner_marker"]),
        "actor": (checks["actor_resource"], checks["actor_marker"]),
    }
    additional = case.get("additional_accounts", {})
    if not isinstance(additional, dict):
        return _insufficient("Additional account declarations are malformed.")
    for name, profile in additional.items():
        if (
            not isinstance(name, str)
            or name in accounts
            or not isinstance(profile, dict)
            or any(key not in profile for key in ("resource", "marker"))
        ):
            return _insufficient("Every additional BOLA account needs its own resource and private marker.")
        accounts[name] = (profile["resource"], profile["marker"])
    evidence_accounts = evidence.get("matrix_accounts")
    if not isinstance(evidence_accounts, list) or set(evidence_accounts) != set(accounts):
        return _insufficient("Evidence account labels do not match the declared matrix accounts.")
    steps = evidence.get("steps")
    matrix = evidence.get("matrix")
    if not isinstance(steps, list) or not isinstance(matrix, list):
        return _insufficient("The native account matrix lacks steps or cells.")
    by_name: dict[str, dict[str, Any]] = {}
    for step in steps:
        if not isinstance(step, dict) or not isinstance(step.get("step"), str):
            continue
        if step["step"] in by_name:
            return _insufficient("The account matrix contains duplicate step labels.")
        by_name[step["step"]] = step
    for name, (resource, marker) in accounts.items():
        control = by_name.get(f"{name}_control")
        if not isinstance(control, dict) or any(
            control.get(field) is not True for field in ("application_success", "resource_match", "private_match")
        ):
            return _assessment(
                "BOLA",
                "insufficient_evidence",
                f"The {name} own-resource positive control did not prove its declared resource and marker.",
                "insufficient_evidence",
                [],
            )
        if resource in (None, "") or marker in (None, ""):
            return _insufficient("A declared account resource or private marker is empty.")

    expected_pairs = {(source, target) for source in accounts for target in accounts if source != target}
    matrix_pairs: set[tuple[str, str]] = set()
    for cell in matrix:
        if not isinstance(cell, dict) or cell.get("access_type") != "cross":
            continue
        source, target = cell.get("session_account"), cell.get("resource_owner")
        if not isinstance(source, str) or not isinstance(target, str) or source == target:
            return _insufficient("The account matrix contains an invalid cross-account cell.")
        pair = (source, target)
        if pair not in expected_pairs or pair in matrix_pairs:
            return _insufficient("The account matrix contains an unknown or duplicate cross-account cell.")
        matrix_pairs.add(pair)

    if matrix_pairs != expected_pairs:
        return _assessment(
            "BOLA",
            "insufficient_evidence",
            "The matrix is incomplete; missing account/resource directions are not treated as denied.",
            "legitimate_access",
            [],
        )
    results: list[dict[str, object]] = []
    candidate_found = False
    all_denied = True
    for source, target in sorted(expected_pairs):
        step = by_name.get(f"cross_{source}_to_{target}")
        if not isinstance(step, dict):
            classification = "insufficient_evidence"
        else:
            resource_match = step.get("resource_match")
            private_match = step.get("private_match")
            success = step.get("application_success")
            if type(resource_match) is not bool or type(private_match) is not bool or type(success) is not bool:
                classification = "insufficient_evidence"
            elif success and resource_match and private_match:
                classification = "possible_unauthorized_access"
                candidate_found = True
            elif not success and not resource_match and not private_match:
                classification = "denied"
            else:
                classification = "insufficient_evidence"
        all_denied &= classification == "denied"
        results.append(
            {
                "session_account": source,
                "resource_owner": target,
                "classification": classification,
                "confirmed": False,
            }
        )
    classification = (
        "possible_unauthorized_access" if candidate_found else "denied" if all_denied else "insufficient_evidence"
    )
    reason = (
        "At least one crossed response matched a declared private resource and marker; manual validation remains required."
        if candidate_found
        else "Every tested crossed direction matched its explicit application-denial predicate."
        if classification == "denied"
        else "One or more matrix directions lack sufficient application-level evidence."
    )
    return _assessment("BOLA", classification, reason, "legitimate_access", results)


def _assess_function_matrix(case: dict[str, Any], evidence: object | None) -> dict[str, object]:
    if case.get("accounts_authorized") is not True or not isinstance(case.get("accounts"), dict):
        return _insufficient("BFLA assessment requires explicit authorized accounts and role labels.")
    account_roles = case["accounts"]
    if not 2 <= len(account_roles) <= 10 or any(
        not isinstance(account, str) or not isinstance(role, str) for account, role in account_roles.items()
    ):
        return _insufficient("BFLA account labels and roles are malformed.")
    functions = case.get("functions")
    if not isinstance(functions, list) or not functions:
        return _insufficient("BFLA case has no function permission declarations.")
    if (
        not isinstance(evidence, dict)
        or evidence.get("type") != "access-control"
        or evidence.get("mode") != "function-matrix"
        or not isinstance(evidence.get("functions"), list)
    ):
        return _insufficient("Evidence must be a native function-matrix result.")
    declared_names = {
        row.get("name") for row in functions if isinstance(row, dict) and isinstance(row.get("name"), str)
    }
    evidence_functions = {
        row.get("function"): row
        for row in evidence["functions"]
        if isinstance(row, dict) and isinstance(row.get("function"), str)
    }
    if (
        len(declared_names) != len(functions)
        or len(evidence_functions) != len(functions)
        or set(evidence_functions) != declared_names
    ):
        return _insufficient("Function evidence does not match the declared permission matrix.")

    findings: list[dict[str, object]] = []
    candidate_found = False
    all_denied = True
    all_controls_valid = True
    for function in functions:
        if not isinstance(function, dict):
            return _insufficient("BFLA function declaration is malformed.")
        name = function.get("name")
        allowed_roles = function.get("allowed_roles")
        if (
            function.get("restricted") is not True
            or function.get("read_only_attested") is not True
            or not isinstance(name, str)
            or not isinstance(allowed_roles, list)
            or not allowed_roles
            or any(not isinstance(role, str) or role not in set(account_roles.values()) for role in allowed_roles)
            or len(set(allowed_roles)) != len(allowed_roles)
            or not isinstance(function.get("requests"), dict)
            or set(function.get("requests", {})) != set(account_roles)
            or not set(allowed_roles) < set(account_roles.values())
        ):
            return _insufficient("BFLA function declaration lacks restricted-function attestations.")
        observed = evidence_functions[name]
        if observed.get("read_only_attested") is not True:
            return _insufficient("BFLA evidence is missing the read-only test attestation.")
        if observed.get("required_roles") != allowed_roles:
            return _insufficient("BFLA evidence role controls do not match the declared allowed roles.")
        results = observed.get("results")
        if not isinstance(results, list) or len(results) != len(account_roles):
            all_controls_valid = False
            all_denied = False
            continue
        result_by_account = {
            row.get("account"): row for row in results if isinstance(row, dict) and isinstance(row.get("account"), str)
        }
        if len(result_by_account) != len(results) or set(result_by_account) != set(account_roles):
            all_controls_valid = False
            all_denied = False
            continue
        controls_valid = True
        function_rows: list[dict[str, object]] = []
        function_candidate = False
        function_denied = True
        for account, role in account_roles.items():
            row = result_by_account[account]
            if row.get("role") != role or row.get("confirmed") is not False:
                controls_valid = False
                function_denied = False
                continue
            success_match = row.get("success_match")
            denial_match = row.get("denial_match")
            marker_match = row.get("marker_match")
            marker_seen = row.get("marker_seen")
            if role in allowed_roles:
                classification = (
                    "legitimate_access"
                    if success_match is True
                    and marker_match is True
                    and row.get("marker_seen") is True
                    and row.get("expected_access") == "allow"
                    else "insufficient_evidence"
                )
                controls_valid &= classification == "legitimate_access"
                if classification != "legitimate_access":
                    function_denied = False
            else:
                if row.get("expected_access") != "deny":
                    classification = "insufficient_evidence"
                    function_denied = False
                elif success_match is True and marker_match is True and marker_seen is True:
                    classification = "possible_bfla"
                    function_candidate = True
                    function_denied = False
                elif denial_match is True and marker_seen is False:
                    classification = "denied"
                else:
                    classification = "insufficient_evidence"
                    function_denied = False
            function_rows.append(
                {
                    "function": name,
                    "account": account,
                    "role": role,
                    "classification": classification,
                    "confirmed": False,
                }
            )
        all_controls_valid &= controls_valid
        candidate_found |= function_candidate and controls_valid and observed.get("controls_valid") is True
        all_denied &= function_denied and controls_valid and observed.get("controls_valid") is True
        findings.extend(function_rows)
    classification = (
        "possible_bfla"
        if candidate_found
        else "denied"
        if all_denied and all_controls_valid
        else "insufficient_evidence"
    )
    reason = (
        "A restricted role received the configured function success and marker after allowed-role controls passed."
        if candidate_found
        else "All tested restricted roles met the configured application-denial predicate."
        if classification == "denied"
        else "Positive role controls or restricted-role denial evidence were incomplete or contradictory."
    )
    return _assessment(
        "BFLA",
        classification,
        reason,
        "legitimate_access" if all_controls_valid else "insufficient_evidence",
        findings,
    )
