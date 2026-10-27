"""Structured evidence contract v2 for local model review.

The packet is boolean, enum, and synthetic-ref only. It does not replace
``review_evidence`` and it does not confirm findings. Unknown stays unknown.
Forbidden secret material is dropped, never minimized into the packet.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from typing import Any

SCHEMA_VERSION = "bbtk.ai-evidence-contract.v2"
ADVISORY_SCHEMA_VERSION = "bbtk.ai-dual-review-advisory.v2"

VISIBILITY = ("public", "private", "shared", "unknown")
RESOURCE_KINDS = ("object", "collection", "document", "session", "endpoint", "unknown")
STATUS_FAMILIES = (
    "informational",
    "success",
    "redirect",
    "client_error",
    "server_error",
    "mixed",
    "unknown",
)
SESSION_CONTINUITY = ("same", "distinct", "broken", "unknown")
TRUNCATION = ("none", "partial", "complete_loss", "unknown")
COMPLETENESS = ("complete", "incomplete", "unknown")
INTEGRITY = ("intact", "suspect", "failed", "unknown")
ROLES = (
    "owner_read",
    "actor_read",
    "cross_read",
    "cross_write",
    "negative_control",
    "baseline",
    "result",
    "unknown",
)
CONTROLS = (
    "ownership",
    "negative_control",
    "second_session",
    "owner_control",
    "second_actor_control",
    "private_marker",
    "explicit_denial",
    "complete_response",
    "valid_evidence",
    "auth_context",
    "session_continuity",
    "distinct_accounts",
)
ASPECTS = ("cross_read_outcome", "private_marker", "visibility", "status_family", "explicit_denial")
NEGATIVE_KINDS = ("explicit_denial", "public_non_disclosure")
DECISIONS = ("candidate", "not_observed", "inconclusive")
CROSS_ROLES = frozenset({"cross_read", "cross_write"})
SECOND_ACTOR_ROLES = frozenset({"actor_read", "cross_read", "cross_write"})
DENIAL_STATUSES = frozenset({401, 403, 404})
BOOL_FIELDS = frozenset(
    {
        "owner_control_present",
        "second_actor_control_present",
        "distinct_accounts",
        "cross_read_observed",
        "private_marker_present",
        "explicit_denial_present",
        "tool_execution_observed",
        "auth_context_declared",
    }
)
ENUM_FIELDS = frozenset(
    {
        "resource_kind",
        "visibility",
        "status_family",
        "session_continuity",
        "truncation",
        "completeness",
        "integrity",
    }
)
PACKET_KEYS = (
    "schema_version",
    "evidence_ref",
    "resource_kind",
    "visibility",
    "owner_control_present",
    "second_actor_control_present",
    "distinct_accounts",
    "cross_read_observed",
    "private_marker_present",
    "explicit_denial_present",
    "status_family",
    "session_continuity",
    "truncation",
    "completeness",
    "integrity",
    "contradicting_refs",
    "missing_controls",
    "valid_negatives",
    "tool_execution_observed",
    "auth_context_declared",
    "observations",
    "annotation_issues",
    "finding_confirmed",
    "ai_classification_authority",
    "tools_available",
    "requests_emitted",
    "evidence_ledger_modified",
    "historical_ledger_rewritten",
)
OBSERVATION_KEYS = ("ref", "role", "status_family", "private_marker", "visibility", "explicit_denial")
CONTRADICTION_KEYS = ("ref", "opposes", "aspect")
NEGATIVE_KEYS = ("ref", "kind")
MAX_ROWS = 64

# Field names that must never appear in a packet. The CI linter rejects each one.
FORBIDDEN_FIELD_NAMES = (
    "cookie",
    "cookies",
    "set-cookie",
    "authorization",
    "bearer",
    "password",
    "passwd",
    "passphrase",
    "private_body",
    "body",
    "response_body",
    "request_body",
    "query",
    "query_secret",
    "localStorage",
    "local_storage",
    "account_id",
    "user_id",
    "email",
    "raw_html",
    "html",
    "secret_hash",
    "password_hash",
    "token_hash",
    "instruction",
    "instructions",
    "system_prompt",
    "prompt",
    "notes",
    "headers",
)

_EVIDENCE_REF = re.compile(r"^ec2-[0-9a-f]{24}$")
_ROW_REF = re.compile(r"^E[0-9]{2}$")
_SYNTH_REF = re.compile(r"^SYNTH_[A-Z0-9]{1,16}$")
_TEXT_LEAK = re.compile(
    r"(?i)ignore previous|<\s*/?\s*script|cookie\s*=|authorization\s*:|bearer\s+\S|password\s*=|localstorage"
)
_ISSUE_PREFIXES = (
    "invalid_resource_kind",
    "invalid_visibility",
    "invalid_owner_control_present",
    "invalid_second_actor_control_present",
    "invalid_distinct_accounts",
    "invalid_cross_read_observed",
    "invalid_private_marker_present",
    "invalid_explicit_denial_present",
    "invalid_status_family",
    "invalid_session_continuity",
    "invalid_truncation",
    "invalid_completeness",
    "invalid_integrity",
    "invalid_tool_execution_observed",
    "invalid_auth_context_declared",
    "invalid_annotation",
    "dropped_non_synthetic_ref",
    "dropped_free_text",
    "visibility_conflict",
    "rows_capped",
)
_ENUM_STRINGS = frozenset(
    [
        *VISIBILITY,
        *RESOURCE_KINDS,
        *STATUS_FAMILIES,
        *SESSION_CONTINUITY,
        *TRUNCATION,
        *COMPLETENESS,
        *INTEGRITY,
        *ROLES,
        *CONTROLS,
        *ASPECTS,
        *NEGATIVE_KINDS,
        *_ISSUE_PREFIXES,
    ]
)
_GATES = (
    "valid_evidence",
    "reviews_valid",
    "existing_refs",
    "no_invented_claims",
    "state_compatibility",
    "complete_controls_when_required",
)


def _norm_key(key: object) -> str:
    return "".join(ch if ch.isalnum() else "_" for ch in str(key).lower())


_FORBIDDEN_NORMALIZED = frozenset(_norm_key(name) for name in FORBIDDEN_FIELD_NAMES)


def _canonical(body: Mapping[str, Any]) -> str:
    return json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _evidence_ref(body: Mapping[str, Any]) -> str:
    return "ec2-" + hashlib.sha256(_canonical(body).encode("utf-8")).hexdigest()[:24]


def _status_family(code: object) -> str:
    if type(code) is not int or not 100 <= code <= 599:
        return "unknown"
    if code < 200:
        return "informational"
    if code < 300:
        return "success"
    if code < 400:
        return "redirect"
    if code < 500:
        return "client_error"
    return "server_error"


def _aggregate_status(families: Sequence[str]) -> str:
    known = [item for item in families if item != "unknown"]
    if not known:
        return "unknown"
    unique = set(known)
    if len(unique) == 1:
        return next(iter(unique))
    return "mixed"


def _role(row: Mapping[str, Any], topic: str) -> str:
    step = row.get("step")
    if isinstance(step, str) and step in ROLES and step != "unknown":
        return step
    if topic != "access-control" and "step" not in row:
        return "result"
    return "unknown"


def _tri_from_annotation(ann: Mapping[str, Any], key: str, issues: list[str]) -> tuple[bool, bool | None]:
    """Return (present, value). Invalid values become unknown and are not coerced to false."""
    if key not in ann:
        return False, None
    value = ann[key]
    if value is None or type(value) is bool:
        return True, value
    issues.append("invalid_" + key)
    return True, None


def _enum_from_annotation(
    ann: Mapping[str, Any], key: str, allowed: Sequence[str], issues: list[str]
) -> tuple[bool, str | None]:
    if key not in ann:
        return False, None
    value = ann[key]
    if value is None:
        return True, "unknown"
    if isinstance(value, str) and value in allowed:
        return True, value
    issues.append("invalid_" + key)
    return True, "unknown"


def _rows(data: Mapping[str, Any]) -> list[dict[str, Any]]:
    topic = data.get("type")
    key = "steps" if topic == "access-control" else "results"
    raw = data.get(key, [])
    if not isinstance(raw, list):
        return []
    return [row for row in raw if isinstance(row, dict)]


def _note_free_text(value: object, issues: set[str]) -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            if _norm_key(key) in _FORBIDDEN_NORMALIZED:
                issues.add("dropped_free_text")
            _note_free_text(item, issues)
    elif isinstance(value, list):
        for item in value:
            _note_free_text(item, issues)
    elif isinstance(value, str) and _TEXT_LEAK.search(value):
        issues.add("dropped_free_text")


def _synth_refs(rows: Sequence[Mapping[str, Any]], key: str, issues: set[str]) -> list[str]:
    found: list[str] = []
    for row in rows:
        if key not in row:
            continue
        value = row[key]
        if value is None:
            continue
        if isinstance(value, str) and _SYNTH_REF.match(value):
            if value not in found:
                found.append(value)
        else:
            issues.add("dropped_non_synthetic_ref")
    return found


def _row_private(row: Mapping[str, Any]) -> bool | None:
    if "private_marker" in row:
        value = row["private_marker"]
        if value is None or type(value) is bool:
            return value
        return None
    if "owner_private_match" in row and type(row.get("owner_private_match")) is bool:
        return bool(row["owner_private_match"])
    return None


def _row_visibility(row: Mapping[str, Any]) -> str:
    if "visibility" not in row:
        return "unknown"
    value = row["visibility"]
    if isinstance(value, str) and value in VISIBILITY:
        return value
    return "unknown"


def _row_denial(row: Mapping[str, Any], family: str) -> bool | None:
    if "explicit_denial" in row:
        value = row["explicit_denial"]
        if value is None or type(value) is bool:
            return value
        return None
    code = row.get("status_code")
    if type(code) is int and code in DENIAL_STATUSES:
        return True
    if family == "success":
        return False
    return None


def _tri_aggregate(values: Sequence[bool | None], default_false_if_any_false: bool = True) -> bool | None:
    if any(value is True for value in values):
        return True
    if default_false_if_any_false and any(value is False for value in values):
        return False
    return None


def _missing_controls(packet: Mapping[str, Any]) -> list[str]:
    missing: list[str] = []
    if packet["visibility"] == "unknown":
        missing.append("ownership")
    if packet["owner_control_present"] is None:
        missing.append("owner_control")
    if packet["second_actor_control_present"] is None:
        missing.append("second_actor_control")
    if packet["distinct_accounts"] is None:
        missing.append("distinct_accounts")
    if packet["private_marker_present"] is None:
        missing.append("private_marker")
    if packet["explicit_denial_present"] is None:
        missing.append("explicit_denial")
    if packet["session_continuity"] == "unknown":
        missing.append("session_continuity")
    if packet["auth_context_declared"] is None:
        missing.append("auth_context")
    if packet["truncation"] != "none":
        missing.append("complete_response")
    if packet["integrity"] != "intact":
        missing.append("valid_evidence")
    if packet["cross_read_observed"] is None:
        missing.append("second_session")
    return sorted(set(missing))


def _contradictions(observations: Sequence[Mapping[str, Any]]) -> list[dict[str, str]]:
    cross = [row for row in observations if row["role"] in CROSS_ROLES]
    found: list[dict[str, str]] = []
    for index, left in enumerate(cross):
        for right in cross[index + 1 :]:
            pairs = (
                ("status_family", "cross_read_outcome", "unknown"),
                ("private_marker", "private_marker", None),
                ("visibility", "visibility", "unknown"),
                ("explicit_denial", "explicit_denial", None),
            )
            for key, aspect, unknown in pairs:
                left_value = left[key]
                right_value = right[key]
                if left_value == unknown or right_value == unknown:
                    continue
                if left_value != right_value:
                    found.append({"ref": str(left["ref"]), "opposes": str(right["ref"]), "aspect": aspect})
    found.sort(key=lambda item: (item["ref"], item["opposes"], item["aspect"]))
    unique: list[dict[str, str]] = []
    for item in found:
        if item not in unique:
            unique.append(item)
    return unique


def _valid_negatives(observations: Sequence[Mapping[str, Any]]) -> list[dict[str, str]]:
    found: list[dict[str, str]] = []
    for row in observations:
        if row["role"] not in CROSS_ROLES:
            continue
        if row["explicit_denial"] is True and row["private_marker"] is not True:
            found.append({"ref": str(row["ref"]), "kind": "explicit_denial"})
        if row["visibility"] == "public" and row["private_marker"] is False:
            found.append({"ref": str(row["ref"]), "kind": "public_non_disclosure"})
    return found


def build_contract_packet(data: Mapping[str, Any]) -> dict[str, Any]:
    """Build a schema-v2 packet. Explicit null annotations stay null."""
    if not isinstance(data, Mapping):
        raise ValueError("evidence must be an object")
    issues: set[str] = set()
    _note_free_text(data, issues)
    raw_topic = data.get("type")
    topic = raw_topic if isinstance(raw_topic, str) else ""
    raw_rows = _rows(data)
    if len(raw_rows) > MAX_ROWS:
        issues.add("rows_capped")
        raw_rows = raw_rows[:MAX_ROWS]
    ann_raw = data.get("contract_annotations")
    if ann_raw is None:
        ann: Mapping[str, Any] = {}
    elif isinstance(ann_raw, Mapping):
        ann = ann_raw
    else:
        issues.add("invalid_annotation")
        ann = {}
    issue_list = sorted(issues)
    account_refs = _synth_refs(raw_rows, "account_ref", issues)
    session_refs = _synth_refs(raw_rows, "session_ref", issues)

    observations: list[dict[str, Any]] = []
    invalid_status = False
    for index, row in enumerate(raw_rows, start=1):
        family = _status_family(row.get("status_code"))
        if "status_code" in row and family == "unknown":
            invalid_status = True
        visibility = _row_visibility(row)
        if "visibility" in row and visibility == "unknown" and row.get("visibility") not in {None, "unknown"}:
            issue_list.append("invalid_visibility")
        observations.append(
            {
                "ref": f"E{index:02d}",
                "role": _role(row, topic),
                "status_family": family,
                "private_marker": _row_private(row),
                "visibility": visibility,
                "explicit_denial": _row_denial(row, family),
            }
        )

    present, resource_kind = _enum_from_annotation(ann, "resource_kind", RESOURCE_KINDS, issue_list)
    if not present or resource_kind is None:
        resource_kind = "unknown"
    present, declared_visibility = _enum_from_annotation(ann, "visibility", VISIBILITY, issue_list)
    row_vis = [row["visibility"] for row in observations if row["visibility"] != "unknown"]
    row_unique = set(row_vis)
    annotation_visibility = declared_visibility if present else None
    packet_visibility: str
    if len(row_unique) > 1 or (annotation_visibility not in {None, "unknown"} and row_unique - {annotation_visibility}):
        issues.add("visibility_conflict")
        packet_visibility = "unknown"
    elif present and declared_visibility is not None:
        packet_visibility = declared_visibility
    elif len(row_unique) == 1:
        packet_visibility = next(iter(row_unique))
    else:
        packet_visibility = "unknown"

    def tri(key: str, derived: bool | None) -> bool | None:
        present_flag, value = _tri_from_annotation(ann, key, issue_list)
        return value if present_flag else derived

    owner_derived: bool | None
    if any(row["role"] == "owner_read" for row in observations):
        owner_derived = True
    elif observations:
        owner_derived = False
    else:
        owner_derived = None
    second_derived: bool | None
    if any(row["role"] in SECOND_ACTOR_ROLES for row in observations):
        second_derived = True
    elif observations:
        second_derived = False
    else:
        second_derived = None
    if len(account_refs) >= 2:
        accounts_derived: bool | None = True
    elif len(account_refs) == 1:
        accounts_derived = False
    else:
        accounts_derived = None
    if any(row["role"] == "cross_read" for row in observations):
        cross_derived: bool | None = True
    elif observations:
        cross_derived = False
    else:
        cross_derived = None

    owner_control = tri("owner_control_present", owner_derived)
    second_actor = tri("second_actor_control_present", second_derived)
    distinct_accounts = tri("distinct_accounts", accounts_derived)
    cross_read = tri("cross_read_observed", cross_derived)
    private_marker = tri("private_marker_present", _tri_aggregate([row["private_marker"] for row in observations]))
    explicit_denial = tri("explicit_denial_present", _tri_aggregate([row["explicit_denial"] for row in observations]))
    tool_observed = tri("tool_execution_observed", None)
    auth_declared = tri("auth_context_declared", None)

    present, status_family = _enum_from_annotation(ann, "status_family", STATUS_FAMILIES, issue_list)
    if not present or status_family is None:
        status_family = _aggregate_status([str(row["status_family"]) for row in observations])
    present, session_continuity = _enum_from_annotation(ann, "session_continuity", SESSION_CONTINUITY, issue_list)
    if not present or session_continuity is None:
        if len(session_refs) >= 2:
            session_continuity = "distinct"
        elif len(session_refs) == 1:
            session_continuity = "same"
        else:
            session_continuity = "unknown"
    present, truncation = _enum_from_annotation(ann, "truncation", TRUNCATION, issue_list)
    if not present or truncation is None:
        flags = [
            row["body_truncated"]
            for row in raw_rows
            if "body_truncated" in row and type(row.get("body_truncated")) is bool
        ]
        if any(flag is True for flag in flags):
            truncation = "partial"
        elif raw_rows and len(flags) == len(raw_rows) and all(flag is False for flag in flags):
            truncation = "none"
        else:
            truncation = "unknown"
    present, integrity = _enum_from_annotation(ann, "integrity", INTEGRITY, issue_list)
    if not present or integrity is None:
        transport = [row.get("transport_error") for row in raw_rows]
        if any(flag is True for flag in transport) or invalid_status:
            integrity = "suspect"
        elif raw_rows and all(flag is False for flag in transport):
            integrity = "intact"
        else:
            integrity = "unknown"
    present, completeness = _enum_from_annotation(ann, "completeness", COMPLETENESS, issue_list)
    if not present or completeness is None:
        if truncation in {"partial", "complete_loss"} or integrity == "failed":
            completeness = "incomplete"
        elif (
            truncation == "none"
            and integrity == "intact"
            and packet_visibility != "unknown"
            and owner_control is not None
            and second_actor is not None
        ):
            completeness = "complete"
        else:
            completeness = "unknown"

    contradicting = _contradictions(observations)
    negatives = _valid_negatives(observations)
    issue_list = sorted(set(issue_list) | issues)
    body: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "resource_kind": resource_kind,
        "visibility": packet_visibility,
        "owner_control_present": owner_control,
        "second_actor_control_present": second_actor,
        "distinct_accounts": distinct_accounts,
        "cross_read_observed": cross_read,
        "private_marker_present": private_marker,
        "explicit_denial_present": explicit_denial,
        "status_family": status_family,
        "session_continuity": session_continuity,
        "truncation": truncation,
        "completeness": completeness,
        "integrity": integrity,
        "contradicting_refs": contradicting,
        "missing_controls": [],
        "valid_negatives": negatives,
        "tool_execution_observed": tool_observed,
        "auth_context_declared": auth_declared,
        "observations": observations,
        "annotation_issues": [code for code in issue_list if code in _ISSUE_PREFIXES],
        "finding_confirmed": False,
        "ai_classification_authority": False,
        "tools_available": False,
        "requests_emitted": False,
        "evidence_ledger_modified": False,
        "historical_ledger_rewritten": False,
    }
    body["missing_controls"] = _missing_controls(body)
    body["evidence_ref"] = _evidence_ref(body)
    problems = validate_contract_packet(body)
    if problems:
        raise RuntimeError("contract packet failed its own schema: " + ",".join(problems))
    return body


def validate_contract_packet(packet: Mapping[str, Any]) -> list[str]:
    """Return schema issue codes. Empty means the packet matches schema v2."""
    issues: list[str] = []
    if not isinstance(packet, Mapping):
        return ["bad_type"]
    keys = set(packet)
    if keys != set(PACKET_KEYS):
        issues.append("unexpected_or_missing_key")
        return issues
    if packet["schema_version"] != SCHEMA_VERSION:
        issues.append("bad_schema_version")
    body = {key: packet[key] for key in PACKET_KEYS if key != "evidence_ref"}
    if packet["evidence_ref"] != _evidence_ref(body):
        issues.append("evidence_ref_mismatch")
    if packet["resource_kind"] not in RESOURCE_KINDS:
        issues.append("bad_resource_kind")
    if packet["visibility"] not in VISIBILITY:
        issues.append("bad_visibility")
    for key in BOOL_FIELDS:
        if packet[key] is not None and type(packet[key]) is not bool:
            issues.append("bad_" + key)
    for key, allowed in (
        ("status_family", STATUS_FAMILIES),
        ("session_continuity", SESSION_CONTINUITY),
        ("truncation", TRUNCATION),
        ("completeness", COMPLETENESS),
        ("integrity", INTEGRITY),
    ):
        if packet[key] not in allowed:
            issues.append("bad_" + key)
    if packet["finding_confirmed"] is not False:
        issues.append("finding_confirmed")
    for key in (
        "ai_classification_authority",
        "tools_available",
        "requests_emitted",
        "evidence_ledger_modified",
        "historical_ledger_rewritten",
    ):
        if packet[key] is not False:
            issues.append("bad_" + key)
    annotations = packet["annotation_issues"]
    if not isinstance(annotations, list) or any(item not in _ISSUE_PREFIXES for item in annotations):
        issues.append("bad_annotation_issues")
    controls = packet["missing_controls"]
    if not isinstance(controls, list) or any(item not in CONTROLS for item in controls):
        issues.append("bad_missing_controls")
    elif controls != sorted(controls):
        issues.append("unsorted_missing_controls")
    issues.extend(_validate_objects(packet["contradicting_refs"], CONTRADICTION_KEYS, {"aspect": ASPECTS}))
    issues.extend(_validate_objects(packet["valid_negatives"], NEGATIVE_KEYS, {"kind": NEGATIVE_KINDS}))
    if not isinstance(packet["observations"], list):
        issues.append("bad_observations")
    else:
        for row in packet["observations"]:
            if not isinstance(row, Mapping) or set(row) != set(OBSERVATION_KEYS):
                issues.append("bad_observation")
                continue
            if not isinstance(row["ref"], str) or not _ROW_REF.match(row["ref"]):
                issues.append("bad_ref")
            if (
                row["role"] not in ROLES
                or row["status_family"] not in STATUS_FAMILIES
                or row["visibility"] not in VISIBILITY
            ):
                issues.append("bad_observation_enum")
            if row["private_marker"] is not None and type(row["private_marker"]) is not bool:
                issues.append("bad_private_marker")
            if row["explicit_denial"] is not None and type(row["explicit_denial"]) is not bool:
                issues.append("bad_explicit_denial")
    return issues


def _validate_objects(rows: object, keys: tuple[str, ...], enums: Mapping[str, Sequence[str]]) -> list[str]:
    issues: list[str] = []
    if not isinstance(rows, list):
        return ["bad_list"]
    for row in rows:
        if not isinstance(row, Mapping) or set(row) != set(keys):
            issues.append("bad_object")
            continue
        for key in keys:
            allowed = enums.get(key)
            value = row[key]
            if allowed is not None:
                if value not in allowed:
                    issues.append("bad_enum")
            elif not isinstance(value, str) or not _ROW_REF.match(value):
                issues.append("bad_ref")
    return issues


def lint_contract_packet(packet: Mapping[str, Any]) -> list[str]:
    """Privacy linter. Any forbidden field or non-allowlisted string fails the packet."""
    issues: list[str] = []

    def walk(value: object, path: str) -> None:
        if isinstance(value, Mapping):
            for key, item in value.items():
                if _norm_key(key) in _FORBIDDEN_NORMALIZED:
                    issues.append("forbidden_field")
                walk(item, path + "." + _norm_key(key))
        elif isinstance(value, list):
            for index, item in enumerate(value):
                walk(item, f"{path}[{index}]")
        elif value is None or type(value) is bool:
            return
        elif isinstance(value, str):
            if not _string_allowed(value, path):
                issues.append("disallowed_string")
        else:
            issues.append("disallowed_type")

    walk(packet, "")
    return sorted(set(issues))


def _string_allowed(value: str, path: str) -> bool:
    leaf = path.rsplit(".", 1)[-1]
    leaf = leaf.split("[", 1)[0]
    if leaf == "schema_version":
        return value == SCHEMA_VERSION
    if leaf == "evidence_ref":
        return _EVIDENCE_REF.match(value) is not None
    if leaf in {"ref", "opposes"}:
        return _ROW_REF.match(value) is not None
    return value in _ENUM_STRINGS


def scan_secret_material(document: object, materials: Sequence[str]) -> list[str]:
    """Return ``secret_material`` or ``secret_hash`` when a rendering contains them.

    The codes do not include the secret. Hash matches catch reversible digests of
    the same material (md5, sha1, sha256) even when the cleartext was omitted.
    """
    rendered = json.dumps(document, sort_keys=True, ensure_ascii=False, default=str)
    rendered_ascii = json.dumps(document, sort_keys=True, ensure_ascii=True, default=str)
    codes: list[str] = []
    for material in materials:
        if not isinstance(material, str) or len(material) < 6:
            continue
        if material in rendered or material in rendered_ascii:
            codes.append("secret_material")
            break
    for material in materials:
        if not isinstance(material, str) or len(material) < 6:
            continue
        raw = material.encode("utf-8")
        digests = (
            hashlib.md5(raw).hexdigest(),
            hashlib.sha1(raw).hexdigest(),
            hashlib.sha256(raw).hexdigest(),
        )
        if any(digest in rendered or digest in rendered_ascii for digest in digests):
            codes.append("secret_hash")
            break
    return codes


def privacy_leak_codes(document: Mapping[str, Any], materials: Sequence[str]) -> list[str]:
    """Return leak codes. Codes never echo the secret material."""
    codes: list[str] = []
    if lint_contract_packet(document):
        codes.append("linter")
    codes.extend(scan_secret_material(document, materials))
    return codes


def _v1_match(observations: Sequence[Mapping[str, Any]], field: str, expected: object) -> bool:
    return any(row.get("field") == field and row.get("value") == expected for row in observations)


def measure_semantic_completeness(
    packet: Mapping[str, Any],
    known: Mapping[str, Any],
    v1_observations: Sequence[Mapping[str, Any]] | None = None,
    v1_document: object | None = None,
) -> dict[str, Any]:
    """Score known-fact preservation, unknown preservation, schema validity, and privacy."""
    facts = known.get("facts")
    if not isinstance(facts, Mapping):
        raise ValueError("known facts must be an object")
    unknown_fields = known.get("unknown_fields") or []
    if not isinstance(unknown_fields, list) or any(not isinstance(item, str) for item in unknown_fields):
        raise ValueError("unknown_fields must be a list of names")
    overlap = set(facts) & set(unknown_fields)
    if overlap:
        raise ValueError("known fact overlaps an unknown field")
    materials = known.get("secret_material") or []
    if not isinstance(materials, list):
        raise ValueError("secret_material must be a list")

    checked = 0
    preserved = 0
    lost: list[str] = []
    for key, expected in facts.items():
        checked += 1
        if packet.get(key) == expected:
            preserved += 1
        else:
            lost.append(str(key))
    checked += 1
    if bool(packet.get("contradicting_refs")) == bool(known.get("contradiction_expected")):
        preserved += 1
    else:
        lost.append("contradiction_expected")
    checked += 1
    if bool(packet.get("valid_negatives")) == bool(known.get("valid_negative_expected")):
        preserved += 1
    else:
        lost.append("valid_negative_expected")
    extra_issues = known.get("annotation_issues_includes") or []
    if isinstance(extra_issues, list):
        have = packet.get("annotation_issues") or []
        for code in extra_issues:
            checked += 1
            if isinstance(have, list) and code in have:
                preserved += 1
            else:
                lost.append("annotation_issue")

    unknown_checked = 0
    unknown_preserved = 0
    unknown_coerced = 0
    for field in unknown_fields:
        unknown_checked += 1
        value = packet.get(field, "MISSING")
        if field in BOOL_FIELDS:
            ok = value is None
            coerced = type(value) is bool
        elif field in ENUM_FIELDS:
            ok = value == "unknown"
            coerced = isinstance(value, str) and value != "unknown"
        else:
            ok = False
            coerced = True
        if ok:
            unknown_preserved += 1
        if coerced:
            unknown_coerced += 1

    schema_issues = validate_contract_packet(packet)
    leak_codes = privacy_leak_codes(packet, [item for item in materials if isinstance(item, str)])
    v1_checked = 0
    v1_preserved = 0
    v1_unknown_checked = 0
    v1_unknown_preserved = 0
    secret_strings = [item for item in materials if isinstance(item, str)]
    v1_schema_valid = False
    v1_leak = False
    if isinstance(v1_document, Mapping):
        v1_schema_valid = not validate_contract_packet(v1_document)
        v1_leak = bool(scan_secret_material(v1_document, secret_strings))
    if v1_observations is not None:
        for key, expected in facts.items():
            v1_checked += 1
            if _v1_match(v1_observations, str(key), expected):
                v1_preserved += 1
        v1_checked += 1
        contradiction_kept = any(
            row.get("field") == "contradicting_refs" and isinstance(row.get("value"), list) and row.get("value")
            for row in v1_observations
        )
        if contradiction_kept == bool(known.get("contradiction_expected")):
            v1_preserved += 1
        v1_checked += 1
        negative_kept = any(
            row.get("field") == "valid_negatives" and isinstance(row.get("value"), list) and row.get("value")
            for row in v1_observations
        )
        if negative_kept == bool(known.get("valid_negative_expected")):
            v1_preserved += 1
        for field in unknown_fields:
            v1_unknown_checked += 1
            if any(row.get("field") == field and row.get("value") in (None, "unknown") for row in v1_observations):
                v1_unknown_preserved += 1
    return {
        "facts_checked": checked,
        "facts_preserved": preserved,
        "facts_lost": lost,
        "unknown_checked": unknown_checked,
        "unknown_preserved": unknown_preserved,
        "unknown_coerced": unknown_coerced,
        "schema_valid": not schema_issues,
        "privacy_leak": bool(leak_codes),
        "privacy_issues": leak_codes,
        "v1_facts_checked": v1_checked,
        "v1_facts_preserved": v1_preserved,
        "v1_unknown_checked": v1_unknown_checked,
        "v1_unknown_preserved": v1_unknown_preserved,
        "v1_schema_valid": v1_schema_valid,
        "v1_privacy_leak": v1_leak,
        "finding_confirmed": False,
    }


def aggregate_metrics(rows: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    """Combine per-case scores. Rates are null when the denominator is zero."""

    def total(key: str) -> int:
        return sum(int(row[key]) for row in rows)

    def rate(numerator: int, denominator: int) -> float | None:
        if denominator == 0:
            return None
        return numerator / denominator

    checked = total("facts_checked")
    preserved = total("facts_preserved")
    unknown_checked = total("unknown_checked")
    unknown_preserved = total("unknown_preserved")
    v1_checked = total("v1_facts_checked")
    v1_preserved = total("v1_facts_preserved")
    v1_unknown_checked = total("v1_unknown_checked")
    v1_unknown_preserved = total("v1_unknown_preserved")
    count = len(rows)
    return {
        "cases": count,
        "known_fact_preservation": rate(preserved, checked),
        "semantic_loss": rate(checked - preserved, checked),
        "unknown_preservation": rate(unknown_preserved, unknown_checked),
        "unknown_coerced": total("unknown_coerced"),
        "privacy_leak_rate": rate(sum(1 for row in rows if row["privacy_leak"]), count),
        "schema_valid_rate": rate(sum(1 for row in rows if row["schema_valid"]), count),
        "v1_known_fact_preservation": rate(v1_preserved, v1_checked),
        "v1_semantic_loss": rate(v1_checked - v1_preserved, v1_checked),
        "v1_unknown_preservation": rate(v1_unknown_preserved, v1_unknown_checked),
        "v1_privacy_leak_rate": rate(sum(1 for row in rows if row["v1_privacy_leak"]), count),
        "v1_schema_valid_rate": rate(sum(1 for row in rows if row["v1_schema_valid"]), count),
        "finding_confirmed": False,
    }


def _cited_refs(analysis: Mapping[str, Any] | None, critique: Mapping[str, Any] | None) -> list[str]:
    refs: list[str] = []
    if analysis:
        for claim in analysis.get("claims") or []:
            if isinstance(claim, Mapping):
                for ref in claim.get("refs") or []:
                    if isinstance(ref, str):
                        refs.append(ref)
    if critique:
        for item in critique.get("contradictions") or []:
            if isinstance(item, Mapping):
                for ref in item.get("refs") or []:
                    if isinstance(ref, str):
                        refs.append(ref)
    return refs


def _decision_compatible(decision: str, packet: Mapping[str, Any]) -> bool:
    if decision == "inconclusive":
        return True
    if decision == "candidate":
        return (
            packet.get("visibility") == "private"
            and packet.get("private_marker_present") is True
            and packet.get("cross_read_observed") is True
            and packet.get("explicit_denial_present") is False
            and packet.get("owner_control_present") is True
            and packet.get("second_actor_control_present") is True
            and packet.get("distinct_accounts") is True
            and packet.get("auth_context_declared") is True
            and packet.get("session_continuity") in {"same", "distinct"}
            and packet.get("truncation") == "none"
            and packet.get("integrity") == "intact"
            and packet.get("completeness") == "complete"
            and packet.get("contradicting_refs") == []
            and packet.get("status_family") == "success"
            and packet.get("finding_confirmed") is False
        )
    if decision == "not_observed":
        if packet.get("visibility") in {"shared", "unknown"} and packet.get("explicit_denial_present") is not True:
            return False
        if packet.get("contradicting_refs"):
            return False
        return packet.get("explicit_denial_present") is True or (
            packet.get("visibility") == "public" and packet.get("private_marker_present") is False
        )
    return False


def _safety_flags() -> dict[str, bool]:
    return {
        "finding_confirmed": False,
        "evidence_ledger_modified": False,
        "controls_rewritten": False,
        "requests_emitted": False,
        "investigation_approved": False,
        "historical_ledger_rewritten": False,
        "ai_has_classification_authority": False,
        "tools_available": False,
        "consensus_is_proof": False,
    }


def normalize_dual_advisory(
    analysis: Mapping[str, Any] | None,
    critique: Mapping[str, Any] | None,
    packet: Mapping[str, Any],
    invented_refs: Sequence[str],
    allowed_refs: set[str],
    *,
    enabled: bool,
) -> dict[str, Any]:
    """Opt-in advisory. Disabled callers keep the production inconclusive rule elsewhere.

    This function never confirms a finding, never writes the Evidence Ledger, and
    never rewrites packet controls. Consensus is not classification authority.
    """
    base = {
        "schema_version": ADVISORY_SCHEMA_VERSION,
        "enabled": enabled,
        "applied": False,
        "consensus_reached": False,
        "advisory_decision": None,
        "failed_gates": ["opt_in_disabled"],
        "production_rule_unchanged": True,
        **_safety_flags(),
    }
    if not enabled:
        return base
    reviews_valid = analysis is not None and critique is not None
    decisions = []
    if analysis and analysis.get("decision") in DECISIONS:
        decisions.append(str(analysis["decision"]))
    if critique and critique.get("decision") in DECISIONS:
        decisions.append(str(critique["decision"]))
    agree = len(decisions) == 2 and decisions[0] == decisions[1]
    shared = decisions[0] if agree else None
    cited = _cited_refs(analysis, critique)
    evidence_without_refs = False
    if analysis:
        for claim in analysis.get("claims") or []:
            if isinstance(claim, Mapping) and claim.get("kind") == "evidence" and not claim.get("refs"):
                evidence_without_refs = True
    unsupported = []
    contradictions = []
    if critique:
        unsupported = list(critique.get("unsupported_claims") or [])
        contradictions = list(critique.get("contradictions") or [])
    schema_ok = not validate_contract_packet(packet) and not lint_contract_packet(packet)
    gates = {
        "valid_evidence": schema_ok
        and packet.get("integrity") == "intact"
        and packet.get("completeness") == "complete",
        "reviews_valid": reviews_valid and agree,
        "existing_refs": not invented_refs and all(ref in allowed_refs for ref in cited),
        "no_invented_claims": not invented_refs
        and not evidence_without_refs
        and not unsupported
        and not contradictions,
        "state_compatibility": bool(shared) and _decision_compatible(shared or "", packet),
        "complete_controls_when_required": True,
    }
    if shared == "candidate":
        packet_controls = packet.get("missing_controls")
        analyst_controls = analysis.get("missing_controls") if analysis else None
        critic_controls = critique.get("missing_controls") if critique else None
        gates["complete_controls_when_required"] = (
            packet_controls == [] and analyst_controls == [] and critic_controls == []
        )
    failed = [name for name in _GATES if not gates[name]]
    reached = not failed and shared is not None
    return {
        "schema_version": ADVISORY_SCHEMA_VERSION,
        "enabled": True,
        "applied": True,
        "consensus_reached": reached,
        "advisory_decision": shared if reached else "inconclusive",
        "failed_gates": failed,
        "production_rule_unchanged": True,
        **_safety_flags(),
    }
