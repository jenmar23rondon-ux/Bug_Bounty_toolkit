"""Evidence-grounded IDOR/BOLA compatibility evaluation (pairing precision v4).

Additive opt-in API. ``propose_object_handoff`` is unchanged and does not call this
module. Decisions are categorical. Nothing here assigns a probability, sends HTTP,
confirms a vulnerability, or writes the Evidence Ledger.

A pair is ``compatible`` only when concrete controls show both captures refer to the
same resource instance (namespace, kind, canonical id, endpoint). Same digits under
two kinds are not a match. Distinct instances of one kind are not the same resource.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import re
from typing import Any, Mapping, Sequence
from urllib.parse import parse_qsl, urlsplit

from ..case_generator import SESSION_HEADER
from .authorization_denial import ACCESS_PROOF_DENIALS, assess_response
from .object_relationships import resource_kind_noun

ASSESSMENT_VERSION = "bbtk.idor-compatibility/1"
COMPATIBILITY_VALUES = frozenset(
    {"compatible", "incompatible", "insufficient_evidence", "conflicting_evidence"}
)
KNOWN_KIND_STATUSES = frozenset({"explicit", "derived"})
_LEVEL_CONFLICT = 3
_LEVEL_INCOMPATIBLE = 2
_LEVEL_INSUFFICIENT = 1

_ID_SEGMENT = re.compile(
    r"^(?:[0-9]+|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$",
    re.I,
)
_IGNORED_HEADERS = frozenset(
    {
        "accept",
        "accept-encoding",
        "accept-language",
        "connection",
        "content-language",
        "content-length",
        "content-type",
        "host",
        "user-agent",
    }
)
_ECHO_KEYS = frozenset(
    {
        "id",
        "uuid",
        "requested_id",
        "request_id",
        "requested",
        "resource_id",
        "object_id",
        "ref",
        "status",
        "ok",
        "success",
        "message",
        "type",
        "kind",
        "timestamp",
        "trace_id",
    }
)

# Legacy default stays on object handoff until this gate is explicitly flipped.
DEFAULT_PAIRING_PATH = "propose_object_handoff"
COMPATIBILITY_GATE = "opt_in"
DEFAULT_FLIPPED = False


def compatibility_gate_status() -> dict[str, Any]:
    """Document the opt-in gate. Does not change legacy pairing."""
    return {
        "version": ASSESSMENT_VERSION,
        "default_pairing_path": DEFAULT_PAIRING_PATH,
        "compatibility_api": "evaluate_compatibility",
        "gate": COMPATIBILITY_GATE,
        "default_flipped": DEFAULT_FLIPPED,
        "finding_confirmed": False,
        "network_requests_sent": 0,
        "flip_criteria": (
            "Keep propose_object_handoff as the default until a same-instance labeled "
            "benchmark shows precision above the frozen IRB FINAL 45 reference of 0.65 "
            "without a silent recall drop, and the FASE-3 hard negatives still refuse "
            "admission. IRB ideal_pair_types mostly name distinct instances of one kind; "
            "they are not proof of one resource and are the wrong flip signal."
        ),
    }


@dataclass(frozen=True)
class EvidenceCapture:
    """One side of a candidate pair. Callers pass already-redacted, local evidence."""

    evidence_ref: str
    method: str | None = None
    url: str | None = None
    origin: str | None = None
    program: str | None = None
    resource_kind: str | None = None
    kind_status: str = "unknown"
    resource_namespace: str | None = None
    resource_id: str | None = None
    parent_ids: tuple[str, ...] = ()
    endpoint_template: str | None = None
    account_ref: str | None = None
    session_ref: str | None = None
    batch_id: str | None = None
    continuity_declared: bool = False
    captured_at: str | None = None
    temporal_not_before: str | None = None
    temporal_not_after: str | None = None
    stale: bool = False
    response_present: bool = False
    status_code: int | None = None
    response_body: str = ""
    response_headers: Mapping[str, str] | None = None
    request_headers: Mapping[str, str] | None = None
    integrity_sha256: str | None = None
    artifact_sha256: str | None = None
    array_object_ids: tuple[str, ...] = ()
    query_id_values: tuple[str, ...] = ()

    @classmethod
    def from_mapping(cls, raw: Mapping[str, Any]) -> EvidenceCapture:
        def text(name: str) -> str | None:
            value = raw.get(name)
            return str(value) if isinstance(value, str) and value else None

        def flag(name: str) -> bool:
            return raw.get(name) is True

        def seq(name: str) -> tuple[str, ...]:
            value = raw.get(name) or ()
            if isinstance(value, str):
                return (value,)
            return tuple(str(item) for item in value)

        def headers(name: str) -> dict[str, str] | None:
            value = raw.get(name)
            if not isinstance(value, Mapping):
                return None
            return {str(key): str(item) for key, item in value.items()}

        status = raw.get("status_code")
        status_code = int(status) if isinstance(status, int) and not isinstance(status, bool) else None
        kind_status = text("kind_status") or "unknown"
        body = raw.get("response_body")
        response_body = body if isinstance(body, str) else ""
        return cls(
            evidence_ref=text("evidence_ref") or "unreferenced",
            method=text("method"),
            url=text("url"),
            origin=text("origin"),
            program=text("program"),
            resource_kind=text("resource_kind"),
            kind_status=kind_status,
            resource_namespace=text("resource_namespace"),
            resource_id=text("resource_id"),
            parent_ids=seq("parent_ids"),
            endpoint_template=text("endpoint_template"),
            account_ref=text("account_ref"),
            session_ref=text("session_ref"),
            batch_id=text("batch_id"),
            continuity_declared=flag("continuity_declared"),
            captured_at=text("captured_at"),
            temporal_not_before=text("temporal_not_before"),
            temporal_not_after=text("temporal_not_after"),
            stale=flag("stale"),
            response_present=flag("response_present"),
            status_code=status_code,
            response_body=response_body,
            response_headers=headers("response_headers"),
            request_headers=headers("request_headers"),
            integrity_sha256=text("integrity_sha256"),
            artifact_sha256=text("artifact_sha256"),
            array_object_ids=seq("array_object_ids"),
            query_id_values=seq("query_id_values"),
        )


def canonical_json(body: str) -> str | None:
    """Stable JSON text. Key order and insignificant spacing are not conflicts."""
    try:
        value = json.loads(body)
    except (json.JSONDecodeError, RecursionError, TypeError):
        return None
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def apply_alias(path: str, alias_rules: Sequence[tuple[str, str]]) -> str:
    """Apply the first declared prefix alias. Unknown prefixes are left unchanged."""
    for prefix, replacement in alias_rules:
        if path == prefix or path.startswith(prefix + "/"):
            path = replacement + path[len(prefix) :]
            if not path.startswith("/"):
                path = "/" + path
            break
    if len(path) > 1:
        path = path.rstrip("/")
    return path or "/"


def describe_http_target(
    url: str | None,
    *,
    alias_rules: Sequence[tuple[str, str]] = (),
) -> dict[str, Any]:
    """Derive origin, kind, leaf id, parents, template and query ids from one URL.

    Kind comes only from the collection segment in front of the leaf id. A bare
    number is never given a kind.
    """
    parsed = urlsplit(url or "")
    origin = f"{parsed.scheme}://{parsed.netloc}" if parsed.scheme and parsed.netloc else None
    path = apply_alias(parsed.path or "/", alias_rules)
    parts = [segment for segment in path.split("/") if segment]
    template: list[str] = []
    ids: list[str] = []
    literals: list[tuple[int, str]] = []
    for segment in parts:
        if _ID_SEGMENT.match(segment):
            template.append("{id}")
            ids.append(segment)
        else:
            literals.append((len(template), segment))
            template.append(segment)
    leaf = ids[-1] if ids else None
    parent_ids = tuple(ids[:-1])
    kind: str | None = None
    kind_status = "unknown"
    if leaf is not None:
        # The collection is the literal immediately before the last id token.
        last_id_at = max(index for index, token in enumerate(template) if token == "{id}")
        collection = next((name for index, name in reversed(literals) if index < last_id_at), None)
        if collection is not None:
            named = resource_kind_noun(collection)
            if named is not None:
                kind, basis = named
                kind_status = "explicit" if basis == "known_vocabulary" else "derived"
    query_ids = tuple(
        value for _name, value in parse_qsl(parsed.query, keep_blank_values=False) if leaf is not None and value == leaf
    )
    return {
        "origin": origin,
        "resource_kind": kind,
        "kind_status": kind_status,
        "resource_id": leaf,
        "parent_ids": parent_ids,
        "endpoint_template": "/" + "/".join(template) if template else "/",
        "query_id_values": query_ids,
        "resource_namespace": f"{origin}|{kind}" if origin and kind else None,
    }


def _parse_time(value: str | None) -> str | None:
    if not value:
        return None
    text = value.replace("Z", "+00:00")
    # Keep the comparison lexical on normalized aware ISO forms, reject naive times.
    if "T" not in text or ("+" not in text[-6:] and not text.endswith("+00:00") and "Z" in value):
        if not (text.endswith("+00:00") or text.endswith("-00:00") or re.search(r"[+-]\d\d:\d\d$", text)):
            return None
    return text


def _windows_disjoint(owner: EvidenceCapture, actor: EvidenceCapture) -> bool:
    """True only when at least one side declared an explicit window and they do not overlap."""
    if not any((owner.temporal_not_before, owner.temporal_not_after, actor.temporal_not_before, actor.temporal_not_after)):
        return False

    def bounds(side: EvidenceCapture) -> tuple[str | None, str | None]:
        start = _parse_time(side.temporal_not_before) or _parse_time(side.captured_at)
        end = _parse_time(side.temporal_not_after) or _parse_time(side.captured_at)
        return start, end

    left = bounds(owner)
    right = bounds(actor)
    if left[0] is None or left[1] is None or right[0] is None or right[1] is None:
        return False
    return left[0] > right[1] or right[0] > left[1]


def _echo_only(body: str, requested_id: str | None) -> bool:
    try:
        root = json.loads(body)
    except (json.JSONDecodeError, RecursionError, TypeError):
        return False
    if not isinstance(root, dict) or not root:
        return False
    keys = {str(key).lower() for key in root}
    if not keys <= _ECHO_KEYS:
        return False
    values = [root[key] for key in root if str(key).lower() not in {"status", "ok", "success", "message", "type", "kind"}]
    if not values:
        return False
    if requested_id is None:
        return True
    return any(str(value) == requested_id for value in values)


def _access_class(side: EvidenceCapture) -> str:
    """Categorical access class. Does not confirm a vulnerability."""
    if not side.response_present:
        return "missing"
    assessed = assess_response(
        side.status_code,
        side.response_body,
        side.response_headers,
        requested_id=side.resource_id,
    )
    if assessed.resource_visibility in {"public", "shared"} or assessed.access_proof == "public_200":
        return "public"
    if _echo_only(side.response_body, side.resource_id) or assessed.access_proof == "id_echo_without_resource":
        return "echo"
    denial = assessed.access_proof in ACCESS_PROOF_DENIALS or (
        assessed.denial_demonstrated and not assessed.access_demonstrated
    )
    if denial and not assessed.access_demonstrated:
        return "denial"
    if assessed.access_demonstrated or assessed.access_proof == "private_resource_200":
        return "content"
    return "ambiguous"


def _header_diff(owner: EvidenceCapture, actor: EvidenceCapture) -> bool:
    if owner.request_headers is None or actor.request_headers is None:
        return False

    def norm(headers: Mapping[str, str]) -> dict[str, str]:
        kept: dict[str, str] = {}
        for key, value in headers.items():
            name = str(key).lower()
            if name in _IGNORED_HEADERS or SESSION_HEADER.search(name):
                continue
            kept[name] = str(value)
        return kept

    return norm(owner.request_headers) != norm(actor.request_headers)


def _resolve_side(side: EvidenceCapture, alias_rules: Sequence[tuple[str, str]]) -> EvidenceCapture:
    derived = describe_http_target(side.url, alias_rules=alias_rules)
    kind = side.resource_kind or derived["resource_kind"]
    kind_status = side.kind_status if side.resource_kind else str(derived["kind_status"])
    if side.resource_kind and side.kind_status in KNOWN_KIND_STATUSES:
        kind_status = side.kind_status
    origin = side.origin or derived["origin"]
    namespace = side.resource_namespace or (f"{origin}|{kind}" if origin and kind else None)
    template = side.endpoint_template or derived["endpoint_template"]
    if side.endpoint_template:
        template = apply_alias(side.endpoint_template, alias_rules)
    resource_id = side.resource_id or derived["resource_id"]
    parents = side.parent_ids or derived["parent_ids"]
    query_ids = side.query_id_values or derived["query_id_values"]
    return EvidenceCapture(
        evidence_ref=side.evidence_ref,
        method=side.method,
        url=side.url,
        origin=origin,
        program=side.program,
        resource_kind=kind,
        kind_status=kind_status,
        resource_namespace=namespace,
        resource_id=None if resource_id is None else str(resource_id),
        parent_ids=tuple(parents),
        endpoint_template=None if template is None else str(template),
        account_ref=side.account_ref,
        session_ref=side.session_ref,
        batch_id=side.batch_id,
        continuity_declared=side.continuity_declared,
        captured_at=side.captured_at,
        temporal_not_before=side.temporal_not_before,
        temporal_not_after=side.temporal_not_after,
        stale=side.stale,
        response_present=side.response_present,
        status_code=side.status_code,
        response_body=side.response_body,
        response_headers=side.response_headers,
        request_headers=side.request_headers,
        integrity_sha256=side.integrity_sha256,
        artifact_sha256=side.artifact_sha256,
        array_object_ids=side.array_object_ids,
        query_id_values=tuple(query_ids),
    )


def _pair_id(owner: EvidenceCapture, actor: EvidenceCapture, explicit: str | None) -> str:
    if explicit:
        return explicit
    material = "|".join(
        (
            ASSESSMENT_VERSION,
            owner.evidence_ref,
            actor.evidence_ref,
            owner.resource_kind or "",
            owner.resource_id or "",
            actor.resource_id or "",
        )
    )
    return "pair:" + hashlib.sha256(material.encode()).hexdigest()[:20]


def evaluate_compatibility(
    owner: EvidenceCapture | Mapping[str, Any],
    actor: EvidenceCapture | Mapping[str, Any],
    *,
    pair_id: str | None = None,
    alias_rules: Sequence[tuple[str, str]] | None = None,
) -> dict[str, Any]:
    """Decide whether two captures are one resource worth human IDOR review.

    Returns a ``bbtk.idor-compatibility/1`` assessment. ``finding_confirmed`` is
    always false. ``pairing_decision`` is true only for ``compatible``.
    """
    rules = tuple(alias_rules or ())
    left_raw = owner if isinstance(owner, EvidenceCapture) else EvidenceCapture.from_mapping(owner)
    right_raw = actor if isinstance(actor, EvidenceCapture) else EvidenceCapture.from_mapping(actor)
    left = _resolve_side(left_raw, rules)
    right = _resolve_side(right_raw, rules)

    matching: list[str] = []
    conflicting: list[str] = []
    missing: list[str] = []
    blockers: list[tuple[int, str]] = []

    def block(level: int, code: str) -> None:
        blockers.append((level, code))
        if level == _LEVEL_INSUFFICIENT:
            if code not in missing:
                missing.append(code)
        elif code not in conflicting:
            conflicting.append(code)

    identity = "unproven"
    session = "unproven"

    if left.integrity_sha256 and left.artifact_sha256 and left.integrity_sha256 != left.artifact_sha256:
        block(_LEVEL_CONFLICT, "owner_integrity_mismatch")
    elif not (left.integrity_sha256 and left.artifact_sha256):
        missing.append("owner_artifact_integrity")
    else:
        matching.append("owner_artifact_integrity")
    if right.integrity_sha256 and right.artifact_sha256 and right.integrity_sha256 != right.artifact_sha256:
        block(_LEVEL_CONFLICT, "actor_integrity_mismatch")
    elif not (right.integrity_sha256 and right.artifact_sha256):
        missing.append("actor_artifact_integrity")
    else:
        matching.append("actor_artifact_integrity")

    if left.program and right.program and left.program != right.program:
        block(_LEVEL_INCOMPATIBLE, "mixed_program")
    elif left.program and left.program == right.program:
        matching.append("same_program")
    else:
        missing.append("program")

    if left.origin and right.origin and left.origin != right.origin:
        block(_LEVEL_INCOMPATIBLE, "mixed_origin")
    elif left.origin and left.origin == right.origin:
        matching.append("same_origin")
    else:
        block(_LEVEL_INSUFFICIENT, "missing_origin")

    left_known = bool(left.resource_kind) and left.kind_status in KNOWN_KIND_STATUSES
    right_known = bool(right.resource_kind) and right.kind_status in KNOWN_KIND_STATUSES
    if not left_known or not right_known:
        block(_LEVEL_INSUFFICIENT, "ambiguous_or_unknown_kind")
        identity = "unproven"
    elif left.resource_kind != right.resource_kind:
        block(_LEVEL_INCOMPATIBLE, "different_kind")
        identity = "different_kind"
        if left.resource_id and left.resource_id == right.resource_id:
            conflicting.append("same_digits_do_not_link_kinds")
    else:
        matching.append("same_kind")

    if left.resource_namespace and right.resource_namespace and left.resource_namespace != right.resource_namespace:
        block(_LEVEL_INCOMPATIBLE, "different_namespace")
    elif left.resource_namespace and left.resource_namespace == right.resource_namespace:
        matching.append("same_namespace")
    elif "different_kind" not in conflicting and "ambiguous_or_unknown_kind" not in missing:
        block(_LEVEL_INSUFFICIENT, "missing_namespace")

    if left.endpoint_template and right.endpoint_template and left.endpoint_template != right.endpoint_template:
        block(_LEVEL_INCOMPATIBLE, "different_endpoint")
    elif left.endpoint_template and left.endpoint_template == right.endpoint_template:
        matching.append("same_endpoint")
    else:
        block(_LEVEL_INSUFFICIENT, "missing_endpoint")

    if left.method and right.method and left.method.upper() != right.method.upper():
        block(_LEVEL_INCOMPATIBLE, "method_mismatch")
    elif not left.method or not right.method:
        block(_LEVEL_INSUFFICIENT, "missing_method")
    elif left.method.upper() != "GET" or right.method.upper() != "GET":
        block(_LEVEL_INCOMPATIBLE, "method_not_read")
    else:
        matching.append("read_method")

    if not left.resource_id or not right.resource_id:
        block(_LEVEL_INSUFFICIENT, "missing_resource_identity")
    elif left.resource_id != right.resource_id:
        block(_LEVEL_INCOMPATIBLE, "different_resource_identity")
        if identity == "unproven":
            identity = "distinct_instances"
    else:
        if identity == "unproven":
            identity = "same_instance"
        matching.append("same_resource_identity")

    if left.parent_ids and right.parent_ids and left.parent_ids != right.parent_ids:
        block(_LEVEL_INCOMPATIBLE, "parent_resource_mismatch")
    elif left.parent_ids and left.parent_ids == right.parent_ids:
        matching.append("same_parent_identity")

    owner_ids = set(left.array_object_ids)
    actor_ids = set(right.array_object_ids)
    if owner_ids and actor_ids:
        overlap = owner_ids & actor_ids
        if overlap and overlap != owner_ids and overlap != actor_ids:
            block(_LEVEL_INCOMPATIBLE, "partial_array_match")
        elif owner_ids == actor_ids and identity == "same_instance":
            matching.append("same_array_membership")

    if left.resource_id and left.resource_id in left.query_id_values:
        block(_LEVEL_INSUFFICIENT, "ambiguous_identifier_binding")
    if right.resource_id and right.resource_id in right.query_id_values:
        block(_LEVEL_INSUFFICIENT, "ambiguous_identifier_binding")

    if _header_diff(left, right):
        block(_LEVEL_INSUFFICIENT, "unscoped_header_difference")

    if left.account_ref and right.account_ref and left.account_ref == right.account_ref:
        block(_LEVEL_INCOMPATIBLE, "same_account_not_second_actor")
        session = "same_account"
    elif left.account_ref and right.account_ref:
        matching.append("distinct_accounts_attested")
        if session == "unproven":
            session = "distinct_sessions"
    else:
        missing.append("distinct_accounts")

    if "ownership" not in matching:
        missing.append("ownership")

    if left.session_ref and right.session_ref and left.session_ref == right.session_ref:
        block(_LEVEL_INCOMPATIBLE, "same_session")
        if session != "same_account":
            session = "same_session"
    elif left.session_ref and right.session_ref:
        matching.append("distinct_sessions")
        if session == "unproven":
            session = "distinct_sessions"
    else:
        block(_LEVEL_INSUFFICIENT, "unproven_session")

    if left.stale or right.stale:
        block(_LEVEL_INCOMPATIBLE, "stale_evidence")
    elif _windows_disjoint(left, right):
        block(_LEVEL_INCOMPATIBLE, "temporal_window_mismatch")
    elif not any(
        (
            left.temporal_not_before,
            left.temporal_not_after,
            right.temporal_not_before,
            right.temporal_not_after,
        )
    ):
        missing.append("temporal_window")
    else:
        matching.append("temporal_window_overlaps")

    if (
        left.batch_id
        and right.batch_id
        and left.batch_id != right.batch_id
        and not (left.continuity_declared or right.continuity_declared)
    ):
        block(_LEVEL_INSUFFICIENT, "different_batch_no_continuity")
    elif left.batch_id and left.batch_id == right.batch_id:
        matching.append("same_batch")
    elif left.continuity_declared or right.continuity_declared:
        matching.append("continuity_declared")
    else:
        missing.append("capture_continuity")

    if not left.response_present or not right.response_present:
        block(_LEVEL_INSUFFICIENT, "missing_response_artifact")
    else:
        left_access = _access_class(left)
        right_access = _access_class(right)
        if left_access == "public" or right_access == "public":
            block(_LEVEL_INCOMPATIBLE, "legitimate_shared")
        elif left_access == "echo" or right_access == "echo":
            block(_LEVEL_INSUFFICIENT, "id_echo_without_resource")
        elif {left_access, right_access} == {"denial", "content"}:
            block(_LEVEL_CONFLICT, "contradictory_access")
        elif left_access == "denial" or right_access == "denial":
            block(_LEVEL_INCOMPATIBLE, "authorization_denial")
        elif left_access == "ambiguous" or right_access == "ambiguous":
            block(_LEVEL_INSUFFICIENT, "ambiguous_response")
        elif left_access == "content" and right_access == "content":
            matching.append("private_resource_content")
        else:
            block(_LEVEL_INSUFFICIENT, "ambiguous_response")

    raw_left = canonical_json(left.response_body) if left.response_body else None
    raw_right = canonical_json(right.response_body) if right.response_body else None
    if raw_left is not None and raw_left == raw_right and left.response_body != right.response_body:
        matching.append("json_canonical_equivalent")

    if not blockers:
        compatibility = "compatible"
    else:
        level = max(item[0] for item in blockers)
        compatibility = {
            _LEVEL_CONFLICT: "conflicting_evidence",
            _LEVEL_INCOMPATIBLE: "incompatible",
            _LEVEL_INSUFFICIENT: "insufficient_evidence",
        }[level]

    admitted = compatibility == "compatible"
    gaps = sorted(set(missing))
    basis = (
        f"Owner evidence {left.evidence_ref} and actor evidence {right.evidence_ref}. "
        f"Identity assessment {identity}; session assessment {session}. "
        f"Compatibility {compatibility} from cited signals only. "
        f"Matching signals: {', '.join(sorted(set(matching))) or 'none'}. "
        f"Conflicting signals: {', '.join(sorted(set(conflicting))) or 'none'}. "
        f"Missing controls: {', '.join(gaps) or 'none'}. "
        "No probability score is assigned. finding_confirmed is false."
    )
    kind_out = left.resource_kind if left.resource_kind == right.resource_kind else None
    namespace_out = left.resource_namespace if left.resource_namespace == right.resource_namespace else None
    return {
        "version": ASSESSMENT_VERSION,
        "pair_id": _pair_id(left, right, pair_id),
        "owner_evidence_ref": left.evidence_ref,
        "actor_evidence_ref": right.evidence_ref,
        "resource_namespace": namespace_out,
        "resource_kind": kind_out,
        "identity_assessment": identity,
        "session_assessment": session,
        "matching_signals": sorted(set(matching)),
        "conflicting_signals": sorted(set(conflicting)),
        "missing_controls": gaps,
        "compatibility": compatibility,
        "pairing_decision": admitted,
        "confidence_basis": basis,
        "requires_human_review": admitted or compatibility in {"insufficient_evidence", "conflicting_evidence"},
        "finding_confirmed": False,
        "network_requests_sent": 0,
        "legacy_default_unchanged": True,
    }
