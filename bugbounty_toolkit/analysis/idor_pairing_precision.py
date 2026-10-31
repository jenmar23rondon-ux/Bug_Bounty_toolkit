"""Evidence-grounded IDOR/BOLA compatibility evaluation (v4).

Opt-in. ``propose_object_handoff`` is unchanged. Callers that want a categorical
owner/actor decision use :func:`evaluate_compatibility`. Decisions are
``compatible``, ``incompatible``, ``insufficient_evidence``, or
``conflicting_evidence``. There is no probability score.

Nothing here sends HTTP, writes the Evidence Ledger, or sets ``finding_confirmed``.
Identity is taken only from attested account refs. A session pseudonym is not an account.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any, Mapping, Sequence
from urllib.parse import urlsplit

from .authorization_denial import assess_response

SCHEMA_VERSION = "bbtk.compatibility-assessment/1"
COMPATIBILITY = frozenset({"compatible", "incompatible", "insufficient_evidence", "conflicting_evidence"})
_PRIVILEGED_ROLES = frozenset({"admin", "staff", "superuser", "root", "internal", "service"})
_IRREGULAR_KINDS = {"addresses": "address", "people": "person"}
_ID_RE = re.compile(
    r"^(?:\d+|[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-8][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12})$"
)


def singularize_kind(word: str) -> str:
    """Conservative English singular for a path collection. Not an ownership claim."""
    kind = word.strip().lower()
    if kind in _IRREGULAR_KINDS:
        return _IRREGULAR_KINDS[kind]
    if kind.endswith("ies") and len(kind) > 4:
        return kind[:-3] + "y"
    if len(kind) > 3 and kind.endswith("s") and not kind.endswith(("ss", "us", "is")):
        return kind[:-1]
    return kind


@dataclass(frozen=True)
class RouteView:
    """Path facts after declared alias stripping. Prefixes not stripped stay visible."""

    kind: str | None
    resource_id: str | None
    qualifier: str | None
    undeclared_prefixes: tuple[str, ...]
    stripped_prefixes: tuple[str, ...]


@dataclass(frozen=True)
class CompatibilityAssessment:
    """Versioned v1 assessment. ``confidence_basis`` is prose, never a float."""

    schema_version: str
    pair_id: str
    owner_evidence_ref: str
    actor_evidence_ref: str
    resource_namespace: str | None
    resource_kind: str | None
    identity_assessment: str
    session_assessment: str
    matching_signals: tuple[str, ...]
    conflicting_signals: tuple[str, ...]
    missing_controls: tuple[str, ...]
    compatibility: str
    pairing_decision: bool
    confidence_basis: str
    requires_human_review: bool
    finding_confirmed: bool = False
    network_requests_sent: int = 0
    external_requests: int = 0

    def __post_init__(self) -> None:
        if self.finding_confirmed:
            raise ValueError("finding_confirmed must stay false")
        if self.compatibility not in COMPATIBILITY:
            raise ValueError(f"invalid compatibility: {self.compatibility}")
        if self.pairing_decision and self.compatibility != "compatible":
            raise ValueError("pairing_decision requires compatibility=compatible")
        if self.requires_human_review and not self.pairing_decision:
            raise ValueError("requires_human_review is only set when the pair is admitted")
        if self.network_requests_sent or self.external_requests:
            raise ValueError("compatibility evaluation must not perform requests")

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "pair_id": self.pair_id,
            "owner_evidence_ref": self.owner_evidence_ref,
            "actor_evidence_ref": self.actor_evidence_ref,
            "resource_namespace": self.resource_namespace,
            "resource_kind": self.resource_kind,
            "identity_assessment": self.identity_assessment,
            "session_assessment": self.session_assessment,
            "matching_signals": list(self.matching_signals),
            "conflicting_signals": list(self.conflicting_signals),
            "missing_controls": list(self.missing_controls),
            "compatibility": self.compatibility,
            "pairing_decision": self.pairing_decision,
            "confidence_basis": self.confidence_basis,
            "requires_human_review": self.requires_human_review,
            "finding_confirmed": False,
            "network_requests_sent": 0,
            "external_requests": 0,
        }


def parse_route(path: str, alias_rules: Mapping[str, Any] | None = None) -> RouteView:
    """Return the leaf collection/id after declared ``strip_prefixes``.

    A leading segment that is not a declared alias and not part of a collection/id
    pair is an undeclared prefix. Identical undeclared prefixes on both sides are a
    shared mount, not an invented alias.
    """
    strip = _strip_prefixes(alias_rules)
    aliases = _kind_aliases(alias_rules)
    raw_parts = [part for part in urlsplit(path).path.split("/") if part]
    stripped: list[str] = []
    parts = list(raw_parts)
    while parts and parts[0].lower() in strip:
        stripped.append(parts.pop(0).lower())
    consumed = [False] * len(parts)
    found: list[tuple[str, str, int]] = []
    index = 0
    while index < len(parts) - 1:
        if _ID_RE.match(parts[index + 1]):
            kind = aliases.get(parts[index].lower(), singularize_kind(parts[index]))
            found.append((kind, parts[index + 1], index))
            consumed[index] = True
            consumed[index + 1] = True
            index += 2
            continue
        index += 1
    qualifier: str | None = None
    if found:
        cursor = found[-1][2] + 2
        rest = parts[cursor:]
        if len(rest) == 1 and not _ID_RE.match(rest[0]):
            qualifier = rest[0].lower()
            consumed[cursor] = True
    undeclared = tuple(parts[pos] for pos, flag in enumerate(consumed) if not flag)
    if not found:
        return RouteView(None, None, qualifier, undeclared, tuple(stripped))
    kind, resource_id, _start = found[-1]
    return RouteView(kind, resource_id, qualifier, undeclared, tuple(stripped))


def evaluate_compatibility(
    owner: Mapping[str, Any],
    actor: Mapping[str, Any],
    *,
    context: Sequence[Mapping[str, Any]] | None = None,
    alias_rules: Mapping[str, Any] | None = None,
    continuity: Mapping[str, Any] | None = None,
    as_of: str | None = None,
    pair_id: str | None = None,
) -> CompatibilityAssessment:
    """Decide whether two captures support a human-reviewable IDOR candidate.

    ``context`` holds sibling exchanges (negative controls). They are evidence, not
    extra identities. Account equality is honored only when both sides set
    ``accounts_attested`` and ``account_ref``.
    """
    owner_view = _side(owner, alias_rules)
    actor_view = _side(actor, alias_rules)
    context_views = tuple(_side(item, alias_rules) for item in (context or ()))
    matching: list[str] = []
    conflicting: list[str] = []
    missing: list[str] = []
    blocks: list[str] = []

    _integrity(owner_view, actor_view, conflicting)
    _contradiction(owner_view, actor_view, conflicting)
    _gaps(owner_view, actor_view, missing, as_of, continuity)
    _identity_conflicts(owner_view, actor_view, matching, conflicting, blocks, missing)
    _session(owner_view, actor_view, matching, blocks, missing)
    _access(owner_view, actor_view, matching, blocks, missing)
    _negative_control(owner_view, actor_view, context_views, blocks)
    _privileged(owner_view, actor_view, context_views, blocks)
    _json_equivalence(owner_view, actor_view, matching)
    _partial_array(owner_view, actor_view, blocks)

    identity = _identity_label(owner_view, actor_view, blocks)
    session = _session_label(owner_view, actor_view)
    # Integrity and same-id denial/access contradictions outrank everything else.
    # A known mismatch (kind, origin, denial, shared ACL) outranks a gap.
    # Account attestation is listed when absent and does not by itself block review.
    informative = [item for item in missing if item != "distinct_account_attestation"]
    if conflicting:
        decision = "conflicting_evidence"
    elif blocks:
        decision = "incompatible"
    elif informative:
        decision = "insufficient_evidence"
    else:
        decision = "compatible"
    if decision == "compatible":
        if owner_view.route.kind and owner_view.route.kind == actor_view.route.kind:
            matching.append("same_kind")
        if owner_view.method == "GET" and actor_view.method == "GET":
            matching.append("method_get")

    admitted = decision == "compatible"
    kind = owner_view.route.kind if owner_view.route.kind == actor_view.route.kind else None
    namespace = _namespace(owner_view, actor_view, kind)
    owner_ref = _ref(owner)
    actor_ref = _ref(actor)
    basis = _basis(owner_ref, actor_ref, decision, identity, session, matching, conflicting, missing, blocks)
    return CompatibilityAssessment(
        schema_version=SCHEMA_VERSION,
        pair_id=pair_id or _pair_id(owner_ref, actor_ref, kind),
        owner_evidence_ref=owner_ref,
        actor_evidence_ref=actor_ref,
        resource_namespace=namespace,
        resource_kind=kind,
        identity_assessment=identity,
        session_assessment=session,
        matching_signals=tuple(sorted(set(matching))),
        conflicting_signals=tuple(sorted(set(conflicting))),
        missing_controls=tuple(sorted(set(missing))),
        compatibility=decision,
        pairing_decision=admitted,
        confidence_basis=basis,
        requires_human_review=admitted,
        finding_confirmed=False,
        network_requests_sent=0,
        external_requests=0,
    )


# --------------------------------------------------------------------------- internals


@dataclass(frozen=True)
class _Side:
    ref: str
    route: RouteView
    method: str
    origin_key: tuple[str, str, int] | None
    origin: str | None
    program: str | None
    namespace: str | None
    session_ref: str | None
    account_ref: str | None
    accounts_attested: bool
    response_present: bool
    body: str | None
    access: bool
    denial: bool
    contradictory: bool
    proof: str
    visibility: str | None
    integrity_conflict: bool
    stale: bool
    window: tuple[str, str] | None
    batch_id: str | None
    capture_run: str | None
    expires_at: str | None
    ambiguous_kind: bool
    request_headers: Mapping[str, str]
    array_ids: frozenset[str]


def _side(raw: Mapping[str, Any], alias_rules: Mapping[str, Any] | None) -> _Side:
    path = str(raw.get("path") or raw.get("url") or "")
    route = parse_route(path, alias_rules)
    explicit_kinds = raw.get("resource_kinds")
    status = str(raw.get("kind_status") or "")
    ambiguous = status in {"ambiguous", "unknown"} or (
        isinstance(explicit_kinds, (list, tuple)) and len(explicit_kinds) != 1
    )
    explicit = raw.get("resource_kind")
    if ambiguous:
        route = RouteView(None, route.resource_id, route.qualifier, route.undeclared_prefixes, route.stripped_prefixes)
    elif isinstance(explicit, str) and explicit.strip():
        aliases = _kind_aliases(alias_rules)
        kind = aliases.get(explicit.strip().lower(), singularize_kind(explicit))
        route = RouteView(
            kind,
            route.resource_id or _text(raw.get("resource_id")),
            route.qualifier,
            route.undeclared_prefixes,
            route.stripped_prefixes,
        )
    elif raw.get("resource_id"):
        route = RouteView(
            route.kind, str(raw["resource_id"]), route.qualifier, route.undeclared_prefixes, route.stripped_prefixes
        )
    body = raw.get("response_body")
    body_text = body if isinstance(body, str) else None
    present = raw.get("response_present")
    if present is None:
        present = body_text is not None or raw.get("status_code") is not None
    status_code = raw.get("status_code")
    code = int(status_code) if isinstance(status_code, int) else None
    headers = _header_map(raw.get("response_headers"))
    proof = assess_response(code, body_text or "", headers, requested_id=route.resource_id)
    explicit_visibility = _text(raw.get("visibility"))
    visibility = (
        explicit_visibility if explicit_visibility in {"public", "shared", "private"} else proof.resource_visibility
    )
    access = bool(proof.access_demonstrated) or proof.access_proof == "private_resource_200"
    denial = bool(proof.denial_demonstrated) and not access
    if visibility in {"public", "shared"}:
        access = False
    return _Side(
        ref=_ref(raw),
        route=route,
        method=str(raw.get("method") or "").upper(),
        origin_key=_origin_key(_text(raw.get("origin"))),
        origin=_text(raw.get("origin")),
        program=_text(raw.get("program")),
        namespace=_text(raw.get("namespace")),
        session_ref=_text(raw.get("session_ref")),
        account_ref=_text(raw.get("account_ref")),
        accounts_attested=bool(raw.get("accounts_attested")),
        response_present=bool(present),
        body=body_text,
        access=access,
        denial=denial,
        contradictory="contradictory_denial_status_with_resource_body" in proof.reasons,
        proof=proof.access_proof,
        visibility=visibility,
        integrity_conflict=_integrity_conflict(raw, body_text),
        stale=_stale(raw),
        window=_window(raw),
        batch_id=_text(raw.get("batch_id")),
        capture_run=_text(raw.get("capture_run")),
        expires_at=_text(raw.get("expires_at")),
        ambiguous_kind=ambiguous or route.kind is None,
        request_headers=_header_map(raw.get("request_headers")),
        array_ids=_array_ids(body_text),
    )


def _integrity(owner: _Side, actor: _Side, conflicting: list[str]) -> None:
    if owner.integrity_conflict or actor.integrity_conflict:
        conflicting.append("artifact_integrity_mismatch")


def _contradiction(owner: _Side, actor: _Side, conflicting: list[str]) -> None:
    if owner.contradictory or actor.contradictory:
        conflicting.append("contradictory_authorization_evidence")
    same = (
        owner.route.kind and owner.route.kind == actor.route.kind and owner.route.resource_id == actor.route.resource_id
    )
    if not same or not owner.route.resource_id:
        return
    if (owner.denial and actor.access) or (actor.denial and owner.access):
        conflicting.append("contradictory_negative_evidence")


def _gaps(
    owner: _Side,
    actor: _Side,
    missing: list[str],
    as_of: str | None,
    continuity: Mapping[str, Any] | None,
) -> None:
    if not owner.response_present or not actor.response_present:
        missing.append("response_artifact")
    if owner.ambiguous_kind or actor.ambiguous_kind or not owner.route.kind or not actor.route.kind:
        missing.append("resource_kind")
    if owner.proof == "id_echo_without_resource" or actor.proof == "id_echo_without_resource":
        missing.append("id_echo_without_resource")
    if owner.stale or actor.stale or _expired(owner, as_of) or _expired(actor, as_of):
        missing.append("fresh_evidence")
    if owner.route.undeclared_prefixes != actor.route.undeclared_prefixes:
        missing.append("declared_route_alias")
    _continuity(owner, actor, missing, continuity)
    if not owner.session_ref or not actor.session_ref:
        missing.append("session_ref")


def _continuity(owner: _Side, actor: _Side, missing: list[str], continuity: Mapping[str, Any] | None) -> None:
    if owner.batch_id and actor.batch_id and owner.batch_id != actor.batch_id:
        if not _linked(continuity, "linked_batches", owner.batch_id, actor.batch_id):
            missing.append("capture_continuity")
    if owner.capture_run and actor.capture_run and owner.capture_run != actor.capture_run:
        if not _linked(continuity, "linked_runs", owner.capture_run, actor.capture_run):
            missing.append("capture_continuity")


def _identity_conflicts(
    owner: _Side,
    actor: _Side,
    matching: list[str],
    conflicting: list[str],
    blocks: list[str],
    missing: list[str],
) -> None:
    if owner.origin_key and actor.origin_key and owner.origin_key != actor.origin_key:
        blocks.append("mixed_origin")
    if owner.program and actor.program and owner.program != actor.program:
        blocks.append("mixed_program")
    if owner.namespace and actor.namespace and owner.namespace != actor.namespace:
        blocks.append("namespace_mismatch")
    if owner.method and actor.method and owner.method != actor.method:
        blocks.append("method_mismatch")
    elif owner.method and owner.method != "GET":
        blocks.append("method_not_read")
    if owner.route.kind and actor.route.kind and owner.route.kind != actor.route.kind:
        blocks.append("cross_kind")
    if owner.route.qualifier and actor.route.qualifier and owner.route.qualifier != actor.route.qualifier:
        blocks.append("qualifier_mismatch")
    if owner.window and actor.window and (owner.window[1] < actor.window[0] or actor.window[1] < owner.window[0]):
        blocks.append("temporal_window_disjoint")
    if owner.route.stripped_prefixes or actor.route.stripped_prefixes:
        matching.append("declared_route_alias")
    if owner.route.undeclared_prefixes and owner.route.undeclared_prefixes == actor.route.undeclared_prefixes:
        matching.append("shared_mount_prefix")
    if owner.route.kind and owner.route.kind == actor.route.kind and owner.route.resource_id == actor.route.resource_id:
        matching.append("same_resource_id")
    if not owner.route.resource_id or not actor.route.resource_id:
        if "resource_kind" not in missing and "partial_array_match" not in blocks:
            missing.append("resource_id")


def _session(owner: _Side, actor: _Side, matching: list[str], blocks: list[str], missing: list[str]) -> None:
    if owner.session_ref and owner.session_ref == actor.session_ref:
        blocks.append("same_session_not_second_actor")
        return
    attested = owner.accounts_attested and actor.accounts_attested
    if attested and owner.account_ref and owner.account_ref == actor.account_ref:
        blocks.append("same_account_not_second_actor")
        return
    if attested and owner.account_ref and actor.account_ref and owner.account_ref != actor.account_ref:
        matching.append("distinct_accounts_attested")
        return
    missing.append("distinct_account_attestation")


def _access(owner: _Side, actor: _Side, matching: list[str], blocks: list[str], missing: list[str]) -> None:
    if owner.visibility in {"public", "shared"} or actor.visibility in {"public", "shared"}:
        blocks.append("legitimate_shared")
        return
    if owner.denial or actor.denial:
        blocks.append("authorization_denial")
        return
    if owner.access and actor.access:
        matching.append("private_access_both_sides")
        return
    if owner.proof == "id_echo_without_resource" or actor.proof == "id_echo_without_resource":
        return
    if owner.response_present and actor.response_present:
        missing.append("private_access")


def _negative_control(owner: _Side, actor: _Side, context: Sequence[_Side], blocks: list[str]) -> None:
    for item in context:
        if not item.denial or not item.route.kind or not item.route.resource_id:
            continue
        denies_owner = (
            item.session_ref == actor.session_ref
            and item.route.kind == owner.route.kind
            and item.route.resource_id == owner.route.resource_id
        )
        denies_actor = (
            item.session_ref == owner.session_ref
            and item.route.kind == actor.route.kind
            and item.route.resource_id == actor.route.resource_id
        )
        if denies_owner or denies_actor:
            blocks.append("negative_control_denies_cross_read")
            return


def _privileged(owner: _Side, actor: _Side, context: Sequence[_Side], blocks: list[str]) -> None:
    views = (owner, actor, *context)
    for privileged, other in ((owner, actor), (actor, owner)):
        if not _role_privileged(privileged.request_headers):
            continue
        if not _cross_read(privileged.session_ref, other, views):
            blocks.append("privileged_role_without_cross_object_access")
            return


def _json_equivalence(owner: _Side, actor: _Side, matching: list[str]) -> None:
    left = _canonical_json(owner.body)
    right = _canonical_json(actor.body)
    if left is None or right is None or left != right:
        return
    matching.append("json_canonical_equivalent")
    if owner.body != actor.body:
        matching.append("json_serialization_equivalent")


def _partial_array(owner: _Side, actor: _Side, blocks: list[str]) -> None:
    if owner.route.resource_id or actor.route.resource_id:
        return
    if not owner.array_ids or not actor.array_ids:
        return
    shared = owner.array_ids & actor.array_ids
    if shared and owner.array_ids != actor.array_ids:
        blocks.append("partial_array_match")


def _identity_label(owner: _Side, actor: _Side, blocks: list[str]) -> str:
    if "partial_array_match" in blocks:
        return "partial_array"
    if owner.ambiguous_kind or actor.ambiguous_kind or not owner.route.kind or not actor.route.kind:
        return "ambiguous"
    if owner.route.kind != actor.route.kind:
        return "different_kind"
    if "namespace_mismatch" in blocks or "mixed_origin" in blocks or "mixed_program" in blocks:
        return "different_namespace"
    if owner.route.resource_id and owner.route.resource_id == actor.route.resource_id:
        return "same_resource"
    if owner.route.resource_id and actor.route.resource_id:
        return "same_kind_distinct_ids"
    return "unproven"


def _session_label(owner: _Side, actor: _Side) -> str:
    if owner.session_ref and owner.session_ref == actor.session_ref:
        return "same_session"
    attested = owner.accounts_attested and actor.accounts_attested
    if attested and owner.account_ref and owner.account_ref == actor.account_ref:
        return "same_account"
    if attested and owner.account_ref and actor.account_ref and owner.account_ref != actor.account_ref:
        return "distinct_accounts_attested"
    if not owner.session_ref or not actor.session_ref:
        return "missing_session"
    return "distinct_sessions_accounts_unproven"


def _namespace(owner: _Side, actor: _Side, kind: str | None) -> str | None:
    if owner.namespace and owner.namespace == actor.namespace:
        return owner.namespace
    if owner.namespace and actor.namespace and owner.namespace != actor.namespace:
        return None
    if not kind or not owner.origin_key or owner.origin_key != actor.origin_key:
        return None
    scheme, host, port = owner.origin_key
    return f"{scheme}://{host}:{port}/{kind}"


def _basis(
    owner_ref: str,
    actor_ref: str,
    decision: str,
    identity: str,
    session: str,
    matching: list[str],
    conflicting: list[str],
    missing: list[str],
    blocks: list[str],
) -> str:
    return (
        f"Evidence {owner_ref} and {actor_ref}: {decision}. "
        f"Identity {identity}; session {session}. "
        f"Matching: {', '.join(sorted(set(matching))) or 'none'}. "
        f"Conflicts: {', '.join(sorted(set(conflicting))) or 'none'}. "
        f"Blocks: {', '.join(sorted(set(blocks))) or 'none'}. "
        f"Missing: {', '.join(sorted(set(missing))) or 'none'}. "
        "Categorical evidence citation, not a probability score."
    )


def _pair_id(owner_ref: str, actor_ref: str, kind: str | None) -> str:
    digest = hashlib.sha256(f"{owner_ref}\n{actor_ref}\n{kind or ''}".encode()).hexdigest()[:16]
    return "pair-" + digest


def _ref(raw: Mapping[str, Any]) -> str:
    ref = raw.get("evidence_ref")
    if isinstance(ref, str) and ref.strip():
        return ref.strip()
    raise ValueError("evidence_ref is required")


def _text(value: object) -> str | None:
    if isinstance(value, str) and value.strip():
        return value.strip()
    return None


def _header_map(value: object) -> dict[str, str]:
    if not isinstance(value, Mapping):
        return {}
    out: dict[str, str] = {}
    for key, item in value.items():
        if isinstance(key, str) and isinstance(item, str):
            out[key] = item
    return out


def _origin_key(origin: str | None) -> tuple[str, str, int] | None:
    if not origin:
        return None
    parsed = urlsplit(origin)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return None
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    return parsed.scheme, parsed.hostname.lower(), port


def _strip_prefixes(alias_rules: Mapping[str, Any] | None) -> set[str]:
    if not alias_rules:
        return set()
    raw = alias_rules.get("strip_prefixes") or ()
    if not isinstance(raw, (list, tuple, set)):
        return set()
    return {str(item).lower() for item in raw}


def _kind_aliases(alias_rules: Mapping[str, Any] | None) -> dict[str, str]:
    if not alias_rules:
        return {}
    raw = alias_rules.get("kind_aliases")
    if not isinstance(raw, Mapping):
        return {}
    return {str(key).lower(): singularize_kind(str(value)) for key, value in raw.items()}


def _integrity_conflict(raw: Mapping[str, Any], body: str | None) -> bool:
    if raw.get("integrity_ok") is False:
        return True
    declared = raw.get("response_sha256")
    if isinstance(declared, str) and body is not None:
        actual = hashlib.sha256(body.encode()).hexdigest()
        return actual != declared
    return False


def _stale(raw: Mapping[str, Any]) -> bool:
    return raw.get("stale") is True


def _expired(side: _Side, as_of: str | None) -> bool:
    return bool(as_of and side.expires_at and side.expires_at <= as_of)


def _window(raw: Mapping[str, Any]) -> tuple[str, str] | None:
    start = _text(raw.get("temporal_start"))
    end = _text(raw.get("temporal_end"))
    if start and end:
        return start, end
    return None


def _linked(continuity: Mapping[str, Any] | None, key: str, left: str, right: str) -> bool:
    if not continuity:
        return False
    groups = continuity.get(key) or ()
    if not isinstance(groups, (list, tuple)):
        return False
    for group in groups:
        if isinstance(group, (list, tuple, set)) and left in group and right in group:
            return True
    return False


def _canonical_json(body: str | None) -> str | None:
    if not body:
        return None
    try:
        value = json.loads(body)
    except (ValueError, RecursionError):
        return None
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _array_ids(body: str | None) -> frozenset[str]:
    if not body:
        return frozenset()
    try:
        root = json.loads(body)
    except (ValueError, RecursionError):
        return frozenset()
    found: set[str] = set()

    def walk(node: Any, in_array: bool) -> None:
        if isinstance(node, list):
            for item in node[:64]:
                walk(item, True)
            return
        if isinstance(node, dict):
            if in_array and "id" in node and not isinstance(node["id"], (dict, list)):
                found.add(str(node["id"]))
            for value in node.values():
                walk(value, in_array)

    walk(root, False)
    return frozenset(found)


def _role_privileged(headers: Mapping[str, str]) -> bool:
    for key, value in headers.items():
        if key.lower() in {"x-role", "x-privilege"} and value.strip().lower() in _PRIVILEGED_ROLES:
            return True
    return False


def _cross_read(session_ref: str | None, other: _Side, views: Sequence[_Side]) -> bool:
    if not session_ref or not other.route.resource_id:
        return False
    for view in views:
        if (
            view.session_ref == session_ref
            and view.route.kind == other.route.kind
            and view.route.resource_id == other.route.resource_id
            and view.access
            and not view.denial
        ):
            return True
    return False
