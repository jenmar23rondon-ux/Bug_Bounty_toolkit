"""Offline authorization control matrix for owner / second / anonymous comparison.

The matrix annotates captures that already exist. It does not send HTTP, does not
rewrite session identity, does not invent actors, and does not confirm a finding.
Ranking and pairing engines are not used. The annotation block uses a new schema
(``bbtk.authorization-control-matrix-annotation/1``) so existing consumers can ignore it.

Hard rules:

* An isolated HTTP 401 is not session expiration.
* A different token is not a different identity without provenance proof.
* A missing mandatory control yields ``blocked`` (never an automatic negative finding).
"""

from __future__ import annotations

from dataclasses import dataclass, field
import re
from typing import Any, Mapping, Sequence

from .authorization_denial import assess_response

SCHEMA = "bbtk.authorization-control-matrix/1"
ANNOTATION_SCHEMA = "bbtk.authorization-control-matrix-annotation/1"
MATRIX_VERSION = "1"

CONTROL_TYPES: tuple[str, ...] = (
    "owner_own_resource",
    "second_own_resource",
    "second_owner_resource",
    "anonymous",
    "public_shared_control",
    "negative_control",
    "owner_recheck",
)
MANDATORY_OWNER_SECOND: tuple[str, ...] = (
    "owner_own_resource",
    "second_own_resource",
    "second_owner_resource",
)
REASON_CODES: tuple[str, ...] = (
    "OWNER_CONTROL_MISSING",
    "ACTOR_CONTROL_MISSING",
    "CROSS_CAPTURE_MISSING",
    "SESSION_POSSIBLY_EXPIRED",
    "PUBLIC_RESOURCE_CONTROL",
    "SHARED_RESOURCE_CONTROL",
    "ID_ECHO_ONLY",
    "OWNER_CONTROL_BROKEN",
    "CAPTURE_ORDER_AMBIGUOUS",
    "COMPLETE_CONTROL_SET",
)
# Codes that already exist on authorization_denial. New matrix codes are emitted
# alongside these aliases; the pair/ranking engines are not asked to change.
REUSED_REASON_CODES: dict[str, tuple[str, ...]] = {
    "OWNER_CONTROL_BROKEN": ("owner_control_broken",),
    "ID_ECHO_ONLY": ("id_echo_without_resource", "actor_id_echo_without_resource"),
    "PUBLIC_RESOURCE_CONTROL": ("public_or_shared_resource",),
    "SHARED_RESOURCE_CONTROL": ("public_or_shared_resource",),
}
OBSERVATION_FIELDS: tuple[str, ...] = (
    "evidence_ref",
    "actor_label",
    "resource_ref",
    "control_type",
    "observed_status",
    "response_assessment",
    "capture_order",
    "integrity_status",
    "session_state",
    "expected_access_declared",
    "observed_access",
    "uncertainty",
)

_SECOND_LABELS = frozenset({"second", "second_account", "actor"})
_AUTH_FAILURES = frozenset({"http_401", "login_redirect"})
_DENIAL_PROOFS = frozenset({"http_401", "http_403", "http_404", "denial_in_200", "login_redirect"})
_KNOWN_PROOFS = frozenset(
    {
        "private_resource_200",
        "public_200",
        "denial_in_200",
        "http_401",
        "http_403",
        "http_404",
        "login_redirect",
        "id_echo_without_resource",
        "ambiguous",
    }
)
_SAFE_TOKEN = re.compile(r"^(?:SYNTH_|CANARY_)[A-Za-z0-9._:-]{1,80}$")
_LEAK = re.compile(r"(AKIA[0-9A-Z]{16}|-----BEGIN |CANARY_SECRET|Bearer\s+|password\s*=)", re.I)
_ISO_TS = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
_SCOPES = frozenset({"owner_second", "owner_second_anonymous"})


@dataclass
class _Row:
    index: int
    evidence_ref: str | None
    actor_label: str
    resource_ref: str | None
    resource_owner_label: str | None
    control_type: str
    explicit_control: bool
    observed_status: int | None
    access_proof: str
    response_class: str
    resource_visibility: str | None
    denial_demonstrated: bool
    access_demonstrated: bool
    capture_order: int | None
    timestamp: str | None
    timestamp_reliable: bool
    integrity_status: str
    session_ref: str | None
    token_ref: str | None
    expected_access_declared: str
    account_attested: bool
    session_change_proven: bool
    identity_change_proven: bool
    declared_account_ref: str | None
    uncertainty: list[str] = field(default_factory=list)


@dataclass
class _Fold:
    state: str
    expiry_proven: bool
    identity_changed: bool
    token_rotated: bool
    isolated_401: bool
    login_after_success: bool
    repeated_401: bool
    notes: list[str]


def _actor(value: object) -> str:
    if value == "owner":
        return "owner"
    if value in _SECOND_LABELS:
        return "second"
    if value == "anonymous":
        return "anonymous"
    return "unknown"


def _safe_id(value: object) -> str | None:
    if not isinstance(value, str) or not value or _LEAK.search(value):
        return None
    if len(value) > 80 or not re.fullmatch(r"[A-Za-z0-9._:-]+", value):
        return None
    return value


def _safe_token(value: object) -> str | None:
    if isinstance(value, str) and _SAFE_TOKEN.fullmatch(value) and not _LEAK.search(value):
        return value
    return None


def _status(value: object) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    if 100 <= value <= 599:
        return value
    return None


def _order(value: object) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    if value < 0 or value > 1_000_000:
        return None
    return value


def _expected(value: object) -> str:
    if value in {"allow", "deny", "public", "shared", "unknown"}:
        return str(value)
    return "unknown"


def _integrity(value: object) -> str:
    if value in {"intact", "tampered", "incomplete", "unknown"}:
        return str(value)
    return "unknown"


def _assessment_from_input(raw: Mapping[str, Any]) -> tuple[int | None, str, str, str | None, bool, bool]:
    """Return status, proof, class, visibility, denial, access. Bodies are not returned."""
    body = raw.get("body")
    headers = raw.get("headers")
    status = _status(raw.get("observed_status", raw.get("status_code")))
    if isinstance(body, (str, bytes, bytearray)) or isinstance(headers, Mapping):
        text = (
            body.decode("utf-8", errors="replace")
            if isinstance(body, (bytes, bytearray))
            else (body if isinstance(body, str) else "")
        )
        header_map: dict[str, str] = {}
        if isinstance(headers, Mapping):
            for key, value in headers.items():
                if isinstance(key, str) and isinstance(value, str) and key.lower() in {"location", "content-type"}:
                    header_map[key] = value
        requested = raw.get("requested_id")
        requested_id = requested if isinstance(requested, str) and not _LEAK.search(requested) else None
        assessed = assess_response(status, text, header_map, requested_id=requested_id)
        return (
            assessed.status_code,
            assessed.access_proof,
            assessed.response_class,
            assessed.resource_visibility,
            assessed.denial_demonstrated,
            assessed.access_demonstrated,
        )
    supplied = raw.get("response_assessment")
    if isinstance(supplied, Mapping):
        proof = supplied.get("access_proof")
        if proof not in _KNOWN_PROOFS:
            proof = "ambiguous"
        visibility = supplied.get("resource_visibility")
        if visibility not in {"public", "shared", None}:
            visibility = None
        response_class = supplied.get("response_class")
        if not isinstance(response_class, str) or not re.fullmatch(r"[a-z0-9_]{1,40}", response_class):
            response_class = "empty_or_unknown"
        return (
            status,
            str(proof),
            response_class,
            visibility if isinstance(visibility, str) else None,
            bool(supplied.get("denial_demonstrated")),
            bool(supplied.get("access_demonstrated")),
        )
    return status, "ambiguous", "empty_or_unknown", None, False, False


def _normalize(index: int, raw: Mapping[str, Any]) -> _Row:
    raw_provenance = raw.get("provenance")
    provenance: Mapping[str, Any] = raw_provenance if isinstance(raw_provenance, Mapping) else {}
    status, proof, response_class, visibility, denial, access = _assessment_from_input(raw)
    explicit = raw.get("control_type") if raw.get("control_type") in CONTROL_TYPES else None
    declared_visibility = raw.get("expected_access_declared")
    if visibility is None and declared_visibility in {"public", "shared"}:
        visibility = str(declared_visibility)
    token_in = raw.get("token_ref")
    token = _safe_token(token_in)
    uncertainty: list[str] = []
    if token_in not in (None, "") and token is None:
        uncertainty.append("token_ref_withheld")
    account = _safe_token(provenance.get("declared_account_ref"))
    if provenance.get("declared_account_ref") not in (None, "") and account is None:
        uncertainty.append("account_ref_withheld")
    actor = _actor(raw.get("actor_label"))
    resource_owner = _actor(raw.get("resource_owner_label")) if raw.get("resource_owner_label") is not None else None
    if resource_owner == "unknown":
        resource_owner = None
    return _Row(
        index=index,
        evidence_ref=_safe_id(raw.get("evidence_ref")),
        actor_label=actor,
        resource_ref=_safe_id(raw.get("resource_ref")),
        resource_owner_label=resource_owner,
        control_type=explicit or "unassigned",
        explicit_control=explicit is not None,
        observed_status=status,
        access_proof=proof,
        response_class=response_class,
        resource_visibility=visibility,
        denial_demonstrated=denial,
        access_demonstrated=access,
        capture_order=_order(raw.get("capture_order")),
        timestamp=raw.get("timestamp") if isinstance(raw.get("timestamp"), str) else None,
        timestamp_reliable=bool(raw.get("timestamp_reliable")),
        integrity_status=_integrity(raw.get("integrity_status")),
        session_ref=_safe_id(raw.get("session_ref")),
        token_ref=token,
        expected_access_declared=_expected(raw.get("expected_access_declared")),
        account_attested=bool(provenance.get("account_attested")),
        session_change_proven=bool(provenance.get("session_change_proven")),
        identity_change_proven=bool(provenance.get("identity_change_proven")),
        declared_account_ref=account,
        uncertainty=uncertainty,
    )


def _assign_control(row: _Row) -> None:
    if row.explicit_control:
        return
    if row.resource_visibility in {"public", "shared"}:
        row.control_type = "public_shared_control"
        return
    if row.actor_label == "anonymous":
        row.control_type = "anonymous"
        return
    if row.actor_label == "second" and row.resource_owner_label == "owner":
        row.control_type = "second_owner_resource"
        return
    if row.actor_label == "second" and row.resource_owner_label == "second":
        row.control_type = "second_own_resource"
        return
    if row.actor_label == "owner" and row.resource_owner_label == "owner":
        row.control_type = "owner_own_resource"


def _is_own(row: _Row) -> bool:
    if row.control_type in {"owner_own_resource", "second_own_resource", "owner_recheck"}:
        return True
    if row.control_type in {"second_owner_resource", "negative_control", "public_shared_control", "anonymous"}:
        return False
    return row.actor_label in {"owner", "second"} and row.actor_label == row.resource_owner_label


def _ordered(rows: Sequence[_Row]) -> list[_Row]:
    return sorted(rows, key=lambda row: (row.capture_order if row.capture_order is not None else 10**9, row.index))


def _order_flags(rows: Sequence[_Row]) -> tuple[bool, bool]:
    """Return ``(order_ambiguous, timestamps_unreliable)``."""
    unreliable = any(row.timestamp and not row.timestamp_reliable for row in rows)
    if len(rows) < 2:
        return False, unreliable
    orders = [row.capture_order for row in rows]
    if any(order is None for order in orders):
        return True, unreliable
    if len(set(orders)) != len(orders):
        return True, unreliable
    sequenced = _ordered(rows)
    reliable = [row for row in sequenced if row.timestamp and row.timestamp_reliable]
    if len(reliable) >= 2:
        if any(not _ISO_TS.fullmatch(row.timestamp or "") for row in reliable):
            return True, unreliable
        stamps = [row.timestamp or "" for row in reliable]
        if stamps != sorted(stamps) or len(set(stamps)) != len(stamps):
            return True, unreliable
    return False, unreliable


def _fold(rows: Sequence[_Row]) -> _Fold:
    notes: list[str] = []
    if not rows:
        return _Fold("identity_unproven", False, False, False, False, False, False, ["empty_session"])
    actor = rows[0].actor_label
    attested = all(row.account_attested for row in rows)
    success = False
    trailing_401 = 0
    login_after = False
    own_attempts = 0
    own_auth_fail = 0
    tokens: list[str] = []
    accounts: list[str] = []
    identity_changed = False
    token_rotated = False
    for row in rows:
        if row.token_ref:
            if tokens and row.token_ref != tokens[-1]:
                token_rotated = True
                previous = accounts[-1] if accounts else None
                current = row.declared_account_ref if row.account_attested else None
                if row.identity_change_proven and previous and current and current != previous:
                    identity_changed = True
                    notes.append("identity_change_proven")
                else:
                    notes.append("token_differs_identity_unproven")
            tokens.append(row.token_ref)
        if row.account_attested and row.declared_account_ref:
            accounts.append(row.declared_account_ref)
        if not _is_own(row):
            continue
        own_attempts += 1
        proof = row.access_proof
        if proof == "private_resource_200":
            success = True
            trailing_401 = 0
            login_after = False
        elif proof == "http_401" and success:
            trailing_401 += 1
        elif proof == "login_redirect" and success:
            login_after = True
            trailing_401 += 1
        elif proof in _AUTH_FAILURES and not success:
            own_auth_fail += 1
    isolated = False
    repeated = False
    if actor == "anonymous":
        if any(row.session_ref for row in rows):
            state = "identity_unproven"
            notes.append("anonymous_label_with_session_material")
        else:
            state = "anonymous"
    elif not attested or actor == "unknown":
        state = "identity_unproven"
        notes.append("cookies_alone_do_not_prove_identity")
    elif success and (login_after or trailing_401 >= 2):
        state = "possibly_expired"
        repeated = trailing_401 >= 2
        if login_after:
            notes.append("login_redirect_after_success")
        if repeated:
            notes.append("repeated_401_after_success")
    elif success and trailing_401 == 1 and not login_after:
        state = "valid"
        isolated = True
        notes.append("isolated_401_not_expiry")
    elif success:
        state = "valid"
    elif own_attempts and own_auth_fail == own_attempts:
        state = "invalid"
        notes.append("own_resource_auth_failure_without_success")
    else:
        state = "identity_unproven"
        notes.append("no_own_object_positive_control")
    return _Fold(state, False, identity_changed, token_rotated, isolated, login_after, repeated, notes)


def _session_key(row: _Row) -> str:
    if row.session_ref:
        return row.session_ref
    if row.actor_label == "anonymous":
        return "anonymous"
    return f"unbound:{row.index}"


def _usable(row: _Row) -> bool:
    if row.integrity_status != "intact" or row.evidence_ref is None or row.observed_status is None:
        return False
    if row.control_type == "public_shared_control":
        return row.resource_visibility in {"public", "shared"}
    if row.control_type == "anonymous":
        return row.actor_label == "anonymous" and row.session_ref is None and row.access_proof != "ambiguous"
    if row.control_type == "negative_control":
        return row.account_attested and row.access_proof in _DENIAL_PROOFS
    if row.control_type == "owner_recheck":
        return row.account_attested and row.actor_label == "owner" and row.access_proof != "ambiguous"
    if row.control_type == "owner_own_resource":
        return row.account_attested and row.actor_label == "owner" and row.access_proof == "private_resource_200"
    if row.control_type == "second_own_resource":
        return row.account_attested and row.actor_label == "second" and row.access_proof == "private_resource_200"
    if row.control_type == "second_owner_resource":
        return row.account_attested and row.actor_label == "second" and row.access_proof not in {"ambiguous"}
    return False


def _observed_access(row: _Row, deleted_resources: Mapping[str, int]) -> str:
    if row.resource_ref and row.resource_ref in deleted_resources:
        deleted_at = deleted_resources[row.resource_ref]
        if row.capture_order is not None and row.capture_order >= deleted_at and row.access_proof == "http_404":
            return "deleted"
    if row.access_proof == "private_resource_200":
        return "accessed"
    if row.access_proof == "public_200":
        return "shared" if row.resource_visibility == "shared" else "public"
    if row.access_proof == "id_echo_without_resource":
        return "echo_only"
    if row.access_proof in _DENIAL_PROOFS:
        return "denied"
    return "unknown"


def _deleted_at(rows: Sequence[_Row], order_ambiguous: bool) -> dict[str, int]:
    found: dict[str, int] = {}
    if order_ambiguous:
        return found
    first_private: dict[str, int] = {}
    for row in _ordered(rows):
        if row.capture_order is None or row.resource_ref is None:
            continue
        if row.actor_label == "owner" and row.access_proof == "private_resource_200":
            first_private.setdefault(row.resource_ref, row.capture_order)
        if (
            row.actor_label == "owner"
            and row.access_proof == "http_404"
            and row.resource_ref in first_private
            and row.capture_order > first_private[row.resource_ref]
        ):
            found.setdefault(row.resource_ref, row.capture_order)
    return found


def _mandatory(scope: str) -> tuple[str, ...]:
    if scope == "owner_second_anonymous":
        return (*MANDATORY_OWNER_SECOND, "anonymous")
    return MANDATORY_OWNER_SECOND


def _reason_for_missing(control: str) -> str | None:
    return {
        "owner_own_resource": "OWNER_CONTROL_MISSING",
        "second_own_resource": "ACTOR_CONTROL_MISSING",
        "second_owner_resource": "CROSS_CAPTURE_MISSING",
    }.get(control)


def _session_change(rows: Sequence[_Row]) -> tuple[bool, bool]:
    """Return ``(proven_mid_capture_change, unproven_session_ref_change)``."""
    proven = False
    unproven = False
    by_actor: dict[str, list[_Row]] = {}
    for row in rows:
        if row.actor_label in {"owner", "second"}:
            by_actor.setdefault(row.actor_label, []).append(row)
    for group in by_actor.values():
        sequenced = _ordered(group)
        seen: str | None = None
        for row in sequenced:
            ref = row.session_ref
            if ref is None:
                continue
            if seen is None:
                seen = ref
                continue
            if ref != seen:
                if row.session_change_proven:
                    proven = True
                else:
                    unproven = True
                seen = ref
    return proven, unproven


def _state_before(group: Sequence[_Row], limit: int) -> _Fold:
    return _fold([row for row in group if row.capture_order is not None and row.capture_order <= limit])


def evaluate_control_matrix(
    observations: Sequence[Mapping[str, Any]],
    *,
    comparison_scope: str = "owner_second",
) -> dict[str, Any]:
    """Build the versioned matrix for one comparison of already-authorized captures.

    ``finding_confirmed`` and ``negative_finding`` are always false. A missing
    mandatory cell is ``blocked``. Isolated 401s do not set ``SESSION_POSSIBLY_EXPIRED``.
    """
    scope = comparison_scope if comparison_scope in _SCOPES else "owner_second"
    scope_invalid = comparison_scope not in _SCOPES
    rows: list[_Row] = []
    malformed = 0
    for index, item in enumerate(observations):
        if not isinstance(item, Mapping):
            malformed += 1
            continue
        row = _normalize(index, item)
        _assign_control(row)
        rows.append(row)

    order_ambiguous, timestamps_unreliable = _order_flags(rows)
    if not order_ambiguous:
        # A later owner capture is a subsequent recheck only after the cross probe.
        # Earlier repeats stay owner controls so an isolated 401 is not a recheck.
        cross_orders = [
            row.capture_order
            for row in rows
            if row.control_type == "second_owner_resource" and row.capture_order is not None
        ]
        last_cross = max(cross_orders) if cross_orders else None
        seen_owner: set[str] = set()
        for row in _ordered(rows):
            if row.control_type != "owner_own_resource" or row.explicit_control or row.resource_ref is None:
                continue
            follows_cross = last_cross is not None and row.capture_order is not None and row.capture_order > last_cross
            if row.resource_ref in seen_owner and follows_cross:
                row.control_type = "owner_recheck"
            else:
                seen_owner.add(row.resource_ref)

    grouped: dict[str, list[_Row]] = {}
    for row in rows:
        grouped.setdefault(_session_key(row), []).append(row)
    folds: dict[str, _Fold] = {}
    for key, group in grouped.items():
        sequenced = _ordered(group)
        local_orders = [row.capture_order for row in group]
        local_ambiguous = len(group) >= 2 and (
            any(order is None for order in local_orders)
            or len(set(local_orders)) != len(local_orders)
            or order_ambiguous
        )
        if local_ambiguous and len(group) >= 2:
            folds[key] = _Fold("out_of_order", False, False, False, False, False, False, ["capture_order_ambiguous"])
        else:
            folds[key] = _fold(sequenced)

    deleted = _deleted_at(rows, order_ambiguous)
    proven_change, unproven_change = _session_change(rows) if not order_ambiguous else (False, False)

    def fold_for(row: _Row) -> _Fold:
        return folds[_session_key(row)]

    crosses = [row for row in rows if row.control_type == "second_owner_resource"]
    owner_before = False
    actor_before = False
    expired_before_cross = False
    if crosses and not order_ambiguous:
        owner_before = all(_owner_ready(rows, grouped, cross) for cross in crosses)
        actor_before = all(_actor_ready(rows, grouped, cross) for cross in crosses)
        expired_before_cross = any(_expired_by(grouped, cross) for cross in crosses)

    cells: dict[str, dict[str, Any]] = {}
    mandatory = set(_mandatory(scope))
    for control in CONTROL_TYPES:
        members = [row for row in rows if row.control_type == control]
        usable = [row for row in members if _usable(row)]
        cells[control] = {
            "control_type": control,
            "required": control in mandatory,
            "present": bool(members),
            "usable": bool(usable),
            "observation_indexes": [row.index for row in members],
            "status": "present" if usable else ("unusable" if members else "missing"),
        }

    reasons: list[str] = []

    def _explained_by_visibility(control: str) -> bool:
        if control == "owner_own_resource":
            return any(
                row.actor_label == "owner"
                and row.resource_owner_label == "owner"
                and row.resource_visibility in {"public", "shared"}
                for row in rows
            )
        if control == "second_own_resource":
            return any(
                row.actor_label == "second"
                and row.resource_owner_label == "second"
                and row.resource_visibility in {"public", "shared"}
                for row in rows
            )
        if control == "second_owner_resource":
            return any(
                row.actor_label == "second"
                and row.resource_owner_label == "owner"
                and row.resource_visibility in {"public", "shared"}
                for row in rows
            )
        if control == "anonymous":
            return any(
                row.actor_label == "anonymous" and row.resource_visibility in {"public", "shared"} for row in rows
            )
        return False

    unexplained_missing: list[str] = []
    for control in _mandatory(scope):
        if cells[control]["usable"] or _explained_by_visibility(control):
            continue
        unexplained_missing.append(control)
        code = _reason_for_missing(control)
        if code:
            reasons.append(code)
        elif control == "anonymous":
            for row in rows:
                row.uncertainty.append("anonymous_control_missing")
    if any(fold.state == "invalid" and fold_actor(rows, key) == "owner" for key, fold in folds.items()):
        reasons.append("OWNER_CONTROL_BROKEN")
    if any(row.access_proof == "id_echo_without_resource" for row in rows):
        reasons.append("ID_ECHO_ONLY")
    if any(row.resource_visibility == "public" for row in rows):
        reasons.append("PUBLIC_RESOURCE_CONTROL")
    if any(row.resource_visibility == "shared" for row in rows):
        reasons.append("SHARED_RESOURCE_CONTROL")
    if order_ambiguous:
        reasons.append("CAPTURE_ORDER_AMBIGUOUS")
    expiry_after_only = _expiry_only_after_crosses(rows, grouped, crosses) if crosses and not order_ambiguous else False
    possibly_expired = any(fold.state == "possibly_expired" for fold in folds.values())
    if possibly_expired and (expired_before_cross or not crosses or not expiry_after_only):
        reasons.append("SESSION_POSSIBLY_EXPIRED")
    elif possibly_expired and expiry_after_only:
        reasons.append("SESSION_POSSIBLY_EXPIRED")

    identity_changed = any(fold.identity_changed for fold in folds.values())
    rules: list[str] = []
    if owner_before and crosses:
        rules.append("owner_valid_before_cross")
    if any(fold.state == "invalid" and fold_actor(rows, key) == "owner" for key, fold in folds.items()):
        rules.append("owner_invalid")
    if any(fold.state == "invalid" and fold_actor(rows, key) == "second" for key, fold in folds.items()):
        rules.append("actor_invalid")
    if any(fold.isolated_401 for fold in folds.values()):
        rules.append("isolated_401")
    if any(fold.repeated_401 for fold in folds.values()):
        rules.append("repeated_401")
    if any(fold.login_after_success for fold in folds.values()):
        rules.append("login_redirect")
    if proven_change:
        rules.append("session_change_mid_capture")
    if deleted:
        rules.append("deleted_resource")
    if any(row.resource_visibility == "public" for row in rows):
        rules.append("public_resource")
    if any(row.resource_visibility == "shared" for row in rows):
        rules.append("shared_resource")
    if possibly_expired:
        rules.append("possibly_expired_session")
    if any(fold.token_rotated for fold in folds.values()):
        rules.append("rotated_token")
    if timestamps_unreliable:
        rules.append("unreliable_timestamps")
    recheck_out_of_order = _recheck_out_of_order(rows, crosses) if not order_ambiguous else False
    if order_ambiguous or recheck_out_of_order:
        rules.append("out_of_order_captures")
        if recheck_out_of_order:
            reasons.append("CAPTURE_ORDER_AMBIGUOUS")

    missing_mandatory = bool(unexplained_missing)
    echo = any(
        row.access_proof == "id_echo_without_resource"
        for row in crosses or rows
        if row.control_type == "second_owner_resource"
    )
    public_cross = any(row.resource_visibility in {"public", "shared"} for row in crosses)
    deleted_blocks = any(
        row.resource_ref in deleted and row.capture_order is not None and row.capture_order >= deleted[row.resource_ref]
        for row in crosses
    )
    uncertain_404 = _unconfirmed_404(rows, crosses, deleted) if not order_ambiguous else False
    contradictory = _contradictory_cross(crosses, deleted)

    denial_consistent = False
    if (
        not missing_mandatory
        and not order_ambiguous
        and not scope_invalid
        and not malformed
        and crosses
        and owner_before
        and actor_before
        and not expired_before_cross
        and not identity_changed
        and not unproven_change
        and not echo
        and not public_cross
        and not deleted_blocks
        and not uncertain_404
        and not contradictory
        and not recheck_out_of_order
        and all(_cross_denial(row, rows, deleted) for row in crosses)
    ):
        denial_consistent = True

    access_review_supported = False
    if (
        not missing_mandatory
        and not order_ambiguous
        and not scope_invalid
        and not malformed
        and crosses
        and owner_before
        and actor_before
        and not expired_before_cross
        and not identity_changed
        and not unproven_change
        and not echo
        and not public_cross
        and not deleted_blocks
        and all(row.access_proof == "private_resource_200" for row in crosses)
    ):
        access_review_supported = True

    if missing_mandatory or scope_invalid or malformed:
        disposition = "blocked"
    elif (
        order_ambiguous
        or unproven_change
        or identity_changed
        or echo
        or public_cross
        or deleted_blocks
        or uncertain_404
        or contradictory
        or expired_before_cross
        or not owner_before
        or not actor_before
        or recheck_out_of_order
        or any(row.resource_visibility in {"public", "shared"} for row in rows)
    ):
        disposition = "inconclusive"
    else:
        disposition = "complete"
        reasons.append("COMPLETE_CONTROL_SET")

    reason_codes = [code for code in REASON_CODES if code in set(reasons)]
    reused: list[str] = []
    for code in reason_codes:
        for alias in REUSED_REASON_CODES.get(code, ()):
            if alias not in reused:
                reused.append(alias)

    sessions: dict[str, dict[str, Any]] = {}
    for key in sorted(folds):
        fold = folds[key]
        sample = grouped[key][0]
        sessions[key] = {
            "actor_label": sample.actor_label,
            "state": fold.state,
            "expiry_proven": False,
            "identity_changed": fold.identity_changed,
            "token_rotated": fold.token_rotated,
            "isolated_401": fold.isolated_401,
            "notes": sorted(set(fold.notes)),
        }

    rendered: list[dict[str, Any]] = []
    provenance_complete = True
    for row in rows:
        uncertainty = list(row.uncertainty)
        if order_ambiguous:
            uncertainty.append("order_ambiguous")
        if timestamps_unreliable and row.timestamp and not row.timestamp_reliable:
            uncertainty.append("timestamps_unreliable")
        if row.integrity_status != "intact":
            uncertainty.append("integrity_not_intact")
        if fold_for(row).isolated_401:
            uncertainty.append("isolated_401")
        if fold_for(row).state == "possibly_expired":
            uncertainty.append("possibly_expired")
        if fold_for(row).token_rotated and not fold_for(row).identity_changed:
            uncertainty.append("token_rotated_identity_unproven")
        if fold_for(row).identity_changed:
            uncertainty.append("identity_changed_proven")
        if proven_change and row.session_change_proven:
            uncertainty.append("session_changed")
        if unproven_change:
            uncertainty.append("session_continuity_unproven")
        if row.resource_ref in deleted:
            uncertainty.append("resource_deleted")
        elif row.access_proof == "http_404":
            uncertainty.append("resource_possibly_deleted")
        if row.resource_visibility in {"public", "shared"}:
            uncertainty.append("public_or_shared")
        if row.access_proof == "id_echo_without_resource":
            uncertainty.append("id_echo_only")
        if row.actor_label in {"owner", "second"} and not row.account_attested:
            uncertainty.append("identity_unproven")
        record = {
            "evidence_ref": row.evidence_ref,
            "actor_label": row.actor_label,
            "resource_ref": row.resource_ref,
            "control_type": row.control_type,
            "observed_status": row.observed_status,
            "response_assessment": {
                "access_proof": row.access_proof,
                "response_class": row.response_class,
                "resource_visibility": row.resource_visibility,
                "denial_demonstrated": row.denial_demonstrated,
                "access_demonstrated": row.access_demonstrated,
            },
            "capture_order": row.capture_order,
            "integrity_status": row.integrity_status,
            "session_state": fold_for(row).state,
            "expected_access_declared": row.expected_access_declared,
            "observed_access": _observed_access(row, deleted),
            "uncertainty": sorted(set(uncertainty)),
        }
        if any(record[name] is None for name in OBSERVATION_FIELDS if name != "uncertainty"):
            provenance_complete = False
        rendered.append(record)

    if not rows:
        provenance_complete = False

    access_unsupported = not access_review_supported
    annotation = {
        "schema": ANNOTATION_SCHEMA,
        "optional": True,
        "safe_to_ignore": True,
        "matrix_schema": SCHEMA,
        "matrix_version": MATRIX_VERSION,
        "comparison_scope": scope,
        "disposition": disposition,
        "reason_codes": reason_codes,
        "reused_reason_codes": reused,
        "finding_confirmed": False,
        "negative_finding": False,
        "denial_consistent": denial_consistent,
        "access_claim": False,
        "access_review_supported": access_review_supported,
        "access_unsupported": access_unsupported,
        "does_not_rewrite_identity": True,
        "actors_invented": False,
        "external_requests": 0,
        "identity_changed": identity_changed,
        "expiry_proven": False,
    }
    return {
        "schema": SCHEMA,
        "matrix_version": MATRIX_VERSION,
        "comparison_scope": scope,
        "finding_confirmed": False,
        "confirmed": False,
        "negative_finding": False,
        "denial_consistent": denial_consistent,
        "access_claim": False,
        "access_review_supported": access_review_supported,
        "access_unsupported": access_unsupported,
        "disposition": disposition,
        "reason_codes": reason_codes,
        "reused_reason_codes": reused,
        "rules_fired": rules,
        "cells": cells,
        "observations": rendered,
        "sessions": sessions,
        "session_continuity": {
            "owner_valid_before_cross": owner_before if crosses and not order_ambiguous else None,
            "proven_session_change": proven_change,
            "unproven_session_change": unproven_change,
            "timestamps_unreliable": timestamps_unreliable,
            "order_ambiguous": order_ambiguous,
            "identity_changed": identity_changed,
            "expiry_proven": False,
            "expired_before_cross": expired_before_cross,
        },
        "annotation": annotation,
        "provenance_complete": provenance_complete and not malformed,
        "malformed_observations": malformed,
        "external_requests": 0,
        "identity_rewritten": False,
        "actors_invented": False,
        "scope_invalid": scope_invalid,
    }


def fold_actor(rows: Sequence[_Row], key: str) -> str:
    for row in rows:
        if _session_key(row) == key:
            return row.actor_label
    return "unknown"


def _recheck_out_of_order(rows: Sequence[_Row], crosses: Sequence[_Row]) -> bool:
    """A subsequent owner recheck that does not follow the cross (and the first owner control)."""
    cross_orders = [row.capture_order for row in crosses if row.capture_order is not None]
    own_orders = [
        row.capture_order for row in rows if row.control_type == "owner_own_resource" and row.capture_order is not None
    ]
    for row in rows:
        if row.control_type != "owner_recheck" or row.capture_order is None:
            continue
        if not cross_orders or row.capture_order <= max(cross_orders):
            return True
        if own_orders and row.capture_order <= min(own_orders):
            return True
    return False


def _owner_ready(rows: Sequence[_Row], grouped: Mapping[str, list[_Row]], cross: _Row) -> bool:
    if cross.capture_order is None or cross.resource_ref is None:
        return False
    for row in rows:
        if row.control_type != "owner_own_resource" or not _usable(row):
            continue
        if (
            row.resource_ref != cross.resource_ref
            or row.capture_order is None
            or row.capture_order >= cross.capture_order
        ):
            continue
        state = _state_before(grouped[_session_key(row)], cross.capture_order).state
        if state == "valid":
            return True
    return False


def _actor_ready(rows: Sequence[_Row], grouped: Mapping[str, list[_Row]], cross: _Row) -> bool:
    if cross.capture_order is None or cross.session_ref is None:
        return False
    for row in rows:
        if row.control_type != "second_own_resource" or not _usable(row):
            continue
        if (
            row.session_ref != cross.session_ref
            or row.capture_order is None
            or row.capture_order >= cross.capture_order
        ):
            continue
        state = _state_before(grouped[_session_key(row)], cross.capture_order).state
        if state == "valid":
            return True
    return False


def _expired_by(grouped: Mapping[str, list[_Row]], cross: _Row) -> bool:
    if cross.capture_order is None:
        return False
    for group in grouped.values():
        if _state_before(group, cross.capture_order).state == "possibly_expired":
            if any(row.actor_label in {"owner", "second"} and row.session_ref == cross.session_ref for row in group):
                return True
            if any(row.actor_label == "owner" and _is_own(row) for row in group):
                return True
    return False


def _expiry_only_after_crosses(
    rows: Sequence[_Row],
    grouped: Mapping[str, list[_Row]],
    crosses: Sequence[_Row],
) -> bool:
    if not crosses:
        return False
    last_cross = max((row.capture_order for row in crosses if row.capture_order is not None), default=None)
    if last_cross is None:
        return False
    for group in grouped.values():
        if _fold(_ordered(group)).state != "possibly_expired":
            continue
        if _state_before(group, last_cross).state == "possibly_expired":
            return False
    return True


def _cross_denial(row: _Row, rows: Sequence[_Row], deleted: Mapping[str, int]) -> bool:
    if row.access_proof in {"http_401", "http_403", "denial_in_200"}:
        return True
    if row.access_proof != "http_404" or row.resource_ref is None or row.capture_order is None:
        return False
    if row.resource_ref in deleted and row.capture_order >= deleted[row.resource_ref]:
        return False
    return any(
        other.actor_label == "owner"
        and other.resource_ref == row.resource_ref
        and other.access_proof == "private_resource_200"
        and other.capture_order is not None
        and other.capture_order > row.capture_order
        for other in rows
    )


def _unconfirmed_404(rows: Sequence[_Row], crosses: Sequence[_Row], deleted: Mapping[str, int]) -> bool:
    for row in crosses:
        if row.access_proof == "http_404" and not _cross_denial(row, rows, deleted):
            return True
    return False


def _contradictory_cross(crosses: Sequence[_Row], deleted: Mapping[str, int]) -> bool:
    if len(crosses) < 2:
        return False
    kinds = set()
    for row in crosses:
        if row.resource_ref in deleted and row.access_proof == "http_404":
            kinds.add("deleted")
        elif row.access_proof == "private_resource_200":
            kinds.add("accessed")
        elif row.access_proof in _DENIAL_PROOFS:
            kinds.add("denied")
        else:
            kinds.add("other")
    return len(kinds) > 1


__all__ = [
    "ANNOTATION_SCHEMA",
    "CONTROL_TYPES",
    "MATRIX_VERSION",
    "OBSERVATION_FIELDS",
    "REASON_CODES",
    "REUSED_REASON_CODES",
    "SCHEMA",
    "evaluate_control_matrix",
]
