"""Synthetic DEV/FINAL scenarios for the authorization control matrix.

Labels are the control-matrix spec, not engine output and not an existing
benchmark's ground truth. Resource and token identifiers are ``SYNTH_`` prefixed.
"""

from __future__ import annotations

from typing import Any

PRIVATE = '{"ok": true, "data": {"id": "SYNTH_obj", "marker": "synthetic-private"}}'
SECOND = '{"ok": true, "data": {"id": "SYNTH_obj_b", "marker": "synthetic-private"}}'
DENY = '{"error": "forbidden"}'
UNAUTH = '{"error": "unauthorized"}'
NOT_FOUND = '{"error": "not found"}'
DENY_BODY = '{"ok": false, "error": "access denied"}'
ECHO = '{"id": "SYNTH_obj", "status": "ok"}'
PUBLIC = '{"visibility": "public", "data": {"id": "SYNTH_pub", "marker": "synthetic-public"}}'
SHARED = '{"visibility": "shared", "shared_with": ["SYNTH_acct_b"], "data": {"id": "SYNTH_sh", "marker": "synthetic"}}'

_BODIES = {
    "private": PRIVATE,
    "second": SECOND,
    "deny": DENY,
    "unauth": UNAUTH,
    "missing": NOT_FOUND,
    "deny_body": DENY_BODY,
    "echo": ECHO,
    "public": PUBLIC,
    "shared": SHARED,
    "empty": "",
}


def _obs(
    evidence: str,
    actor: str,
    resource: str,
    owner: str,
    order: int,
    status: int,
    kind: str,
    *,
    session: str | None,
    token: str,
    account: str,
    attested: bool = True,
    control_type: str | None = None,
    expected: str = "unknown",
    timestamp: str | None = None,
    timestamp_reliable: bool = True,
    session_change_proven: bool = False,
    identity_change_proven: bool = False,
    requested_id: str | None = None,
    headers: dict[str, str] | None = None,
    integrity: str = "intact",
) -> dict[str, Any]:
    row: dict[str, Any] = {
        "evidence_ref": evidence,
        "actor_label": actor,
        "resource_ref": resource,
        "resource_owner_label": owner,
        "capture_order": order,
        "observed_status": status,
        "body": _BODIES[kind],
        "headers": headers or {},
        "integrity_status": integrity,
        "session_ref": session,
        "token_ref": token,
        "expected_access_declared": expected,
        "timestamp": timestamp,
        "timestamp_reliable": timestamp_reliable,
        "provenance": {
            "account_attested": attested,
            "declared_account_ref": account,
            "session_change_proven": session_change_proven,
            "identity_change_proven": identity_change_proven,
        },
    }
    if control_type:
        row["control_type"] = control_type
    if requested_id:
        row["requested_id"] = requested_id
    return row


def _owner(split: str, evidence: str, order: int, status: int, kind: str, **kwargs: Any) -> dict[str, Any]:
    return _obs(
        evidence,
        "owner",
        f"SYNTH_{split}_res_owner",
        "owner",
        order,
        status,
        kind,
        session=kwargs.pop("session", f"SYNTH_{split}_sess_owner"),
        token=kwargs.pop("token", f"SYNTH_{split}_tok_owner"),
        account=kwargs.pop("account", f"SYNTH_{split}_acct_owner"),
        **kwargs,
    )


def _second(
    split: str, evidence: str, order: int, status: int, kind: str, *, resource: str, owner: str, **kwargs: Any
) -> dict[str, Any]:
    return _obs(
        evidence,
        "second",
        resource,
        owner,
        order,
        status,
        kind,
        session=kwargs.pop("session", f"SYNTH_{split}_sess_second"),
        token=kwargs.pop("token", f"SYNTH_{split}_tok_second"),
        account=kwargs.pop("account", f"SYNTH_{split}_acct_second"),
        **kwargs,
    )


def _expect(
    disposition: str,
    *,
    denial: bool,
    include: list[str],
    exclude: list[str] | None = None,
    rules: list[str] | None = None,
    sessions: dict[str, str] | None = None,
    cells: list[str] | None = None,
    missing: list[str] | None = None,
    identity_changed: bool = False,
    scope: str = "owner_second",
) -> dict[str, Any]:
    return {
        "disposition": disposition,
        "denial_consistent": denial,
        "negative_finding": False,
        "finding_confirmed": False,
        "access_claim": False,
        "identity_changed": identity_changed,
        "expiry_proven": False,
        "reason_codes_include": include,
        "reason_codes_exclude": exclude or [],
        "rules_include": rules or [],
        "session_states": sessions or {},
        "cells_present": cells or [],
        "missing_reasons": missing or [],
        "comparison_scope": scope,
    }


def scenarios(split: str) -> list[dict[str, Any]]:
    """Return the labeled scenarios for ``dev`` or ``final``.

    The two splits use different synthetic ids. DEV is the only split used to
    check the engine while labels are still editable. FINAL is frozen as JSON.
    """
    if split not in {"dev", "final"}:
        raise ValueError(split)
    tag = "d" if split == "dev" else "f"
    own = f"SYNTH_{tag}_res_owner"
    sec = f"SYNTH_{tag}_res_second"
    pub = f"SYNTH_{tag}_res_public"
    sha = f"SYNTH_{tag}_res_shared"
    s_owner = f"SYNTH_{tag}_sess_owner"
    s_second = f"SYNTH_{tag}_sess_second"
    s_owner_b = f"SYNTH_{tag}_sess_owner_b"
    cross_status = 401 if split == "dev" else 403
    cross_kind = "unauth" if split == "dev" else "deny"
    rows: list[dict[str, Any]] = []

    def add(scenario_id: str, observations: list[dict[str, Any]], expected: dict[str, Any]) -> None:
        rows.append(
            {
                "id": f"{tag.upper()}{scenario_id}",
                "comparison_scope": expected["comparison_scope"],
                "observations": observations,
                "expected": expected,
            }
        )

    valid = {s_owner: "valid", s_second: "valid"}
    mandatory_cells = ["owner_own_resource", "second_own_resource", "second_owner_resource"]

    add(
        "01-complete-denial",
        [
            _owner(tag, "ev-owner", 0, 200, "private"),
            _second(tag, "ev-second", 1, 200, "second", resource=sec, owner="second"),
            _second(tag, "ev-cross", 2, cross_status, cross_kind, resource=own, owner="owner", expected="deny"),
        ],
        _expect(
            "complete",
            denial=True,
            include=["COMPLETE_CONTROL_SET"],
            exclude=["SESSION_POSSIBLY_EXPIRED", "OWNER_CONTROL_MISSING"],
            rules=["owner_valid_before_cross"],
            sessions=valid,
            cells=mandatory_cells,
        ),
    )
    add(
        "02-private-cross-access",
        [
            _owner(tag, "ev-owner", 0, 200, "private"),
            _second(tag, "ev-second", 1, 200, "second", resource=sec, owner="second"),
            _second(tag, "ev-cross", 2, 200, "private", resource=own, owner="owner", expected="allow"),
        ],
        _expect(
            "complete",
            denial=False,
            include=["COMPLETE_CONTROL_SET"],
            exclude=["SESSION_POSSIBLY_EXPIRED"],
            rules=["owner_valid_before_cross"],
            sessions=valid,
            cells=mandatory_cells,
        ),
    )
    add(
        "03-missing-owner",
        [
            _second(tag, "ev-second", 0, 200, "second", resource=sec, owner="second"),
            _second(tag, "ev-cross", 1, 403, "deny", resource=own, owner="owner"),
        ],
        _expect(
            "blocked",
            denial=False,
            include=["OWNER_CONTROL_MISSING"],
            exclude=["COMPLETE_CONTROL_SET"],
            sessions={s_second: "valid"},
            missing=["OWNER_CONTROL_MISSING"],
        ),
    )
    add(
        "04-missing-cross",
        [
            _owner(tag, "ev-owner", 0, 200, "private"),
            _second(tag, "ev-second", 1, 200, "second", resource=sec, owner="second"),
        ],
        _expect(
            "blocked",
            denial=False,
            include=["CROSS_CAPTURE_MISSING"],
            sessions=valid,
            cells=["owner_own_resource", "second_own_resource"],
            missing=["CROSS_CAPTURE_MISSING"],
        ),
    )
    add(
        "05-missing-actor",
        [
            _owner(tag, "ev-owner", 0, 200, "private"),
            _second(tag, "ev-cross", 1, 403, "deny", resource=own, owner="owner"),
        ],
        _expect(
            "blocked",
            denial=False,
            include=["ACTOR_CONTROL_MISSING"],
            sessions={s_owner: "valid", s_second: "identity_unproven"},
            missing=["ACTOR_CONTROL_MISSING"],
        ),
    )
    add(
        "06-isolated-401",
        [
            _owner(tag, "ev-owner", 0, 200, "private"),
            _owner(tag, "ev-iso", 1, 401, "unauth"),
            _second(tag, "ev-second", 2, 200, "second", resource=sec, owner="second"),
            _second(tag, "ev-cross", 3, 403, "deny", resource=own, owner="owner"),
        ],
        _expect(
            "complete",
            denial=True,
            include=["COMPLETE_CONTROL_SET"],
            exclude=["SESSION_POSSIBLY_EXPIRED"],
            rules=["isolated_401", "owner_valid_before_cross"],
            sessions=valid,
            cells=mandatory_cells,
        ),
    )
    add(
        "07-repeated-401",
        [
            _owner(tag, "ev-owner", 0, 200, "private"),
            _owner(tag, "ev-a", 1, 401, "unauth"),
            _owner(tag, "ev-b", 2, 401, "unauth"),
            _second(tag, "ev-second", 3, 200, "second", resource=sec, owner="second"),
            _second(tag, "ev-cross", 4, 403, "deny", resource=own, owner="owner"),
        ],
        _expect(
            "inconclusive",
            denial=False,
            include=["SESSION_POSSIBLY_EXPIRED"],
            exclude=["COMPLETE_CONTROL_SET"],
            rules=["repeated_401", "possibly_expired_session"],
            sessions={s_owner: "possibly_expired", s_second: "valid"},
        ),
    )
    add(
        "08-login-redirect",
        [
            _owner(tag, "ev-owner", 0, 200, "private"),
            _owner(tag, "ev-login", 1, 302, "empty", headers={"Location": "/login"}),
            _second(tag, "ev-second", 2, 200, "second", resource=sec, owner="second"),
            _second(tag, "ev-cross", 3, 403, "deny", resource=own, owner="owner"),
        ],
        _expect(
            "inconclusive",
            denial=False,
            include=["SESSION_POSSIBLY_EXPIRED"],
            rules=["login_redirect", "possibly_expired_session"],
            sessions={s_owner: "possibly_expired", s_second: "valid"},
        ),
    )
    add(
        "09-owner-invalid",
        [
            _owner(tag, "ev-owner", 0, 401, "unauth"),
            _second(tag, "ev-second", 1, 200, "second", resource=sec, owner="second"),
            _second(tag, "ev-cross", 2, 403, "deny", resource=own, owner="owner"),
        ],
        _expect(
            "blocked",
            denial=False,
            include=["OWNER_CONTROL_MISSING", "OWNER_CONTROL_BROKEN"],
            exclude=["SESSION_POSSIBLY_EXPIRED", "COMPLETE_CONTROL_SET"],
            rules=["owner_invalid"],
            sessions={s_owner: "invalid", s_second: "valid"},
            missing=["OWNER_CONTROL_MISSING", "OWNER_CONTROL_BROKEN"],
        ),
    )
    add(
        "10-actor-invalid",
        [
            _owner(tag, "ev-owner", 0, 200, "private"),
            _second(tag, "ev-second", 1, 401, "unauth", resource=sec, owner="second"),
            _second(tag, "ev-cross", 2, 403, "deny", resource=own, owner="owner"),
        ],
        _expect(
            "blocked",
            denial=False,
            include=["ACTOR_CONTROL_MISSING"],
            exclude=["SESSION_POSSIBLY_EXPIRED"],
            rules=["actor_invalid"],
            sessions={s_owner: "valid", s_second: "invalid"},
            missing=["ACTOR_CONTROL_MISSING"],
        ),
    )
    add(
        "11-rotated-token",
        [
            _owner(tag, "ev-owner", 0, 200, "private", token=f"SYNTH_{tag}_tok_owner_a"),
            _owner(tag, "ev-rot", 1, 200, "private", token=f"SYNTH_{tag}_tok_owner_b"),
            _second(tag, "ev-second", 2, 200, "second", resource=sec, owner="second"),
            _second(tag, "ev-cross", 3, 403, "deny", resource=own, owner="owner"),
        ],
        _expect(
            "complete",
            denial=True,
            include=["COMPLETE_CONTROL_SET"],
            rules=["rotated_token", "owner_valid_before_cross"],
            sessions=valid,
            cells=mandatory_cells,
        ),
    )
    add(
        "12-proven-identity-change",
        [
            _owner(tag, "ev-owner", 0, 200, "private", token=f"SYNTH_{tag}_tok_owner_a"),
            _owner(
                tag,
                "ev-id",
                1,
                200,
                "private",
                token=f"SYNTH_{tag}_tok_owner_b",
                account=f"SYNTH_{tag}_acct_other",
                identity_change_proven=True,
            ),
            _second(tag, "ev-second", 2, 200, "second", resource=sec, owner="second"),
            _second(tag, "ev-cross", 3, 403, "deny", resource=own, owner="owner"),
        ],
        _expect(
            "inconclusive",
            denial=False,
            include=[],
            exclude=["COMPLETE_CONTROL_SET"],
            rules=["rotated_token"],
            sessions=valid,
            identity_changed=True,
        ),
    )
    add(
        "13-public-resource",
        [
            _owner(tag, "ev-pub-o", 0, 200, "public", expected="public"),
            _second(
                tag,
                "ev-pub-s",
                1,
                200,
                "public",
                resource=f"SYNTH_{tag}_res_public_b",
                owner="second",
                expected="public",
            ),
            _second(tag, "ev-pub-c", 2, 200, "public", resource=pub, owner="owner", expected="public"),
        ],
        _expect(
            "inconclusive",
            denial=False,
            include=["PUBLIC_RESOURCE_CONTROL"],
            exclude=["COMPLETE_CONTROL_SET", "OWNER_CONTROL_MISSING"],
            rules=["public_resource"],
            cells=["public_shared_control"],
        ),
    )
    add(
        "14-shared-resource",
        [
            _obs(
                "ev-sh-o",
                "owner",
                sha,
                "owner",
                0,
                200,
                "shared",
                session=s_owner,
                token=f"SYNTH_{tag}_tok_owner",
                account=f"SYNTH_{tag}_acct_owner",
                expected="shared",
            ),
            _obs(
                "ev-sh-s",
                "second",
                f"SYNTH_{tag}_res_shared_b",
                "second",
                1,
                200,
                "shared",
                session=s_second,
                token=f"SYNTH_{tag}_tok_second",
                account=f"SYNTH_{tag}_acct_second",
                expected="shared",
            ),
            _obs(
                "ev-sh-c",
                "second",
                sha,
                "owner",
                2,
                200,
                "shared",
                session=s_second,
                token=f"SYNTH_{tag}_tok_second",
                account=f"SYNTH_{tag}_acct_second",
                expected="shared",
            ),
        ],
        _expect(
            "inconclusive",
            denial=False,
            include=["SHARED_RESOURCE_CONTROL"],
            exclude=["COMPLETE_CONTROL_SET"],
            rules=["shared_resource"],
            cells=["public_shared_control"],
        ),
    )
    add(
        "15-id-echo",
        [
            _owner(tag, "ev-owner", 0, 200, "private"),
            _second(tag, "ev-second", 1, 200, "second", resource=sec, owner="second"),
            _second(tag, "ev-cross", 2, 200, "echo", resource=own, owner="owner", requested_id="SYNTH_obj"),
        ],
        _expect(
            "inconclusive",
            denial=False,
            include=["ID_ECHO_ONLY"],
            exclude=["COMPLETE_CONTROL_SET"],
            sessions=valid,
        ),
    )
    add(
        "16-body-denial",
        [
            _owner(tag, "ev-owner", 0, 200, "private"),
            _second(tag, "ev-second", 1, 200, "second", resource=sec, owner="second"),
            _second(tag, "ev-cross", 2, 200, "deny_body", resource=own, owner="owner", expected="deny"),
        ],
        _expect(
            "complete",
            denial=True,
            include=["COMPLETE_CONTROL_SET"],
            rules=["owner_valid_before_cross"],
            sessions=valid,
            cells=mandatory_cells,
        ),
    )
    add(
        "17-deleted-resource",
        [
            _owner(tag, "ev-owner", 0, 200, "private"),
            _second(tag, "ev-second", 1, 200, "second", resource=sec, owner="second"),
            _second(tag, "ev-cross", 2, 404, "missing", resource=own, owner="owner"),
            _owner(tag, "ev-re", 3, 404, "missing"),
        ],
        _expect(
            "inconclusive",
            denial=False,
            include=[],
            exclude=["SESSION_POSSIBLY_EXPIRED", "COMPLETE_CONTROL_SET"],
            rules=["deleted_resource"],
            sessions=valid,
        ),
    )
    add(
        "18-owner-recheck",
        [
            _owner(tag, "ev-owner", 0, 200, "private"),
            _second(tag, "ev-second", 1, 200, "second", resource=sec, owner="second"),
            _second(tag, "ev-cross", 2, 404, "missing", resource=own, owner="owner"),
            _owner(tag, "ev-re", 3, 200, "private"),
        ],
        _expect(
            "complete",
            denial=True,
            include=["COMPLETE_CONTROL_SET"],
            rules=["owner_valid_before_cross"],
            sessions=valid,
            cells=[*mandatory_cells, "owner_recheck"],
        ),
    )
    add(
        "19-session-change",
        [
            _owner(tag, "ev-owner", 0, 200, "private"),
            _owner(tag, "ev-new", 1, 200, "private", session=s_owner_b, session_change_proven=True),
            _second(tag, "ev-second", 2, 200, "second", resource=sec, owner="second"),
            _second(tag, "ev-cross", 3, 403, "deny", resource=own, owner="owner"),
        ],
        _expect(
            "complete",
            denial=True,
            include=["COMPLETE_CONTROL_SET"],
            rules=["session_change_mid_capture"],
            sessions={s_owner: "valid", s_owner_b: "valid", s_second: "valid"},
            cells=mandatory_cells,
        ),
    )
    add(
        "20-unproven-session-change",
        [
            _owner(tag, "ev-owner", 0, 200, "private"),
            _owner(tag, "ev-new", 1, 200, "private", session=s_owner_b),
            _second(tag, "ev-second", 2, 200, "second", resource=sec, owner="second"),
            _second(tag, "ev-cross", 3, 403, "deny", resource=own, owner="owner"),
        ],
        _expect(
            "inconclusive",
            denial=False,
            include=[],
            exclude=["COMPLETE_CONTROL_SET"],
            sessions={s_owner: "valid", s_owner_b: "valid", s_second: "valid"},
        ),
    )
    add(
        "21-unreliable-timestamps",
        [
            _owner(tag, "ev-owner", 0, 200, "private", timestamp="2026-10-27T00:00:02Z", timestamp_reliable=False),
            _second(
                tag,
                "ev-second",
                1,
                200,
                "second",
                resource=sec,
                owner="second",
                timestamp="2026-10-27T00:00:01Z",
                timestamp_reliable=False,
            ),
            _second(
                tag,
                "ev-cross",
                2,
                403,
                "deny",
                resource=own,
                owner="owner",
                timestamp="2026-10-27T00:00:00Z",
                timestamp_reliable=False,
            ),
        ],
        _expect(
            "complete",
            denial=True,
            include=["COMPLETE_CONTROL_SET"],
            exclude=["CAPTURE_ORDER_AMBIGUOUS"],
            rules=["unreliable_timestamps", "owner_valid_before_cross"],
            sessions=valid,
        ),
    )
    add(
        "22-out-of-order",
        [
            _owner(tag, "ev-owner", 0, 200, "private", timestamp="2026-10-27T00:00:02Z", timestamp_reliable=True),
            _second(
                tag,
                "ev-second",
                1,
                200,
                "second",
                resource=sec,
                owner="second",
                timestamp="2026-10-27T00:00:01Z",
                timestamp_reliable=True,
            ),
            _second(
                tag,
                "ev-cross",
                2,
                403,
                "deny",
                resource=own,
                owner="owner",
                timestamp="2026-10-27T00:00:00Z",
                timestamp_reliable=True,
            ),
        ],
        _expect(
            "inconclusive",
            denial=False,
            include=["CAPTURE_ORDER_AMBIGUOUS"],
            exclude=["COMPLETE_CONTROL_SET", "SESSION_POSSIBLY_EXPIRED"],
            rules=["out_of_order_captures"],
            sessions={s_owner: "valid", s_second: "out_of_order"},
        ),
    )
    add(
        "23-recheck-before-cross",
        [
            _owner(tag, "ev-re", 0, 200, "private", control_type="owner_recheck"),
            _second(tag, "ev-second", 1, 200, "second", resource=sec, owner="second"),
            _second(tag, "ev-cross", 2, 403, "deny", resource=own, owner="owner"),
        ],
        _expect(
            "blocked",
            denial=False,
            include=["OWNER_CONTROL_MISSING", "CAPTURE_ORDER_AMBIGUOUS"],
            exclude=["COMPLETE_CONTROL_SET"],
            rules=["out_of_order_captures"],
            missing=["OWNER_CONTROL_MISSING"],
        ),
    )
    add(
        "24-negative-control",
        [
            _owner(tag, "ev-owner", 0, 200, "private"),
            _second(tag, "ev-second", 1, 200, "second", resource=sec, owner="second"),
            _second(tag, "ev-cross", 2, 403, "deny", resource=own, owner="owner", expected="deny"),
            _second(
                tag,
                "ev-neg",
                3,
                403,
                "deny",
                resource=f"SYNTH_{tag}_res_other",
                owner="owner",
                control_type="negative_control",
                expected="deny",
            ),
        ],
        _expect(
            "complete",
            denial=True,
            include=["COMPLETE_CONTROL_SET"],
            rules=["owner_valid_before_cross"],
            sessions=valid,
            cells=[*mandatory_cells, "negative_control"],
        ),
    )
    anon = _obs(
        "ev-anon",
        "anonymous",
        own,
        "owner",
        3,
        401,
        "unauth",
        session=None,
        token=f"SYNTH_{tag}_tok_anon",
        account=f"SYNTH_{tag}_acct_anon",
        attested=False,
    )
    add(
        "25-anonymous",
        [
            _owner(tag, "ev-owner", 0, 200, "private"),
            _second(tag, "ev-second", 1, 200, "second", resource=sec, owner="second"),
            _second(tag, "ev-cross", 2, 403, "deny", resource=own, owner="owner"),
            anon,
        ],
        _expect(
            "complete",
            denial=True,
            include=["COMPLETE_CONTROL_SET"],
            rules=["owner_valid_before_cross"],
            sessions={**valid, "anonymous": "anonymous"},
            cells=[*mandatory_cells, "anonymous"],
            scope="owner_second_anonymous",
        ),
    )
    add(
        "26-missing-anonymous",
        [
            _owner(tag, "ev-owner", 0, 200, "private"),
            _second(tag, "ev-second", 1, 200, "second", resource=sec, owner="second"),
            _second(tag, "ev-cross", 2, 403, "deny", resource=own, owner="owner"),
        ],
        _expect(
            "blocked",
            denial=False,
            include=[],
            exclude=["COMPLETE_CONTROL_SET"],
            sessions=valid,
            scope="owner_second_anonymous",
        ),
    )
    return rows
