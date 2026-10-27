"""Synthetic DEV/FINAL cases for pairing precision v4.

Cases are evidence dicts, not live captures. FINAL expectations are frozen in
``final/cases.json``; this module is the generator used before that freeze.
"""

from __future__ import annotations

import json
from typing import Any

ORIGIN = "http://127.0.0.1:8199"
CANARY = "SYNTH_CANARY_PAIRING_V4"


def _resource(kind: str, oid: int | str, label: str) -> str:
    body: dict[str, Any] = {"id": oid, "marker": f"synth-{kind}-{oid}", "owner_label": label}
    if label == CANARY:
        body["note"] = CANARY
    payload: dict[str, Any] = {"ok": True, kind: body}
    return json.dumps(payload)


def _ev(ref: str, path: str, *, session: str, body: str | None, **extra: Any) -> dict[str, Any]:
    row: dict[str, Any] = {
        "evidence_ref": ref,
        "program": "synth-program",
        "origin": ORIGIN,
        "method": "GET",
        "path": path,
        "session_ref": session,
        "accounts_attested": False,
        "response_present": body is not None,
        "status_code": 200 if body is not None else None,
        "response_body": body,
    }
    row.update(extra)
    return row


def _case(
    case_id: str,
    owner: dict[str, Any],
    actor: dict[str, Any],
    *,
    compatibility: str,
    admit: bool,
    tags: list[str],
    alias_rules: dict[str, Any] | None = None,
    continuity: dict[str, Any] | None = None,
    as_of: str | None = None,
    context: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    return {
        "id": case_id,
        "tags": tags,
        "owner": owner,
        "actor": actor,
        "context": context or [],
        "alias_rules": alias_rules,
        "continuity": continuity,
        "as_of": as_of,
        "expect_compatibility": compatibility,
        "expect_pairing_decision": admit,
        "finding_confirmed": False,
    }


def all_cases() -> list[dict[str, Any]]:
    """Full synthetic set. DEV is a prefix used while tuning; FINAL is the frozen superset."""
    order_owner = _resource("order", 7, "owner")
    order_actor = _resource("order", 8, "actor")
    same_order = {"ok": True, "order": {"id": 7, "marker": "synth-order-7", "owner_label": "shared"}}
    cases = [
        _case(
            "hn-cross-kind",
            _ev("ck-owner", "/users/42", session="sess-a", body=_resource("user", 42, "owner")),
            _ev("ck-actor", "/orders/42", session="sess-b", body=_resource("order", 42, "actor")),
            compatibility="incompatible",
            admit=False,
            tags=["hard_negative", "cross_kind"],
        ),
        _case(
            "hn-json-equivalent",
            _ev(
                "js-owner",
                "/orders/7",
                session="sess-a",
                body=json.dumps(same_order, sort_keys=True),
                account_ref="SYNTH_acct_owner",
                accounts_attested=True,
            ),
            _ev(
                "js-actor",
                "/orders/7",
                session="sess-b",
                body='{"order": {"owner_label": "shared", "marker": "synth-order-7", "id": 7}, "ok": true}',
                account_ref="SYNTH_acct_actor",
                accounts_attested=True,
            ),
            compatibility="compatible",
            admit=True,
            tags=["hard_negative", "json_equivalence", "positive"],
        ),
        _case(
            "hn-route-alias",
            _ev(
                "al-owner",
                "/api/v1/orders/7",
                session="sess-a",
                body=_resource("order", 7, "owner"),
                account_ref="SYNTH_acct_owner",
                accounts_attested=True,
            ),
            _ev(
                "al-actor",
                "/orders/7",
                session="sess-b",
                body=_resource("order", 7, "actor"),
                account_ref="SYNTH_acct_actor",
                accounts_attested=True,
            ),
            compatibility="compatible",
            admit=True,
            tags=["hard_negative", "route_alias", "positive"],
            alias_rules={"strip_prefixes": ["api", "v1"]},
        ),
        _case(
            "hn-same-account",
            _ev(
                "sa-owner",
                "/orders/7",
                session="sess-a",
                body=order_owner,
                account_ref="SYNTH_acct_same",
                accounts_attested=True,
            ),
            _ev(
                "sa-actor",
                "/orders/8",
                session="sess-b",
                body=order_actor,
                account_ref="SYNTH_acct_same",
                accounts_attested=True,
            ),
            compatibility="incompatible",
            admit=False,
            tags=["hard_negative", "same_account"],
        ),
        _case(
            "hn-shared-acl",
            _ev(
                "sh-owner",
                "/documents/5",
                session="sess-a",
                body=json.dumps({"ok": True, "document": {"id": 5, "acl": "shared", "shared_with": ["a", "b"]}}),
            ),
            _ev(
                "sh-actor",
                "/documents/5",
                session="sess-b",
                body=json.dumps({"ok": True, "document": {"id": 5, "acl": "shared", "shared_with": ["a", "b"]}}),
            ),
            compatibility="incompatible",
            admit=False,
            tags=["hard_negative", "legitimate_shared"],
        ),
        _case(
            "hn-missing-response",
            _ev("mr-owner", "/orders/7", session="sess-a", body=order_owner),
            _ev("mr-actor", "/orders/8", session="sess-b", body=None, response_present=False, status_code=None),
            compatibility="insufficient_evidence",
            admit=False,
            tags=["hard_negative", "missing_artifact"],
        ),
        _case(
            "hn-denial-200",
            _ev("dn-owner", "/contracts/1", session="sess-a", body=_resource("contract", 1, "owner")),
            _ev(
                "dn-actor",
                "/contracts/2",
                session="sess-b",
                body=json.dumps({"ok": False, "error": "access denied", "contract": None}),
            ),
            compatibility="incompatible",
            admit=False,
            tags=["hard_negative", "denial"],
        ),
        _case(
            "hn-id-echo",
            _ev("ec-owner", "/widgets/42", session="sess-a", body=json.dumps({"ok": True, "id": 42})),
            _ev("ec-actor", "/widgets/42", session="sess-b", body=json.dumps({"ok": True, "id": 42})),
            compatibility="insufficient_evidence",
            admit=False,
            tags=["hard_negative", "id_echo"],
        ),
        _case(
            "hn-temporal",
            _ev(
                "tm-owner",
                "/orders/7",
                session="sess-a",
                body=order_owner,
                temporal_start="2020-01-01T00:00:00Z",
                temporal_end="2020-02-01T00:00:00Z",
            ),
            _ev(
                "tm-actor",
                "/orders/8",
                session="sess-b",
                body=order_actor,
                temporal_start="2024-01-01T00:00:00Z",
                temporal_end="2024-02-01T00:00:00Z",
            ),
            compatibility="incompatible",
            admit=False,
            tags=["hard_negative", "temporal"],
        ),
        _case(
            "hn-ambiguous-kind",
            _ev(
                "ak-owner",
                "/widgets/1",
                session="sess-a",
                body=_resource("widget", 1, "owner"),
                kind_status="ambiguous",
                resource_kinds=["widget", "record"],
            ),
            _ev(
                "ak-actor",
                "/widgets/2",
                session="sess-b",
                body=_resource("widget", 2, "actor"),
                kind_status="unknown",
            ),
            compatibility="insufficient_evidence",
            admit=False,
            tags=["hard_negative", "ambiguous_kind"],
        ),
        _case(
            "hn-integrity",
            _ev("in-owner", "/orders/7", session="sess-a", body=order_owner, integrity_ok=False),
            _ev("in-actor", "/orders/8", session="sess-b", body=order_actor),
            compatibility="conflicting_evidence",
            admit=False,
            tags=["hard_negative", "integrity"],
        ),
        _case(
            "hn-mixed-origin",
            _ev("mo-owner", "/orders/7", session="sess-a", body=order_owner),
            _ev("mo-actor", "/orders/8", session="sess-b", body=order_actor, origin="http://127.0.0.1:8198"),
            compatibility="incompatible",
            admit=False,
            tags=["hard_negative", "mixed_origin"],
        ),
        _case(
            "hn-mixed-program",
            _ev("mp-owner", "/orders/7", session="sess-a", body=order_owner),
            _ev("mp-actor", "/orders/8", session="sess-b", body=order_actor, program="synth-other-program"),
            compatibility="incompatible",
            admit=False,
            tags=["hard_negative", "cross_program"],
        ),
        _case(
            "hn-partial-array",
            _ev(
                "pa-owner",
                "/items",
                session="sess-a",
                body=json.dumps([{"id": 1, "marker": "a"}, {"id": 2, "marker": "b"}]),
                resource_kind="item",
                kind_status="explicit",
            ),
            _ev(
                "pa-actor",
                "/items",
                session="sess-b",
                body=json.dumps([{"id": 2, "marker": "b"}, {"id": 3, "marker": "c"}]),
                resource_kind="item",
                kind_status="explicit",
            ),
            compatibility="incompatible",
            admit=False,
            tags=["hard_negative", "partial_array"],
        ),
        _case(
            "hn-batch-continuity",
            _ev("ba-owner", "/orders/7", session="sess-a", body=order_owner, batch_id="batch-a", capture_run="run-a"),
            _ev("ba-actor", "/orders/8", session="sess-b", body=order_actor, batch_id="batch-b", capture_run="run-b"),
            compatibility="insufficient_evidence",
            admit=False,
            tags=["hard_negative", "continuity"],
        ),
        _case(
            "hn-contradiction",
            _ev(
                "co-owner",
                "/orders/5",
                session="sess-a",
                status_code=403,
                body=json.dumps({"ok": False, "error": "forbidden"}),
            ),
            _ev("co-actor", "/orders/5", session="sess-b", body=_resource("order", 5, "owner")),
            compatibility="conflicting_evidence",
            admit=False,
            tags=["hard_negative", "contradiction"],
        ),
        _case(
            "pos-distinct-ids",
            _ev(
                "pd-owner",
                "/orders/7",
                session="sess-a",
                body=order_owner,
                account_ref="SYNTH_acct_owner",
                accounts_attested=True,
            ),
            _ev(
                "pd-actor",
                "/orders/8",
                session="sess-b",
                body=order_actor,
                account_ref="SYNTH_acct_actor",
                accounts_attested=True,
            ),
            compatibility="compatible",
            admit=True,
            tags=["positive"],
        ),
        _case(
            "pos-cross-read",
            _ev(
                "pc-owner",
                "/statements/11",
                session="sess-a",
                body=_resource("statement", 11, "owner"),
                account_ref="SYNTH_acct_owner",
                accounts_attested=True,
            ),
            _ev(
                "pc-actor",
                "/statements/11",
                session="sess-b",
                body=_resource("statement", 11, CANARY),
                account_ref="SYNTH_acct_actor",
                accounts_attested=True,
            ),
            compatibility="compatible",
            admit=True,
            tags=["positive"],
        ),
    ]
    return cases


DEV_IDS = (
    "hn-cross-kind",
    "hn-json-equivalent",
    "hn-route-alias",
    "hn-same-account",
    "hn-shared-acl",
    "hn-missing-response",
    "pos-distinct-ids",
)


def cases_for(split: str) -> list[dict[str, Any]]:
    rows = all_cases()
    if split == "dev":
        return [row for row in rows if row["id"] in DEV_IDS]
    if split == "final":
        return rows
    raise ValueError(f"unknown split: {split}")
