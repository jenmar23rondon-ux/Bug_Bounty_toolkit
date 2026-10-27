"""Naive comparison used only as a before-column.

It treats any HTTP 401 as proven expiry, any second token as a new identity,
a missing owner control as an automatic negative, and a cross-resource HTTP 200
as an access claim. It is not a product classifier.
"""

from __future__ import annotations

from typing import Any, Mapping, Sequence

from bugbounty_toolkit.analysis.authorization_control_matrix import CONTROL_TYPES


def naive_control_matrix(
    observations: Sequence[Mapping[str, Any]],
    *,
    comparison_scope: str = "owner_second",
) -> dict[str, Any]:
    """Status-only reading of the same captures. ``finding_confirmed`` stays false."""
    del comparison_scope
    sessions: dict[str, dict[str, Any]] = {}
    tokens: list[str] = []
    has_owner_success = False
    has_401 = False
    access_claim = False
    for item in observations:
        if not isinstance(item, Mapping):
            continue
        status = item.get("observed_status")
        actor = str(item.get("actor_label") or "")
        raw_session = item.get("session_ref")
        session = raw_session if isinstance(raw_session, str) else "anonymous"
        token = item.get("token_ref")
        if isinstance(token, str):
            tokens.append(token)
        if actor == "owner" and status == 200:
            has_owner_success = True
        if status == 401:
            has_401 = True
        state = "possibly_expired" if status == 401 else "valid"
        sessions[session] = {"state": state, "expiry_proven": status == 401, "identity_changed": False}
        if (
            actor in {"second", "second_account", "actor"}
            and item.get("resource_owner_label") == "owner"
            and status == 200
        ):
            access_claim = True
    identity_changed = len(set(tokens)) > 1
    for row in sessions.values():
        row["identity_changed"] = identity_changed
    denial = (not has_owner_success) or any(
        isinstance(item, Mapping)
        and item.get("observed_status") in {401, 403, 404}
        and item.get("actor_label") != "owner"
        for item in observations
    )
    return {
        "schema": "bbtk.naive-authorization-baseline/0",
        "disposition": "complete",
        "denial_consistent": denial,
        "negative_finding": not has_owner_success,
        "finding_confirmed": False,
        "access_claim": access_claim,
        "reason_codes": ["SESSION_POSSIBLY_EXPIRED"] if has_401 else [],
        "rules_fired": ["possibly_expired_session"] if has_401 else [],
        "sessions": sessions,
        "session_continuity": {"identity_changed": identity_changed, "expiry_proven": has_401},
        "cells": {name: {"present": False, "usable": False} for name in CONTROL_TYPES},
        "observations": [],
        "provenance_complete": False,
        "external_requests": 0,
    }
