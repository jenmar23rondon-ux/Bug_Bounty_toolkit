"""Hard negatives and admission rules for compatibility assessment v1.

Offline fixtures only. Synthetic ``SYNTH_`` markers. No network and no confirmation.
"""

from __future__ import annotations

import hashlib
import json
import socket
import unittest
from typing import Any

from bugbounty_toolkit.analysis.idor_pairing_precision import evaluate_compatibility
from bugbounty_toolkit.analysis.object_handoff import HANDOFF_VERSION

ORIGIN = "http://127.0.0.1:8199"
CANARY = "SYNTH_CANARY_PAIRING_V4"


def _resource(kind: str, oid: int | str, label: str) -> str:
    return json.dumps({"ok": True, kind: {"id": oid, "marker": f"synth-{kind}-{oid}", "owner_label": label}})


def _ev(ref: str, path: str, *, session: str, body: str | None = None, **extra: Any) -> dict[str, Any]:
    row: dict[str, Any] = {
        "evidence_ref": ref,
        "program": "synth-program",
        "origin": ORIGIN,
        "method": "GET",
        "path": path,
        "session_ref": session,
        "account_ref": None,
        "accounts_attested": False,
        "response_present": True,
        "status_code": 200,
        "response_body": body,
    }
    row.update(extra)
    return row


def _pair(owner: dict[str, Any], actor: dict[str, Any], **kwargs: Any) -> Any:
    return evaluate_compatibility(owner, actor, **kwargs)


class CompatibilityV4Tests(unittest.TestCase):
    def test_legacy_handoff_version_unchanged(self) -> None:
        self.assertEqual(HANDOFF_VERSION, "1.1")

    def test_cross_kind_same_digits_are_incompatible(self) -> None:
        owner = _ev("own-users", "/users/42", session="sess-a", body=_resource("user", 42, "owner"))
        actor = _ev("act-orders", "/orders/42", session="sess-b", body=_resource("order", 42, "actor"))
        result = _pair(owner, actor)
        self.assertEqual(result.compatibility, "incompatible")
        self.assertEqual(result.identity_assessment, "different_kind")
        self.assertFalse(result.pairing_decision)
        self.assertNotIn("same_resource_id", result.matching_signals)

    def test_equivalent_json_does_not_invent_conflict(self) -> None:
        canonical = {"ok": True, "order": {"id": 7, "marker": "synth-order-7", "owner_label": "shared"}}
        owner = _ev(
            "own-json",
            "/orders/7",
            session="sess-a",
            body=json.dumps(canonical, sort_keys=True),
            account_ref="SYNTH_acct_owner",
            accounts_attested=True,
        )
        actor = _ev(
            "act-json",
            "/orders/7",
            session="sess-b",
            body='{"order": {"owner_label": "shared", "marker": "synth-order-7", "id": 7}, "ok": true}',
            account_ref="SYNTH_acct_actor",
            accounts_attested=True,
        )
        result = _pair(owner, actor)
        self.assertIn("json_serialization_equivalent", result.matching_signals)
        self.assertNotIn("json_mismatch", result.conflicting_signals)
        self.assertEqual(result.conflicting_signals, ())
        self.assertEqual(result.compatibility, "compatible")
        self.assertTrue(result.pairing_decision)
        self.assertTrue(result.requires_human_review)
        self.assertFalse(result.finding_confirmed)

    def test_declared_alias_routes_are_the_same_resource(self) -> None:
        rules = {"strip_prefixes": ["api", "v1"]}
        owner = _ev(
            "own-alias",
            "/api/v1/orders/7",
            session="sess-a",
            body=_resource("order", 7, "owner"),
            account_ref="SYNTH_acct_owner",
            accounts_attested=True,
        )
        actor = _ev(
            "act-alias",
            "/orders/7",
            session="sess-b",
            body=_resource("order", 7, "actor"),
            account_ref="SYNTH_acct_actor",
            accounts_attested=True,
        )
        withheld = _pair(owner, actor)
        self.assertNotEqual(withheld.compatibility, "compatible")
        self.assertFalse(withheld.pairing_decision)
        admitted = _pair(owner, actor, alias_rules=rules)
        self.assertEqual(admitted.compatibility, "compatible")
        self.assertEqual(admitted.identity_assessment, "same_resource")
        self.assertIn("declared_route_alias", admitted.matching_signals)
        self.assertTrue(admitted.pairing_decision)

    def test_same_account_two_sessions_are_not_a_second_actor(self) -> None:
        owner = _ev(
            "own-same",
            "/orders/7",
            session="sess-a",
            body=_resource("order", 7, "owner"),
            account_ref="SYNTH_acct_same",
            accounts_attested=True,
        )
        actor = _ev(
            "act-same",
            "/orders/8",
            session="sess-b",
            body=_resource("order", 8, "owner"),
            account_ref="SYNTH_acct_same",
            accounts_attested=True,
        )
        result = _pair(owner, actor)
        self.assertEqual(result.compatibility, "incompatible")
        self.assertEqual(result.session_assessment, "same_account")
        self.assertFalse(result.pairing_decision)

    def test_shared_acl_is_not_an_idor_candidate(self) -> None:
        body = json.dumps({"ok": True, "document": {"id": 5, "acl": "shared", "shared_with": ["a", "b"]}})
        owner = _ev("own-share", "/documents/5", session="sess-a", body=body)
        actor = _ev("act-share", "/documents/5", session="sess-b", body=body)
        result = _pair(owner, actor)
        self.assertEqual(result.compatibility, "incompatible")
        self.assertFalse(result.pairing_decision)

    def test_missing_response_artifact_is_insufficient(self) -> None:
        owner = _ev("own-miss", "/orders/7", session="sess-a", body=_resource("order", 7, "owner"))
        actor = _ev(
            "act-miss",
            "/orders/8",
            session="sess-b",
            body=None,
            response_present=False,
            status_code=None,
        )
        result = _pair(owner, actor)
        self.assertEqual(result.compatibility, "insufficient_evidence")
        self.assertIn("response_artifact", result.missing_controls)
        self.assertFalse(result.pairing_decision)

    def test_http_200_denial_body_is_incompatible(self) -> None:
        owner = _ev("own-deny", "/contracts/1", session="sess-a", body=_resource("contract", 1, "owner"))
        actor = _ev(
            "act-deny",
            "/contracts/2",
            session="sess-b",
            body=json.dumps({"ok": False, "error": "access denied", "contract": None}),
        )
        result = _pair(owner, actor)
        self.assertEqual(result.compatibility, "incompatible")
        self.assertFalse(result.pairing_decision)

    def test_id_echo_is_insufficient(self) -> None:
        owner = _ev("own-echo", "/widgets/42", session="sess-a", body=json.dumps({"ok": True, "id": 42}))
        actor = _ev("act-echo", "/widgets/42", session="sess-b", body=json.dumps({"ok": True, "id": 42}))
        result = _pair(owner, actor)
        self.assertEqual(result.compatibility, "insufficient_evidence")
        self.assertIn("id_echo_without_resource", result.missing_controls)
        self.assertFalse(result.pairing_decision)

    def test_temporal_windows_and_stale_evidence_are_not_admitted(self) -> None:
        owner = _ev(
            "own-time",
            "/orders/7",
            session="sess-a",
            body=_resource("order", 7, "owner"),
            temporal_start="2020-01-01T00:00:00Z",
            temporal_end="2020-02-01T00:00:00Z",
        )
        actor = _ev(
            "act-time",
            "/orders/8",
            session="sess-b",
            body=_resource("order", 8, "actor"),
            temporal_start="2024-01-01T00:00:00Z",
            temporal_end="2024-02-01T00:00:00Z",
        )
        disjoint = _pair(owner, actor)
        self.assertEqual(disjoint.compatibility, "incompatible")
        self.assertFalse(disjoint.pairing_decision)
        stale = _pair(
            _ev("own-stale", "/orders/7", session="sess-a", body=_resource("order", 7, "owner"), stale=True),
            _ev(
                "act-stale",
                "/orders/8",
                session="sess-b",
                body=_resource("order", 8, "actor"),
                expires_at="2024-01-01T00:00:00Z",
            ),
            as_of="2026-01-01T00:00:00Z",
        )
        self.assertEqual(stale.compatibility, "insufficient_evidence")
        self.assertIn("fresh_evidence", stale.missing_controls)
        self.assertFalse(stale.pairing_decision)

    def test_ambiguous_kind_is_insufficient(self) -> None:
        owner = _ev(
            "own-amb",
            "/widgets/1",
            session="sess-a",
            body=_resource("widget", 1, "owner"),
            kind_status="ambiguous",
            resource_kinds=["widget", "record"],
        )
        actor = _ev(
            "act-amb",
            "/widgets/2",
            session="sess-b",
            body=_resource("widget", 2, "actor"),
            kind_status="unknown",
        )
        result = _pair(owner, actor)
        self.assertEqual(result.compatibility, "insufficient_evidence")
        self.assertEqual(result.identity_assessment, "ambiguous")
        self.assertFalse(result.pairing_decision)

    def test_integrity_mismatch_conflicts(self) -> None:
        body = _resource("order", 7, "owner")
        owner = _ev("own-int", "/orders/7", session="sess-a", body=body, integrity_ok=False)
        actor = _ev("act-int", "/orders/8", session="sess-b", body=_resource("order", 8, "actor"))
        flagged = _pair(owner, actor)
        self.assertEqual(flagged.compatibility, "conflicting_evidence")
        self.assertIn("artifact_integrity_mismatch", flagged.conflicting_signals)
        self.assertFalse(flagged.pairing_decision)
        tampered = _ev(
            "act-hash",
            "/orders/8",
            session="sess-b",
            body=_resource("order", 8, "actor"),
            response_sha256=hashlib.sha256(b"not-the-body").hexdigest(),
        )
        hashed = _pair(_ev("own-hash", "/orders/7", session="sess-a", body=body), tampered)
        self.assertEqual(hashed.compatibility, "conflicting_evidence")
        self.assertFalse(hashed.pairing_decision)

    def test_mixed_origin_and_program_are_incompatible(self) -> None:
        owner = _ev("own-org", "/orders/7", session="sess-a", body=_resource("order", 7, "owner"))
        other_host = _ev(
            "act-host",
            "/orders/8",
            session="sess-b",
            body=_resource("order", 8, "actor"),
            origin="http://127.0.0.1:8198",
        )
        hosts = _pair(owner, other_host)
        self.assertEqual(hosts.compatibility, "incompatible")
        self.assertFalse(hosts.pairing_decision)
        other_program = _ev(
            "act-prog",
            "/orders/8",
            session="sess-b",
            body=_resource("order", 8, "actor"),
            program="synth-other-program",
        )
        programs = _pair(owner, other_program)
        self.assertEqual(programs.compatibility, "incompatible")
        self.assertFalse(programs.pairing_decision)

    def test_partial_array_overlap_is_not_the_same_resource(self) -> None:
        owner = _ev(
            "own-arr",
            "/items",
            session="sess-a",
            body=json.dumps([{"id": 1, "marker": "a"}, {"id": 2, "marker": "b"}]),
            resource_kind="item",
            kind_status="explicit",
        )
        actor = _ev(
            "act-arr",
            "/items",
            session="sess-b",
            body=json.dumps([{"id": 2, "marker": "b"}, {"id": 3, "marker": "c"}]),
            resource_kind="item",
            kind_status="explicit",
        )
        result = _pair(owner, actor)
        self.assertEqual(result.compatibility, "incompatible")
        self.assertEqual(result.identity_assessment, "partial_array")
        self.assertFalse(result.pairing_decision)

    def test_different_batches_without_continuity_are_insufficient(self) -> None:
        owner = _ev(
            "own-batch",
            "/orders/7",
            session="sess-a",
            body=_resource("order", 7, "owner"),
            batch_id="batch-a",
            capture_run="run-a",
        )
        actor = _ev(
            "act-batch",
            "/orders/8",
            session="sess-b",
            body=_resource("order", 8, "actor"),
            batch_id="batch-b",
            capture_run="run-b",
        )
        blocked = _pair(owner, actor)
        self.assertEqual(blocked.compatibility, "insufficient_evidence")
        self.assertIn("capture_continuity", blocked.missing_controls)
        self.assertFalse(blocked.pairing_decision)
        linked = _pair(
            owner,
            actor,
            continuity={"linked_batches": [["batch-a", "batch-b"]], "linked_runs": [["run-a", "run-b"]]},
        )
        self.assertEqual(linked.compatibility, "compatible")
        self.assertTrue(linked.pairing_decision)

    def test_contradictory_denial_and_access_conflict(self) -> None:
        owner = _ev(
            "own-con",
            "/orders/5",
            session="sess-a",
            status_code=403,
            body=json.dumps({"ok": False, "error": "forbidden"}),
        )
        actor = _ev("act-con", "/orders/5", session="sess-b", body=_resource("order", 5, "owner"))
        result = _pair(owner, actor)
        self.assertEqual(result.compatibility, "conflicting_evidence")
        self.assertIn("contradictory_negative_evidence", result.conflicting_signals)
        self.assertFalse(result.pairing_decision)

    def test_distinct_private_reads_are_admitted_for_review(self) -> None:
        owner = _ev(
            "own-ok",
            "/orders/7",
            session="sess-a",
            body=_resource("order", 7, "owner"),
            account_ref="SYNTH_acct_owner",
            accounts_attested=True,
        )
        actor = _ev(
            "act-ok",
            "/orders/8",
            session="sess-b",
            body=_resource("order", 8, "actor"),
            account_ref="SYNTH_acct_actor",
            accounts_attested=True,
        )
        result = _pair(owner, actor)
        self.assertEqual(result.compatibility, "compatible")
        self.assertEqual(result.identity_assessment, "same_kind_distinct_ids")
        self.assertTrue(result.pairing_decision)
        self.assertTrue(result.requires_human_review)
        self.assertFalse(result.finding_confirmed)
        self.assertEqual(result.network_requests_sent, 0)
        self.assertEqual(result.external_requests, 0)

    def test_outputs_omit_bodies_scores_and_canaries(self) -> None:
        owner = _ev("own-sec", "/orders/7", session="sess-a", body=_resource("order", 7, CANARY))
        actor = _ev("act-sec", "/orders/8", session="sess-b", body=_resource("order", 8, "actor"))
        payload = json.dumps(_pair(owner, actor).as_dict())
        self.assertNotIn(CANARY, payload)
        self.assertNotIn("response_body", payload)
        for value in _pair(owner, actor).as_dict().values():
            self.assertNotIsInstance(value, float)

    def test_evaluation_does_not_open_sockets(self) -> None:
        attempts = {"count": 0}
        real = socket.socket.connect

        def guard(*_args: Any, **_kwargs: Any) -> Any:
            attempts["count"] += 1
            raise AssertionError("network disabled")

        socket.socket.connect = guard  # type: ignore[method-assign]
        try:
            result = _pair(
                _ev("own-net", "/orders/7", session="sess-a", body=_resource("order", 7, "owner")),
                _ev("act-net", "/orders/8", session="sess-b", body=_resource("order", 8, "actor")),
            )
        finally:
            socket.socket.connect = real  # type: ignore[method-assign]
        self.assertEqual(attempts["count"], 0)
        self.assertFalse(result.finding_confirmed)


if __name__ == "__main__":
    unittest.main()
