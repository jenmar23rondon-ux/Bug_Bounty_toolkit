"""Hard negatives and schema checks for IDOR pairing compatibility v4."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any
import unittest

from bugbounty_toolkit import __version__
from bugbounty_toolkit.analysis.idor_pairing_compatibility import (
    ASSESSMENT_VERSION,
    evaluate_compatibility,
    compatibility_gate_status,
)

ROOT = Path(__file__).resolve().parents[1]
ORDER_BODY = json.dumps({"ok": True, "order": {"id": "7", "owner_label": "SYNTH_OWNER", "marker": "lab"}})
ORDER_BODY_REORDERED = '{"order":{"marker":"lab","owner_label":"SYNTH_OWNER","id":"7"},"ok":true}'


def _side(role: str, **overrides: object) -> dict[str, Any]:
    base: dict[str, object] = {
        "evidence_ref": f"ev-{role}",
        "method": "GET",
        "url": "http://127.0.0.1:8177/orders/7",
        "origin": "http://127.0.0.1:8177",
        "program": "synth-lab",
        "resource_kind": "order",
        "kind_status": "explicit",
        "resource_namespace": "http://127.0.0.1:8177|order",
        "resource_id": "7",
        "parent_ids": [],
        "endpoint_template": "/orders/{id}",
        "account_ref": f"acct:SYNTH_{role.upper()}",
        "session_ref": f"sess:SYNTH_{role.upper()}",
        "batch_id": "batch-1",
        "continuity_declared": True,
        "captured_at": "2026-10-01T00:00:00+00:00",
        "temporal_not_before": "2026-09-01T00:00:00+00:00",
        "temporal_not_after": "2026-11-01T00:00:00+00:00",
        "stale": False,
        "response_present": True,
        "status_code": 200,
        "response_body": ORDER_BODY,
        "response_headers": {"content-type": "application/json"},
        "request_headers": {"authorization": f"Bearer SYNTH_{role.upper()}"},
        "integrity_sha256": "sha256:intact",
        "artifact_sha256": "sha256:intact",
        "array_object_ids": [],
        "query_id_values": [],
    }
    base.update(overrides)
    return base


def _pair(
    owner: dict[str, Any] | None = None,
    actor: dict[str, Any] | None = None,
    alias_rules: tuple[tuple[str, str], ...] | None = None,
) -> dict[str, Any]:
    left = _side("owner")
    right = _side("actor")
    if owner:
        left.update(owner)
    if actor:
        right.update(actor)
    return evaluate_compatibility(left, right, alias_rules=alias_rules)


class CompatibilitySchemaTests(unittest.TestCase):
    def test_version_stays_022(self) -> None:
        self.assertEqual(__version__, "0.2.2")

    def test_positive_same_instance_is_reviewable_and_unconfirmed(self) -> None:
        result = _pair()
        self.assertEqual(result["version"], ASSESSMENT_VERSION)
        self.assertEqual(result["compatibility"], "compatible")
        self.assertTrue(result["pairing_decision"])
        self.assertTrue(result["requires_human_review"])
        self.assertFalse(result["finding_confirmed"])
        self.assertEqual(result["network_requests_sent"], 0)
        self.assertEqual(result["identity_assessment"], "same_instance")
        self.assertNotIn("confidence", result)
        self.assertNotIsInstance(result["confidence_basis"], float)
        self.assertIn("ev-owner", result["confidence_basis"])
        self.assertNotIn("SYNTH_", result["confidence_basis"])
        self.assertEqual(result["resource_kind"], "order")

    def test_legacy_gate_is_opt_in(self) -> None:
        status = compatibility_gate_status()
        self.assertFalse(status["default_flipped"])
        self.assertEqual(status["default_pairing_path"], "propose_object_handoff")
        self.assertFalse(status["finding_confirmed"])
        handoff = (ROOT / "bugbounty_toolkit/analysis/object_handoff.py").read_text(encoding="utf-8")
        self.assertNotIn("evaluate_compatibility", handoff)
        self.assertNotIn("idor_pairing_compatibility", handoff)


class HardNegativeTests(unittest.TestCase):
    def test_01_same_digits_different_kind(self) -> None:
        result = _pair(
            owner={"url": "http://127.0.0.1:8177/users/42", "resource_kind": "user", "resource_id": "42",
                   "resource_namespace": "http://127.0.0.1:8177|user", "endpoint_template": "/users/{id}"},
            actor={"url": "http://127.0.0.1:8177/orders/42", "resource_kind": "order", "resource_id": "42",
                   "resource_namespace": "http://127.0.0.1:8177|order", "endpoint_template": "/orders/{id}"},
        )
        self.assertEqual(result["compatibility"], "incompatible")
        self.assertFalse(result["pairing_decision"])
        self.assertIn("different_kind", result["conflicting_signals"])
        self.assertIn("same_digits_do_not_link_kinds", result["conflicting_signals"])

    def test_02_equivalent_json_is_not_a_conflict(self) -> None:
        result = _pair(actor={"response_body": ORDER_BODY_REORDERED})
        self.assertEqual(result["compatibility"], "compatible")
        self.assertTrue(result["pairing_decision"])
        self.assertIn("json_canonical_equivalent", result["matching_signals"])
        self.assertNotIn("json_textual_difference", result["conflicting_signals"])
        self.assertFalse(result["finding_confirmed"])

    def test_03_declared_route_alias_is_the_same_resource(self) -> None:
        result = _pair(
            owner={
                "url": "http://127.0.0.1:8177/api/v1/orders/7",
                "endpoint_template": "/api/v1/orders/{id}",
            },
            actor={
                "url": "http://127.0.0.1:8177/orders/7",
                "endpoint_template": "/orders/{id}",
            },
            alias_rules=(("/api/v1", ""),),
        )
        self.assertEqual(result["compatibility"], "compatible")
        self.assertTrue(result["pairing_decision"])
        self.assertIn("same_endpoint", result["matching_signals"])

    def test_04_same_account_two_sessions_is_not_a_second_actor(self) -> None:
        result = _pair(
            actor={"account_ref": "acct:SYNTH_OWNER", "session_ref": "sess:SYNTH_OTHER"},
        )
        self.assertEqual(result["compatibility"], "incompatible")
        self.assertFalse(result["pairing_decision"])
        self.assertEqual(result["session_assessment"], "same_account")
        self.assertIn("same_account_not_second_actor", result["conflicting_signals"])

    def test_05_shared_acl_is_not_an_idor_candidate(self) -> None:
        shared = json.dumps({"ok": True, "order": {"id": "7", "acl": "shared", "shared_with": ["a", "b"]}})
        result = _pair(owner={"response_body": shared}, actor={"response_body": shared})
        self.assertEqual(result["compatibility"], "incompatible")
        self.assertFalse(result["pairing_decision"])
        self.assertIn("legitimate_shared", result["conflicting_signals"])

    def test_06_missing_response_artifact(self) -> None:
        result = _pair(actor={"response_present": False, "response_body": "", "status_code": None})
        self.assertEqual(result["compatibility"], "insufficient_evidence")
        self.assertFalse(result["pairing_decision"])
        self.assertIn("missing_response_artifact", result["missing_controls"])

    def test_07_http_200_denial_body(self) -> None:
        denial = json.dumps({"ok": False, "error": "not_authorized", "order": None})
        result = _pair(owner={"response_body": denial}, actor={"response_body": denial})
        self.assertEqual(result["compatibility"], "incompatible")
        self.assertFalse(result["pairing_decision"])
        self.assertIn("authorization_denial", result["conflicting_signals"])

    def test_08_id_echo_only(self) -> None:
        echo = json.dumps({"id": "7", "ok": True})
        result = _pair(owner={"response_body": echo}, actor={"response_body": echo})
        self.assertEqual(result["compatibility"], "insufficient_evidence")
        self.assertFalse(result["pairing_decision"])
        self.assertIn("id_echo_without_resource", result["missing_controls"])

    def test_09_disjoint_temporal_window_and_stale(self) -> None:
        stale = _pair(owner={"stale": True})
        self.assertEqual(stale["compatibility"], "incompatible")
        self.assertFalse(stale["pairing_decision"])
        self.assertIn("stale_evidence", stale["conflicting_signals"])
        window = _pair(
            actor={
                "temporal_not_before": "2027-01-01T00:00:00+00:00",
                "temporal_not_after": "2027-02-01T00:00:00+00:00",
                "captured_at": "2027-01-15T00:00:00+00:00",
            }
        )
        self.assertEqual(window["compatibility"], "incompatible")
        self.assertFalse(window["pairing_decision"])
        self.assertIn("temporal_window_mismatch", window["conflicting_signals"])

    def test_10_ambiguous_kind(self) -> None:
        unknown = _pair(owner={"kind_status": "unknown"}, actor={"kind_status": "ambiguous"})
        self.assertEqual(unknown["compatibility"], "insufficient_evidence")
        self.assertFalse(unknown["pairing_decision"])
        self.assertIn("ambiguous_or_unknown_kind", unknown["missing_controls"])

    def test_11_tampered_response_hash(self) -> None:
        result = _pair(actor={"artifact_sha256": "sha256:tampered"})
        self.assertEqual(result["compatibility"], "conflicting_evidence")
        self.assertFalse(result["pairing_decision"])
        self.assertIn("actor_integrity_mismatch", result["conflicting_signals"])

    def test_12_mixed_origin_and_program(self) -> None:
        origin = _pair(
            actor={
                "origin": "http://127.0.0.1:8178",
                "url": "http://127.0.0.1:8178/orders/7",
                "resource_namespace": "http://127.0.0.1:8178|order",
            }
        )
        self.assertEqual(origin["compatibility"], "incompatible")
        self.assertFalse(origin["pairing_decision"])
        self.assertIn("mixed_origin", origin["conflicting_signals"])
        program = _pair(actor={"program": "other-synth-lab"})
        self.assertEqual(program["compatibility"], "incompatible")
        self.assertFalse(program["pairing_decision"])
        self.assertIn("mixed_program", program["conflicting_signals"])

    def test_13_partial_array_is_not_the_same_resource(self) -> None:
        result = _pair(
            owner={"resource_id": "9", "array_object_ids": ["1", "2"], "endpoint_template": "/batches/{id}",
                   "url": "http://127.0.0.1:8177/batches/9"},
            actor={"resource_id": "10", "array_object_ids": ["1", "3"], "endpoint_template": "/batches/{id}",
                   "url": "http://127.0.0.1:8177/batches/10"},
        )
        self.assertEqual(result["compatibility"], "incompatible")
        self.assertFalse(result["pairing_decision"])
        self.assertIn("partial_array_match", result["conflicting_signals"])

    def test_14_different_batch_without_continuity(self) -> None:
        result = _pair(
            owner={"continuity_declared": False},
            actor={"batch_id": "batch-2", "continuity_declared": False},
        )
        self.assertEqual(result["compatibility"], "insufficient_evidence")
        self.assertFalse(result["pairing_decision"])
        self.assertIn("different_batch_no_continuity", result["missing_controls"])

    def test_15_contradictory_denial_versus_access(self) -> None:
        denial = json.dumps({"ok": False, "error": "forbidden"})
        result = _pair(actor={"response_body": denial, "status_code": 200})
        self.assertEqual(result["compatibility"], "conflicting_evidence")
        self.assertFalse(result["pairing_decision"])
        self.assertTrue(result["requires_human_review"])
        self.assertIn("contradictory_access", result["conflicting_signals"])
        self.assertFalse(result["finding_confirmed"])

    def test_distinct_instances_are_not_compatible(self) -> None:
        result = _pair(actor={"resource_id": "8", "url": "http://127.0.0.1:8177/orders/8"})
        self.assertEqual(result["compatibility"], "incompatible")
        self.assertEqual(result["identity_assessment"], "distinct_instances")
        self.assertFalse(result["pairing_decision"])

    def test_assessment_does_not_echo_secret_marker(self) -> None:
        marker = "SYNTH_PRIVATE_MARKER"
        body = json.dumps({"ok": True, "order": {"id": "7", "note": marker}})
        result = _pair(owner={"response_body": body})
        encoded = json.dumps(result)
        self.assertNotIn(marker, encoded)
        self.assertNotIn("Bearer", encoded)


class UrlDerivationTests(unittest.TestCase):
    def test_alias_and_nested_parent_from_url_only(self) -> None:
        owner = {
            "evidence_ref": "ev-owner",
            "method": "GET",
            "url": "http://127.0.0.1:8177/api/v1/orders/7",
            "program": "synth-lab",
            "account_ref": "acct:SYNTH_OWNER",
            "session_ref": "sess:SYNTH_OWNER",
            "batch_id": "batch-1",
            "continuity_declared": True,
            "response_present": True,
            "status_code": 200,
            "response_body": ORDER_BODY,
            "integrity_sha256": "sha256:intact",
            "artifact_sha256": "sha256:intact",
            "temporal_not_before": "2026-09-01T00:00:00+00:00",
            "temporal_not_after": "2026-11-01T00:00:00+00:00",
        }
        actor = dict(owner)
        actor["evidence_ref"] = "ev-actor"
        actor["url"] = "http://127.0.0.1:8177/orders/7"
        actor["account_ref"] = "acct:SYNTH_ACTOR"
        actor["session_ref"] = "sess:SYNTH_ACTOR"
        result = evaluate_compatibility(owner, actor, alias_rules=(("/api/v1", ""),))
        self.assertEqual(result["compatibility"], "compatible")
        self.assertEqual(result["resource_kind"], "order")
        self.assertTrue(result["pairing_decision"])
        digest = hashlib.sha256(b"offline").hexdigest()
        self.assertNotIn(digest, json.dumps(result))


if __name__ == "__main__":
    unittest.main()
