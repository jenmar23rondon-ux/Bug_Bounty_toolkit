"""Adversarial authorization envelopes; all transports are mocked."""

import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock

from bugbounty_toolkit.access_control.comparison import AccessControlTester
from bugbounty_toolkit.access_control.range_checker import AccessRangeOptions, AccessRangeTester
from bugbounty_toolkit.analysis.authorization_denial import assess_pair_authorization, assess_response
from bugbounty_toolkit.analysis.idor_pairing_precision import evaluate_compatibility
from bugbounty_toolkit.core.http_client import ResponseRecord
from bugbounty_toolkit.core.rate_limiter import RateLimiter
from bugbounty_toolkit.core.scope_validator import ScopeValidator


def resource(identifier="20"):
    return {"success": True, "data": {"id": identifier, "proof": "synthetic-private-proof-" + identifier}}


class ContradictoryDenialTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.base = "http://127.0.0.1:8099"
        (self.root / "scope.txt").write_text(self.base + "\n")
        self.scope = ScopeValidator(self.root / "scope.txt")
        for name, identifier in (("owner", "20"), ("actor", "10"), ("actor2", "30")):
            (self.root / f"{name}.http").write_text(
                f"GET /orders/{identifier} HTTP/1.1\r\nHost: 127.0.0.1:8099\r\n"
                f"Authorization: Bearer synthetic-{identifier}\r\n\r\n"
            )
        self.case = self.root / "case.json"
        self.data = {
            "owner_request": "owner.http",
            "actor_request": "actor.http",
            "base_url": self.base,
            "session_headers": ["Authorization"],
            "resource": {"path_segment": 1},
            "accounts_authorized": True,
            "resource_private": True,
            "expected_cross_access": "deny",
            "identifier_enumeration_authorized": True,
            "checks": {
                "success_pointer": "/success",
                "success_value": True,
                "resource_pointer": "/data/id",
                "owner_resource": "20",
                "actor_resource": "10",
                "private_pointer": "/data/proof",
                "owner_marker": "synthetic-private-proof-20",
                "actor_marker": "synthetic-private-proof-10",
            },
        }
        self.save()

    def save(self):
        self.case.write_text(json.dumps(self.data))

    def client(self, status=200, failure=None, *, invalid_owner=False, cross_resource=None, omit_resource=False):
        client = Mock()
        client.rate_limiter = RateLimiter(10000)

        def send(request):
            identifier = request.prepared_url().rsplit("/", 1)[1]
            own = request.headers.get("Authorization") == "Bearer synthetic-" + identifier
            body = resource(identifier)
            code = 200
            if not own or invalid_owner:
                code = status
                if cross_resource is not None:
                    body = resource(cross_resource)
                body.update(failure or {"success": False})
                if omit_resource:
                    body.pop("data")
            encoded = json.dumps(body)
            return ResponseRecord(request, request.prepared_url(), code, "test", 1, {}, encoded, len(encoded))

        client.send.side_effect = send
        return client

    def test_read_contradictions_abstain_and_keep_private_evidence_redacted(self):
        for status, failure in ((403, {}), (200, {"success": False}), (200, {"error": "access_denied"})):
            with self.subTest(status=status, failure=failure):
                client = self.client(status, failure)
                path, result = AccessControlTester(self.scope, client).run(self.case, self.root / "evidence")
                self.assertEqual(result["classification"], "inconclusive")
                self.assertFalse(result["confirmed"])
                self.assertEqual(result["stop_reason"], "contradictory_authorization_evidence")
                self.assertEqual(client.send.call_count, 3)
                self.assertTrue(result["steps"][-1]["owner_private_match"])
                self.assertNotIn("synthetic-private-proof-20", path.read_text())

    def test_inverse_and_anonymous_do_not_promote_contradictions(self):
        client = self.client(200, {"error": "forbidden"})
        _, result = AccessControlTester(self.scope, client).run(
            self.case, self.root / "evidence", max_tests=5, inverse_cross=True, anonymous_check=True
        )
        self.assertEqual(client.send.call_count, 5)
        self.assertEqual(result["inverse_result"], "inconclusive")
        self.assertEqual(result["anonymous_classification"], "inconclusive")
        self.assertFalse(result["anonymous_finding"])
        self.assertFalse(result["confirmed"])

    def test_matrix_contradictions_are_not_candidates(self):
        self.data["additional_accounts"] = {
            "actor2": {"request": "actor2.http", "resource": "30", "marker": "synthetic-private-proof-30"}
        }
        self.save()
        _, result = AccessControlTester(self.scope, self.client()).run(
            self.case, self.root / "evidence", max_tests=9, multi_account=True
        )
        crosses = [cell for cell in result["matrix"] if cell["access_type"] == "cross"]
        self.assertEqual(len(crosses), 6)
        self.assertTrue(all(cell["classification"] == "inconclusive" for cell in crosses))
        self.assertFalse(result["confirmed"])

    def test_range_preserves_conflicting_markers_without_confirmation(self):
        client = self.client()
        _, result = AccessRangeTester(self.scope, client).run(
            self.case, AccessRangeOptions("20-20", 3, min_interval=0.01), self.root / "evidence"
        )
        self.assertEqual(result["classification"], "inconclusive")
        self.assertFalse(result["confirmed"])
        self.assertTrue(result["results"][0]["contradictory_authorization_evidence"])
        self.assertEqual(client.send.call_count, 3)

    def test_contradictory_owner_is_not_a_valid_control(self):
        client = self.client(200, {"error": "forbidden"}, invalid_owner=True)
        _, result = AccessControlTester(self.scope, client).run(self.case, self.root / "evidence")
        self.assertFalse(result["controls_valid"])
        self.assertEqual(client.send.call_count, 1)

    def test_unknown_resource_conflict_is_not_denied_in_read_inverse_or_anonymous(self):
        self.data["expected_anonymous"] = "allow"
        self.save()
        client = self.client(403, cross_resource="40")
        _, result = AccessControlTester(self.scope, client).run(
            self.case, self.root / "evidence", max_tests=5, inverse_cross=True, anonymous_check=True
        )
        self.assertEqual(client.send.call_count, 5)
        for field in ("cross_result", "inverse_result", "anonymous_classification"):
            self.assertEqual(result[field], "inconclusive")
        self.assertFalse(result["anonymous_expectation_mismatch"])
        self.assertFalse(result["anonymous_finding"])
        self.assertFalse(result["steps"][-1]["private_match"])
        self.assertTrue(result["steps"][-1]["contradictory_authorization_evidence"])

    def test_range_unknown_resource_conflicts_remain_inconclusive(self):
        for status in (200, 403):
            with self.subTest(status=status):
                client = self.client(status)
                _, result = AccessRangeTester(self.scope, client).run(
                    self.case, AccessRangeOptions("30-30", 3, min_interval=0.01), self.root / "evidence"
                )
                row = result["results"][0]
                self.assertEqual(row["classification"], "inconclusive")
                self.assertTrue(row["contradictory_authorization_evidence"])
                self.assertFalse(row["owner_resource_match"])
                self.assertFalse(result["confirmed"])
                self.assertEqual(client.send.call_count, 3)

    def test_complete_denied_matrix_remains_a_negative_control(self):
        self.data["additional_accounts"] = {
            "actor2": {"request": "actor2.http", "resource": "30", "marker": "synthetic-private-proof-30"}
        }
        self.save()
        client = self.client(403, omit_resource=True)
        _, result = AccessControlTester(self.scope, client).run(
            self.case, self.root / "evidence", max_tests=9, multi_account=True
        )
        self.assertEqual(client.send.call_count, 9)
        self.assertEqual(result["matrix_crosses"], 6)
        self.assertEqual(result["finding_state"], "not_observed")
        self.assertEqual(result["stop_reason"], "cross_matrix_rejected")
        self.assertTrue(
            all(
                row["classification"] == "rejected_in_this_test"
                for row in result["matrix"]
                if row["access_type"] == "cross"
            )
        )

    def test_offline_response_and_pairing_do_not_treat_conflict_as_access(self):
        clean = resource()
        for status, extra in ((403, {}), (200, {"success": False}), (200, {"error": "forbidden"})):
            with self.subTest(status=status, extra=extra):
                body = json.dumps({**clean, **extra})
                assessment = assess_response(status, body)
                self.assertFalse(assessment.access_demonstrated)
                self.assertFalse(assessment.denial_demonstrated)
                self.assertEqual(assessment.access_proof, "ambiguous")
                owner = "HTTP/1.1 200 OK\r\n\r\n" + json.dumps(clean)
                actor = f"HTTP/1.1 {status} test\r\n\r\n" + body
                self.assertEqual(assess_pair_authorization(owner, actor).outcome, "inconclusive")
                common = {"path": "/orders/20", "method": "GET", "origin": self.base, "response_present": True}
                compatibility = evaluate_compatibility(
                    {
                        **common,
                        "session_ref": "owner",
                        "evidence_ref": "owner-evidence",
                        "status_code": 200,
                        "response_body": json.dumps(clean),
                    },
                    {
                        **common,
                        "session_ref": "actor",
                        "evidence_ref": "actor-evidence",
                        "status_code": status,
                        "response_body": body,
                    },
                )
                self.assertEqual(compatibility.compatibility, "conflicting_evidence")
                self.assertFalse(compatibility.pairing_decision)
                self.assertFalse(compatibility.finding_confirmed)
