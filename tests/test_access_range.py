import json
from pathlib import Path
import tempfile
import threading
import time
import unittest
from unittest.mock import Mock, patch

from bugbounty_toolkit.access_control.range_checker import AccessRangeOptions, AccessRangeTester, parse_id_range
from bugbounty_toolkit.core.http_client import RequestSpec, ResponseRecord
from bugbounty_toolkit.core.rate_limiter import RateLimiter
from bugbounty_toolkit.core.scope_validator import ScopeValidator


class AccessRangeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.base = "http://127.0.0.1:3000"
        (self.root / "scope.txt").write_text("127.0.0.1\n", encoding="utf-8")
        host = "127.0.0.1:3000"
        (self.root / "owner.http").write_text(
            f"GET /api/items/20 HTTP/1.1\r\nHost: {host}\r\nAuthorization: Bearer owner-session\r\n\r\n",
            encoding="utf-8",
        )
        (self.root / "actor.http").write_text(
            f"GET /api/items/10 HTTP/1.1\r\nHost: {host}\r\nAuthorization: Bearer actor-session\r\n\r\n",
            encoding="utf-8",
        )
        case = {
            "owner_request": "owner.http", "actor_request": "actor.http", "base_url": self.base,
            "session_headers": ["Authorization"], "resource": {"path_segment": 2},
            "accounts_authorized": True, "resource_private": True, "expected_cross_access": "deny",
            "identifier_enumeration_authorized": True,
            "checks": {
                "success_pointer": "/success", "success_value": True, "resource_pointer": "/data/id",
                "owner_resource": "20", "actor_resource": "10", "private_pointer": "/data/proof",
                "owner_marker": "owner-proof-123456", "actor_marker": "actor-proof-654321",
            },
        }
        self.case_file = self.root / "case.json"
        self.case_file.write_text(json.dumps(case), encoding="utf-8")
        self.client = Mock()
        self.client.rate_limiter = RateLimiter(1)
        self.tester = AccessRangeTester(ScopeValidator(self.root / "scope.txt"), self.client)

    def tearDown(self):
        self.temp.cleanup()

    def response(self, request, status, value):
        body = json.dumps(value)
        return ResponseRecord(request, request.prepared_url(), status, "OK", 1,
                              {"content-type": "application/json"}, body, len(body), False)

    def test_numeric_range_is_strictly_bounded(self):
        self.assertEqual(list(parse_id_range("4-6")), [4, 5, 6])
        self.assertEqual(len(parse_id_range("1-25")), 25)
        for invalid in ("1-26", "6-4", "1,2,3", "-1-2", "0-2", "1-x"):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                parse_id_range(invalid)

    def test_preflight_builds_scoped_gets_and_enforces_total_budget(self):
        case, requests = self.tester.validate(self.case_file, AccessRangeOptions("40-42", 5))
        self.assertEqual([request.prepared_url().rsplit("/", 1)[-1] for request in requests], ["40", "41", "42"])
        self.assertTrue(all(request.method == "GET" and request.body is None for request in requests))
        self.assertEqual(case.cross.headers["Authorization"], "Bearer actor-session")
        with self.assertRaises(ValueError):
            self.tester.validate(self.case_file, AccessRangeOptions("40-42", 4))
        with self.assertRaises(ValueError):
            self.tester.validate(self.case_file, AccessRangeOptions("1-26", 27))
        self.client.send.assert_not_called()

    def test_local_lab_can_configure_cap_concurrency_and_interval(self):
        _, requests = self.tester.validate(
            self.case_file, AccessRangeOptions("40-69", 32, max_range=30, concurrency=3, min_interval=0.01)
        )
        self.assertEqual(len(requests), 30)

    def test_non_loopback_keeps_range_sequential_and_slow(self):
        remote = self.root / "remote"
        remote.mkdir()
        host = "authorized.example"
        (remote / "scope.txt").write_text(host + "\n", encoding="utf-8")
        (remote / "owner.http").write_text(
            f"GET /api/items/20 HTTP/1.1\r\nHost: {host}\r\nAuthorization: Bearer owner-session\r\n\r\n",
            encoding="utf-8",
        )
        (remote / "actor.http").write_text(
            f"GET /api/items/10 HTTP/1.1\r\nHost: {host}\r\nAuthorization: Bearer actor-session\r\n\r\n",
            encoding="utf-8",
        )
        data = json.loads(self.case_file.read_text(encoding="utf-8"))
        data["base_url"] = "https://authorized.example"
        case_file = remote / "case.json"
        case_file.write_text(json.dumps(data), encoding="utf-8")
        tester = AccessRangeTester(ScopeValidator(remote / "scope.txt"), self.client)
        unsafe_options = (
            AccessRangeOptions("1-2", 4, max_range=26),
            AccessRangeOptions("1-2", 4, max_range=2, concurrency=2),
            AccessRangeOptions("1-2", 4, max_range=2, min_interval=9.99),
        )
        for options in unsafe_options:
            with self.subTest(options=options), self.assertRaises(ValueError):
                tester.validate(case_file, options)
        self.client.send.assert_not_called()

    def test_concurrency_stops_new_windows_and_marks_in_flight_overrun(self):
        owner = {"success": True, "data": {"id": "20", "proof": "owner-proof-123456"}}
        actor = {"success": True, "data": {"id": "10", "proof": "actor-proof-654321"}}
        crossed = {"success": True, "data": {"id": "20", "proof": "owner-proof-123456"}}
        denied = {"success": False}
        active_lock = threading.Lock()
        active = 0
        peak_active = 0

        def send(request):
            nonlocal active, peak_active
            path = request.prepared_url()
            probe = not (path.endswith("/20") or path.endswith("/10"))
            with active_lock:
                active += 1
                peak_active = max(peak_active, active)
            try:
                time.sleep(0.04 if probe else 0.005)
                value = owner if path.endswith("/20") else actor if path.endswith("/10") else crossed if path.endswith("/1") else denied
                return self.response(request, 200 if value is not denied else 403, value)
            finally:
                with active_lock:
                    active -= 1

        self.client.send.side_effect = send
        _, result = self.tester.run(
            self.case_file, AccessRangeOptions("1-5", 7, max_range=5, concurrency=3, min_interval=0.01),
            self.root / "concurrent-evidence",
        )
        self.assertGreaterEqual(peak_active, 2)
        self.assertEqual(result["candidate_offset"], 0)
        self.assertEqual(result["requests_attempted"], 5)
        self.assertEqual(result["concurrent_requests_not_evaluated"], 2)
        self.assertEqual(result["not_completed"], 2)
        self.assertEqual(result["minimum_interval_seconds"], 0.01)

    def test_range_requires_explicit_enumeration_authorization(self):
        case = json.loads(self.case_file.read_text(encoding="utf-8"))
        del case["identifier_enumeration_authorized"]
        self.case_file.write_text(json.dumps(case), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "identifier-enumeration authorization"):
            self.tester.validate(self.case_file, AccessRangeOptions("40-42", 5))
        self.client.send.assert_not_called()

    def test_candidate_stops_after_one_probe_and_evidence_omits_ids_and_body(self):
        owner = {"success": True, "data": {"id": "20", "proof": "owner-proof-123456"}}
        actor = {"success": True, "data": {"id": "10", "proof": "actor-proof-654321"}}
        cross = {"success": True, "data": {"id": "secret-other-id", "proof": None}}
        def send(request):
            path = request.prepared_url()
            if path.endswith("/20"):
                return self.response(request, 200, owner)
            if path.endswith("/10"):
                return self.response(request, 200, actor)
            return self.response(request, 200, cross)
        self.client.send.side_effect = send
        with patch.object(RateLimiter, "wait", return_value=None):
            evidence_path, result = self.tester.run(self.case_file, AccessRangeOptions("1-5", 7), self.root / "evidence")
        self.assertEqual(result["classification"], "candidate")
        self.assertEqual(result["candidate_offset"], 0)
        self.assertEqual(result["requests_attempted"], 3)
        self.assertEqual(result["not_completed"], 4)
        self.assertEqual(self.client.rate_limiter.requests_per_second, 0.1)
        serialized = evidence_path.read_text(encoding="utf-8")
        self.assertNotIn("secret-other-id", serialized)
        self.assertNotIn("owner-proof-123456", serialized)
        self.assertNotIn("/api/items/1", serialized)

    def test_protected_range_completes_with_bounded_result_rows(self):
        owner = {"success": True, "data": {"id": "20", "proof": "owner-proof-123456"}}
        actor = {"success": True, "data": {"id": "10", "proof": "actor-proof-654321"}}
        denied = {"success": False}
        def send(request):
            path = request.prepared_url()
            if path.endswith("/20"):
                return self.response(request, 200, owner)
            if path.endswith("/10"):
                return self.response(request, 200, actor)
            return self.response(request, 403, denied)
        self.client.send.side_effect = send
        with patch.object(RateLimiter, "wait", return_value=None):
            _, result = self.tester.run(self.case_file, AccessRangeOptions("1-3", 5), self.root / "evidence")
        self.assertEqual(result["classification"], "rejected_in_this_test")
        self.assertEqual(result["requests_attempted"], 5)
        self.assertEqual(len(result["results"]), 3)
        self.assertEqual(result["concurrency"], 1)

    def test_identity_differential_is_recorded_only_as_a_boolean(self):
        case = json.loads(self.case_file.read_text(encoding="utf-8"))
        case["identity_check"] = {"pointer": "/data/account_id", "actor_value": "account-A-private"}
        self.case_file.write_text(json.dumps(case), encoding="utf-8")
        owner = {"success": True, "data": {"id": "20", "proof": "owner-proof-123456"}}
        actor = {"success": True, "data": {"id": "10", "proof": "actor-proof-654321"}}
        crossed = {"success": True, "data": {"id": "10", "proof": "actor-proof-654321", "account_id": "account-B-private"}}
        self.client.send.side_effect = [
            self.response(RequestSpec("GET", self.base + "/api/items/20", {}), 200, owner),
            self.response(RequestSpec("GET", self.base + "/api/items/10", {}), 200, actor),
            self.response(RequestSpec("GET", self.base + "/api/items/10", {}), 200, crossed),
        ]
        with patch.object(RateLimiter, "wait", return_value=None):
            path, result = self.tester.run(self.case_file, AccessRangeOptions("10-11", 4), self.root / "identity-evidence")
        self.assertEqual(result["classification"], "candidate")
        self.assertTrue(result["results"][0]["identity_differs_from_actor"])
        self.assertNotIn("account-B-private", path.read_text(encoding="utf-8"))
