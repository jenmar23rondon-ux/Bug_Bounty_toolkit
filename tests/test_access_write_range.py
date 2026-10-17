import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock

from bugbounty_toolkit.access_control.range_checker import AccessRangeOptions
from bugbounty_toolkit.access_control.write_range import AccessWriteRangeTester
from bugbounty_toolkit.core.http_client import ResponseRecord
from bugbounty_toolkit.core.rate_limiter import RateLimiter
from bugbounty_toolkit.core.scope_validator import ScopeValidator


class AccessWriteRangeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.host = "127.0.0.1:3000"
        self.base = "http://" + self.host
        (self.root / "scope.txt").write_text("127.0.0.1\n", encoding="utf-8")
        self._write_request("owner.http", "owner-session", "B")
        self._write_request("actor.http", "actor-session", "A")
        self.case_file = self.root / "case.json"
        self.case_file.write_text(json.dumps({
            "owner_request": "owner.http", "actor_request": "actor.http", "base_url": self.base,
            "session_headers": ["Authorization"], "resource": {"json_body_pointer": "/mutation/item/id"},
            "accounts_authorized": True, "resource_private": True, "expected_cross_access": "deny",
            "disposable_test_resources": True, "identifier_enumeration_authorized": True,
            "checks": {"success_pointer": "/success", "success_value": True,
                       "resource_pointer": "/data/id", "owner_resource": "B", "actor_resource": "A",
                       "private_pointer": "/data/proof", "owner_marker": "owner-proof-123456",
                       "actor_marker": "actor-proof-654321"},
        }), encoding="utf-8")
        self.scope = ScopeValidator(self.root / "scope.txt")
        self.client = Mock()
        self.client.rate_limiter = RateLimiter(1)
        self.tester = AccessWriteRangeTester(self.scope, self.client)

    def tearDown(self):
        self.temp.cleanup()

    def _write_request(self, name, token, identifier, method="PATCH"):
        body = json.dumps({"mutation": {"item": {"id": identifier, "title": "disposable"},
                                         "flags": [True, 7]}, "keep": {"region": "lab"}})
        raw = (f"{method} /api/items/update HTTP/1.1\r\nHost: {self.host}\r\n"
               f"Authorization: Bearer {token}\r\nContent-Type: application/json\r\n\r\n{body}")
        (self.root / name).write_text(raw, encoding="utf-8", newline="")

    @staticmethod
    def _response(request, status, identifier, proof, success=True):
        body = json.dumps({"success": success, "data": {"id": identifier, "proof": proof}})
        return ResponseRecord(request, request.prepared_url(), status, "OK", 1,
                              {"content-type": "application/json"}, body, len(body), False)

    def test_validation_rebuilds_each_json_body_and_enforces_budget_and_attestation(self):
        options = AccessRangeOptions("1-3", 5, max_range=3, concurrency=2, min_interval=0.01)
        case, requests = self.tester.validate(self.case_file, options)
        self.assertEqual(case.mode, "lab-write")
        self.assertEqual([json.loads(request.body)["mutation"]["item"]["id"] for request in requests],
                         ["1", "2", "3"])
        self.assertTrue(all(request.method == "PATCH" for request in requests))
        self.assertTrue(all(request.headers["Authorization"] == "Bearer actor-session" for request in requests))
        self.assertTrue(all(json.loads(request.body)["keep"] == {"region": "lab"} for request in requests))
        with self.assertRaisesRegex(ValueError, "Budget"):
            self.tester.validate(self.case_file, AccessRangeOptions("1-3", 4, max_range=3, min_interval=0.01))
        data = json.loads(self.case_file.read_text(encoding="utf-8"))
        data["identifier_enumeration_authorized"] = False
        self.case_file.write_text(json.dumps(data), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "identifier-enumeration"):
            self.tester.validate(self.case_file, options)
        self.client.send.assert_not_called()

    def test_candidate_stops_after_crossed_write_and_evidence_omits_ids(self):
        def send(request):
            identifier = json.loads(request.body)["mutation"]["item"]["id"]
            token = request.headers["Authorization"]
            if token == "Bearer owner-session":
                return self._response(request, 200, "B", "owner-proof-123456")
            if identifier == "A":
                return self._response(request, 200, "A", "actor-proof-654321")
            return self._response(request, 200, "B", "owner-proof-123456")

        self.client.send.side_effect = send
        path, result = self.tester.run(
            self.case_file, AccessRangeOptions("1-5", 7, max_range=5, min_interval=0.01),
            self.root / "candidate-evidence",
        )
        self.assertEqual(result["mode"], "bounded-write-range")
        self.assertEqual(result["classification"], "candidate")
        self.assertEqual(result["candidate_offset"], 0)
        self.assertEqual(result["requests_attempted"], 3)
        self.assertEqual(result["steps"][-1]["step"], "cross_write")
        self.assertEqual(self.client.send.call_args_list[2].args[0].headers["Authorization"],
                         "Bearer actor-session")
        saved = path.read_text(encoding="utf-8")
        self.assertNotIn("owner-proof-123456", saved)
        self.assertNotIn('"id": "1"', saved)

    def test_write_error_stops_remaining_ids_without_retry(self):
        def send(request):
            identifier = json.loads(request.body)["mutation"]["item"]["id"]
            if request.headers["Authorization"] == "Bearer owner-session":
                return self._response(request, 200, "B", "owner-proof-123456")
            if identifier == "A":
                return self._response(request, 200, "A", "actor-proof-654321")
            return self._response(request, 500, "", "", success=False)

        self.client.send.side_effect = send
        _, result = self.tester.run(
            self.case_file, AccessRangeOptions("1-5", 7, max_range=5, min_interval=0.01),
            self.root / "error-evidence",
        )
        self.assertEqual(result["stop_reason"], "write_probe_rejected")
        self.assertEqual(result["requests_attempted"], 3)
        self.assertEqual(self.client.send.call_count, 3)

    def test_public_write_range_requires_both_public_opt_ins_for_relaxed_limits(self):
        host = "authorized.example"
        (self.root / "scope.txt").write_text(host + "\n", encoding="utf-8")
        self.host = host
        self.base = "https://" + host
        self._write_request("owner.http", "owner-session", "B")
        self._write_request("actor.http", "actor-session", "A")
        data = json.loads(self.case_file.read_text(encoding="utf-8"))
        data["base_url"] = self.base
        self.case_file.write_text(json.dumps(data), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "restricted to localhost"):
            self.tester.validate(self.case_file, AccessRangeOptions("1-2", 4, min_interval=10))

        public_tester = AccessWriteRangeTester(self.scope, self.client, allow_public_writes=True)
        with self.assertRaisesRegex(ValueError, "allow-public-range"):
            public_tester.validate(self.case_file,
                                   AccessRangeOptions("1-2", 4, max_range=2, concurrency=2, min_interval=1))
        options = AccessRangeOptions("1-3", 5, max_range=100, concurrency=4,
                                     min_interval=1, allow_public_range=True)
        _, requests = public_tester.validate(self.case_file, options)
        self.assertEqual(len(requests), 3)
        self.client.send.assert_not_called()


if __name__ == "__main__":
    unittest.main()
