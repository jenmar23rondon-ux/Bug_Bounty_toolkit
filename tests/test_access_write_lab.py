import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock

from bugbounty_toolkit.access_control.comparison import AccessControlTester
from bugbounty_toolkit.access_control.write_lab import AccessWriteLabTester
from bugbounty_toolkit.core.http_client import RequestSpec, ResponseRecord
from bugbounty_toolkit.core.scope_validator import ScopeValidator


class AccessWriteLabTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.base = "http://127.0.0.1:3000"
        self.host = "127.0.0.1:3000"
        (self.root / "scope.txt").write_text("127.0.0.1\n", encoding="utf-8")
        self._write_request("owner.http", "owner-session", "B")
        self._write_request("actor.http", "actor-session", "A")
        self.case_file = self.root / "case.json"
        self.case_file.write_text(json.dumps({
            "owner_request": "owner.http", "actor_request": "actor.http", "base_url": self.base,
            "session_headers": ["Authorization"], "resource": {"json_body_pointer": "/mutation/item/id"},
            "accounts_authorized": True, "resource_private": True, "expected_cross_access": "deny",
            "disposable_test_resources": True,
            "checks": {"success_pointer": "/success", "success_value": True,
                       "resource_pointer": "/data/id", "owner_resource": "B", "actor_resource": "A",
                       "private_pointer": "/data/proof", "owner_marker": "owner-proof-123456",
                       "actor_marker": "actor-proof-654321"},
        }), encoding="utf-8")
        self.scope = ScopeValidator(self.root / "scope.txt")
        self.client = Mock()
        self.tester = AccessWriteLabTester(self.scope, self.client)

    def tearDown(self):
        self.temp.cleanup()

    def _write_request(self, name, token, resource_id, method="PATCH", title="same"):
        body = json.dumps({"mutation": {"item": {"id": resource_id, "title": title}, "flags": [1, 2]},
                           "metadata": {"keep": True}})
        raw = (f"{method} /api/items/update HTTP/1.1\r\nHost: {self.host}\r\n"
               f"Authorization: Bearer {token}\r\nContent-Type: application/json; charset=utf-8\r\n\r\n{body}")
        (self.root / name).write_text(raw, encoding="utf-8", newline="")

    @staticmethod
    def _response(request, resource_id, proof):
        body = json.dumps({"success": True, "data": {"id": resource_id, "proof": proof}})
        return ResponseRecord(request, request.prepared_url(), 200, "OK", 1,
                              {"content-type": "application/json"}, body, len(body), False)

    def test_cross_rebuilds_nested_json_and_preserves_actor_context(self):
        for method in ("POST", "PUT", "PATCH"):
            with self.subTest(method=method):
                self._write_request("owner.http", "owner-session", "B", method=method)
                self._write_request("actor.http", "actor-session", "A", method=method)
                case = self.tester.validate(self.case_file)
                self.assertEqual(case.mode, "lab-write")
                self.assertEqual(case.owner.method, method)
                self.assertEqual(case.actor.method, method)
                self.assertEqual(case.cross.headers["Authorization"], "Bearer actor-session")
                body = json.loads(case.cross.body)
                self.assertEqual(body, {"mutation": {"item": {"id": "B", "title": "same"}, "flags": [1, 2]},
                                        "metadata": {"keep": True}})
                self.assertEqual(json.loads(case.actor.body)["mutation"]["item"]["id"], "A")
        self.client.send.assert_not_called()

    def test_only_loopback_lab_writes_are_executable_and_a_b_is_compared(self):
        def send(request):
            body_id = json.loads(request.body)["mutation"]["item"]["id"]
            token = request.headers["Authorization"]
            is_owner = token == "Bearer owner-session"
            resource_id = "B" if is_owner or body_id == "B" else "A"
            proof = "owner-proof-123456" if resource_id == "B" else "actor-proof-654321"
            return self._response(request, resource_id, proof)

        self.client.send.side_effect = send
        path, result = self.tester.run(self.case_file, self.root / "evidence")
        self.assertEqual(result["mode"], "lab-write")
        self.assertEqual(result["classification"], "candidate")
        self.assertEqual(result["requests_attempted"], 3)
        self.assertTrue(result["controls_valid"])
        self.assertEqual(result["steps"][-1]["step"], "cross_write")
        self.assertEqual(self.client.send.call_args_list[2].args[0].method, "PATCH")
        self.assertEqual(json.loads(self.client.send.call_args_list[2].args[0].body)["mutation"]["item"]["id"], "B")
        self.assertTrue(path.is_file())

    def test_write_controls_accept_successful_created_responses(self):
        def send(request):
            body_id = json.loads(request.body)["mutation"]["item"]["id"]
            token = request.headers["Authorization"]
            resource_id = "B" if token == "Bearer owner-session" or body_id == "B" else "A"
            proof = "owner-proof-123456" if resource_id == "B" else "actor-proof-654321"
            response = self._response(request, resource_id, proof)
            response.status_code = 201
            return response

        self.client.send.side_effect = send
        _, result = self.tester.run(self.case_file, self.root / "created-evidence")
        self.assertTrue(result["controls_valid"])
        self.assertEqual(result["classification"], "candidate")

    def test_regular_access_checker_still_rejects_writes(self):
        with self.assertRaisesRegex(ValueError, "local lab mode"):
            AccessControlTester(self.scope, self.client).validate(self.case_file)
        self.client.send.assert_not_called()

    def test_external_host_is_rejected_before_any_request(self):
        host = "authorized.example"
        (self.root / "scope.txt").write_text(host + "\n", encoding="utf-8")
        self.base = "https://authorized.example"
        self.host = host
        self._write_request("owner.http", "owner-session", "B")
        self._write_request("actor.http", "actor-session", "A")
        data = json.loads(self.case_file.read_text(encoding="utf-8"))
        data["base_url"] = self.base
        self.case_file.write_text(json.dumps(data), encoding="utf-8")
        tester = AccessWriteLabTester(ScopeValidator(self.root / "scope.txt"), self.client)
        with self.assertRaisesRegex(ValueError, "restricted to localhost"):
            tester.validate(self.case_file)
        self.client.send.assert_not_called()

    def test_write_requires_disposable_resources_and_only_changes_declared_pointer(self):
        data = json.loads(self.case_file.read_text(encoding="utf-8"))
        data["disposable_test_resources"] = False
        self.case_file.write_text(json.dumps(data), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "disposable lab resources"):
            self.tester.validate(self.case_file)

        self.case_file.write_text(json.dumps({**data, "disposable_test_resources": True}), encoding="utf-8")
        self._write_request("actor.http", "actor-session", "A", title="changed")
        with self.assertRaisesRegex(ValueError, "differ only at the declared JSON body resource pointer"):
            self.tester.validate(self.case_file)
        self.client.send.assert_not_called()


if __name__ == "__main__":
    unittest.main()
