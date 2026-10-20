import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock

from bugbounty_toolkit.access_control.comparison import AccessControlTester
from bugbounty_toolkit.access_control.write_lab import AccessWriteLabTester
from bugbounty_toolkit.core.http_client import ResponseRecord
from bugbounty_toolkit.core.scope_validator import ScopeValidator
from bugbounty_toolkit.utils.exceptions import ToolkitError


class AccessWriteLabTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.base = "http://127.0.0.1:3000"
        self.host = "127.0.0.1:3000"
        (self.root / "scope.txt").write_text("127.0.0.1\n", encoding="utf-8")
        self._write_request("owner.http", "owner-session", "B")
        self._write_request("actor.http", "actor-session", "A")
        self._write_readback("cleanup-owner.http", "owner-session", "B")
        self._write_readback("cleanup-actor.http", "actor-session", "A")
        self.case_file = self.root / "case.json"
        self.case_file.write_text(
            json.dumps(
                {
                    "owner_request": "owner.http",
                    "actor_request": "actor.http",
                    "base_url": self.base,
                    "session_headers": ["Authorization"],
                    "resource": {"json_body_pointer": "/mutation/item/id"},
                    "accounts_authorized": True,
                    "resource_private": True,
                    "expected_cross_access": "deny",
                    "disposable_test_resources": True,
                    "checks": {
                        "success_pointer": "/success",
                        "success_value": True,
                        "resource_pointer": "/data/id",
                        "owner_resource": "B",
                        "actor_resource": "A",
                        "private_pointer": "/data/proof",
                        "owner_marker": "owner-proof-123456",
                        "actor_marker": "actor-proof-654321",
                    },
                }
            ),
            encoding="utf-8",
        )
        self.scope = ScopeValidator(self.root / "scope.txt")
        self.client = Mock()
        self.tester = AccessWriteLabTester(self.scope, self.client)

    def tearDown(self):
        self.temp.cleanup()

    def _write_request(self, name, token, resource_id, method="PATCH", title="same"):
        body = json.dumps(
            {"mutation": {"item": {"id": resource_id, "title": title}, "flags": [1, 2]}, "metadata": {"keep": True}}
        )
        raw = (
            f"{method} /api/items/update HTTP/1.1\r\nHost: {self.host}\r\n"
            f"Authorization: Bearer {token}\r\nContent-Type: application/json; charset=utf-8\r\n\r\n{body}"
        )
        (self.root / name).write_text(raw, encoding="utf-8", newline="")

    def _write_readback(self, name, token, resource_id):
        (self.root / name).write_text(
            f"GET /api/items/{resource_id} HTTP/1.1\r\nHost: {self.host}\r\nAuthorization: Bearer {token}\r\n\r\n",
            encoding="utf-8",
            newline="",
        )

    def _enable_cleanup(self, include_actor=True):
        data = json.loads(self.case_file.read_text(encoding="utf-8"))
        data["cleanup_check"] = {
            "owner_request": "cleanup-owner.http",
            "body_pointer": "/mutation/item/title",
            "response_pointer": "/data/title",
        }
        if include_actor:
            data["cleanup_check"]["actor_request"] = "cleanup-actor.http"
        self.case_file.write_text(json.dumps(data), encoding="utf-8")

    @staticmethod
    def _response(request, resource_id, proof, title="same"):
        body = json.dumps({"success": True, "data": {"id": resource_id, "proof": proof, "title": title}})
        return ResponseRecord(
            request, request.prepared_url(), 200, "OK", 1, {"content-type": "application/json"}, body, len(body), False
        )

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
                self.assertEqual(
                    body,
                    {"mutation": {"item": {"id": "B", "title": "same"}, "flags": [1, 2]}, "metadata": {"keep": True}},
                )
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
        self.assertNotIn("cleanup_status", result)
        self.assertNotIn("cleanup_verified", result)
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

    def test_persistence_verification_requires_and_confirms_changed_value(self):
        self._write_request("owner.http", "owner-session", "B", title="original")
        self._write_request("actor.http", "actor-session", "A", title="original")
        (self.root / "readback.http").write_text(
            f"GET /api/items/B HTTP/1.1\r\nHost: {self.host}\r\nAuthorization: Bearer owner-session\r\n\r\n",
            encoding="utf-8",
            newline="",
        )
        data = json.loads(self.case_file.read_text(encoding="utf-8"))
        data["persistence_check"] = {
            "request": "readback.http",
            "body_pointer": "/mutation/item/title",
            "response_pointer": "/data/title",
            "value": "changed",
        }
        self.case_file.write_text(json.dumps(data), encoding="utf-8")

        def send(request):
            if request.method == "GET":
                body = json.dumps(
                    {"success": True, "data": {"id": "B", "proof": "owner-proof-123456", "title": "changed"}}
                )
                return ResponseRecord(
                    request,
                    request.prepared_url(),
                    200,
                    "OK",
                    1,
                    {"content-type": "application/json"},
                    body,
                    len(body),
                    False,
                )
            body_id = json.loads(request.body)["mutation"]["item"]["id"]
            token = request.headers["Authorization"]
            resource_id = "B" if token == "Bearer owner-session" or body_id == "B" else "A"
            proof = "owner-proof-123456" if resource_id == "B" else "actor-proof-654321"
            return self._response(request, resource_id, proof)

        self.client.send.side_effect = send
        _, result = self.tester.run(self.case_file, self.root / "persisted", max_tests=4, verify_persistence=True)
        self.assertEqual(result["requests_attempted"], 4)
        self.assertEqual(result["classification"], "write_confirmed_persisted")
        self.assertTrue(result["write_effect_verified"])
        self.assertEqual(self.client.send.call_args_list[-1].args[0].method, "GET")

    def test_inverse_write_and_cleanup_restore_both_disposable_resources(self):
        self._enable_cleanup()

        def send(request):
            resource_id = (
                request.prepared_url().rsplit("/", 1)[-1]
                if request.method == "GET"
                else json.loads(request.body)["mutation"]["item"]["id"]
            )
            proof = "owner-proof-123456" if resource_id == "B" else "actor-proof-654321"
            return self._response(request, resource_id, proof)

        self.client.send.side_effect = send
        _, result = self.tester.run(
            self.case_file, self.root / "inverse-cleanup", max_tests=8, inverse_write=True, cleanup=True
        )
        self.assertEqual(result["requests_attempted"], 8)
        self.assertEqual(result["inverse_result"], "candidate")
        self.assertTrue(result["inverse_sent"])
        self.assertTrue(result["bidirectional_write_candidate"])
        self.assertTrue(result["cleanup_success"])
        self.assertEqual(result["cleanup_status"], "cleanup_confirmed")
        self.assertEqual([row["resource_owner"] for row in result["cleanup_results"]], ["owner", "actor"])
        cleanup_requests = self.client.send.call_args_list[-4:]
        self.assertEqual([call.args[0].method for call in cleanup_requests], ["PATCH", "GET", "PATCH", "GET"])
        self.assertEqual(
            [call.args[0].headers["Authorization"] for call in cleanup_requests],
            ["Bearer owner-session", "Bearer owner-session", "Bearer actor-session", "Bearer actor-session"],
        )
        self.assertEqual(
            [json.loads(cleanup_requests[index].args[0].body)["mutation"]["item"]["id"] for index in (0, 2)],
            ["B", "A"],
        )

    def test_cleanup_adds_restore_write_and_final_get(self):
        self._enable_cleanup(include_actor=False)

        def send(request):
            if request.method == "GET":
                resource_id = "B"
            else:
                resource_id = json.loads(request.body)["mutation"]["item"]["id"]
            proof = "owner-proof-123456" if resource_id == "B" else "actor-proof-654321"
            return self._response(request, resource_id, proof)

        self.client.send.side_effect = send
        evidence, result = self.tester.run(self.case_file, self.root / "cleanup-only", max_tests=5, cleanup=True)
        self.assertEqual(result["requests_attempted"], 5)
        self.assertTrue(result["cleanup_success"])
        self.assertEqual(result["cleanup_status"], "cleanup_confirmed")
        self.assertTrue(result["cleanup_verified"])
        saved = json.loads(evidence.read_text(encoding="utf-8"))
        self.assertEqual(saved["cleanup_status"], "cleanup_confirmed")
        self.assertTrue(saved["cleanup_verified"])
        self.assertEqual([call.args[0].method for call in self.client.send.call_args_list[-2:]], ["PATCH", "GET"])
        self.assertEqual(result["cleanup_results"][0]["resource_owner"], "owner")

    def test_cleanup_fails_when_final_get_shows_a_different_original_value(self):
        self._enable_cleanup(include_actor=False)

        def send(request):
            if request.method == "GET":
                return self._response(request, "B", "owner-proof-123456", title="not-original")
            resource = json.loads(request.body)["mutation"]["item"]["id"]
            proof = "owner-proof-123456" if resource == "B" else "actor-proof-654321"
            return self._response(request, resource, proof)

        self.client.send.side_effect = send
        _, result = self.tester.run(self.case_file, self.root / "cleanup-mismatch", max_tests=5, cleanup=True)
        self.assertEqual(result["requests_attempted"], 5)
        self.assertEqual(result["cleanup_status"], "cleanup_failed")
        self.assertFalse(result["cleanup_verified"])

    def test_cleanup_is_unconfirmed_when_final_get_fails(self):
        self._enable_cleanup(include_actor=False)
        calls = 0

        def send(request):
            nonlocal calls
            calls += 1
            if request.method == "GET":
                raise ToolkitError("readback timed out")
            resource = json.loads(request.body)["mutation"]["item"]["id"]
            proof = "owner-proof-123456" if resource == "B" else "actor-proof-654321"
            return self._response(request, resource, proof)

        self.client.send.side_effect = send
        _, result = self.tester.run(self.case_file, self.root / "cleanup-unconfirmed", max_tests=5, cleanup=True)
        self.assertEqual(result["requests_attempted"], 5)
        self.assertEqual(result["cleanup_status"], "cleanup_unconfirmed")
        self.assertFalse(result["cleanup_verified"])
        self.assertEqual(calls, 5)

    def test_cleanup_budget_requires_restore_and_final_get(self):
        self._enable_cleanup(include_actor=False)
        with self.assertRaisesRegex(ValueError, "budget of at least 5"):
            self.tester.validate(self.case_file, max_tests=4, cleanup=True)
        self.client.send.assert_not_called()

    def test_cleanup_requires_readback_contract_and_inverse_capture(self):
        with self.assertRaisesRegex(ValueError, "requires cleanup_check"):
            self.tester.validate(self.case_file, max_tests=5, cleanup=True)
        self._enable_cleanup(include_actor=False)
        with self.assertRaisesRegex(ValueError, "requires cleanup_check.actor_request"):
            self.tester.validate(self.case_file, max_tests=8, inverse_write=True, cleanup=True)
        self.client.send.assert_not_called()

    def test_all_write_flags_are_composable_and_budget_is_checked_before_sends(self):
        self._enable_cleanup()
        self._write_request("owner.http", "owner-session", "B", title="original")
        self._write_request("actor.http", "actor-session", "A", title="original")
        (self.root / "readback.http").write_text(
            f"GET /api/items/B HTTP/1.1\r\nHost: {self.host}\r\nAuthorization: Bearer owner-session\r\n\r\n",
            encoding="utf-8",
            newline="",
        )
        data = json.loads(self.case_file.read_text(encoding="utf-8"))
        data["persistence_check"] = {
            "request": "readback.http",
            "body_pointer": "/mutation/item/title",
            "response_pointer": "/data/title",
            "value": "changed",
        }
        self.case_file.write_text(json.dumps(data), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "budget of at least 9"):
            self.tester.validate(self.case_file, 8, True, True, True)
        self.client.send.assert_not_called()

        get_calls = 0

        def send(request):
            nonlocal get_calls
            if request.method == "GET":
                resource = request.prepared_url().rsplit("/", 1)[-1]
                title = "changed" if get_calls == 0 else "original"
                get_calls += 1
                proof = "owner-proof-123456" if resource == "B" else "actor-proof-654321"
                body = json.dumps({"success": True, "data": {"id": resource, "proof": proof, "title": title}})
                return ResponseRecord(
                    request,
                    request.prepared_url(),
                    200,
                    "OK",
                    1,
                    {"content-type": "application/json"},
                    body,
                    len(body),
                    False,
                )
            body_id = json.loads(request.body)["mutation"]["item"]["id"]
            proof = "owner-proof-123456" if body_id == "B" else "actor-proof-654321"
            return self._response(request, body_id, proof)

        self.client.send.side_effect = send
        _, result = self.tester.run(
            self.case_file,
            self.root / "all-flags",
            max_tests=9,
            verify_persistence=True,
            inverse_write=True,
            cleanup=True,
        )
        self.assertEqual(result["requests_attempted"], 9)
        self.assertTrue(result["write_effect_verified"])
        self.assertTrue(result["cleanup_success"])

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

    def test_public_write_opt_in_allows_scoped_crossed_write(self):
        host = "authorized.example"
        (self.root / "scope.txt").write_text(host + "\n", encoding="utf-8")
        self.base = "https://authorized.example"
        self.host = host
        self._write_request("owner.http", "owner-session", "B")
        self._write_request("actor.http", "actor-session", "A")
        data = json.loads(self.case_file.read_text(encoding="utf-8"))
        data["base_url"] = self.base
        self.case_file.write_text(json.dumps(data), encoding="utf-8")
        tester = AccessWriteLabTester(ScopeValidator(self.root / "scope.txt"), self.client, allow_public_writes=True)

        def send(request):
            identifier = json.loads(request.body)["mutation"]["item"]["id"]
            account = request.headers["Authorization"]
            resource_id = "B" if account == "Bearer owner-session" or identifier == "B" else "A"
            proof = "owner-proof-123456" if resource_id == "B" else "actor-proof-654321"
            return self._response(request, resource_id, proof)

        self.client.send.side_effect = send
        case = tester.validate(self.case_file)
        self.assertEqual(case.cross.prepared_url(), "https://authorized.example/api/items/update")
        _, result = tester.run(self.case_file, self.root / "public-write-evidence")
        self.assertEqual(result["requests_attempted"], 3)
        self.assertEqual(result["classification"], "candidate")
        self.assertEqual(self.client.send.call_args_list[2].args[0].headers["Authorization"], "Bearer actor-session")

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

    def test_write_preflight_rejects_invalid_flags_budget_and_read_cases(self):
        with self.assertRaisesRegex(ValueError, "must be a boolean"):
            AccessWriteLabTester(self.scope, self.client, allow_public_writes="yes")
        with self.assertRaisesRegex(ValueError, "flags must be booleans"):
            self.tester.validate(self.case_file, verify_persistence=1)
        with self.assertRaisesRegex(ValueError, "budget of at least 3"):
            self.tester.validate(self.case_file, max_tests=2)

        read_data = json.loads(self.case_file.read_text(encoding="utf-8"))
        read_data["resource"] = {"query_parameter": "id"}
        self._write_request("owner.http", "owner-session", "B", method="GET")
        self._write_request("actor.http", "actor-session", "A", method="GET")
        for filename, resource_id, token in (
            ("owner.http", "B", "owner-session"),
            ("actor.http", "A", "actor-session"),
        ):
            (self.root / filename).write_text(
                f"GET /api/items/update?id={resource_id} HTTP/1.1\r\nHost: {self.host}\r\n"
                f"Authorization: Bearer {token}\r\n\r\n",
                encoding="utf-8",
                newline="",
            )
        self.case_file.write_text(json.dumps(read_data), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "JSON body resource pointer"):
            self.tester.validate(self.case_file)
        self.client.send.assert_not_called()

    def test_truncated_and_redirect_responses_stop_write_controls_and_crosses(self):
        for blocked_status, truncated, expected in (
            (200, True, "truncated_response"),
            (302, False, "redirect_not_followed"),
        ):
            calls = 0

            def send(request):
                nonlocal calls
                calls += 1
                response = self._response(request, "B", "owner-proof-123456")
                if calls == 1:
                    response.status_code = blocked_status
                    response.body_truncated = truncated
                return response

            with self.subTest(status=blocked_status, truncated=truncated):
                calls = 0
                self.client.send.side_effect = send
                _, result = self.tester.run(self.case_file, self.root / f"blocked-{blocked_status}")
                self.assertEqual(result["requests_attempted"], 1)
                self.assertEqual(result["stop_reason"], expected)

        calls = 0

        def redirect_cross(request):
            nonlocal calls
            calls += 1
            resource = "B" if request.headers["Authorization"] == "Bearer owner-session" else "A"
            proof = "owner-proof-123456" if resource == "B" else "actor-proof-654321"
            response = self._response(request, resource, proof)
            if calls == 3:
                response.status_code = 302
            return response

        self.client.send.side_effect = redirect_cross
        _, result = self.tester.run(self.case_file, self.root / "redirect-cross")
        self.assertEqual(result["classification"], "inconclusive")
        self.assertEqual(result["stop_reason"], "redirect_not_followed")

    def test_control_transport_and_http_failures_stop_before_cross(self):
        self.client.send.side_effect = ToolkitError("private transport detail")
        _, result = self.tester.run(self.case_file, self.root / "transport-failure")
        self.assertEqual(result["requests_attempted"], 1)
        self.assertEqual(result["stop_reason"], "transport_error")
        self.assertFalse(result["controls_valid"])
        self.assertNotIn("private transport detail", json.dumps(result))

        def limited(request):
            response = self._response(request, "B", "owner-proof-123456")
            response.status_code = 429
            return response

        self.client.send.side_effect = limited
        self._enable_cleanup(include_actor=False)
        _, result = self.tester.run(self.case_file, self.root / "limited-control", cleanup=True, max_tests=5)
        self.assertEqual(result["stop_reason"], "rate_limited")
        self.assertEqual(result["requests_attempted"], 1)
        self.assertFalse(result["cleanup_success"])

    def test_invalid_control_and_cross_transport_failure_are_inconclusive(self):
        def invalid_control(request):
            response = self._response(request, "B", "owner-proof-123456")
            response.status_code = 200
            response.body_text = '{"success":false}'
            return response

        self.client.send.side_effect = invalid_control
        _, result = self.tester.run(self.case_file, self.root / "invalid-control")
        self.assertFalse(result["controls_valid"])
        self.assertEqual(result["stop_reason"], "invalid_owner_control")
        self.assertEqual(result["requests_attempted"], 1)

        cross_calls = 0

        def cross_fails(request):
            nonlocal cross_calls
            cross_calls += 1
            if cross_calls == 3:
                raise ToolkitError("cross failed")
            resource = "B" if request.headers["Authorization"] == "Bearer owner-session" else "A"
            proof = "owner-proof-123456" if resource == "B" else "actor-proof-654321"
            return self._response(request, resource, proof)

        self.client.send.side_effect = cross_fails
        _, result = self.tester.run(self.case_file, self.root / "cross-failure")
        self.assertEqual(result["requests_attempted"], 3)
        self.assertEqual(result["classification"], "inconclusive")
        self.assertEqual(result["steps"][-1], {"step": "cross_write", "transport_error": True})

    def test_cleanup_reports_failure_and_rate_limit_without_claiming_restore(self):
        self._enable_cleanup(include_actor=False)
        calls = 0

        def cleanup_fails(request):
            nonlocal calls
            calls += 1
            resource = "B" if request.headers["Authorization"] == "Bearer owner-session" else "A"
            proof = "owner-proof-123456" if resource == "B" else "actor-proof-654321"
            response = self._response(request, resource, proof)
            if calls == 4:
                response.status_code = 500
            return response

        self.client.send.side_effect = cleanup_fails
        _, result = self.tester.run(self.case_file, self.root / "cleanup-failed", cleanup=True, max_tests=5)
        self.assertFalse(result["cleanup_success"])
        self.assertEqual(result["cleanup_status"], "cleanup_failed")
        self.assertEqual(result["cleanup_results"][0]["classification"], "cleanup_failed")

        calls = 0

        def cleanup_limited(request):
            nonlocal calls
            calls += 1
            resource = "B" if request.headers["Authorization"] == "Bearer owner-session" else "A"
            proof = "owner-proof-123456" if resource == "B" else "actor-proof-654321"
            response = self._response(request, resource, proof)
            if calls == 4:
                response.status_code = 429
            return response

        self.client.send.side_effect = cleanup_limited
        _, result = self.tester.run(self.case_file, self.root / "cleanup-limited", cleanup=True, max_tests=5)
        self.assertFalse(result["cleanup_success"])
        self.assertEqual(result["stop_reason"], "rate_limited")
        self.assertEqual(result["cleanup_status"], "cleanup_failed")

    def test_inverse_transport_failure_is_reported_separately(self):
        calls = 0

        def inverse_fails(request):
            nonlocal calls
            calls += 1
            if calls == 4:
                raise ToolkitError("inverse failed")
            resource = "B" if request.headers["Authorization"] == "Bearer owner-session" else "A"
            proof = "owner-proof-123456" if resource == "B" else "actor-proof-654321"
            return self._response(request, resource, proof)

        self.client.send.side_effect = inverse_fails
        _, result = self.tester.run(self.case_file, self.root / "inverse-failure", inverse_write=True, max_tests=4)
        self.assertTrue(result["inverse_sent"])
        self.assertEqual(result["inverse_result"], "inconclusive")
        self.assertEqual(result["stop_reason"], "transport_error")


if __name__ == "__main__":
    unittest.main()
