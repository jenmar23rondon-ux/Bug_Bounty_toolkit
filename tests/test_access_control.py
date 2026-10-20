import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import Mock
from urllib.parse import parse_qs, urlsplit

from bugbounty_toolkit.access_control.comparison import (
    AccessControlTester,
    load_case,
    lookup,
    MISSING,
    parse_json,
    read_local,
    replace_pointer,
)
from bugbounty_toolkit.core.http_client import HttpClient, ResponseRecord
from bugbounty_toolkit.core.rate_limiter import RateLimiter
from bugbounty_toolkit.core.scope_validator import ScopeValidator
from bugbounty_toolkit.utils.exceptions import ToolkitError


MARKERS = {"A": "private-A-marker-3c91", "B": "private-B-marker-5f28", "C": "private-C-marker-9d31"}
TOKENS = {"A": "Bearer laboratory-session-A", "B": "Bearer laboratory-session-B", "C": "Bearer laboratory-session-C"}


class AccessLab(BaseHTTPRequestHandler):
    hits = []
    mode = "protected"

    def do_GET(self):
        self.hits.append(
            {
                "path": self.path,
                "authorization": self.headers.get("Authorization"),
                "owner_header": self.headers.get("X-Owner-Only"),
                "encoding": self.headers.get("Accept-Encoding"),
                "at": time.monotonic(),
            }
        )
        parsed = urlsplit(self.path)
        resource = parse_qs(parsed.query).get("id", [parsed.path.split("/")[-1]])[0]
        viewer = next((name for name, value in TOKENS.items() if self.headers.get("Authorization") == value), None)
        status = 200
        body = {"success": True, "data": {"id": resource, "proof": MARKERS.get(resource)}}
        if viewer == "A" and self.mode == "invalid_actor":
            status, body = 401, {"success": False}
        elif resource == "B" and viewer == "B" and self.mode == "invalid_owner":
            body = {"success": False, "error_code": 90003}
        elif viewer != resource:
            if (
                self.mode == "vulnerable"
                or (self.mode == "inverse_candidate" and viewer == "B" and resource == "A")
                or (self.mode == "anonymous_leak" and viewer is None)
            ):
                pass
            elif self.mode == "protected" or self.mode in {"inverse_candidate", "anonymous_leak"}:
                status, body = 403, {"success": False}
            elif self.mode == "soft_deny":
                body = {"success": False, "error_code": 80002}
            elif self.mode == "leak_on_error":
                status, body["success"] = 403, False
            elif self.mode == "partial":
                body = {"success": True, "other": MARKERS["B"]}
            elif self.mode == "wrong_shape":
                body = {"success": "true", "public": "no proof"}
            elif self.mode == "redirect":
                status, body = 302, {}
            elif self.mode == "limited":
                status, body = 429, {}
            else:
                status, body = 403, {"success": False}
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        if status == 302:
            self.send_header("Location", "https://outside.invalid/do-not-follow")
        self.end_headers()
        self.wfile.write(json.dumps(body).encode())

    def log_message(self, *args):
        pass


class AccessControlTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), AccessLab)
        cls.worker = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.worker.start()
        cls.base = f"http://127.0.0.1:{cls.server.server_port}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.worker.join()
        cls.server.server_close()

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.scope_file = self.root / "scope.txt"
        self.scope_file.write_text(self.base + "\n")
        self.scope = ScopeValidator(self.scope_file)
        self.client = HttpClient(self.scope, rate_limiter=RateLimiter(10000))
        self.tester = AccessControlTester(self.scope, self.client)
        host = urlsplit(self.base).netloc
        for account, file in (("B", "owner.http"), ("A", "actor.http")):
            extra = "X-Owner-Only: owner-context\r\n" if account == "B" else "X-Actor-Only: actor-context\r\n"
            (self.root / file).write_text(
                f"GET /objects/{account} HTTP/1.1\r\nHost: {host}\r\nAuthorization: {TOKENS[account]}\r\n{extra}\r\n",
                encoding="utf-8",
                newline="",
            )
        self.data = {
            "owner_request": "owner.http",
            "actor_request": "actor.http",
            "base_url": self.base,
            "session_headers": ["Authorization"],
            "resource": {"path_segment": 1},
            "accounts_authorized": True,
            "resource_private": True,
            "expected_cross_access": "deny",
            "checks": {
                "success_pointer": "/success",
                "success_value": True,
                "resource_pointer": "/data/id",
                "owner_resource": "B",
                "actor_resource": "A",
                "private_pointer": "/data/proof",
                "owner_marker": MARKERS["B"],
                "actor_marker": MARKERS["A"],
            },
        }
        self.case = self.root / "case.private.json"
        self.save_case()
        AccessLab.hits.clear()
        AccessLab.mode = "protected"

    def tearDown(self):
        self.temp.cleanup()

    def save_case(self):
        self.case.write_text(json.dumps(self.data), encoding="utf-8")

    def run_case(self):
        return self.tester.run(self.case, self.root / "evidence")

    def mock_tester(self, mode="protected"):
        client = Mock()

        def send(request):
            resource = urlsplit(request.prepared_url()).path.split("/")[-1]
            viewer = next(
                (name for name, token in TOKENS.items() if request.headers.get("Authorization") == token), None
            )
            allowed = viewer == resource or mode == "vulnerable"
            if mode == "inverse_candidate" and viewer == "B" and resource == "A":
                allowed = True
            if mode == "anonymous_leak" and viewer is None:
                allowed = True
            status = 200 if allowed else 403
            if mode == "public_endpoint" and viewer != resource:
                status = 200
                body = {"success": True, "data": {"id": resource, "public": True}}
            else:
                body = (
                    {"success": True, "data": {"id": resource, "proof": MARKERS[resource]}}
                    if allowed
                    else {"success": False}
                )
            encoded = json.dumps(body)
            return ResponseRecord(
                request,
                request.prepared_url(),
                status,
                "OK",
                1,
                {"content-type": "application/json"},
                encoded,
                len(encoded),
                False,
            )

        client.send.side_effect = send
        return AccessControlTester(self.scope, client), client

    def test_native_cross_uses_actor_context_and_exposes_only_predicates(self):
        AccessLab.mode = "vulnerable"
        path, result = self.run_case()
        self.assertEqual(result["classification"], "candidate")
        self.assertTrue(result["controls_valid"])
        self.assertFalse(result["confirmed"])
        self.assertFalse(result["inverse_sent"])
        self.assertFalse(result["anonymous_sent"])
        self.assertEqual([hit["path"] for hit in AccessLab.hits], ["/objects/B", "/objects/A", "/objects/B"])
        self.assertEqual([hit["authorization"] for hit in AccessLab.hits], [TOKENS["B"], TOKENS["A"], TOKENS["A"]])
        self.assertIsNone(AccessLab.hits[-1]["owner_header"])
        self.assertTrue(all(hit["encoding"] == "identity" for hit in AccessLab.hits))
        serialized = path.read_text()
        for private in (*TOKENS.values(), *MARKERS.values(), "/objects/B", "owner-context"):
            self.assertNotIn(private, serialized)

    def test_anonymous_check_sends_one_cross_without_session_headers(self):
        tester, client = self.mock_tester("anonymous_leak")
        _, result = tester.run(self.case, self.root / "anonymous", max_tests=4, anonymous_check=True)
        self.assertEqual(result["requests_attempted"], 4)
        self.assertEqual(result["classification"], "anonymous_access")
        self.assertEqual(result["anonymous_classification"], "anonymous_access")
        self.assertTrue(result["anonymous_sent"])
        self.assertTrue(result["anonymous_finding"])
        self.assertTrue(result["anonymous_expectation_mismatch"])
        last_request = client.send.call_args_list[-1].args[0]
        self.assertEqual(urlsplit(last_request.prepared_url()).path, "/objects/B")
        self.assertNotIn("Authorization", last_request.headers)

    def test_public_resource_anonymous_result_is_informational_not_idor(self):
        self.data["resource_private"] = False
        self.data["expected_anonymous"] = "allow"
        self.save_case()
        tester, _ = self.mock_tester("public_endpoint")
        _, result = tester.run(self.case, self.root / "public-anonymous", max_tests=4, anonymous_check=True)
        self.assertEqual(result["classification"], "public_endpoint")
        self.assertEqual(result["cross_result"], "public_endpoint")
        self.assertEqual(result["anonymous_classification"], "public_endpoint")
        self.assertFalse(result["anonymous_access_observed"])
        self.assertTrue(result["anonymous_request_allowed"])
        self.assertFalse(result["anonymous_finding"])
        self.assertFalse(result["anonymous_expectation_mismatch"])

        self.data["expected_anonymous"] = "deny"
        self.save_case()
        tester, _ = self.mock_tester("public_endpoint")
        _, mismatch = tester.run(self.case, self.root / "public-anonymous-mismatch", max_tests=4, anonymous_check=True)
        self.assertEqual(mismatch["anonymous_classification"], "public_endpoint")
        self.assertTrue(mismatch["anonymous_request_allowed"])
        self.assertTrue(mismatch["anonymous_expectation_mismatch"])
        self.assertTrue(mismatch["anonymous_finding"])

    def test_anonymous_expectation_mismatch_is_reported_separately(self):
        self.data["expected_anonymous"] = "allow"
        self.save_case()
        tester, _ = self.mock_tester("protected")
        _, result = tester.run(self.case, self.root / "anonymous-mismatch", max_tests=4, anonymous_check=True)
        self.assertEqual(result["anonymous_classification"], "anonymous_expectation_mismatch")
        self.assertEqual(result["classification"], "anonymous_expectation_mismatch")
        self.assertTrue(result["anonymous_finding"])
        self.assertTrue(result["anonymous_expectation_mismatch"])

    def test_inverse_cross_is_one_extra_request_and_reports_each_direction(self):
        tester, client = self.mock_tester("inverse_candidate")
        _, result = tester.run(self.case, self.root / "inverse", max_tests=4, inverse_cross=True)
        self.assertEqual(result["requests_attempted"], 4)
        self.assertEqual(result["cross_result"], "rejected_in_this_test")
        self.assertEqual(result["inverse_result"], "candidate")
        self.assertTrue(result["inverse_sent"])
        self.assertFalse(result["bidirectional_access"])
        last_request = client.send.call_args_list[-1].args[0]
        self.assertEqual(urlsplit(last_request.prepared_url()).path, "/objects/A")
        self.assertEqual(last_request.headers["Authorization"], TOKENS["B"])

    def test_multi_account_builds_complete_matrix_with_controls_on_diagonal(self):
        host = urlsplit(self.base).netloc
        (self.root / "third.http").write_text(
            f"GET /objects/C HTTP/1.1\r\nHost: {host}\r\nAuthorization: {TOKENS['C']}\r\n\r\n",
            encoding="utf-8",
            newline="",
        )
        self.data["additional_accounts"] = {
            "actor2": {"request": "third.http", "resource": "C", "marker": MARKERS["C"]}
        }
        self.save_case()
        tester, _ = self.mock_tester("vulnerable")
        with self.assertRaisesRegex(ValueError, "budget of at least 9"):
            tester.validate(self.case, 8, multi_account=True)
        path, result = tester.run(self.case, self.root / "matrix", max_tests=9, multi_account=True)
        self.assertEqual(result["requests_attempted"], 9)
        self.assertEqual(result["request_budget"], 9)
        self.assertEqual(result["classification"], "candidate")
        self.assertEqual(len(result["matrix"]), 9)
        self.assertEqual(result["matrix_crosses"], 6)
        self.assertEqual(sum(cell["access_type"] == "control" for cell in result["matrix"]), 3)
        self.assertTrue(
            all(cell["classification"] == "candidate" for cell in result["matrix"] if cell["access_type"] == "cross")
        )
        self.assertFalse(
            any(
                cell["access_type"] == "cross" and cell["session_account"] == cell["resource_owner"]
                for cell in result["matrix"]
            )
        )
        for private in (*TOKENS.values(), *MARKERS.values(), "/objects/C"):
            self.assertNotIn(private, path.read_text(encoding="utf-8"))

    def test_denial_and_http200_api_failure_are_not_confirmation(self):
        for mode, code in (("protected", 403), ("soft_deny", 200)):
            with self.subTest(mode=mode):
                AccessLab.mode = mode
                _, result = self.run_case()
                self.assertEqual(result["classification"], "rejected_in_this_test")
                self.assertEqual(result["steps"][-1]["status_code"], code)
                self.assertEqual(result["requests_attempted"], 3)
                self.assertFalse(result["confirmed"])

    def test_private_leak_is_not_hidden_by_error_status(self):
        AccessLab.mode = "leak_on_error"
        _, result = self.run_case()
        self.assertEqual(result["classification"], "candidate")
        self.assertFalse(result["steps"][-1]["application_success"])

    def test_invalid_controls_stop_before_cross(self):
        for mode, count in (("invalid_owner", 1), ("invalid_actor", 2)):
            with self.subTest(mode=mode):
                AccessLab.hits.clear()
                AccessLab.mode = mode
                _, result = self.run_case()
                self.assertEqual(len(AccessLab.hits), count)
                self.assertFalse(result["controls_valid"])
                self.assertEqual(result["classification"], "inconclusive")

    def test_partial_evidence_unknown_shape_redirect_and_rate_limit_stop(self):
        for mode in ("partial", "wrong_shape", "redirect", "limited"):
            with self.subTest(mode=mode):
                AccessLab.hits.clear()
                AccessLab.mode = mode
                _, result = self.run_case()
                self.assertEqual(result["classification"], "inconclusive")
                self.assertEqual(len(AccessLab.hits), 3)

    def test_truncation_and_transport_failure_do_not_retry(self):
        self.client.max_response_bytes = 10
        _, result = self.run_case()
        self.assertEqual(result["stop_reason"], "truncated_response")
        self.assertEqual(len(AccessLab.hits), 1)
        broken = Mock()
        broken.send.side_effect = ToolkitError("not echoed credential")
        _, result = AccessControlTester(self.scope, broken).run(self.case, self.root / "errors")
        self.assertEqual(result["requests_attempted"], 1)
        self.assertEqual(result["stop_reason"], "transport_error")
        broken.send.assert_called_once()
        self.assertNotIn("not echoed credential", json.dumps(result))

    def test_preflight_scope_budget_and_case_contract_send_nothing(self):
        with self.assertRaises(ValueError):
            self.tester.validate(self.case, 2)
        self.scope_file.write_text(self.base + "\n!" + self.base + "/objects/A\n")
        with self.assertRaises(ValueError):
            self.run_case()
        self.scope_file.write_text(self.base + "\n")
        original = copy.deepcopy(self.data)
        for key, value in (
            ("accounts_authorized", False),
            ("session_headers", ["Authorization", "Cookie"]),
            ("resource", {"path_segment": True}),
            ("extra_command", "do not execute"),
        ):
            with self.subTest(field=key):
                self.data = copy.deepcopy(original)
                self.data[key] = value
                self.save_case()
                with self.assertRaises(ValueError):
                    self.run_case()
        self.assertEqual(AccessLab.hits, [])

    def test_query_resource_validation_and_duplicate_session_queries(self):
        self.data["resource"] = {"query_parameter": "id"}
        host = urlsplit(self.base).netloc
        for account, file in (("B", "owner.http"), ("A", "actor.http")):
            (self.root / file).write_text(
                f"GET /objects?id={account}&page=1 HTTP/1.1\nHost: {host}\nAuthorization: {TOKENS[account]}\n\n"
            )
        self.save_case()
        AccessLab.mode = "vulnerable"
        _, result = self.run_case()
        self.assertEqual(result["classification"], "candidate")
        for query in ("id=B&id=B&page=1", "id=B&page=2", "id=B&token=private"):
            AccessLab.hits.clear()
            (self.root / "owner.http").write_text(
                f"GET /objects?{query} HTTP/1.1\nHost: {host}\nAuthorization: {TOKENS['B']}\n\n"
            )
            with self.assertRaises(ValueError):
                self.run_case()
            self.assertEqual(AccessLab.hits, [])

    def test_same_session_host_override_and_write_request_are_rejected(self):
        actor = self.root / "actor.http"
        original = actor.read_text()
        for changed in (
            original.replace(TOKENS["A"], TOKENS["B"]),
            original.replace("GET ", "POST "),
            original.replace(urlsplit(self.base).netloc, "other.invalid"),
        ):
            actor.write_text(changed)
            with self.assertRaises(ValueError):
                self.run_case()
        self.assertEqual(AccessLab.hits, [])

    def test_absolute_target_does_not_hide_conflicting_host(self):
        actor = self.root / "actor.http"
        actor.write_text(
            f"GET {self.base}/objects/A HTTP/1.1\nHost: wrong-host.invalid\nAuthorization: {TOKENS['A']}\n\n"
        )
        with self.assertRaisesRegex(ValueError, "Host conflicts"):
            self.run_case()
        self.assertEqual(AccessLab.hits, [])

    def test_three_requests_share_the_same_limiter(self):
        self.client.rate_limiter = RateLimiter(20)
        self.run_case()
        times = [hit["at"] for hit in AccessLab.hits]
        self.assertEqual(len(times), 3)
        self.assertTrue(all(later - earlier >= 0.035 for earlier, later in zip(times, times[1:])))

    def test_json_pointer_escapes_lists_missing_and_type_safe_predicates(self):
        self.assertEqual(lookup({"a/b": {"~": ["value"]}}, "/a~1b/~0/0"), "value")
        self.assertIs(lookup({"list": []}, "/list/0"), MISSING)
        with self.assertRaises(ValueError):
            lookup({}, "/bad~2pointer")
        with self.assertRaisesRegex(ValueError, "pointer does not exist"):
            replace_pointer({"items": []}, "/items/0/id", "x")
        with self.assertRaisesRegex(ValueError, "pointer does not exist"):
            replace_pointer({"items": []}, "/items/0", "x")
        self.assertEqual(replace_pointer({"items": [{"id": "old"}]}, "/items/0/id", "new"), {"items": [{"id": "new"}]})

    def test_case_validation_rejects_malformed_multi_account_profiles(self):
        host = urlsplit(self.base).netloc
        (self.root / "third.http").write_text(
            f"GET /objects/C HTTP/1.1\r\nHost: {host}\r\nAuthorization: {TOKENS['C']}\r\n\r\n",
            encoding="utf-8",
            newline="",
        )
        cases = [
            (
                "additional_accounts",
                {"actor2": {"request": "third.http", "resource": "C", "marker": MARKERS["C"]}},
                False,
                False,
            ),
            (
                "additional_accounts",
                {"bad label": {"request": "third.http", "resource": "C", "marker": MARKERS["C"]}},
                True,
                False,
            ),
            ("additional_accounts", {"actor2": {"request": "", "resource": "C", "marker": MARKERS["C"]}}, True, False),
            (
                "additional_accounts",
                {
                    f"actor{i}": {"request": "third.http", "resource": str(i), "marker": f"marker_{i}_private"}
                    for i in range(9)
                },
                True,
                False,
            ),
        ]
        original = copy.deepcopy(self.data)
        for field, value, allow_multi, allow_write in cases:
            with self.subTest(value=value):
                self.data = copy.deepcopy(original)
                self.data[field] = value
                self.save_case()
                with self.assertRaises(ValueError):
                    load_case(self.case, self.scope, allow_lab_writes=allow_write, allow_multi_accounts=allow_multi)

        self.data = copy.deepcopy(original)
        self.save_case()
        with self.assertRaisesRegex(ValueError, "requires at least one additional"):
            load_case(self.case, self.scope, allow_multi_accounts=True)

        self.data["additional_accounts"] = {
            "actor2": {"request": "third.http", "resource": "C", "marker": MARKERS["C"]}
        }
        self.save_case()
        with self.assertRaisesRegex(ValueError, "read-mode --multi-account"):
            load_case(self.case, self.scope, allow_multi_accounts=True, allow_lab_writes=True)

        self.data = copy.deepcopy(original)
        self.data["base_url"] = self.base + "/path"
        self.save_case()
        with self.assertRaisesRegex(ValueError, "without a path"):
            load_case(self.case, self.scope)
        self.assertEqual(AccessLab.hits, [])

    def test_case_validation_rejects_invalid_resources_sessions_and_checks(self):
        original = copy.deepcopy(self.data)
        invalid_updates = (
            {"resource": {"other": "id"}},
            {"resource": {"path_segment": 9}},
            {"session_headers": ["Authorization", "authorization"]},
            {"session_headers": ["Host"]},
            {"checks": {"success_pointer": "/success"}},
            {"checks": {**original["checks"], "success_pointer": "/data/id"}},
            {"checks": {**original["checks"], "owner_resource": []}},
            {"checks": {**original["checks"], "owner_marker": "short"}},
            {"checks": {**original["checks"], "actor_marker": original["checks"]["owner_marker"]}},
            {"identity_check": {"pointer": "/data/id", "actor_value": ""}},
            {"expected_anonymous": "maybe"},
        )
        for update in invalid_updates:
            with self.subTest(update=update):
                self.data = copy.deepcopy(original)
                self.data.update(update)
                self.save_case()
                with self.assertRaises(ValueError):
                    load_case(self.case, self.scope)
        self.assertEqual(AccessLab.hits, [])

    def test_public_resource_case_requires_explicit_anonymous_check(self):
        self.data["resource_private"] = False
        self.save_case()
        with self.assertRaisesRegex(ValueError, "only for an explicit --anonymous-check"):
            self.tester.validate(self.case)

    def test_case_json_parser_rejects_duplicate_and_excessive_nesting(self):
        with self.assertRaisesRegex(ValueError, "duplicate JSON keys"):
            parse_json('{"a":1,"a":2}')
        with self.assertRaisesRegex(ValueError, "nesting exceeds"):
            parse_json("[" * 10000 + "0" + "]" * 10000)
        self.assertEqual(AccessLab.hits, [])

    def test_case_input_size_limit_is_enforced(self):
        oversized = self.root / "oversized.json"
        oversized.write_bytes(b" " * 1025)
        with self.assertRaisesRegex(ValueError, "size limit"):
            read_local(oversized, 1024)

    def test_duplicate_case_keys_and_unencodable_headers_fail_preflight(self):
        self.case.write_text('{"accounts_authorized":true,"accounts_authorized":false}')
        with self.assertRaises(ValueError):
            self.run_case()
        self.save_case()
        actor = self.root / "actor.http"
        actor.write_text(actor.read_text().replace("actor-context", "actor-context\x00private"))
        with self.assertRaises(ValueError):
            self.run_case()
        self.assertEqual(AccessLab.hits, [])

    def test_malformed_raw_request_does_not_echo_credentials(self):
        actor = self.root / "actor.http"
        actor.write_text(actor.read_text().replace("Authorization: ", "Authorization "))
        with self.assertRaises(ValueError) as failure:
            self.run_case()
        self.assertNotIn("laboratory-session", str(failure.exception))
        self.assertEqual(AccessLab.hits, [])

    def test_cli_dry_run_execution_reports_and_agent_review(self):
        records = self.root / "records"
        config = self.root / "settings.yaml"
        config.write_text("requests_per_second: 30\nmax_tests: 3\n")

        def cli(*args):
            process = subprocess.run(
                [sys.executable, "-m", "bugbounty_toolkit.cli", "--records-root", str(records), *args],
                capture_output=True,
                text=True,
                timeout=30,
                env=os.environ.copy(),
            )
            self.assertEqual(process.returncode, 0, process.stdout + process.stderr)
            return process

        cli(
            "init", "lab", "--authorization", "own isolated laboratory", "--automation-allowed", "--config", str(config)
        )
        cli("scope", "add", "lab", self.base)
        cli("access-check", "lab", "--case-file", str(self.case), "--dry-run")
        self.assertEqual(AccessLab.hits, [])
        cli("access-check", "lab", "--case-file", str(self.case))
        cli("report", "lab", "--format", "json")
        cli("report", "lab", "--format", "html")
        evidence = next((records / "lab" / "evidence" / "access-control").glob("*.json"))
        output = self.root / "review.json"
        cli("analyze", "evidence", "--input", str(evidence), "--output", str(output))
        packet = json.loads(output.read_text())
        self.assertEqual(packet["access_result"], "rejected_in_this_test")
        self.assertFalse(packet["external_model_called"])
        self.assertEqual(len(AccessLab.hits), 3)
