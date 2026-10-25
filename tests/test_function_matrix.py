from __future__ import annotations

import json
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from bugbounty_toolkit import cli
from bugbounty_toolkit.access_control.function_matrix import AccessFunctionMatrixTester, load_function_matrix_case
from bugbounty_toolkit.core.http_client import RequestSpec, ResponseRecord
from bugbounty_toolkit.core.scope_validator import ScopeValidator


MARKER = "admin-export-fixture-7f31"
TOKENS = {"admin": "Bearer admin-test-session", "reader": "Bearer reader-test-session"}


class MatrixClient:
    def __init__(
        self,
        reader_body: dict[str, object],
        reader_status: int = 200,
        admin_body=None,
        admin_status: int = 200,
    ):
        self.reader_body = reader_body
        self.reader_status = reader_status
        self.admin_body = admin_body or {"success": True, "proof": MARKER}
        self.admin_status = admin_status
        self.requests: list[RequestSpec] = []

    def send(self, request: RequestSpec) -> ResponseRecord:
        self.requests.append(request)
        account = next((name for name, token in TOKENS.items() if request.headers.get("Authorization") == token), None)
        body = self.admin_body if account == "admin" else self.reader_body
        status = self.admin_status if account == "admin" else self.reader_status
        encoded = json.dumps(body)
        return ResponseRecord(request, request.prepared_url(), status, "fixture", 1, {}, encoded, len(encoded))


class FunctionMatrixTests(unittest.TestCase):
    def setUp(self) -> None:
        test_tmp = Path(__file__).resolve().parents[1] / ".test-tmp"
        test_tmp.mkdir(exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(dir=test_tmp)
        self.root = Path(self.temp.name)
        self.host = "authorized.example"
        self.base = f"https://{self.host}"
        self.scope_file = self.root / "scope.txt"
        self.scope_file.write_text(self.host + "\n", encoding="utf-8")
        self.scope = ScopeValidator(self.scope_file)
        for name, token in TOKENS.items():
            (self.root / f"{name}.http").write_text(
                f"GET /api/reports/export HTTP/1.1\r\nHost: {self.host}\r\n"
                f"Authorization: {token}\r\nAccept: application/json\r\n\r\n",
                encoding="utf-8",
                newline="",
            )
        self.case_path = self.root / "function-case.json"
        self._write_case()

    def tearDown(self) -> None:
        self.temp.cleanup()

    def _case(self) -> dict[str, object]:
        return {
            "type": "function-access-case",
            "base_url": self.base,
            "accounts_authorized": True,
            "session_headers": ["Authorization"],
            "accounts": {"admin": "admin", "reader": "reader"},
            "functions": [
                {
                    "name": "report_export",
                    "allowed_roles": ["admin"],
                    "requests": {"admin": "admin.http", "reader": "reader.http"},
                    "success_pointer": "/success",
                    "success_value": True,
                    "denial_value": False,
                    "marker_pointer": "/proof",
                    "marker": MARKER,
                    "restricted": True,
                    "read_only_attested": True,
                }
            ],
        }

    def _write_case(self, case: dict[str, object] | None = None) -> None:
        self.case_path.write_text(json.dumps(case or self._case()), encoding="utf-8")

    def test_case_loads_same_endpoint_and_distinct_sessions_offline(self) -> None:
        case = load_function_matrix_case(self.case_path, self.scope)
        self.assertEqual(case.request_count, 2)
        self.assertEqual(case.functions[0].allowed_roles, ("admin",))
        self.assertEqual(
            case.functions[0].accounts[0].request.prepared_url(), case.functions[0].accounts[1].request.prepared_url()
        )

    def test_reader_receiving_private_function_marker_is_candidate_even_on_403(self) -> None:
        client = MatrixClient({"success": True, "proof": MARKER}, reader_status=403)
        evidence_dir = self.root / "evidence"
        path, result = AccessFunctionMatrixTester(self.scope, client).run(self.case_path, evidence_dir, 2)
        self.assertEqual(result["classification"], "possible_bfla")
        self.assertEqual(result["requests_attempted"], 2)
        self.assertFalse(result["confirmed"])
        saved = json.loads(path.read_text(encoding="utf-8"))
        serialized = json.dumps(saved)
        self.assertNotIn("admin-test-session", serialized)
        self.assertNotIn("reader-test-session", serialized)
        self.assertNotIn(MARKER, serialized)

    def test_http_200_alone_does_not_prove_function_access(self) -> None:
        client = MatrixClient({"success": False, "proof": "public"}, reader_status=200)
        _, result = AccessFunctionMatrixTester(self.scope, client).run(self.case_path, self.root / "evidence", 2)
        self.assertEqual(result["classification"], "denied")

    def test_invalid_allowed_role_control_prevents_denied_role_request(self) -> None:
        client = MatrixClient(
            {"success": True, "proof": MARKER},
            admin_body={"success": False, "proof": "wrong"},
        )
        _, result = AccessFunctionMatrixTester(self.scope, client).run(self.case_path, self.root / "evidence", 2)
        self.assertEqual(result["classification"], "insufficient_evidence")
        self.assertEqual(result["requests_attempted"], 1)
        self.assertEqual(len(client.requests), 1)

    def test_rate_limit_on_positive_control_stops_the_function(self) -> None:
        client = MatrixClient({"success": True, "proof": MARKER}, admin_status=429)
        _, result = AccessFunctionMatrixTester(self.scope, client).run(self.case_path, self.root / "evidence", 2)
        self.assertEqual(result["classification"], "insufficient_evidence")
        self.assertEqual(result["stop_reason"], "rate_limited")
        self.assertEqual(result["requests_attempted"], 1)
        self.assertEqual(len(client.requests), 1)

    def test_missing_read_only_attestation_is_rejected(self) -> None:
        case = self._case()
        functions = case["functions"]
        assert isinstance(functions, list) and isinstance(functions[0], dict)
        functions[0]["read_only_attested"] = False
        self._write_case(case)
        with self.assertRaisesRegex(ValueError, "read_only_attested=true"):
            load_function_matrix_case(self.case_path, self.scope)

    def test_identical_sessions_are_rejected(self) -> None:
        (self.root / "reader.http").write_text(
            f"GET /api/reports/export HTTP/1.1\r\nHost: {self.host}\r\nAuthorization: {TOKENS['admin']}\r\n\r\n",
            encoding="utf-8",
            newline="",
        )
        with self.assertRaisesRegex(ValueError, "distinct captured session"):
            load_function_matrix_case(self.case_path, self.scope)

    def test_captures_for_one_function_must_match_endpoint(self) -> None:
        (self.root / "reader.http").write_text(
            f"GET /api/reports/internal HTTP/1.1\r\nHost: {self.host}\r\nAuthorization: {TOKENS['reader']}\r\n\r\n",
            encoding="utf-8",
            newline="",
        )
        with self.assertRaisesRegex(ValueError, "exact same endpoint and query"):
            load_function_matrix_case(self.case_path, self.scope)

    def test_budget_and_method_are_validated_before_network(self) -> None:
        tester = AccessFunctionMatrixTester(self.scope, MatrixClient({"success": False}))
        with self.assertRaisesRegex(ValueError, "requires 2 requests"):
            tester.validate(self.case_path, 1)
        reader_path = self.root / "reader.http"
        reader_path.write_text(
            f"POST /api/reports/export HTTP/1.1\r\nHost: {self.host}\r\nAuthorization: {TOKENS['reader']}\r\n\r\n",
            encoding="utf-8",
            newline="",
        )
        with self.assertRaisesRegex(ValueError, "GET-only"):
            load_function_matrix_case(self.case_path, self.scope)

    def test_http_scheme_is_taken_from_declared_origin_for_raw_burp_capture(self) -> None:
        self._write_case({**self._case(), "base_url": "http://authorized.example"})
        self.assertEqual(load_function_matrix_case(self.case_path, self.scope).base_url, "http://authorized.example/")

    def test_cli_dry_run_validates_without_sending(self) -> None:
        store = SimpleNamespace(paths=SimpleNamespace(evidence_dir=self.root / "records"))
        settings = SimpleNamespace(max_tests=10)
        client = MatrixClient({"success": False})
        args = cli.build_parser().parse_args(
            ["access-check", "lab", "--case-file", str(self.case_path), "--function-matrix", "--dry-run"]
        )
        output = StringIO()
        with (
            patch.object(cli, "executor_context", return_value=(store, settings, self.scope)),
            patch.object(cli, "client_for", return_value=client),
            redirect_stdout(output),
        ):
            cli.cmd_access_check(args)
        self.assertIn("2 GET requests planned", output.getvalue())
        self.assertEqual(client.requests, [])
        self.assertFalse((self.root / "records").exists())

    def test_function_matrix_cannot_be_combined_with_range(self) -> None:
        args = cli.build_parser().parse_args(
            [
                "access-check",
                "lab",
                "--case-file",
                str(self.case_path),
                "--function-matrix",
                "--range",
                "1-2",
            ]
        )
        with patch.object(cli, "executor_context") as context:
            with self.assertRaisesRegex(ValueError, "separate read-only mode"):
                cli.cmd_access_check(args)
        context.assert_not_called()


if __name__ == "__main__":
    unittest.main()
