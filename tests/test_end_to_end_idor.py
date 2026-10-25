from __future__ import annotations

import json
import os
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch
from urllib.error import HTTPError, URLError
from urllib.request import ProxyHandler, Request, build_opener

from bugbounty_toolkit.access_control.comparison import load_case
from bugbounty_toolkit import cli
from bugbounty_toolkit.core.scope_validator import ScopeValidator
from bugbounty_toolkit.idor_lab_server import make_server


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
FIXTURE_ROOT = REPOSITORY_ROOT / "labs" / "idor_lab"


class IdorEndToEndTests(unittest.TestCase):
    def _cli(self, records_root: Path, *arguments: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                sys.executable,
                "-m",
                "bugbounty_toolkit.cli",
                "--records-root",
                str(records_root),
                *arguments,
            ],
            cwd=REPOSITORY_ROOT,
            capture_output=True,
            text=True,
            timeout=30,
            env=os.environ.copy(),
            check=False,
        )

    def _assert_cli_ok(self, records_root: Path, *arguments: str) -> subprocess.CompletedProcess[str]:
        result = self._cli(records_root, *arguments)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        return result

    @staticmethod
    def _login(base_url: str, user: str) -> str:
        body = json.dumps({"user": user}).encode("utf-8")
        request = Request(
            base_url + "/login",
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with build_opener(ProxyHandler({})).open(request, timeout=3) as response:
            payload = json.loads(response.read().decode("utf-8"))
            if payload.get("success") is not True:
                raise AssertionError(f"Lab login failed for fixture user {user}.")
            return response.headers["Authorization"]

    @staticmethod
    def _write_raw_request(path: Path, target: str, host: str, authorization: str) -> None:
        path.write_text(
            f"GET {target} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Authorization: {authorization}\r\n"
            "Accept: application/json\r\n"
            "User-Agent: bbtk-idor-lab\r\n\r\n",
            encoding="utf-8",
        )

    def test_real_cli_flow_import_range_negative_control_and_report(self) -> None:
        try:
            server = make_server("127.0.0.1", 0)
        except OSError as exc:
            self.skipTest(f"Could not bind the local IDOR lab server in this CI environment: {exc}")
        server_thread = threading.Thread(target=server.serve_forever, daemon=True)
        server_thread.start()
        try:
            port = int(server.server_address[1])
            origin = f"http://127.0.0.1:{port}"
            try:
                owner_auth = self._login(origin, "owner")
                actor_auth = self._login(origin, "actor")
            except URLError as exc:
                reason = exc.reason
                if isinstance(reason, PermissionError) or (
                    isinstance(reason, OSError) and getattr(reason, "winerror", None) == 10013
                ):
                    self.skipTest(f"CI sandbox denies loopback client sockets; end-to-end lab skipped: {reason}")
                raise
            self.assertNotEqual(owner_auth, actor_auth)

            temporary_parent = REPOSITORY_ROOT / ".test-tmp"
            temporary_parent.mkdir(exist_ok=True)
            with tempfile.TemporaryDirectory(prefix="bbtk-idor-e2e-", dir=temporary_parent) as temp_dir:
                root = Path(temp_dir)
                records = root / "records"
                config = root / "settings.yaml"
                config.write_text(
                    "requests_per_second: 30\ntimeout: 3\nmax_concurrency: 4\nmax_tests: 8\nmax_response_bytes: 65536\n",
                    encoding="utf-8",
                )
                private_dir = records / "idor-lab" / "private"
                captures_dir = private_dir / "captures"
                captures_dir.mkdir(parents=True)
                for name, authorization in (("owner.txt", owner_auth), ("actor.txt", actor_auth)):
                    fixture = (FIXTURE_ROOT / "captures" / name).read_text(encoding="utf-8")
                    fixture = fixture.replace("127.0.0.1:8099", f"127.0.0.1:{port}")
                    fixture = fixture.replace(
                        "Bearer lab-owner-token" if name == "owner.txt" else "Bearer lab-actor-token",
                        authorization,
                    )
                    (captures_dir / name).write_text(fixture, encoding="utf-8")

                self._assert_cli_ok(
                    records,
                    "init",
                    "idor-lab",
                    "--authorization",
                    "isolated local IDOR lab fixture",
                    "--automation-allowed",
                    "--config",
                    str(config),
                )
                self._assert_cli_ok(records, "scope", "add", "idor-lab", "127.0.0.1")
                self._assert_cli_ok(
                    records,
                    "import",
                    "case",
                    "idor-lab",
                    "--owner",
                    str(captures_dir / "owner.txt"),
                    "--actor",
                    str(captures_dir / "actor.txt"),
                    "--base-url",
                    origin,
                    "--resource-pointer",
                    "/data/id",
                    "--success-pointer",
                    "/success",
                    "--success-value",
                    "true",
                    "--private-pointer",
                    "/data/marker",
                    "--private-marker",
                    "owner-order-marker-1001",
                    "--actor-marker",
                    "actor-order-marker-1002",
                    "--attest-authorized-accounts",
                    "--attest-private-resource",
                )

                case_path = private_dir / "case.json"
                generated = json.loads(case_path.read_text(encoding="utf-8"))
                # Range mode needs a separate explicit enumeration attestation; this fixture is wholly local.
                generated["identifier_enumeration_authorized"] = True
                case_path.write_text(json.dumps(generated, indent=2) + "\n", encoding="utf-8")
                loaded = load_case(case_path, ScopeValidator(records / "idor-lab" / "scope.txt"))
                self.assertEqual(loaded.accounts[0].resource, "1001")
                self.assertEqual(loaded.accounts[1].resource, "1002")

                range_result = self._assert_cli_ok(
                    records,
                    "access-check",
                    "idor-lab",
                    "--case-file",
                    str(case_path),
                    "--range",
                    "1001-1002",
                    "--max-range",
                    "2",
                    "--max-tests",
                    "4",
                    "--min-interval",
                    "0.01",
                )
                self.assertIn("comparison: candidate", range_result.stdout)
                private_capture = self._latest_evidence(records / "idor-lab" / "evidence" / "access-control")
                private_data = json.loads(private_capture.read_text(encoding="utf-8"))
                self.assertEqual(private_data["classification"], "candidate")
                self.assertIs(private_data["confirmed"], False)

                self._assert_cli_ok(
                    records,
                    "access-check",
                    "idor-lab",
                    "--case-file",
                    str(case_path),
                    "--inverse-cross",
                    "--max-tests",
                    "4",
                )
                inverse_data = json.loads(
                    self._latest_evidence(records / "idor-lab" / "evidence" / "access-control").read_text(
                        encoding="utf-8"
                    )
                )
                self.assertEqual(inverse_data["classification"], "candidate")
                self.assertEqual(inverse_data["inverse_result"], "rejected_in_this_test")
                self.assertFalse(inverse_data["bidirectional_access"])

                public_owner = captures_dir / "public-owner.txt"
                public_actor = captures_dir / "public-actor.txt"
                self._write_raw_request(public_owner, "/api/public/status?id=1001", f"127.0.0.1:{port}", owner_auth)
                self._write_raw_request(public_actor, "/api/public/status?id=1002", f"127.0.0.1:{port}", actor_auth)
                public_case_path = private_dir / "public-case.json"
                public_case = {
                    "owner_request": "captures/public-owner.txt",
                    "actor_request": "captures/public-actor.txt",
                    "base_url": origin,
                    "session_headers": ["Authorization"],
                    "resource": {"query_parameter": "id"},
                    "accounts_authorized": True,
                    "resource_private": False,
                    "expected_cross_access": "deny",
                    "expected_anonymous": "allow",
                    "checks": {
                        "success_pointer": "/success",
                        "success_value": True,
                        "resource_pointer": "/data/id",
                        "owner_resource": "1001",
                        "actor_resource": "1002",
                        "private_pointer": "/data/marker",
                        "owner_marker": "public-status-marker-1001",
                        "actor_marker": "public-status-marker-1002",
                    },
                }
                public_case_path.write_text(json.dumps(public_case, indent=2) + "\n", encoding="utf-8")
                public_result = self._assert_cli_ok(
                    records,
                    "access-check",
                    "idor-lab",
                    "--case-file",
                    str(public_case_path),
                    "--anonymous-check",
                    "--max-tests",
                    "4",
                )
                self.assertIn("public_endpoint", public_result.stdout)
                public_capture = self._latest_evidence(records / "idor-lab" / "evidence" / "access-control")
                public_data = json.loads(public_capture.read_text(encoding="utf-8"))
                self.assertEqual(public_data["classification"], "public_endpoint")
                self.assertEqual(public_data["anonymous_classification"], "public_endpoint")
                self.assertNotEqual(public_data["classification"], "candidate")

                self._assert_cli_ok(records, "report", "idor-lab", "--format", "json")
                self._assert_cli_ok(records, "report", "idor-lab", "--format", "html")
                json_report = records / "idor-lab" / "reports" / "program-report.json"
                html_report = records / "idor-lab" / "reports" / "program-report.html"
                report = json.loads(json_report.read_text(encoding="utf-8"))
                report_evidence = [item["data"] for item in report["evidence"] if "data" in item]
                self.assertIn("candidate", [item["classification"] for item in report_evidence])
                self.assertIn("public_endpoint", [item["classification"] for item in report_evidence])
                self.assertTrue(html_report.is_file())
                self.assertGreater(html_report.stat().st_size, 0)

        finally:
            server.shutdown()
            server.server_close()
            server_thread.join(timeout=3)

    def test_protected_endpoint_end_to_end_pipeline_and_report(self) -> None:
        try:
            server = make_server("127.0.0.1", 0)
        except OSError as exc:
            self.skipTest(f"Could not bind the local IDOR lab server in this CI environment: {exc}")
        server_thread = threading.Thread(target=server.serve_forever, daemon=True)
        server_thread.start()
        try:
            port = int(server.server_address[1])
            origin = f"http://127.0.0.1:{port}"
            try:
                owner_auth = self._login(origin, "owner")
                actor_auth = self._login(origin, "actor")
            except URLError as exc:
                reason = exc.reason
                if isinstance(reason, PermissionError) or (
                    isinstance(reason, OSError) and getattr(reason, "winerror", None) == 10013
                ):
                    self.skipTest(f"CI sandbox denies loopback client sockets; protected E2E skipped: {reason}")
                raise

            temporary_parent = REPOSITORY_ROOT / ".test-tmp"
            temporary_parent.mkdir(exist_ok=True)
            with tempfile.TemporaryDirectory(prefix="bbtk-idor-protected-e2e-", dir=temporary_parent) as temp_dir:
                root = Path(temp_dir)
                records = root / "records"
                config = root / "settings.yaml"
                config.write_text(
                    "requests_per_second: 30\ntimeout: 3\nmax_concurrency: 4\nmax_tests: 8\nmax_response_bytes: 65536\n",
                    encoding="utf-8",
                )
                private_dir = records / "idor-lab" / "private"
                captures_dir = private_dir / "captures"
                captures_dir.mkdir(parents=True)
                captures = ("protected-owner.txt", "protected-actor.txt")
                credentials = (owner_auth, actor_auth)
                for name, filename, authorization in zip(captures, ("owner.txt", "actor.txt"), credentials):
                    fixture = (FIXTURE_ROOT / "captures" / name).read_text(encoding="utf-8")
                    fixture = fixture.replace("127.0.0.1:8099", f"127.0.0.1:{port}")
                    fixture = fixture.replace(
                        "Bearer lab-owner-token" if filename == "owner.txt" else "Bearer lab-actor-token",
                        authorization,
                    )
                    (captures_dir / filename).write_text(fixture, encoding="utf-8")

                self._assert_cli_ok(
                    records,
                    "init",
                    "idor-lab",
                    "--authorization",
                    "isolated local protected IDOR lab fixture",
                    "--automation-allowed",
                    "--config",
                    str(config),
                )
                self._assert_cli_ok(records, "scope", "add", "idor-lab", "127.0.0.1")
                case_path = private_dir / "protected-case.json"
                self._assert_cli_ok(
                    records,
                    "import",
                    "case",
                    "idor-lab",
                    "--owner",
                    str(captures_dir / "owner.txt"),
                    "--actor",
                    str(captures_dir / "actor.txt"),
                    "--base-url",
                    origin,
                    "--resource-pointer",
                    "/data/id",
                    "--success-pointer",
                    "/success",
                    "--success-value",
                    "true",
                    "--private-pointer",
                    "/data/marker",
                    "--private-marker",
                    "owner-order-marker-1001",
                    "--actor-marker",
                    "actor-order-marker-1002",
                    "--attest-authorized-accounts",
                    "--attest-private-resource",
                    "--output",
                    str(case_path),
                )
                loaded = load_case(case_path, ScopeValidator(records / "idor-lab" / "scope.txt"))
                self.assertEqual([account.resource for account in loaded.accounts], ["1001", "1002"])

                # The agent workflow starts with local normalization and correlation.
                bundle_path = root / "protected-unified-evidence.json"
                owner_capture, actor_capture = captures_dir / "owner.txt", captures_dir / "actor.txt"
                self._assert_cli_ok(
                    records,
                    "evidence",
                    "import",
                    "idor-lab",
                    "--input",
                    str(owner_capture),
                    str(actor_capture),
                    "--format",
                    "http",
                    "--output",
                    str(bundle_path),
                )
                bundle = json.loads(bundle_path.read_text(encoding="utf-8"))
                self.assertGreaterEqual(bundle["summary"]["correlation_groups"], 1)
                correlations_path = root / "protected-correlations.json"
                self._assert_cli_ok(
                    records,
                    "evidence",
                    "correlate",
                    "idor-lab",
                    "--input",
                    str(bundle_path),
                    "--output",
                    str(correlations_path),
                )
                correlations = json.loads(correlations_path.read_text(encoding="utf-8"))
                self.assertGreaterEqual(correlations["summary"]["correlation_groups"], 1)

                record_id = bundle["records"][0]["evidence_id"]
                hypothesis = {
                    "category": "access_control",
                    "summary": "Two authorized sessions use the same resource endpoint pattern.",
                    "evidence_for": [
                        {"record_id": record_id, "why": "A captured request identifies the resource pattern."}
                    ],
                    "evidence_against": [],
                    "missing_controls": ["The cross-account authorization result has not yet been measured."],
                    "confidence": "medium",
                    "next_check": {
                        "kind": "http",
                        "suggestion": "Run the bounded owner/actor controls against the disposable local fixture.",
                        "why": "The captured requests alone do not establish access behavior.",
                    },
                    "status": "hypothesis",
                }
                hypothesis_args = cli.build_parser().parse_args(
                    [
                        "--records-root",
                        str(records),
                        "ai",
                        "hypotheses",
                        "idor-lab",
                        "--input",
                        str(bundle_path),
                    ]
                )
                hypothesis_output = StringIO()
                with (
                    patch(
                        "bugbounty_toolkit.analysis.hypotheses.chat_with_ollama",
                        return_value=json.dumps(hypothesis),
                    ),
                    redirect_stdout(hypothesis_output),
                ):
                    hypothesis_args.func(hypothesis_args)
                rendered = hypothesis_output.getvalue()
                hypotheses = json.loads(rendered[rendered.index("{\n") :])
                self.assertEqual(hypotheses["groups"][0]["hypothesis"]["status"], "hypothesis")
                self.assertEqual(hypotheses["vulnerabilities_confirmed"], 0)
                hypotheses_path = root / "protected-hypotheses.json"
                hypotheses_path.write_text(json.dumps(hypotheses), encoding="utf-8")

                route = self._assert_cli_ok(
                    records,
                    "ai",
                    "route",
                    "idor-lab",
                    "--input",
                    str(hypotheses_path),
                    "--dry-run",
                )
                route_json = json.loads(route.stdout[route.stdout.index("{\n") :])
                self.assertEqual(route_json["selected"][0]["skill"], "bugbounty-access-control")
                self.assertTrue(route_json["plan"][0]["command"].startswith("bbtk access-check idor-lab"))

                # Run only the selected, three-request control/cross comparison in the loopback lab.
                run = self._assert_cli_ok(
                    records,
                    "access-check",
                    "idor-lab",
                    "--case-file",
                    str(case_path),
                    "--max-tests",
                    "3",
                )
                self.assertIn("Access comparison: rejected_in_this_test", run.stdout)
                access_evidence = self._latest_evidence(records / "idor-lab" / "evidence" / "access-control")
                observed = json.loads(access_evidence.read_text(encoding="utf-8"))
                self.assertEqual(observed["classification"], "rejected_in_this_test")
                self.assertEqual(observed["requests_attempted"], 3)
                self.assertIs(observed["confirmed"], False)
                cross = next(row for row in observed["steps"] if row["step"] == "cross_read")
                self.assertIs(cross["application_success"], False)
                self.assertIs(cross["owner_resource_match"], False)
                self.assertIs(cross["owner_private_match"], False)

                assessment_args = cli.build_parser().parse_args(
                    [
                        "--records-root",
                        str(records),
                        "ai",
                        "hypotheses",
                        "idor-lab",
                        "--input",
                        str(bundle_path),
                        "--case-file",
                        str(case_path),
                        "--access-evidence",
                        str(access_evidence),
                        "--dry-run",
                    ]
                )
                assessment_output = StringIO()
                with redirect_stdout(assessment_output):
                    assessment_args.func(assessment_args)
                assessment_json = json.loads(assessment_output.getvalue()[assessment_output.getvalue().index("{\n") :])
                assessment = assessment_json["access_control_assessment"]
                self.assertEqual(assessment["classification"], "denied")
                self.assertIs(assessment["confirmed"], False)
                self.assertIs(assessment["status_code_used"], False)
                self.assertIs(assessment["model_opinion_used"], False)

                report_path = root / "protected-review.json"
                self._assert_cli_ok(
                    records,
                    "report",
                    "idor-lab",
                    "--evidence-file",
                    str(access_evidence),
                    "--format",
                    "json",
                    "--output",
                    str(report_path),
                )
                report = json.loads(report_path.read_text(encoding="utf-8"))
                self.assertEqual(report["validation_state"], "not_observed")
                self.assertNotEqual(report["validation_state"], "validated")
                for path in (access_evidence, report_path):
                    text = path.read_text(encoding="utf-8")
                    self.assertNotIn("lab-owner-token", text)
                    self.assertNotIn("lab-actor-token", text)
        finally:
            server.shutdown()
            server.server_close()
            server_thread.join(timeout=3)

    def test_lab_models_one_way_flaw_protected_ambiguous_error_and_public_paths(self) -> None:
        try:
            server = make_server("127.0.0.1", 0)
        except OSError as exc:
            self.skipTest(f"Could not bind the local IDOR lab server in this CI environment: {exc}")
        server_thread = threading.Thread(target=server.serve_forever, daemon=True)
        server_thread.start()
        try:
            origin = f"http://127.0.0.1:{server.server_address[1]}"
            try:
                owner = self._login(origin, "owner")
                actor = self._login(origin, "actor")
            except URLError as exc:
                reason = exc.reason
                if isinstance(reason, PermissionError) or (
                    isinstance(reason, OSError) and getattr(reason, "winerror", None) == 10013
                ):
                    self.skipTest(f"CI sandbox denies loopback client sockets; lab scenario skipped: {reason}")
                raise

            def get(path: str, token: str) -> tuple[int, dict[str, object]]:
                request = Request(
                    origin + path,
                    headers={"Authorization": token, "Accept": "application/json"},
                    method="GET",
                )
                try:
                    response = build_opener(ProxyHandler({})).open(request, timeout=3)
                except HTTPError as error:
                    return error.code, json.loads(error.read().decode("utf-8"))
                with response:
                    return response.status, json.loads(response.read().decode("utf-8"))

            status, owner_record = get("/api/orders/1001", actor)
            self.assertEqual(status, 200)
            self.assertEqual(owner_record["data"]["marker"], "owner-order-marker-1001")
            self.assertEqual(get("/api/orders/1002", owner)[0], 403)

            self.assertEqual(get("/api/protected-orders/1001", owner)[0], 200)
            self.assertEqual(get("/api/protected-orders/1002", actor)[0], 200)
            self.assertEqual(get("/api/protected-orders/1001", actor)[0], 403)

            status, denied_page = get("/api/ambiguous-orders/1001", actor)
            self.assertEqual(status, 200)
            self.assertIs(denied_page["success"], False)
            self.assertEqual(get("/api/error-orders/1001", actor)[0], 500)
            self.assertEqual(get("/api/public/status", actor)[0], 200)
        finally:
            server.shutdown()
            server.server_close()
            server_thread.join(timeout=3)

    def test_cli_lab_dry_run_only_prints_local_steps(self) -> None:
        temporary_parent = REPOSITORY_ROOT / ".test-tmp"
        temporary_parent.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="bbtk-idor-dry-run-", dir=temporary_parent) as temp_dir:
            result = self._cli(Path(temp_dir) / "records", "lab", "idor", "--dry-run")
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("127.0.0.1", result.stdout)
            self.assertIn("import case", result.stdout)
            self.assertIn("access-check idor-lab", result.stdout)
            self.assertIn("--range 1001-1002", result.stdout)
            self.assertIn("report idor-lab --format json", result.stdout)
            self.assertIn("sends no requests", result.stdout)

    @staticmethod
    def _latest_evidence(directory: Path) -> Path:
        return max(directory.glob("*.json"), key=lambda path: path.stat().st_mtime_ns)


if __name__ == "__main__":
    unittest.main()
