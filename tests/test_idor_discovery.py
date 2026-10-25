from __future__ import annotations

import base64
from contextlib import redirect_stdout
from io import StringIO
import json
import os
from pathlib import Path
import stat
import tempfile
import threading
import unittest
from unittest.mock import patch
from xml.sax.saxutils import escape

from bugbounty_toolkit import cli
from bugbounty_toolkit.access_control.comparison import AccessControlTester, load_case
from bugbounty_toolkit.burp_import import parse_captured_exchanges, read_capture_file
from bugbounty_toolkit.core.execution_budget import ExecutionBudget
from bugbounty_toolkit.core.http_client import HttpClient
from bugbounty_toolkit.core.rate_limiter import RateLimiter
from bugbounty_toolkit.core.scope_validator import ScopeValidator
from bugbounty_toolkit.idor_discovery import (
    POINTER_FIELDS,
    REVIEW_ATTESTATIONS,
    approve_idor,
    discover_idor,
    discovery_summary,
    save_proposal,
)
from bugbounty_toolkit.idor_lab_server import make_server


class IdorDiscoveryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.owner, self.actor = self.root / "owner.xml", self.root / "actor.xml"
        self.bundle = self.root / "private" / "discovery"
        self.scope_path = self.root / "scope.txt"
        self.scope_path.write_text("http://127.0.0.1:8099/api\n", encoding="utf-8")
        self.scope = ScopeValidator(self.scope_path)
        self._captures()

    @staticmethod
    def _request(account, identifier, target=None, host="127.0.0.1:8099", headers="", method="GET"):
        return (
            f"{method} {target or '/api/orders/' + str(identifier)} HTTP/1.1\r\n"
            f"Host: {host}\r\nAuthorization: Bearer lab-{account}-token\r\n"
            f"Cookie: session={account}-cookie-secret\r\nAccept: application/json\r\n{headers}\r\n"
        )

    @staticmethod
    def _response(account, identifier, *, body=None, status=200):
        if body is None:
            body = {
                "success": True,
                "data": {"id": identifier, "marker": f"{account}-order-marker-{identifier}"},
                "password": "response-password-secret",
                "token": "response-token-secret",
            }
        rendered = json.dumps(body, ensure_ascii=False)
        return f"HTTP/1.1 {status} Fixture\r\nContent-Type: application/json\r\nContent-Length: {len(rendered.encode())}\r\n\r\n{rendered}"

    @staticmethod
    def _xml(items):
        records = []
        for request, response, url in items:
            messages = f'<request base64="true">{base64.b64encode(request.encode()).decode()}</request>'
            if response is not None:
                messages += f'<response base64="true">{base64.b64encode(response.encode()).decode()}</response>'
            records.append(f"<item><url>{escape(url)}</url>{messages}</item>")
        return ("<items>" + "".join(records) + "</items>").encode()

    def _captures(self, *, owner_id="1001", actor_id="1002", query=False, owner_body=None, actor_body=None):
        for path, account, identifier, body in (
            (self.owner, "owner", owner_id, owner_body),
            (self.actor, "actor", actor_id, actor_body),
        ):
            target = f"/api/orders?id={identifier}&view=full" if query else f"/api/orders/{identifier}"
            raw = self._request(account, identifier, target)
            response = self._response(account, identifier, body=body)
            path.write_bytes(self._xml([(raw, response, "http://127.0.0.1:8099" + target)]))

    def _discover(self, **options):
        with patch("socket.socket", side_effect=AssertionError("Discovery must stay offline")):
            return discover_idor("lab", self.owner, self.actor, **options)

    def _saved(self):
        return save_proposal(self._discover(), self.bundle)

    def _review(self, path, **overrides):
        data = json.loads(path.read_text())
        row = data["candidates"][0]
        row["review"].update(
            success_pointer="/success",
            resource_pointer="/data/id",
            private_pointer="/data/marker",
            expected_cross_access="deny",
            **dict.fromkeys(REVIEW_ATTESTATIONS, True),
        )
        row["review"].update(overrides)
        path.write_text(json.dumps(data), encoding="utf-8")
        return data

    def _approve(self, path, **options):
        with patch("socket.socket", side_effect=AssertionError("Approval must stay offline")):
            return approve_idor(path, "candidate-001", "lab", self.scope, approve=True, **options)

    def test_two_xml_accounts_produce_reviewable_proposal_and_lossless_private_snapshots(self):
        result = self._discover()
        candidate = result.proposal["candidates"][0]
        self.assertEqual(candidate["resource"], {"path_segment": 2})
        self.assertEqual(candidate["suggested_checks"]["resource_pointer"], ["/data/id"])
        self.assertEqual(candidate["suggested_checks"]["private_pointer"], ["/data/marker"])
        self.assertEqual(candidate["suggested_checks"]["success_pointer"], ["/success"])
        self.assertTrue(all(candidate["review"][field] is None for field in POINTER_FIELDS))
        self.assertTrue(all(candidate["review"][field] is False for field in REVIEW_ATTESTATIONS))
        path = save_proposal(result, self.bundle)
        self.assertEqual(
            (path.parent / "captures/owner-001.request.http").read_bytes(), result.owner[0].raw_request.encode()
        )
        self.assertEqual(
            (path.parent / "captures/actor-001.response.http").read_bytes(), result.actor[0].raw_response.encode()
        )
        self.assertFalse(list(self.bundle.glob("case-*.json")))

    def test_reviewed_approval_reuses_access_loader_and_never_confirms_a_finding(self):
        path = self._saved()
        self._review(path)
        result = self._approve(path)
        case_path = self.bundle / "case-candidate-001.json"
        case = load_case(case_path, self.scope)
        self.assertEqual(case.owner.prepared_url(), "http://127.0.0.1:8099/api/orders/1001")
        self.assertEqual(case.cross.headers, case.actor.headers)
        self.assertEqual(case.cross.prepared_url(), case.owner.prepared_url())
        self.assertEqual(result["assessment"]["classification"], "insufficient_evidence")
        self.assertFalse(result["confirmed"])
        self.assertEqual(result["network_requests_sent"], 0)
        self.assertNotIn("identifier_enumeration_authorized", json.loads(case_path.read_text()))
        with self.assertRaisesRegex(ValueError, "already exists"):
            self._approve(path)

    def test_query_resource_and_numeric_json_identifiers_preserve_native_types(self):
        self._captures(owner_id=1001, actor_id=987654321, query=True)
        path = self._saved()
        self._review(path)
        self._approve(path)
        case = load_case(self.bundle / "case-candidate-001.json", self.scope)
        self.assertEqual(case.resource, {"query_parameter": "id"})
        self.assertIs(type(case.checks["owner_resource"]), int)
        self.assertIn("view=full", case.owner.prepared_url())

    def test_differences_only_in_session_are_not_resource_candidates(self):
        self._captures(actor_id="1001")
        result = self._discover()
        self.assertEqual(result.proposal["session_only_pairs"], 1)
        self.assertEqual(result.proposal["candidates"], [])

    def test_identical_session_and_nonresource_differences_are_not_guessed(self):
        for replace in (("lab-actor-token", "lab-owner-token", "actor-cookie-secret", "owner-cookie-secret"),):
            raw = self._request("actor", "1002").replace(replace[0], replace[1]).replace(replace[2], replace[3])
            self.actor.write_bytes(
                self._xml([(raw, self._response("actor", "1002"), "http://127.0.0.1:8099/api/orders/1002")])
            )
            self.assertEqual(self._discover().proposal["candidates"], [])
        raw = self._request("actor", "1002", "/api/orders/1002?extra=secret-value")
        self.actor.write_bytes(self._xml([(raw, None, "http://127.0.0.1:8099/api/orders/1002?extra=secret-value")]))
        result = self._discover()
        self.assertEqual(result.proposal["unsupported_pairs"], 1)
        self.assertNotIn("secret-value", json.dumps(discovery_summary(result)))

    def test_multiple_xml_items_preserve_response_pairing_and_do_not_pair_by_order(self):
        for file, account, ids in ((self.owner, "owner", ["1001", "2001"]), (self.actor, "actor", ["2002", "1002"])):
            items = []
            for identifier in ids:
                route = "orders" if identifier.startswith("1") else "invoices"
                target = f"/api/{route}/{identifier}"
                items.append(
                    (
                        self._request(account, identifier, target),
                        self._response(account, identifier),
                        "http://127.0.0.1:8099" + target,
                    )
                )
            file.write_bytes(self._xml(items))
        result = self._discover()
        self.assertEqual(len(result.proposal["candidates"]), 2)
        self.assertEqual(
            [(row["owner_index"], row["actor_index"]) for row in result.proposal["candidates"]], [(0, 1), (1, 0)]
        )

    def test_missing_response_allows_only_pending_proposal_and_prevents_approval(self):
        self.owner.write_text(self._request("owner", "1001"))
        self.actor.write_text(self._request("actor", "1002"))
        path = save_proposal(self._discover(base_url="http://127.0.0.1:8099"), self.bundle)
        data = self._review(path)
        self.assertEqual(data["candidates"][0]["suggested_checks"]["private_pointer"], [])
        with self.assertRaisesRegex(ValueError, "unchanged request and response"):
            self._approve(path)

    def test_missing_ownership_declaration_cannot_be_promoted(self):
        path = self._saved()
        for field in REVIEW_ATTESTATIONS:
            self._review(path, **{field: False})
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, "Researcher review"):
                self._approve(path)
        self._review(path)
        with self.assertRaisesRegex(ValueError, "Explicit --approve"):
            approve_idor(path, "candidate-001", "lab", self.scope)
        self.assertFalse(list(self.bundle.glob("case-*.json")))

    def test_selected_fields_must_prove_own_resource_and_nonreflected_marker(self):
        body = {"success": True, "data": {"id": "unrelated", "marker": "actor-order-marker-1002"}}
        self._captures(actor_body=body)
        path = self._saved()
        data = self._review(path)
        self.assertEqual(data["candidates"][0]["suggested_checks"]["resource_pointer"], [])
        with self.assertRaisesRegex(ValueError, "resource fields"):
            self._approve(path)
        self._review(path, private_pointer="/password")
        with self.assertRaisesRegex(ValueError, "Credentials/session"):
            self._approve(path)

    def test_reflected_marker_is_not_offered_as_private_proof(self):
        raw = self._request("owner", "1001", headers="X-Marker: owner-order-marker-1001\r\n")
        self.owner.write_bytes(
            self._xml([(raw, self._response("owner", "1001"), "http://127.0.0.1:8099/api/orders/1001")])
        )
        raw_actor = self._request("actor", "1002", headers="X-Marker: owner-order-marker-1001\r\n")
        self.actor.write_bytes(
            self._xml([(raw_actor, self._response("actor", "1002"), "http://127.0.0.1:8099/api/orders/1002")])
        )
        path = self._saved()
        data = self._review(path)
        self.assertEqual(data["candidates"][0]["suggested_checks"]["private_pointer"], [])
        with self.assertRaisesRegex(ValueError, "non-reflected"):
            self._approve(path)

    def test_no_secrets_in_count_only_summary_proposal_case_or_cli(self):
        result = self._discover()
        path = save_proposal(result, self.bundle)
        self._review(path)
        self._approve(path)
        args = cli.build_parser().parse_args(
            ["import", "discover-idor", "lab", "--owner", str(self.owner), "--actor", str(self.actor), "--dry-run"]
        )
        output = StringIO()
        with (
            patch.object(cli, "RECORDS_ROOT", self.root / "unused"),
            redirect_stdout(output),
            patch("socket.socket", side_effect=AssertionError("offline")),
        ):
            args.func(args)
        shared = (
            json.dumps(discovery_summary(result))
            + path.read_text()
            + (self.bundle / "case-candidate-001.json").read_text()
            + output.getvalue()
        )
        for secret in (
            "lab-owner-token",
            "lab-actor-token",
            "owner-cookie-secret",
            "actor-cookie-secret",
            "response-password-secret",
            "response-token-secret",
        ):
            self.assertNotIn(secret, shared)
        self.assertNotIn("1001", json.dumps(discovery_summary(result)))
        self.assertFalse((self.root / "unused").exists())

    def test_approval_dry_run_has_no_writes_and_scope_is_still_required(self):
        path = self._saved()
        self._review(path)
        before = {p: (p.read_bytes(), p.stat().st_mtime_ns) for p in self.bundle.rglob("*") if p.is_file()}
        result = self._approve(path, dry_run=True)
        after = {p: (p.read_bytes(), p.stat().st_mtime_ns) for p in self.bundle.rglob("*") if p.is_file()}
        self.assertEqual(before, after)
        self.assertFalse(result["case_written"])
        self.scope_path.write_text("https://outside.invalid\n")
        with self.assertRaisesRegex(ValueError, "outside the existing program scope"):
            self._approve(path)

    def test_snapshot_changes_traversal_and_other_program_are_rejected(self):
        path = self._saved()
        original = self._review(path)
        data = json.loads(json.dumps(original))
        data["captures"]["owner"][0]["request"] = "../external-secret.http"
        path.write_text(json.dumps(data))
        with self.assertRaisesRegex(ValueError, "original private bundle"):
            self._approve(path)
        path.write_text(json.dumps(original))
        with self.assertRaisesRegex(ValueError, "program"):
            approve_idor(path, "candidate-001", "another-program", self.scope, approve=True)
        (self.bundle / "captures/owner-001.request.http").write_text(self._request("owner", "9999"))
        with self.assertRaisesRegex(ValueError, "unchanged"):
            self._approve(path)

    def test_invalid_incomplete_oversized_and_entity_captures_fail_without_echo(self):
        bad_inputs = (
            b"<items><item>",
            b"<items><item><response>HTTP/1.1 200 OK</response></item></items>",
            b'<items><item><request base64="true">not-base64-secret</request></item></items>',
            b'<!DOCTYPE items [<!ENTITY x "secret">]><items>&x;</items>',
            "<!DOCTYPE items><items/>".encode("utf-16"),
            b"GET / HTTP/1.1\r\nHost: private-secret.invalid",
            b"\xff\xfe",
        )
        for data in bad_inputs:
            with self.subTest(data=data), self.assertRaises(ValueError) as caught:
                parse_captured_exchanges(data)
            self.assertNotIn("private-secret", str(caught.exception))
            self.assertNotIn("not-base64-secret", str(caught.exception))
        with self.assertRaisesRegex(ValueError, "size limit"):
            read_capture_file(self.owner, 8)
        with self.assertRaisesRegex(ValueError, "regular"):
            read_capture_file(self.root)
        link = self.root / "link.xml"
        link.symlink_to(self.owner)
        with self.assertRaisesRegex(ValueError, "symbolic"):
            read_capture_file(link)

    def test_response_framing_origin_and_json_limits(self):
        raw = self._request("owner", "1001").encode()
        for response in (
            b"HTTP/1.1 200 OK",
            b"HTTP/1.1 200 OK\r\nContent-Length: 8\r\n\r\n{}",
            b"HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\n\r\nbody",
        ):
            with self.assertRaises(ValueError):
                parse_captured_exchanges(raw, "http://127.0.0.1:8099", response)
        with self.assertRaisesRegex(ValueError, "inconsistent origin"):
            parse_captured_exchanges(raw, "http://other.invalid")
        too_many = {f"field{index}": index for index in range(129)}
        self._captures(owner_body=too_many)
        with self.assertRaisesRegex(ValueError, "field limit"):
            self._discover()
        self._captures(owner_body={"success": True})
        self.assertEqual(self._discover().proposal["candidates"][0]["suggested_checks"]["private_pointer"], [])

    def test_cli_save_and_explicit_approval_are_offline_and_use_existing_scope(self):
        records = self.root / "records"
        (records / "lab").mkdir(parents=True)
        (records / "lab/scope.txt").write_text(self.scope_path.read_text())
        parser = cli.build_parser()
        args = parser.parse_args(
            [
                "import",
                "discover-idor",
                "lab",
                "--owner",
                str(self.owner),
                "--actor",
                str(self.actor),
                "--attest-authorized-accounts",
                "--output-dir",
                str(self.bundle),
            ]
        )
        with (
            patch.object(cli, "RECORDS_ROOT", records),
            patch("socket.socket", side_effect=AssertionError("offline")),
            redirect_stdout(StringIO()),
        ):
            args.func(args)
        path = self.bundle / "proposal.json"
        data = self._review(path)
        self.assertTrue(data["accounts_authorized"])
        self.assertEqual(data["candidates"][0]["session_headers"], ["Authorization", "Cookie"])
        options = [
            "import",
            "approve-idor",
            "lab",
            "--proposal",
            str(path),
            "--candidate",
            "candidate-001",
            "--approve",
        ]
        for dry_run in (True, False):
            args = parser.parse_args(options + (["--dry-run"] if dry_run else []))
            with (
                patch.object(cli, "RECORDS_ROOT", records),
                patch("socket.socket", side_effect=AssertionError("offline")),
                redirect_stdout(StringIO()),
            ):
                args.func(args)
            self.assertEqual((self.bundle / "case-candidate-001.json").exists(), not dry_run)
        self.assertFalse((records / "lab/toolkit.sqlite3").exists())

    def test_credentials_cannot_be_reused_as_proof_under_a_benign_field(self):
        for account, identifier, path in (("owner", "1001", self.owner), ("actor", "1002", self.actor)):
            marker = account + "-sensitive-credential-value"
            body = {"success": True, "data": {"id": identifier, "marker": marker}, "password": marker}
            path.write_bytes(
                self._xml(
                    [
                        (
                            self._request(account, identifier),
                            self._response(account, identifier, body=body),
                            f"http://127.0.0.1:8099/api/orders/{identifier}",
                        )
                    ]
                )
            )
        path = self._saved()
        data = self._review(path)
        self.assertEqual(data["candidates"][0]["suggested_checks"]["private_pointer"], [])
        with self.assertRaisesRegex(ValueError, "non-reflected"):
            self._approve(path)

    def test_failed_captured_control_or_disagreeing_success_cannot_be_approved(self):
        for success, status in ((False, 200), (True, 403)):
            body = {"success": success, "data": {"id": "1002", "marker": "actor-order-marker-1002"}}
            self.actor.write_bytes(
                self._xml(
                    [
                        (
                            self._request("actor", "1002"),
                            self._response("actor", "1002", body=body, status=status),
                            "http://127.0.0.1:8099/api/orders/1002",
                        )
                    ]
                )
            )
            bundle = self.root / f"control-{status}"
            path = save_proposal(self._discover(), bundle)
            self._review(path)
            with self.assertRaisesRegex(ValueError, "success value|controls do not validate"):
                self._approve(path)
            self.assertFalse(list(bundle.glob("case-*.json")))

    def test_malformed_proposals_and_review_pointers_fail_closed(self):
        path = self._saved()
        original = self._review(path)
        for value in ([], {"type": "untrusted-command", "command": "secret"}):
            path.write_text(json.dumps(value))
            with self.assertRaisesRegex(ValueError, "structure"):
                self._approve(path)
        path.write_text(json.dumps(original))
        self._review(path, private_pointer="invalid/~2pointer")
        with self.assertRaises(ValueError):
            self._approve(path)
        path.write_text(json.dumps(original))
        with self.assertRaisesRegex(ValueError, "missing or ambiguous"):
            approve_idor(path, "candidate-999", "lab", self.scope, approve=True)
        with self.assertRaisesRegex(ValueError, "candidate ID"):
            approve_idor(path, "../../escape", "lab", self.scope, approve=True)

    def test_item_candidate_and_proposal_limits_are_explicit(self):
        item = (self._request("owner", "1001"), None, "http://127.0.0.1:8099/api/orders/1001")
        with self.assertRaisesRegex(ValueError, "32-item"):
            parse_captured_exchanges(self._xml([item] * 33))
        for file, account, identifiers in (
            (self.owner, "owner", ["1001", "1003"]),
            (self.actor, "actor", ["1002", "1004"]),
        ):
            file.write_bytes(
                self._xml(
                    [
                        (
                            self._request(account, identifier),
                            self._response(account, identifier),
                            f"http://127.0.0.1:8099/api/orders/{identifier}",
                        )
                        for identifier in identifiers
                    ]
                )
            )
        with patch("bugbounty_toolkit.idor_discovery.MAX_CANDIDATES", 1):
            result = self._discover()
        self.assertTrue(result.proposal["candidates_truncated"])
        self.assertEqual(len(result.proposal["candidates"]), 1)
        with (
            patch("bugbounty_toolkit.idor_discovery.MAX_PROPOSAL_BYTES", 1),
            self.assertRaisesRegex(ValueError, "Proposal exceeds"),
        ):
            save_proposal(result, self.bundle)
        self.assertFalse(self.bundle.exists())

    def test_invalid_base_http2_json_and_separate_xml_response_are_rejected(self):
        request = self._request("owner", "1001").encode()
        with self.assertRaisesRegex(ValueError, "origin"):
            parse_captured_exchanges(request, "ftp://127.0.0.1:8099")
        with self.assertRaisesRegex(ValueError, "path or query"):
            parse_captured_exchanges(request, "http://127.0.0.1:8099/path")
        with self.assertRaisesRegex(ValueError, "HTTP/1.x"):
            parse_captured_exchanges(request.replace(b"HTTP/1.1", b"HTTP/2"))
        with self.assertRaisesRegex(ValueError, "Separate responses"):
            parse_captured_exchanges(self.owner.read_bytes(), response_data=b"response")
        raw = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{bad-json-secret}"
        self.owner.write_bytes(
            self._xml([(self._request("owner", "1001"), raw, "http://127.0.0.1:8099/api/orders/1001")])
        )
        with self.assertRaisesRegex(ValueError, "malformed or ambiguous") as caught:
            self._discover()
        self.assertNotIn("bad-json-secret", str(caught.exception))

    def test_escaped_json_pointers_and_repeated_set_cookies_preserve_structure(self):
        for account, identifier, path in (("owner", "1001", self.owner), ("actor", "1002", self.actor)):
            body = {"success": True, "da/ta": {"~id": identifier, "marker": account + "-controlled-marker-123"}}
            response = self._response(account, identifier, body=body).replace(
                "Content-Type:", "Set-Cookie: first=secret-one\r\nSet-Cookie: second=secret-two\r\nContent-Type:"
            )
            path.write_bytes(
                self._xml(
                    [(self._request(account, identifier), response, f"http://127.0.0.1:8099/api/orders/{identifier}")]
                )
            )
        path = self._saved()
        data = self._review(path, resource_pointer="/da~1ta/~0id", private_pointer="/da~1ta/marker")
        self.assertEqual(data["candidates"][0]["suggested_checks"]["resource_pointer"], ["/da~1ta/~0id"])
        self._approve(path)
        self.assertEqual(
            load_case(self.bundle / "case-candidate-001.json", self.scope).checks["owner_resource"], "1001"
        )

    @unittest.skipUnless(os.name == "posix", "POSIX permissions")
    def test_bundles_are_exclusive_and_private_even_with_permissive_umask(self):
        previous = os.umask(0)
        try:
            path = self._saved()
        finally:
            os.umask(previous)
        self.assertEqual(stat.S_IMODE(self.bundle.stat().st_mode), 0o700)
        for item in self.bundle.rglob("*"):
            self.assertEqual(stat.S_IMODE(item.stat().st_mode), 0o700 if item.is_dir() else 0o600)
        original = path.read_bytes()
        with self.assertRaisesRegex(ValueError, "already exists"):
            save_proposal(self._discover(), self.bundle)
        self.assertEqual(path.read_bytes(), original)

    def test_native_engine_runs_generated_cases_only_against_existing_loopback_lab(self):
        server = make_server("127.0.0.1", 0)
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()
        try:
            port = server.server_address[1]
            origin = f"http://127.0.0.1:{port}"
            self.scope_path.write_text(origin + "/api\n")
            for endpoint, expected in (("orders", "candidate"), ("protected-orders", "rejected_in_this_test")):
                for path, account, identifier in ((self.owner, "owner", "1001"), (self.actor, "actor", "1002")):
                    target = f"/api/{endpoint}/{identifier}"
                    request = self._request(account, identifier, target, host=f"127.0.0.1:{port}")
                    path.write_bytes(self._xml([(request, self._response(account, identifier), origin + target)]))
                bundle = self.root / endpoint
                with patch("socket.socket", side_effect=AssertionError("Preparation must not contact the lab")):
                    proposal = save_proposal(discover_idor("lab", self.owner, self.actor), bundle)
                    self._review(proposal)
                    approve_idor(proposal, "candidate-001", "lab", ScopeValidator(self.scope_path), approve=True)
                scope = ScopeValidator(self.scope_path)
                client = HttpClient(
                    scope, rate_limiter=RateLimiter(10000), execution_budget=ExecutionBudget(max_requests=3)
                )
                _, result = AccessControlTester(scope, client).run(
                    bundle / "case-candidate-001.json", bundle / "evidence", max_tests=3
                )
                self.assertEqual(result["classification"], expected)
                self.assertFalse(result["confirmed"])
                self.assertEqual(result["requests_attempted"], 3)
        finally:
            server.shutdown()
            worker.join()
            server.server_close()


if __name__ == "__main__":
    unittest.main()
