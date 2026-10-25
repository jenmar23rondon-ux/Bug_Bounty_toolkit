import json
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from bugbounty_toolkit import cli
from bugbounty_toolkit.access_control.comparison import load_case
from bugbounty_toolkit.case_generator import CaseGenerationOptions, generate_case
from bugbounty_toolkit.core.scope_validator import ScopeValidator


class CaseGeneratorTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.owner = self.root / "owner-a.txt"
        self.actor = self.root / "actor-b.txt"
        self.output = self.root / "records" / "sample" / "private" / "case.json"
        self._write_captures()

    def tearDown(self):
        self.temp.cleanup()

    def _write_captures(
        self,
        *,
        owner_id="owner-123",
        actor_id="actor-456",
        owner_host="target.example",
        actor_host="target.example",
        owner_scheme=None,
        actor_scheme=None,
        owner_cookie="session=owner-cookie-secret",
        actor_cookie="session=actor-cookie-secret",
        owner_method="GET",
        actor_method="GET",
        owner_query="",
        actor_query="",
        actor_user_agent="case-generator-tests",
    ):
        def request(resource_id, host, cookie, method, query, scheme, user_agent):
            target = f"/api/items/{resource_id}{query}"
            if scheme:
                target = f"{scheme}://{host}{target}"
            head = (
                f"{method} {target} HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                f"Cookie: {cookie}\r\n"
                f"Authorization: Bearer {cookie.split('=', 1)[-1]}\r\n"
                "Accept: application/json\r\n"
                f"User-Agent: {user_agent}"
            )
            return head + "\r\n\r\n"

        self.owner.write_text(
            request(
                owner_id, owner_host, owner_cookie, owner_method, owner_query, owner_scheme, "case-generator-tests"
            ),
            encoding="utf-8",
        )
        self.actor.write_text(
            request(actor_id, actor_host, actor_cookie, actor_method, actor_query, actor_scheme, actor_user_agent),
            encoding="utf-8",
        )

    def _options(self, **overrides):
        values = {
            "owner": self.owner,
            "actor": self.actor,
            "output": self.output,
            "resource_pointer": "/data/id",
            "private_pointer": "/data/marker",
            "success_pointer": "/success",
            "success_value": True,
            "private_marker": "owner-private-marker-123",
            "actor_marker": "actor-private-marker-456",
            "accounts_authorized": True,
            "resource_private": True,
        }
        values.update(overrides)
        return CaseGenerationOptions(**values)

    def test_happy_path_writes_case_accepted_by_access_check_loader(self):
        result = generate_case(self._options())
        case_data = json.loads(self.output.read_text(encoding="utf-8"))
        self.assertEqual(case_data["resource"], {"path_segment": 2})
        self.assertEqual(case_data["base_url"], "https://target.example")
        self.assertEqual(case_data["session_headers"], ["Authorization", "Cookie"])
        self.assertNotIn("owner-cookie-secret", self.output.read_text(encoding="utf-8"))
        self.assertNotIn("actor-cookie-secret", self.output.read_text(encoding="utf-8"))
        self.assertEqual(result.resource_kind, "path segment")
        scope_file = self.root / "scope.txt"
        scope_file.write_text("target.example\n", encoding="utf-8")
        case = load_case(self.output, ScopeValidator(scope_file))
        self.assertEqual(case.accounts[0].resource, "owner-123")
        self.assertEqual(case.accounts[1].resource, "actor-456")

    def test_rejects_different_origin(self):
        self._write_captures(actor_host="other.example")
        with self.assertRaisesRegex(ValueError, "same origin"):
            generate_case(self._options())

    def test_origin_includes_scheme_and_port(self):
        for changes in ({"actor_scheme": "http"}, {"actor_host": "target.example:8443"}):
            with self.subTest(changes=changes):
                self._write_captures(**changes)
                with self.assertRaisesRegex(ValueError, "same origin"):
                    generate_case(self._options())

    def test_reports_every_target_difference_without_showing_values(self):
        self._write_captures(actor_query="?view=other")
        with self.assertRaisesRegex(ValueError, "path segment 2.*query parameter 'view'"):
            generate_case(self._options())

    def test_infers_one_changed_query_parameter(self):
        self._write_captures(
            owner_id="same-path",
            actor_id="same-path",
            owner_query="?item=owner-123",
            actor_query="?item=actor-456",
        )
        result = generate_case(self._options())
        case_data = json.loads(self.output.read_text(encoding="utf-8"))
        self.assertEqual(case_data["resource"], {"query_parameter": "item"})
        self.assertEqual(result.resource_name, "item")

    def test_rejects_invalid_json_pointer(self):
        with self.assertRaisesRegex(ValueError, "Invalid --resource-pointer"):
            generate_case(self._options(resource_pointer="/data/~2id"))
        with self.assertRaisesRegex(ValueError, "start with"):
            generate_case(self._options(private_pointer="data/marker"))

    def test_method_mismatch_explains_write_mode(self):
        self._write_captures(actor_method="POST")
        with self.assertRaisesRegex(ValueError, "methods differ.*--lab-write"):
            generate_case(self._options())

    def test_rejects_matching_write_methods_in_read_case_generator(self):
        # A matching write is still outside this read-case generator's scope.
        self._write_captures(owner_method="POST", actor_method="POST")
        with self.assertRaisesRegex(ValueError, "creates read cases and requires GET"):
            generate_case(self._options())

    def test_reports_non_session_header_differences_exactly(self):
        self._write_captures(actor_user_agent="different-agent")
        with self.assertRaisesRegex(ValueError, r"user-agent \(values differ\)"):
            generate_case(self._options())

    def test_same_session_is_rejected_as_probable_same_account(self):
        self._write_captures(actor_cookie="session=owner-cookie-secret")
        with self.assertRaisesRegex(
            ValueError, "Sesión detectada.*probablemente ambas capturas son de la misma cuenta"
        ):
            generate_case(self._options())

    def test_dry_run_validates_without_creating_output(self):
        result = generate_case(self._options(dry_run=True))
        self.assertTrue(result.dry_run)
        self.assertFalse(self.output.exists())
        self.assertFalse(self.output.parent.exists())

    def test_existing_case_requires_force(self):
        self.output.parent.mkdir(parents=True)
        self.output.write_text("existing", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "Pass --force"):
            generate_case(self._options())
        self.assertEqual(self.output.read_text(encoding="utf-8"), "existing")
        generate_case(self._options(force=True))
        self.assertNotEqual(self.output.read_text(encoding="utf-8"), "existing")

    def test_cli_dry_run_reports_redacted_session_and_does_not_write(self):
        args = cli.build_parser().parse_args(
            [
                "--records-root",
                str(self.root / "records"),
                "import",
                "case",
                "sample",
                "--owner",
                str(self.owner),
                "--actor",
                str(self.actor),
                "--resource-pointer",
                "/data/id",
                "--private-pointer",
                "/data/marker",
                "--success-pointer",
                "/success",
                "--success-value",
                "true",
                "--private-marker",
                "owner-private-marker-123",
                "--actor-marker",
                "actor-private-marker-456",
                "--attest-authorized-accounts",
                "--attest-private-resource",
                "--dry-run",
            ]
        )
        output = StringIO()
        with patch.object(cli, "RECORDS_ROOT", self.root / "records"), redirect_stdout(output):
            args.func(args)
        rendered = output.getvalue()
        self.assertIn("Sesión detectada: Authorization=[redacted], Cookie=[redacted]", rendered)
        self.assertIn("no HTTP requests sent", rendered)
        self.assertNotIn("owner-cookie-secret", rendered)
        self.assertFalse(self.output.exists())


if __name__ == "__main__":
    unittest.main()
