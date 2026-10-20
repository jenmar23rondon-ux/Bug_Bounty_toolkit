from contextlib import redirect_stdout
import io
import json
from pathlib import Path
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

from bugbounty_toolkit import cli
from bugbounty_toolkit.core.scope_validator import ScopeValidator


class AccessCliTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.host = "authorized.example"
        self.base = "https://" + self.host
        (self.root / "scope.txt").write_text(self.host + "\n", encoding="utf-8")
        (self.root / "owner.http").write_text(
            f"PATCH /api/items/update HTTP/1.1\r\nHost: {self.host}\r\nAuthorization: Bearer owner-session\r\n"
            'Content-Type: application/json\r\n\r\n{"item":{"id":"B","title":"same"}}',
            encoding="utf-8",
            newline="",
        )
        (self.root / "actor.http").write_text(
            f"PATCH /api/items/update HTTP/1.1\r\nHost: {self.host}\r\nAuthorization: Bearer actor-session\r\n"
            'Content-Type: application/json\r\n\r\n{"item":{"id":"A","title":"same"}}',
            encoding="utf-8",
            newline="",
        )
        for name, resource_id, token in (
            ("cleanup-owner.http", "B", "owner-session"),
            ("cleanup-actor.http", "A", "actor-session"),
        ):
            (self.root / name).write_text(
                f"GET /api/items/{resource_id} HTTP/1.1\r\nHost: {self.host}\r\nAuthorization: Bearer {token}\r\n\r\n",
                encoding="utf-8",
                newline="",
            )
        self.case_file = self.root / "write-case.json"
        self.case_file.write_text(
            json.dumps(
                {
                    "owner_request": "owner.http",
                    "actor_request": "actor.http",
                    "base_url": self.base,
                    "session_headers": ["Authorization"],
                    "resource": {"json_body_pointer": "/item/id"},
                    "accounts_authorized": True,
                    "resource_private": True,
                    "expected_cross_access": "deny",
                    "disposable_test_resources": True,
                    "cleanup_check": {
                        "owner_request": "cleanup-owner.http",
                        "actor_request": "cleanup-actor.http",
                        "body_pointer": "/item/title",
                        "response_pointer": "/data/title",
                    },
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
        self.store = SimpleNamespace(paths=SimpleNamespace(evidence_dir=self.root))
        self.settings = SimpleNamespace(max_tests=110, max_concurrency=4)
        self.scope = ScopeValidator(self.root / "scope.txt")

    def tearDown(self):
        self.temp.cleanup()

    def _args(self, *options):
        return cli.build_parser().parse_args(
            [
                "access-check",
                "lab",
                "--case-file",
                str(self.case_file),
                *options,
            ]
        )

    def test_public_write_flag_is_opt_in_and_emits_warning(self):
        args = self._args("--lab-write", "--allow-public-writes", "--dry-run")
        output = io.StringIO()
        with (
            patch.object(cli, "executor_context", return_value=(self.store, self.settings, self.scope)),
            patch.object(cli, "client_for", return_value=Mock()),
            redirect_stdout(output),
        ):
            args.func(args)
        self.assertIn("[!] Public writes enabled: requests may modify remote state", output.getvalue())
        self.assertIn("no requests sent", output.getvalue().lower())

    def test_public_write_flag_without_lab_write_is_rejected(self):
        args = self._args("--allow-public-writes")
        with (
            patch.object(cli, "executor_context") as context,
            self.assertRaisesRegex(ValueError, "requires --lab-write"),
        ):
            args.func(args)
        context.assert_not_called()

    def test_lab_write_range_requires_explicit_lab_write_mode(self):
        args = self._args("--lab-write-range", "1-5")
        with (
            patch.object(cli, "executor_context") as context,
            self.assertRaisesRegex(ValueError, "requires --lab-write"),
        ):
            args.func(args)
        context.assert_not_called()

    def test_write_options_require_lab_write(self):
        for option in ("--verify-persistence", "--inverse-write", "--cleanup"):
            args = self._args(option)
            with (
                self.subTest(option=option),
                patch.object(cli, "executor_context") as context,
                self.assertRaisesRegex(ValueError, "require --lab-write"),
            ):
                args.func(args)
            context.assert_not_called()

    def test_read_options_cannot_be_combined_with_write_or_range(self):
        for options in (
            ("--lab-write", "--anonymous-check"),
            ("--range", "1-2", "--inverse-cross"),
            ("--multi-account", "--lab-write"),
        ):
            args = self._args(*options)
            with (
                self.subTest(options=options),
                patch.object(cli, "executor_context") as context,
                self.assertRaisesRegex(ValueError, "apply only to single read-mode"),
            ):
                args.func(args)
            context.assert_not_called()

    def test_public_write_inverse_and_cleanup_dry_run_uses_summed_budget(self):
        args = self._args("--lab-write", "--allow-public-writes", "--inverse-write", "--cleanup", "--dry-run")
        output = io.StringIO()
        client = Mock()
        with (
            patch.object(cli, "executor_context", return_value=(self.store, self.settings, self.scope)),
            patch.object(cli, "client_for", return_value=client),
            redirect_stdout(output),
        ):
            args.func(args)
        self.assertIn("8 requests budgeted", output.getvalue())
        self.assertIn("no requests sent", output.getvalue().lower())
        client.send.assert_not_called()

    def test_public_range_flag_warns_and_defaults_to_one_second(self):
        self._write_get_case()
        args = self._args("--range", "1-2", "--allow-public-range", "--dry-run")
        output = io.StringIO()
        client = Mock()
        with (
            patch.object(cli, "executor_context", return_value=(self.store, self.settings, self.scope)),
            patch.object(cli, "client_for", return_value=client),
            redirect_stdout(output),
        ):
            args.func(args)
        self.assertIn("[!] Public range relaxed: more requests than default", output.getvalue())
        self.assertIn("minimum interval 1s", output.getvalue())
        client.send.assert_not_called()

    def _write_get_case(self):
        for account, identifier, token in (("owner", "20", "owner-session"), ("actor", "10", "actor-session")):
            (self.root / f"{account}.http").write_text(
                f"GET /api/items/{identifier} HTTP/1.1\r\nHost: {self.host}\r\nAuthorization: Bearer {token}\r\n\r\n",
                encoding="utf-8",
                newline="",
            )
        self.case_file = self.root / "read-case.json"
        self.case_file.write_text(
            json.dumps(
                {
                    "owner_request": "owner.http",
                    "actor_request": "actor.http",
                    "base_url": self.base,
                    "session_headers": ["Authorization"],
                    "resource": {"path_segment": 2},
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
                        "owner_marker": "owner-proof-123456",
                        "actor_marker": "actor-proof-654321",
                    },
                }
            ),
            encoding="utf-8",
        )


if __name__ == "__main__":
    unittest.main()
