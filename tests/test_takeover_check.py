from __future__ import annotations

import json
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from bugbounty_toolkit import cli
from bugbounty_toolkit.core.records import ProgramPaths, RecordStore
from bugbounty_toolkit.takeover_check import (
    MAX_CNAME_RECORDS,
    analyze_cnames,
    match_services,
    normalize_dns_name,
    resolve_cname_records,
)


class TakeoverCheckTests(unittest.TestCase):
    def test_local_signatures_match_known_provider_suffixes(self):
        cases = {
            "docs-bucket.s3-website.us-west-2.amazonaws.com.": "Amazon S3",
            "custom-123.herokudns.com": "Heroku",
            "jenmar.github.io": "GitHub Pages",
            "site-name.netlify.app": "Netlify",
        }
        for cname, provider in cases.items():
            with self.subTest(provider=provider):
                self.assertIn(provider, match_services(cname))

    def test_candidate_is_possible_only_and_does_not_claim_unavailability(self):
        result = analyze_cnames(
            "Docs.Example.com.",
            ["project.netlify.app.", "project.netlify.app"],
            "supplied_offline",
        )
        self.assertEqual(result["host"], "docs.example.com")
        self.assertEqual(result["cname_records"], ["project.netlify.app"])
        self.assertEqual(result["classification"], "possible_takeover")
        self.assertEqual(result["unclaimed_status"], "not_verified")
        self.assertFalse(result["confirmed"])
        self.assertEqual(result["network_requests_sent"], 0)
        self.assertEqual(result["http_requests_sent"], 0)

    def test_unknown_suffix_and_similarly_named_attacker_host_do_not_match(self):
        self.assertEqual(match_services("project.netlify.app.attacker.invalid"), [])
        result = analyze_cnames("docs.example.com", ["host.other.invalid"], "supplied_offline")
        self.assertEqual(result["classification"], "not_observed")

    def test_invalid_hosts_and_urls_are_rejected(self):
        for value in ("https://example.com/path", "127.0.0.1", "bad..example.com", "*.example.com"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                normalize_dns_name(value)

    def test_cname_input_count_is_bounded(self):
        with self.assertRaisesRegex(ValueError, str(MAX_CNAME_RECORDS)):
            analyze_cnames("docs.example.com", ["x.invalid"] * (MAX_CNAME_RECORDS + 1), "supplied_offline")

    def test_dns_lookup_uses_one_cname_query_and_normalizes_answer(self):
        resolver = SimpleNamespace(
            resolve=lambda host, record_type, lifetime: self._answer(host, record_type, lifetime)
        )
        module = SimpleNamespace(Resolver=lambda: resolver)
        records, status, queries = resolve_cname_records("Docs.Example.com.", module)
        self.assertEqual(records, ["project.netlify.app"])
        self.assertEqual(status, "resolved")
        self.assertEqual(queries, 1)

    @staticmethod
    def _answer(host: str, record_type: str, lifetime: float) -> list[object]:
        if (host, record_type, lifetime) != ("docs.example.com", "CNAME", 3.0):
            raise AssertionError("unexpected DNS query")
        return [SimpleNamespace(target="Project.Netlify.App.")]

    def test_missing_optional_dns_dependency_is_reported_without_query(self):
        with patch("bugbounty_toolkit.takeover_check.importlib.import_module", side_effect=ModuleNotFoundError):
            records, status, queries = resolve_cname_records("docs.example.com")
        self.assertEqual(records, [])
        self.assertEqual(status, "dnspython_unavailable")
        self.assertEqual(queries, 0)

    def test_dns_errors_are_summarized_without_echoing_resolver_details(self):
        def fail(*args, **kwargs):
            raise TimeoutError("private resolver diagnostic")

        module = SimpleNamespace(Resolver=lambda: SimpleNamespace(resolve=fail))
        records, status, queries = resolve_cname_records("docs.example.com", module)
        self.assertEqual(records, [])
        self.assertEqual(status, "timeout")
        self.assertEqual(queries, 1)
        self.assertNotIn("private", status)

    def test_cli_offline_mode_checks_scope_writes_evidence_and_never_queries_dns(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            paths = ProgramPaths(root, "lab")
            paths.program_dir.mkdir(parents=True)
            paths.scope_file.write_text("*.example.com\n", encoding="utf-8")
            output = StringIO()
            argv = [
                "bbtk",
                "--records-root",
                str(root),
                "takeover-check",
                "lab",
                "--host",
                "docs.example.com",
                "--cname",
                "docs-project.github.io",
            ]
            with (
                patch.object(sys, "argv", argv),
                patch("bugbounty_toolkit.cli.resolve_cname_records", side_effect=AssertionError("DNS must stay off")),
                redirect_stdout(output),
            ):
                cli.main()
            evidence_files = list((paths.evidence_dir / "takeover").glob("*.json"))
            self.assertEqual(len(evidence_files), 1)
            data = json.loads(evidence_files[0].read_text(encoding="utf-8"))
            self.assertEqual(data["classification"], "possible_takeover")
            self.assertEqual(data["dns_queries_attempted"], 0)
            self.assertIn("possible_takeover", output.getvalue())

    def test_cli_rejects_out_of_scope_host_before_dns(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            paths = ProgramPaths(root, "lab")
            paths.program_dir.mkdir(parents=True)
            paths.scope_file.write_text("example.com\n", encoding="utf-8")
            argv = [
                "bbtk",
                "--records-root",
                str(root),
                "takeover-check",
                "lab",
                "--host",
                "outside.invalid",
                "--resolve-dns",
            ]
            with (
                patch.object(sys, "argv", argv),
                patch("bugbounty_toolkit.cli.resolve_cname_records", side_effect=AssertionError("DNS must stay off")),
                patch("sys.stderr", new_callable=StringIO) as stderr,
                self.assertRaises(SystemExit),
            ):
                cli.main()
            self.assertIn("outside configured scope", stderr.getvalue())

    def test_dns_dry_run_requires_authorization_but_never_queries(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            paths = ProgramPaths(root, "lab")
            paths.program_dir.mkdir(parents=True)
            paths.scope_file.write_text("*.example.com\n", encoding="utf-8")
            store = RecordStore(paths)
            store.set_program_meta(authorization="test-policy-reference")
            store.close()
            output = StringIO()
            argv = [
                "bbtk",
                "--records-root",
                str(root),
                "takeover-check",
                "lab",
                "--host",
                "docs.example.com",
                "--resolve-dns",
                "--dry-run",
            ]
            with (
                patch.object(sys, "argv", argv),
                patch("bugbounty_toolkit.cli.resolve_cname_records", side_effect=AssertionError("dry-run queried DNS")),
                redirect_stdout(output),
            ):
                cli.main()
            self.assertIn("No DNS or HTTP requests sent", output.getvalue())


if __name__ == "__main__":
    unittest.main()
