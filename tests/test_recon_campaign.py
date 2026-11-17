"""Offline tests for scope import, run config, leads, and the resumable pipeline."""

from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
import gc
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from bugbounty_toolkit.recon.campaign import execute_run, progress_visible
from bugbounty_toolkit.recon.config import load_run_config
from bugbounty_toolkit.recon.exports import render_dashboard_html, render_sarif
from bugbounty_toolkit.recon.leads import build_leads, group_assets
from bugbounty_toolkit.recon.models import Observation, ReconReport
from bugbounty_toolkit.recon.pipeline import correlate
from bugbounty_toolkit.recon.program_scope import parse_scope_file
from bugbounty_toolkit.recon.sources import provider_plans

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "recon"
ROOT = Path(__file__).resolve().parents[1]


def _sqlite_paths_still_open(database: Path) -> list[str]:
    target = str(database.resolve())
    open_paths: list[str] = []
    for obj in gc.get_objects():
        if not isinstance(obj, sqlite3.Connection):
            continue
        try:
            rows = obj.execute("PRAGMA database_list").fetchall()
        except sqlite3.ProgrammingError:
            continue
        for row in rows:
            path = row[2]
            if isinstance(path, str) and path and str(Path(path).resolve()) == target:
                open_paths.append(path)
    return open_paths


class MapTransport:
    def __init__(self, pages: dict[str, str]) -> None:
        self.pages = pages
        self.urls: list[str] = []

    def get_text(self, url: str, headers: dict[str, str] | None = None) -> str:
        self.urls.append(url)
        if url not in self.pages:
            raise ValueError("missing fixture")
        return self.pages[url]


class CountingLimiter:
    def __init__(self) -> None:
        self.waits = 0

    def wait(self, max_wait: float | None = None) -> None:
        self.waits += 1


def _pages(target: str, bodies: dict[str, str]) -> dict[str, str]:
    pages: dict[str, str] = {}
    for plan in provider_plans(target, {}):
        if plan.skipped or not plan.url:
            continue
        pages[plan.url] = bodies.get(plan.source, "[]")
    return pages


class ConfigTests(unittest.TestCase):
    def test_example_yaml_and_toml_match(self) -> None:
        yaml_config = load_run_config(ROOT / "config" / "recon.example.yml")
        toml_config = load_run_config(ROOT / "config" / "recon.example.toml")
        self.assertEqual(yaml_config.target, "example.com")
        self.assertEqual(toml_config.target, yaml_config.target)
        self.assertFalse(yaml_config.active)
        self.assertIn("sarif", yaml_config.formats)
        self.assertIn("dashboard", toml_config.formats)

    def test_config_rejects_confirm_unknown_fields_and_bad_types(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            confirm = root / "confirm.yml"
            confirm.write_text("target: example.com\nconfirm: true\n", encoding="utf-8")
            with self.assertRaises(ValueError) as caught:
                load_run_config(confirm)
            self.assertIn("confirm cannot be set", str(caught.exception))
            unknown = root / "unknown.toml"
            unknown.write_text('target = "example.com"\nthreads = 4\n', encoding="utf-8")
            with self.assertRaises(ValueError) as caught:
                load_run_config(unknown)
            self.assertIn("unknown setting threads", str(caught.exception))
            table = root / "table.toml"
            table.write_text("[active]\nenabled = true\n", encoding="utf-8")
            with self.assertRaises(ValueError) as caught:
                load_run_config(table)
            self.assertIn("table.toml:1", str(caught.exception))
            quoted = root / "quoted.yml"
            quoted.write_text('active: "false"\n', encoding="utf-8")
            with self.assertRaises(ValueError) as caught:
                load_run_config(quoted)
            self.assertIn("active must be true or false", str(caught.exception))
            listing = root / "list.yml"
            listing.write_text("- example.com\n", encoding="utf-8")
            with self.assertRaises(ValueError) as caught:
                load_run_config(listing)
            self.assertIn("mapping", str(caught.exception))
            level = root / "level.toml"
            level.write_text('log_level = "loud"\ntarget = "example.com"\ntarget = "example.com"\n', encoding="utf-8")
            with self.assertRaises(ValueError) as caught:
                load_run_config(level)
            self.assertIn("more than once", str(caught.exception))


class ScopeImportTests(unittest.TestCase):
    def test_hackerone_bugcrowd_and_csv_fixtures(self) -> None:
        hackerone = parse_scope_file(FIXTURES / "hackerone.json")
        self.assertEqual(hackerone.source, "hackerone")
        self.assertIn("*.example.com", hackerone.allowed)
        self.assertIn("https://admin.example.com/login", hackerone.excluded)
        self.assertFalse(any("10.0.0.0/8" in rule for rule in hackerone.allowed))
        self.assertFalse(any("com.example.app" in rule for rule in hackerone.allowed))
        self.assertFalse(any(rule == "*.com" for rule in hackerone.allowed))
        self.assertTrue(any("CIDR" in reason for reason in hackerone.skipped))
        self.assertTrue(any("public suffix" in reason for reason in hackerone.skipped))

        bugcrowd = parse_scope_file(FIXTURES / "bugcrowd.json")
        self.assertEqual(bugcrowd.allowed, ("*.example.com",))
        self.assertEqual(bugcrowd.excluded, ("admin.example.com",))

        csv_scope = parse_scope_file(FIXTURES / "scope.csv")
        self.assertIn("app.example.com", csv_scope.allowed)
        self.assertIn("secret.example.com", csv_scope.excluded)
        self.assertNotIn("maybe.example.com", csv_scope.allowed)
        self.assertTrue(any("CIDR" in reason or "cidr" in reason.lower() for reason in csv_scope.skipped))
        self.assertTrue(any("maybe" in reason for reason in csv_scope.skipped))

    def test_ambiguous_json_asks_for_a_format(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "both.json"
            path.write_text(
                json.dumps(
                    {
                        "target_groups": [{"in_scope": True, "targets": [{"uri": "example.com"}]}],
                        "data": [{"attributes": {"asset_identifier": "example.com", "asset_type": "URL"}}],
                    }
                ),
                encoding="utf-8",
            )
            with self.assertRaises(ValueError) as caught:
                parse_scope_file(path)
            self.assertIn("--format", str(caught.exception))
            chosen = parse_scope_file(path, "bugcrowd")
            self.assertEqual(chosen.source, "bugcrowd")

    def test_yaml_csv_and_loose_json_shapes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            yaml_scope = root / "scope.yaml"
            yaml_scope.write_text("allowed:\n  - example.com\nexcluded:\n  - admin.example.com\n", encoding="utf-8")
            imported = parse_scope_file(yaml_scope)
            self.assertEqual(imported.allowed, ("example.com",))
            self.assertEqual(imported.excluded, ("admin.example.com",))
            broken = root / "broken.yaml"
            broken.write_text("notes: []\n", encoding="utf-8")
            with self.assertRaises(ValueError) as caught:
                parse_scope_file(broken)
            self.assertIn("allowed and excluded", str(caught.exception))
            csv_scope = root / "missing.csv"
            csv_scope.write_text("notes\nhello\n", encoding="utf-8")
            with self.assertRaises(ValueError) as caught:
                parse_scope_file(csv_scope)
            self.assertIn("target column", str(caught.exception))
            bad_json = root / "bad.json"
            bad_json.write_text("{", encoding="utf-8")
            with self.assertRaises(ValueError) as caught:
                parse_scope_file(bad_json)
            self.assertIn("not valid JSON", str(caught.exception))
            listed = root / "targets.json"
            listed.write_text(
                json.dumps(
                    {
                        "targets": [
                            {"uri": "app.example.com", "in_scope": True},
                            {"uri": "vpn.example.com", "in_scope": False},
                        ]
                    }
                ),
                encoding="utf-8",
            )
            bugcrowd = parse_scope_file(listed)
            self.assertIn("app.example.com", bugcrowd.allowed)
            self.assertIn("vpn.example.com", bugcrowd.excluded)
            grouped = root / "groups.json"
            grouped.write_text(
                json.dumps(
                    {
                        "targets": {
                            "in_scope": [{"asset_identifier": "*.example.net", "asset_type": "WILDCARD"}],
                            "out_of_scope": [{"asset_identifier": "admin.example.net", "asset_type": "URL"}],
                        }
                    }
                ),
                encoding="utf-8",
            )
            hackerone = parse_scope_file(grouped, "hackerone")
            self.assertIn("*.example.net", hackerone.allowed)
            self.assertIn("admin.example.net", hackerone.excluded)
            with self.assertRaises(ValueError):
                parse_scope_file(yaml_scope, "xml")


class LeadTests(unittest.TestCase):
    def test_leads_are_grouped_and_never_confirmed(self) -> None:
        report = ReconReport(target="203.0.113.10", dry_run=False, active=False, nuclei=False)
        report.observations = [
            Observation("203.0.113.10", "shodan-internetdb", "port", "22"),
            Observation("203.0.113.10", "shodan-internetdb", "cve", "CVE-2024-12345"),
            Observation("203.0.113.10", "manual", "tech", "OpenSSL", "1.0.1"),
            Observation("dev.example.com", "saved", "host", "dev.example.com"),
            Observation("jenkins.example.com", "saved", "host", "jenkins.example.com"),
            Observation("app.example.com", "wayback", "url", "https://app.example.com/wp-admin/"),
            Observation("app.example.com", "hackertarget", "ip", "198.51.100.10"),
            Observation("dev.example.com", "hackertarget", "ip", "198.51.100.10"),
            Observation("example.dev", "saved", "host", "example.dev"),
        ]
        report.assets = correlate(report.observations)
        leads = build_leads(report)
        groups = group_assets(report)
        categories = {lead.category for lead in leads}
        self.assertIn("exposed-service", categories)
        self.assertIn("outdated-tech", categories)
        self.assertIn("staging-or-dev", categories)
        self.assertTrue(all(lead.confirmed is False for lead in leads))
        self.assertTrue(all(lead.to_dict()["confirmed"] is False for lead in leads))
        exposed = next(lead for lead in leads if lead.category == "exposed-service")
        self.assertIn("not probed", exposed.detail)
        self.assertIn("not a confirmed vulnerability", exposed.detail.lower())
        ip_groups = [group for group in groups if group.kind == "ip"]
        self.assertEqual(ip_groups[0].key, "198.51.100.10")
        self.assertEqual(set(ip_groups[0].members), {"app.example.com", "dev.example.com"})
        self.assertTrue(any(group.kind == "tech" and group.key == "Jenkins" for group in groups))
        self.assertTrue(any(group.kind == "tech" and group.key == "WordPress" for group in groups))
        self.assertFalse(any(lead.host == "example.dev" and lead.category == "staging-or-dev" for lead in leads))
        html = render_dashboard_html(
            report,
            leads,
            groups,
            {"passive": "complete"},
            {"baseline_present": False},
        )
        report.errors.append("<script>alert(1)</script>")
        html = render_dashboard_html(report, leads, groups, {"passive": "complete"}, {"baseline_present": False})
        self.assertIn("Confirmed vulnerabilities: 0", html)
        self.assertIn("&lt;script&gt;", html)
        self.assertNotIn("<script>", html)
        sarif = json.loads(render_sarif(report, leads))
        self.assertEqual(sarif["version"], "2.1.0")
        self.assertTrue(sarif["runs"][0]["results"])
        self.assertTrue(all(result["level"] == "note" for result in sarif["runs"][0]["results"]))
        self.assertTrue(all(result["properties"]["confirmed"] is False for result in sarif["runs"][0]["results"]))
        self.assertIn("Not a confirmed vulnerability", sarif["runs"][0]["results"][0]["message"]["text"])


class CampaignTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.scope = self.root / "scope.txt"
        self.scope.write_text("example.com\n*.example.com\n!admin.example.com\n", encoding="utf-8")
        self.reports = self.root / "reports"
        self.bodies = {
            "crtsh": "[]",
            "certspotter": "[]",
            "wayback": json.dumps(
                [["original"], ["https://app.example.com/admin/login"], ["https://app.example.com/wp-admin/"]]
            ),
            "otx": "{}",
            "hackertarget": "app.example.com,198.51.100.10\n",
            "urlscan": "{}",
        }

    def tearDown(self) -> None:
        self.temp.cleanup()

    def _run(self, transport: MapTransport, **kwargs: object) -> object:
        options: dict[str, object] = {
            "transport": transport,
            "rate_limiter": CountingLimiter(),
            "run_tools": False,
            "formats": ("json", "sarif", "dashboard", "markdown", "html"),
        }
        options.update(kwargs)
        return execute_run("example.com", self.scope, self.reports, **options)  # type: ignore[arg-type]

    def test_resume_does_not_repeat_provider_requests_and_diff_lists_new_hosts(self) -> None:
        first_transport = MapTransport(_pages("example.com", self.bodies))
        first = self._run(first_transport)
        self.assertGreater(len(first_transport.urls), 0)
        self.assertTrue(any(lead.category == "admin-panel" for lead in first.leads))  # type: ignore[attr-defined]
        self.assertTrue((self.reports / "run-state.json").is_file())
        self.assertTrue((self.reports / "recon.sarif.json").is_file())
        self.assertTrue((self.reports / "dashboard.html").is_file())
        self.assertIn('"confirmed": false', (self.reports / "run.json").read_text(encoding="utf-8"))
        second_transport = MapTransport({})
        second = self._run(second_transport, resume=True)
        self.assertEqual(second_transport.urls, [])
        self.assertTrue(second.resumed)  # type: ignore[attr-defined]
        self.bodies["hackertarget"] = "app.example.com,198.51.100.10\nstaging.example.com,198.51.100.11\n"
        third_transport = MapTransport(_pages("example.com", self.bodies))
        third = self._run(third_transport, refresh=True, show_diff=True)
        self.assertGreater(len(third_transport.urls), 0)
        self.assertIn("staging.example.com", third.diff.new_hosts)  # type: ignore[attr-defined]
        self.assertTrue(any("new host staging.example.com" in event.text for event in third.progress))  # type: ignore[attr-defined]
        self.assertNotIn("trail-secret", (self.reports / "run.json").read_text(encoding="utf-8"))

    def test_active_without_confirm_contacts_nobody_and_nuclei_can_be_turned_off(self) -> None:
        transport = MapTransport(_pages("example.com", self.bodies))
        with self.assertRaises(ValueError) as caught:
            self._run(transport, active=True, confirm=False)
        self.assertIn("--confirm", str(caught.exception))
        self.assertEqual(transport.urls, [])

        calls: list[str] = []

        def runner(name: str, argv: list[str]) -> str:
            calls.append(name)
            self.assertEqual(argv[0], name)
            if name == "nuclei":
                return "[exposed-panel] [http] [medium] https://api.example.com/login\n"
            if name == "httpx":
                return "https://api.example.com/login\n"
            return "api.example.com\n"

        self.bodies["hackertarget"] = "api.example.com,198.51.100.10\n"
        live = MapTransport(_pages("example.com", self.bodies))
        first = self._run(
            live,
            active=True,
            nuclei=True,
            confirm=True,
            tool_runner=runner,
            hosts_path=self.root / "raw" / "subdomains.txt",
        )
        self.assertIn("nuclei", calls)
        self.assertTrue(any(asset.nuclei for asset in first.report.assets))  # type: ignore[attr-defined]
        self.assertTrue(all(asset.confirmed is False for asset in first.report.assets))  # type: ignore[attr-defined]
        calls.clear()
        again = MapTransport({})
        second = self._run(
            again,
            active=True,
            nuclei=False,
            confirm=True,
            resume=True,
            tool_runner=runner,
            hosts_path=self.root / "raw" / "subdomains.txt",
        )
        self.assertEqual(again.urls, [])
        self.assertNotIn("nuclei", calls)
        self.assertIn("dnsx", calls)
        self.assertFalse(any(asset.nuclei for asset in second.report.assets))  # type: ignore[attr-defined]

    def test_dry_run_plans_active_tools_without_writing_state(self) -> None:
        outcome = self._run(MapTransport({}), dry_run=True, active=True, nuclei=True)
        self.assertTrue(outcome.report.dry_run)  # type: ignore[attr-defined]
        self.assertTrue(any("httpx" in event.text for event in outcome.progress))  # type: ignore[attr-defined]
        self.assertFalse((self.reports / "run-state.json").exists())
        with self.assertRaises(ValueError) as caught:
            self._run(MapTransport({}), resume=True)
        self.assertIn("No saved run state", str(caught.exception))

    def test_corrupt_resume_state_names_the_file(self) -> None:
        self.reports.mkdir()
        (self.reports / "run-state.json").write_text("{", encoding="utf-8")
        with self.assertRaises(ValueError) as caught:
            self._run(MapTransport({}), resume=True)
        self.assertIn("run-state.json", str(caught.exception))

    def test_log_level_hides_info_progress(self) -> None:
        from bugbounty_toolkit.recon.campaign import Progress

        info = Progress("info", "stage")
        summary = Progress("info", "done", always=True)
        warning = Progress("warning", "check")
        self.assertFalse(progress_visible(info, "warning"))
        self.assertTrue(progress_visible(summary, "warning"))
        self.assertTrue(progress_visible(warning, "warning"))


class CliTests(unittest.TestCase):
    def test_import_and_dry_run_write_nothing_and_close_the_database(self) -> None:
        from io import StringIO

        from bugbounty_toolkit import cli

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            commands = [
                [
                    "bbtk",
                    "--records-root",
                    str(root),
                    "init",
                    "lab",
                    "--authorization",
                    "written approval",
                    "--automation-allowed",
                ],
                [
                    "bbtk",
                    "--records-root",
                    str(root),
                    "scope",
                    "import",
                    "lab",
                    str(FIXTURES / "hackerone.json"),
                ],
                [
                    "bbtk",
                    "--records-root",
                    str(root),
                    "run",
                    "lab",
                    "--target",
                    "example.com",
                    "--dry-run",
                    "--log-level",
                    "warning",
                ],
            ]
            output: list[str] = []
            for command in commands:
                buffer = StringIO()
                with patch("sys.argv", command), redirect_stdout(buffer):
                    cli.main()
                output.append(buffer.getvalue())
            scope = (root / "lab" / "scope.txt").read_text(encoding="utf-8")
            self.assertIn("*.example.com", scope)
            self.assertIn("!https://admin.example.com/login", scope)
            self.assertNotIn("10.0.0.0/8", scope)
            self.assertNotIn("*.com", scope)
            self.assertIn("Dry run", output[-1])
            self.assertNotIn("passive: planned", output[-1])
            self.assertFalse((root / "lab" / "reports" / "run-state.json").exists())
            database = root / "lab" / "toolkit.sqlite3"
            self.assertEqual(_sqlite_paths_still_open(database), [])

    def test_missing_target_and_config_confirm_fail_before_a_saved_run(self) -> None:
        from io import StringIO

        from bugbounty_toolkit import cli

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = root / "bad.yml"
            config.write_text("target: example.com\nconfirm: true\n", encoding="utf-8")
            init = [
                "bbtk",
                "--records-root",
                str(root),
                "init",
                "lab",
                "--authorization",
                "written approval",
                "--automation-allowed",
            ]
            with patch("sys.argv", init), redirect_stdout(StringIO()):
                cli.main()
            stderr = StringIO()
            command = ["bbtk", "--records-root", str(root), "run", "lab", "--config", str(config)]
            with patch("sys.argv", command), redirect_stderr(stderr), self.assertRaises(SystemExit) as caught:
                cli.main()
            self.assertEqual(caught.exception.code, 1)
            self.assertIn("confirm cannot be set", stderr.getvalue())
            database = root / "lab" / "toolkit.sqlite3"
            self.assertEqual(_sqlite_paths_still_open(database), [])


if __name__ == "__main__":
    unittest.main()
