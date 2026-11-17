"""Offline recon fixtures. No test in this module opens a socket."""

from __future__ import annotations

import gc
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from bugbounty_toolkit.core.scope import ensure_in_scope
from bugbounty_toolkit.recon.models import Observation
from bugbounty_toolkit.recon.pipeline import run_recon
from bugbounty_toolkit.recon.reporting import write_recon_reports
from bugbounty_toolkit.recon.sources import PassiveHttpTransport, assert_provider_url, provider_plans
from bugbounty_toolkit.recon.tools import ToolMissing


FIXTURES = {
    "crtsh": json.dumps(
        [
            {
                "name_value": (
                    "app.example.com\nadmin.example.com\nevil.com\n"
                    "*.secret.example.com\nchild.secret.example.com\ntrail-secret.example.com"
                )
            }
        ]
    ),
    "certspotter": json.dumps([{"dns_names": ["app.example.com", "api.example.com"]}]),
    "wayback": json.dumps(
        [
            ["original"],
            ["https://app.example.com/admin/login"],
            ["https://evil.com/secret"],
            ["http://user:pass@app.example.com/"],
        ]
    ),
    "otx": json.dumps({"passive_dns": [{"hostname": "app.example.com"}, {"hostname": "out.example.net"}]}),
    "hackertarget": "app.example.com,1.2.3.4\nevil.com,9.9.9.9\n",
    "urlscan": json.dumps(
        {
            "results": [
                {
                    "page": {"domain": "app.example.com", "url": "https://app.example.com/login"},
                    "task": {"url": "https://app.example.com/"},
                }
            ]
        }
    ),
    "securitytrails": json.dumps({"subdomains": ["api", "admin", "../evil"]}),
    "virustotal": json.dumps({"data": [{"id": "api.example.com"}]}),
    "shodan-internetdb": json.dumps(
        {
            "ip": "203.0.113.10",
            "ports": [22, 80, True],
            "vulns": ["CVE-2024-12345", "not-a-cve"],
            "hostnames": ["app.example.com", "evil.com"],
        }
    ),
}


def _sqlite_paths_still_open(database: Path) -> list[str]:
    """Paths of live SQLite connections still holding this file.

    An unclosed connection keeps the file locked on Windows after the CLI returns.
    """
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
        self.headers: list[dict[str, str]] = []

    def get_text(self, url: str, headers: dict[str, str] | None = None) -> str:
        self.urls.append(url)
        self.headers.append(dict(headers or {}))
        if url not in self.pages:
            raise ValueError("missing fixture")
        return self.pages[url]


class CountingLimiter:
    def __init__(self) -> None:
        self.waits = 0

    def wait(self, max_wait: float | None = None) -> None:
        self.waits += 1


class ReconPipelineTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.scope = Path(self.temp.name) / "scope.txt"
        self.scope.write_text(
            "*.example.com\n!admin.example.com\n!secret.example.com\n!*.secret.example.com\n203.0.113.10\n",
            encoding="utf-8",
        )
        self.keys = {"securitytrails": "trail-secret", "virustotal": "vt-secret"}

    def tearDown(self) -> None:
        self.temp.cleanup()

    def _pages(self, target: str) -> dict[str, str]:
        pages: dict[str, str] = {}
        for plan in provider_plans(target, self.keys):
            if plan.skipped or not plan.url:
                continue
            pages[plan.url] = FIXTURES[plan.source]
        return pages

    def test_passive_results_are_deduped_scoped_sourced_and_scored(self) -> None:
        transport = MapTransport(self._pages("example.com"))
        limiter = CountingLimiter()
        report = run_recon(
            "example.com",
            self.scope,
            transport=transport,
            rate_limiter=limiter,
            api_keys=self.keys,
        )
        self.assertEqual(report.requests_sent, limiter.waits)
        self.assertGreaterEqual(limiter.waits, 6)
        self.assertFalse(report.active)
        self.assertEqual(report.tool_argv, [])
        hosts = {asset.host: asset for asset in report.assets}
        self.assertIn("app.example.com", hosts)
        self.assertIn("api.example.com", hosts)
        self.assertNotIn("admin.example.com", hosts)
        self.assertNotIn("secret.example.com", hosts)
        self.assertNotIn("child.secret.example.com", hosts)
        self.assertNotIn("evil.com", hosts)
        self.assertNotIn("out.example.net", hosts)
        app = hosts["app.example.com"]
        self.assertGreaterEqual(len(app.sources), 2)
        self.assertIn("crtsh", app.sources)
        self.assertIn("wayback", app.sources)
        ip_observations = {(item.host, item.value) for item in report.observations if item.kind == "ip"}
        self.assertIn(("app.example.com", "1.2.3.4"), ip_observations)
        self.assertNotIn("evil.com", {item.host for item in report.observations if item.kind == "ip"})
        self.assertTrue(any("/admin/login" in url for url in app.urls))
        self.assertNotIn("user:pass", " ".join(app.urls))
        self.assertFalse(app.confirmed)
        self.assertIn(app.severity, {"low", "medium"})
        self.assertLessEqual(app.score, 5)
        rendered = json.dumps(report.to_dict())
        self.assertNotIn("trail-secret", rendered)
        self.assertNotIn("vt-secret", rendered)
        self.assertTrue(any(headers.get("APIKEY") == "trail-secret" for headers in transport.headers))
        for url in transport.urls:
            assert_provider_url(url)
            self.assertNotIn("trail-secret", url)
            self.assertNotIn("vt-secret", url)

    def test_dry_run_and_unconfirmed_active_plan_do_not_fetch(self) -> None:
        transport = MapTransport(self._pages("example.com"))
        limiter = CountingLimiter()
        dry = run_recon("example.com", self.scope, transport=transport, rate_limiter=limiter, dry_run=True, active=True)
        self.assertEqual(transport.urls, [])
        self.assertEqual(limiter.waits, 0)
        self.assertEqual(dry.requests_sent, 0)
        self.assertTrue(any(argv[0] == "httpx" for argv in dry.tool_argv))
        self.assertTrue(any(argv[0] == "dnsx" for argv in dry.tool_argv))
        self.assertFalse(any(argv[0] == "nuclei" for argv in dry.tool_argv))
        with self.assertRaises(ValueError):
            run_recon(
                "example.com",
                self.scope,
                transport=transport,
                rate_limiter=limiter,
                active=True,
                confirm=False,
            )
        self.assertEqual(transport.urls, [])

    def test_active_tools_are_opt_in_and_missing_binaries_are_explicit(self) -> None:
        calls: list[list[str]] = []

        def runner(name: str, argv: list[str]) -> str:
            calls.append(argv)
            self.assertEqual(argv[0], name)
            self.assertNotIn("shell=True", " ".join(argv))
            if name == "amass":
                raise ToolMissing(name)
            if name == "subfinder":
                return "api.example.com\nevil.com\nadmin.example.com\n"
            if name == "dnsx":
                return "api.example.com\n"
            if name == "httpx":
                return "https://api.example.com/login [200]\nhttps://evil.com/\n"
            if name == "nuclei":
                return (
                    "[exposed-panel] [http] [medium] https://api.example.com/login\n"
                    "ignore this free-form scanner payload line\n"
                )
            raise AssertionError(name)

        report = run_recon(
            "example.com",
            self.scope,
            transport=MapTransport({}),
            rate_limiter=CountingLimiter(),
            tool_runner=runner,
            active=True,
            nuclei=True,
            confirm=True,
            run_tools=True,
            api_keys={},
            hosts_path=Path(self.temp.name) / "raw" / "subdomains.txt",
        )
        joined = "\n".join(" ".join(argv) for argv in calls)
        self.assertIn("subfinder", joined)
        self.assertIn("-disable-update-check", joined)
        self.assertIn("-ni", joined)
        self.assertIn("dos,intrusive,fuzz", joined)
        self.assertTrue(any("not installed" in error and "shell" in error for error in report.errors))
        hosts = {asset.host: asset for asset in report.assets}
        self.assertIn("api.example.com", hosts)
        self.assertNotIn("evil.com", hosts)
        self.assertNotIn("admin.example.com", hosts)
        self.assertTrue(hosts["api.example.com"].nuclei)
        self.assertFalse(hosts["api.example.com"].confirmed)
        self.assertEqual(hosts["api.example.com"].severity, "medium")
        text = (Path(self.temp.name) / "raw" / "subdomains.txt").read_text(encoding="utf-8")
        self.assertNotIn("evil.com", text)
        self.assertNotIn("admin.example.com", text)

    def test_skip_providers_reuses_seed_without_contacting_providers(self) -> None:
        transport = MapTransport({})

        def runner(name: str, argv: list[str]) -> str:
            self.assertEqual(argv[0], name)
            return ""

        report = run_recon(
            "example.com",
            self.scope,
            transport=transport,
            rate_limiter=CountingLimiter(),
            tool_runner=runner,
            active=True,
            confirm=True,
            run_tools=True,
            skip_providers=True,
            skip_passive_tools=True,
            seed=[Observation("app.example.com", "saved", "host", "app.example.com")],
            hosts_path=Path(self.temp.name) / "raw" / "subdomains.txt",
        )
        self.assertEqual(transport.urls, [])
        self.assertEqual(report.requests_sent, 0)
        self.assertIn("app.example.com", {asset.host for asset in report.assets})
        hosts = (Path(self.temp.name) / "raw" / "subdomains.txt").read_text(encoding="utf-8")
        self.assertIn("app.example.com", hosts)
        self.assertNotIn("evil.com", hosts)

    def test_out_of_scope_target_never_builds_requests(self) -> None:
        transport = MapTransport({})
        with self.assertRaises(ValueError):
            run_recon("other.com", self.scope, transport=transport, rate_limiter=CountingLimiter())
        self.assertEqual(transport.urls, [])

    def test_internetdb_ips_are_correlated_without_probing_ports(self) -> None:
        transport = MapTransport(self._pages("203.0.113.10"))
        report = run_recon(
            "203.0.113.10",
            self.scope,
            transport=transport,
            rate_limiter=CountingLimiter(),
        )
        self.assertEqual(len(transport.urls), 1)
        self.assertIn("internetdb.shodan.io", transport.urls[0])
        asset = next(item for item in report.assets if item.host == "203.0.113.10")
        self.assertIn(22, asset.ports)
        self.assertNotIn(1, asset.ports)
        self.assertEqual(asset.cves, ["CVE-2024-12345"])
        self.assertIn("app.example.com", {item.host for item in report.assets})
        self.assertNotIn("evil.com", {item.host for item in report.assets})
        self.assertFalse(asset.confirmed)
        self.assertIn("not probed", " ".join(asset.reasons))

    def test_reports_escape_html_and_do_not_confirm_findings(self) -> None:
        report = run_recon("example.com", self.scope, dry_run=True)
        written = write_recon_reports(report, Path(self.temp.name) / "reports")
        html = written["html"].read_text(encoding="utf-8")
        markdown = written["markdown"].read_text(encoding="utf-8")
        self.assertIn("no vulnerability is confirmed", markdown.lower())
        self.assertIn('"confirmed": false', written["json"].read_text(encoding="utf-8"))
        self.assertNotIn("<script>", html)

    def test_provider_transport_rejects_non_allowlisted_urls(self) -> None:
        transport = PassiveHttpTransport()
        opener_calls: list[str] = []

        def open_request(request, timeout):  # noqa: ANN001
            opener_calls.append(request.full_url)
            raise OSError("stopped")

        transport.opener.open = open_request  # type: ignore[method-assign]
        for url in ("http://127.0.0.1/", "https://crt.sh.evil/x", "https://user:pass@crt.sh/", "https://crt.sh:444/"):
            with self.subTest(url=url), self.assertRaises(ValueError):
                transport.get_text(url)
        self.assertEqual(opener_calls, [])
        with self.assertRaises(ValueError):
            transport.get_text("https://crt.sh/?q=example.com")
        self.assertEqual(opener_calls, ["https://crt.sh/?q=example.com"])

    def test_recon_package_does_not_shell_out_or_unpickle(self) -> None:
        root = Path(__file__).resolve().parents[1] / "bugbounty_toolkit" / "recon"
        for path in root.rglob("*.py"):
            text = path.read_text(encoding="utf-8")
            self.assertNotIn("shell=True", text)
            self.assertNotIn("pickle", text)

    def test_cli_dry_run_prints_plan_without_network(self) -> None:
        from io import StringIO
        from contextlib import redirect_stdout

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
                ["bbtk", "--records-root", str(root), "scope", "add", "lab", "example.com"],
                ["bbtk", "--records-root", str(root), "scope", "add", "lab", "*.example.com"],
                ["bbtk", "--records-root", str(root), "recon", "lab", "--target", "example.com", "--dry-run"],
            ]
            output: list[str] = []
            for command in commands:
                buffer = StringIO()
                with patch("sys.argv", command), redirect_stdout(buffer):
                    cli.main()
                output.append(buffer.getvalue())
            self.assertIn("No provider requests", output[-1])
            self.assertIn("crtsh", output[-1])
            self.assertFalse((root / "lab" / "reports" / "recon.json").exists())
            database = root / "lab" / "toolkit.sqlite3"
            self.assertTrue(database.is_file())
            self.assertEqual(_sqlite_paths_still_open(database), [])


class ScopeHelperTests(unittest.TestCase):
    def test_explicit_ip_remains_addressable(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            scope = Path(directory) / "scope.txt"
            scope.write_text("203.0.113.10\n", encoding="utf-8")
            ensure_in_scope("https://203.0.113.10/", scope)


if __name__ == "__main__":
    unittest.main()
