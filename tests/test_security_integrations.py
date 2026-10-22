import base64
import importlib.util
import json
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch

from bugbounty_toolkit.analysis.html_context import analyze_html
from bugbounty_toolkit.analysis.jwt_inspector import inspect_jwt
from bugbounty_toolkit.analysis.sql_query import analyze_sql
from bugbounty_toolkit.core.scope_validator import ScopeValidator
from bugbounty_toolkit.core.settings import ExecutorSettings
from bugbounty_toolkit.integrations.catalog import catalog
from bugbounty_toolkit.integrations.external_plan import build_external_plan
from bugbounty_toolkit import cli


class CatalogAndPlanTests(unittest.TestCase):
    def test_catalog_is_available_without_optional_dependencies(self):
        with patch("subprocess.run") as process:
            data = catalog()
        self.assertEqual(data["network_requests_sent"], 0)
        self.assertIn("jwt", data["python_extras"])
        self.assertIn("seclists-sqli", {item["name"] for item in data["resources"]})
        process.assert_not_called()

    def test_access_resources_distinguish_catalog_from_adapters(self):
        with (
            patch("socket.create_connection", side_effect=AssertionError("offline catalog")),
            patch("subprocess.run") as process,
        ):
            data = catalog()
        resources = {item["name"]: item for item in data["resources"]}
        for name in ("autorize", "authmatrix", "authz"):
            self.assertEqual(resources[name]["mode"], "burp-extension")
            self.assertIsNone(resources[name]["on_path"])
        for name in ("feroxbuster", "gobuster", "arjun", "x8", "paramspider"):
            self.assertTrue(resources[name]["mode"].startswith("manual-"))
        self.assertEqual(resources["ffuf"]["mode"], "bounded-adapter")
        self.assertEqual(resources["seclists-passwords"]["mode"], "reference-no-guessing-adapter")
        self.assertIn("httpx", data["python_extras"]["http"])
        self.assertEqual(data["network_requests_sent"], 0)
        process.assert_not_called()

    def test_plans_are_literal_scoped_and_not_executed(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "scope.txt"
            path.write_text("https://example.com/search\n!https://example.com/search/private\n")
            scope = ScopeValidator(path)
            settings = ExecutorSettings(requests_per_second=0.1)
            with patch("subprocess.run") as process:
                for tool in ("sqlmap", "xsstrike", "dalfox"):
                    plan = build_external_plan(tool, "https://example.com/search?q=1", "q", scope, settings)
                    self.assertFalse(plan["executed"])
                    self.assertFalse(plan["automatic_request_budget_enforced"])
                    self.assertEqual(plan["minimum_delay_seconds"], 10)
                    self.assertIn("https://example.com/search?q=1", plan["command"])
                    self.assertNotIn("--dump", plan["command"])
                    if tool == "dalfox":
                        self.assertIn("--insecure=false", plan["command"])
                        self.assertIn("10000", plan["command"])
                process.assert_not_called()
            for url in ("https://outside.example/search?q=1", "https://example.com/search/private?q=1"):
                with self.assertRaises(ValueError):
                    build_external_plan("sqlmap", url, "q", scope, settings)
            for tool, url, name in (
                ("xsstrike", "https://example.com/search?q=1&other=2", "q"),
                ("sqlmap", "https://example.com/search?q=1&q=2", "q"),
                ("sqlmap", "https://example.com/search?q=1", "missing"),
                ("sqlmap", "https://example.com/search?q=1", "--dump"),
            ):
                with self.assertRaises(ValueError):
                    build_external_plan(tool, url, name, scope, settings)
            with self.assertRaises(ValueError):
                build_external_plan(
                    "dalfox", "https://example.com/search?q=1", "q", scope, ExecutorSettings(requests_per_second=0.001)
                )

    def test_missing_optional_dependency_has_actionable_error(self):
        with patch.dict("sys.modules", {"bs4": None}), self.assertRaisesRegex(ValueError, "xss"):
            analyze_html("<p>marker</p>", "marker")

    def test_planner_reuses_http_url_validation_and_normalization(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "scope.txt"
            path.write_text("example.com\n")
            scope = ScopeValidator(path)
            for url in (
                "ftp://example.com/search?q=1",
                "file://example.com/search?q=1",
                "gopher://example.com/search?q=1",
                "https://user:private-password@example.com/search?q=1",
            ):
                with self.subTest(url=url), self.assertRaises(ValueError):
                    build_external_plan("sqlmap", url, "q", scope, ExecutorSettings())
            plan = build_external_plan("sqlmap", "example.com/search?q=1", "q", scope, ExecutorSettings())
            self.assertEqual(plan["target"], "https://example.com/search?q=1")
            self.assertIn(plan["target"], plan["command"])


@unittest.skipUnless(
    importlib.util.find_spec("bs4") and importlib.util.find_spec("sqlparse"), "optional xss/sqli extras not installed"
)
class OfflineWorkflowTests(unittest.TestCase):
    def test_sequential_local_analysis_needs_no_program_or_network(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            records = root / "no-program-config"
            parser = cli.build_parser()
            with (
                patch.object(cli, "store_for", side_effect=AssertionError("offline work needs no program")),
                patch("socket.create_connection", side_effect=AssertionError("offline work sends no traffic")),
            ):
                for kind, content, options in (
                    ("html", "<p>MARKER</p>", ["--marker", "MARKER"]),
                    ("sql", "SELECT 1;", []),
                ):
                    input_file = root / f"input.{kind}"
                    input_file.write_text(content, encoding="utf-8")
                    output = root / f"{kind}.json"
                    args = parser.parse_args(
                        [
                            "--records-root",
                            str(records),
                            "analyze",
                            kind,
                            "--input",
                            str(input_file),
                            "--output",
                            str(output),
                            *options,
                        ]
                    )
                    args.func(args)
                    self.assertIsInstance(json.loads(output.read_text(encoding="utf-8")), dict)
            self.assertFalse(records.exists())


@unittest.skipUnless(importlib.util.find_spec("bs4"), "optional xss extra not installed")
class HtmlContextTests(unittest.TestCase):
    def test_source_reflection_survives_parser_normalization(self):
        for document, marker in (
            ("<MARKER></MARKER>", "MARKER"),
            ('<p data-MARKER="value">x</p>', "MARKER"),
            ('<p class="WORD ONE">x</p>', "WORD ONE"),
        ):
            with self.subTest(document=document):
                result = analyze_html(document, marker)
                self.assertTrue(result["reflected"])
                self.assertTrue(result["source_reflected"])
                self.assertFalse(result["confirmed"])

    def test_contexts_without_execution_or_private_text(self):
        document = '<p>private-value MARKER</p><!-- MARKER --><a href="/MARKER" title="MARKER">link</a><img onerror="MARKER"><script>MARKER</script><style>MARKER</style>'
        with patch("urllib.request.urlopen", side_effect=AssertionError("offline only")):
            result = analyze_html(document, "MARKER")
        kinds = {item["context"] for item in result["contexts"]}
        self.assertTrue(
            {"html_text", "comment", "url_attribute", "attribute", "event_attribute", "script", "style"}.issubset(kinds)
        )
        self.assertFalse(result["confirmed"])
        self.assertNotIn("private-value", json.dumps(result))
        self.assertFalse(analyze_html("<p>other</p>", "MARKER")["reflected"])

    def test_installed_parser_variants(self):
        for parser in ("lxml", "html5lib"):
            if importlib.util.find_spec(parser):
                with self.subTest(parser=parser):
                    self.assertTrue(analyze_html('<a title="MARKER">text', "MARKER", parser)["reflected"])


@unittest.skipUnless(importlib.util.find_spec("jwt"), "optional jwt extra not installed")
class JwtTests(unittest.TestCase):
    key = "only-a-local-laboratory-key-with-enough-entropy"

    def token(self, **changes):
        import jwt

        claims = {"sub": "private-user", "iss": "own-issuer", "aud": "own-app", "exp": int(time.time()) + 600}
        claims.update(changes)
        return jwt.encode(claims, self.key, algorithm="HS256", headers={"jku": "http://127.0.0.1:9/never-fetch"})

    def test_malformed_algorithm_is_not_echoed(self):
        def segment(value):
            return base64.urlsafe_b64encode(json.dumps(value).encode()).rstrip(b"=").decode()

        for algorithm in ({"private": "private-algorithm-data"}, ["private-algorithm-data"], None, "x" * 100):
            token = segment({"alg": algorithm}) + "." + segment({"sub": "private-user"}) + ".AAAA"
            with self.assertRaises(ValueError) as error:
                inspect_jwt(token)
            self.assertNotIn("private-algorithm-data", str(error.exception))
        token = segment({"alg": "private-algorithm-data"}) + "." + segment({"sub": "private-user"}) + ".AAAA"
        result = inspect_jwt(token)
        self.assertEqual(result["algorithm"], "unsupported")
        self.assertNotIn("private-algorithm-data", json.dumps(result))

    def test_decode_is_not_verification_and_does_not_fetch_keys(self):
        token = self.token()
        with patch("urllib.request.urlopen", side_effect=AssertionError("must not fetch jku")):
            result = inspect_jwt(token)
        self.assertFalse(result["signature_verified"])
        self.assertTrue(result["has_jku"])
        self.assertNotIn(token, json.dumps(result))
        self.assertNotIn("private-user", json.dumps(result))

    def test_explicit_key_algorithm_and_claim_validation(self):
        result = inspect_jwt(self.token(), self.key.encode(), "HS256", "own-issuer", "own-app")
        self.assertTrue(result["signature_verified"])
        self.assertTrue(result["expiration_checked"])
        for token, key, algorithm, issuer, audience in (
            (self.token(exp=1), self.key.encode(), "HS256", "own-issuer", "own-app"),
            (self.token(), b"wrong-local-laboratory-key-with-32-plus-bytes", "HS256", "own-issuer", "own-app"),
            (self.token(), self.key.encode(), "RS256", "own-issuer", "own-app"),
            (self.token(), self.key.encode(), "HS256", "wrong-issuer", "own-app"),
            (self.token(), self.key.encode(), "HS256", "own-issuer", "wrong-app"),
        ):
            with self.assertRaises(ValueError):
                inspect_jwt(token, key, algorithm, issuer, audience)

    def test_unsigned_missing_exp_and_implicit_algorithm_rejected_for_verification(self):
        import jwt

        unsigned = jwt.encode({"sub": "private-user"}, "", algorithm="none")
        self.assertIn("unsigned_algorithm", inspect_jwt(unsigned)["warnings"])
        for token, key, algorithm in (
            (unsigned, self.key.encode(), "none"),
            (self.token(), self.key.encode(), None),
            (jwt.encode({"sub": "private-user"}, self.key, algorithm="HS256"), self.key.encode(), "HS256"),
        ):
            with self.assertRaises(ValueError):
                inspect_jwt(token, key, algorithm)


@unittest.skipUnless(importlib.util.find_spec("sqlparse"), "optional sqli extra not installed")
class SqlAnalysisTests(unittest.TestCase):
    def test_queries_are_parsed_not_executed_or_echoed(self):
        with patch("sqlite3.connect", side_effect=AssertionError("offline analysis")):
            result = analyze_sql("SELECT * FROM own_table WHERE name='private-value'; UPDATE own_table SET name=?;")
        self.assertEqual(result["statement_types"], ["SELECT", "UPDATE"])
        self.assertFalse(result["executed"])
        self.assertNotIn("private-value", json.dumps(result))
