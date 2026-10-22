import tempfile
import unittest
from pathlib import Path

from bugbounty_toolkit.core.scope import ensure_in_scope, validate_rule
from bugbounty_toolkit.core.target import normalize_url, load_routes


class ScopeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.scope = Path(self.temp.name) / "scope.txt"

    def tearDown(self):
        self.temp.cleanup()

    def test_exact_host_does_not_authorize_subdomains(self):
        self.scope.write_text("example.com\n")
        ensure_in_scope("https://example.com/search", self.scope)
        for target in ("https://sub.example.com", "https://badexample.com", "https://example.com.evil.test"):
            with self.subTest(target=target), self.assertRaises(ValueError):
                ensure_in_scope(target, self.scope)

    def test_explicit_wildcard_with_exclusion(self):
        self.scope.write_text("*.example.com\n!admin.example.com\n")
        ensure_in_scope("https://app.example.com", self.scope)
        for target in ("https://example.com", "https://admin.example.com", "https://child.admin.example.com"):
            if target == "https://child.admin.example.com":
                # Exact exclusions apply only to the named host; use !*.admin.example.com to exclude descendants.
                ensure_in_scope(target, self.scope)
            else:
                with self.assertRaises(ValueError):
                    ensure_in_scope(target, self.scope)

    def test_url_scope_binds_scheme_port_and_path(self):
        self.scope.write_text("https://example.com:8443/api\n")
        ensure_in_scope("https://example.com:8443/api/items", self.scope)
        for target in (
            "http://example.com:8443/api",
            "https://example.com/api",
            "https://example.com:8443/apix",
            "https://example.com:8443/api/../admin",
        ):
            with self.subTest(target=target), self.assertRaises(ValueError):
                ensure_in_scope(target, self.scope)

    def test_excluded_paths_block_encoded_traversal(self):
        self.scope.write_text("example.com\n!https://example.com/admin\n")
        for path in ("/admin", "/admin/settings", "/api/%2e%2e/admin", "/%61dmin", "/%2561dmin"):
            with self.subTest(path=path), self.assertRaises(ValueError):
                ensure_in_scope("https://example.com" + path, self.scope)
        ensure_in_scope("https://example.com/administrator", self.scope)

    def test_empty_or_invalid_scope_fails_closed(self):
        self.scope.write_text("")
        with self.assertRaises(ValueError):
            ensure_in_scope("https://example.com", self.scope)
        for rule in ("*", "bad*example.com", "https://user:pass@example.com", "https://example.com?token=x"):
            with self.subTest(rule=rule), self.assertRaises(ValueError):
                validate_rule(rule)

    def test_normalize_and_load_routes(self):
        self.assertEqual(normalize_url("localhost:8000"), "https://localhost:8000/")
        self.assertEqual(normalize_url("https://EXAMPLE.com/a;b?q=1#frag"), "https://example.com/a;b?q=1")
        routes = Path(self.temp.name) / "routes.txt"
        routes.write_text("# supplied routes\n/search\nsearch\n/search\n")
        self.assertEqual(load_routes(routes, "https://example.com"), ["https://example.com/search"])
        with self.assertRaises(ValueError):
            load_routes(routes)
