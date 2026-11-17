"""Connection guard tests. DNS and HTTP are mocked."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from bugbounty_toolkit.core.destinations import canonical_ip, refuse_unapproved_resolution
from bugbounty_toolkit.core.http_client import HttpClient, RequestSpec
from bugbounty_toolkit.core.rate_limiter import RateLimiter
from bugbounty_toolkit.core.scope_validator import ScopeValidator
from bugbounty_toolkit.core.target import normalize_url
from bugbounty_toolkit.utils.exceptions import ToolkitError


class DestinationGuardTests(unittest.TestCase):
    def test_decimal_hex_and_short_ips_canonicalize(self) -> None:
        self.assertEqual(canonical_ip("2130706433"), "127.0.0.1")
        self.assertEqual(canonical_ip("0x7f000001"), "127.0.0.1")
        self.assertEqual(canonical_ip("127.1"), "127.0.0.1")
        self.assertEqual(canonical_ip("8.8.8.8"), "8.8.8.8")
        self.assertIsNone(canonical_ip("example.com"))
        self.assertEqual(normalize_url("http://2130706433/health"), "http://127.0.0.1/health")

    def test_metadata_resolution_is_refused_before_connect(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            scope_file = Path(directory) / "scope.txt"
            scope_file.write_text("example.com\n", encoding="utf-8")
            scope = ScopeValidator(scope_file)
            client = HttpClient(scope, rate_limiter=RateLimiter(1000))
            with (
                patch(
                    "bugbounty_toolkit.core.destinations._resolve",
                    return_value=["169.254.169.254"],
                ),
                patch.object(client.opener, "open", side_effect=AssertionError("request was sent")),
                self.assertRaises(ToolkitError),
            ):
                client.send(RequestSpec("GET", "https://example.com/"))

    def test_public_resolution_reaches_the_opener(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            scope_file = Path(directory) / "scope.txt"
            scope_file.write_text("example.com\n", encoding="utf-8")
            client = HttpClient(ScopeValidator(scope_file), rate_limiter=RateLimiter(1000))

            class Response:
                url = "https://example.com/"
                code = 204
                reason = "No Content"
                headers = _Headers()

                def read(self, _limit: int) -> bytes:
                    return b""

                def __enter__(self) -> Response:
                    return self

                def __exit__(self, *_args: object) -> bool:
                    return False

            with (
                patch("bugbounty_toolkit.core.destinations._resolve", return_value=["8.8.8.8"]) as resolve,
                patch.object(client.opener, "open", return_value=Response()) as opened,
            ):
                record = client.send(RequestSpec("GET", "https://example.com/health"))
            self.assertEqual(record.status_code, 204)
            resolve.assert_called_once()
            opened.assert_called_once()

    def test_literal_loopback_does_not_resolve(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            scope_file = Path(directory) / "scope.txt"
            scope_file.write_text("127.0.0.1\n", encoding="utf-8")
            with patch(
                "bugbounty_toolkit.core.destinations._resolve",
                side_effect=AssertionError("literal IP must not be resolved"),
            ):
                refuse_unapproved_resolution("http://127.0.0.1/", ScopeValidator(scope_file))


class _Headers:
    def get_content_charset(self) -> str:
        return "utf-8"

    def items(self) -> list[tuple[str, str]]:
        return []

    def get_all(self, _name: str, default: list[str] | None = None) -> list[str]:
        return list(default or [])


if __name__ == "__main__":
    unittest.main()
