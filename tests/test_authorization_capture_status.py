"""Independent synthetic capture regressions; no network or frozen corpus edits."""

from __future__ import annotations

import unittest

from bugbounty_toolkit.analysis.authorization_denial import assess_pair_authorization, parse_raw_response

PRIVATE = '{"ok":true,"data":{"id":"20","marker":"synthetic-owner-resource"}}'
PUBLIC = '{"ok":true,"data":{"id":"20","visibility":"public"}}'
VERSIONS = ("HTTP/1.0", "HTTP/1.1", "HTTP/2", "HTTP/3")
# These are development regressions, not new holdout labels or real-target results.
SCENARIOS = (
    ("private_payload", 200, PRIVATE, "", "possible_access"),
    ("unauthenticated", 401, "", "", "cross_account_denied"),
    ("forbidden", 403, "", "", "cross_account_denied"),
    ("not_found", 404, "", "", "cross_account_denied"),
    ("login_redirect", 302, "", "Location: /login\r\n", "cross_account_denied"),
    ("application_denial", 200, '{"success":false}', "", "cross_account_denied"),
    ("contradiction", 403, PRIVATE, "", "inconclusive"),
    ("public", 200, PUBLIC, "", "inconclusive"),
    ("server_error", 503, '{"error":"unavailable"}', "", "inconclusive"),
    ("empty", 200, "", "", "inconclusive"),
)


def capture(version: str, status: int, body: str, headers: str = "") -> str:
    """Build a textual export, not HTTP/2 or HTTP/3 wire frames."""
    return f"{version} {status}\r\n{headers}\r\n{body}"


class AuthorizationCaptureStatusTests(unittest.TestCase):
    def test_protocol_independent_authorization_outcomes(self) -> None:
        """Keep positive, negative and ambiguous controls across export versions."""
        for version in VERSIONS:
            owner = capture(version, 200, PRIVATE)
            for name, status, body, headers, expected in SCENARIOS:
                with self.subTest(version=version, scenario=name):
                    result = assess_pair_authorization(owner, capture(version, status, body, headers))
                    self.assertEqual(result.outcome, expected)
                    self.assertEqual(result.owner.status_code, 200)
                    self.assertEqual(result.actor.status_code, status)
                    self.assertIsNot((result.annotation or {}).get("access_confirmed"), True)

    def test_mixed_protocol_controls(self) -> None:
        for owner_version in VERSIONS:
            for actor_version in VERSIONS:
                with self.subTest(owner=owner_version, actor=actor_version):
                    result = assess_pair_authorization(
                        capture(owner_version, 200, PRIVATE), capture(actor_version, 403, "")
                    )
                    self.assertEqual(result.outcome, "cross_account_denied")

    def test_invalid_status_never_becomes_positive_evidence(self) -> None:
        for line in (
            "HTTP/1.1 200.0",
            "HTTP/1.1 200:OK",
            "HTTP/1.1 200-OK",
            "HTTP/1.1 200/OK",
            "HTTP/1.1 2000",
            "HTTP/1.1 099",
            "HTTP/1.1 600",
            "HTTP/1.1 ２００",
            "HTTP/1.1 20",
            "HTTP/2xyz 200",
            "HTTP/9 200",
            "200 OK",
        ):
            with self.subTest(line=line):
                raw = line + "\r\n\r\n" + PRIVATE
                self.assertIsNone(parse_raw_response(raw)[0])
                result = assess_pair_authorization(capture("HTTP/1.1", 200, PRIVATE), raw)
                self.assertEqual(result.outcome, "inconclusive")

    def test_preserves_export_body_and_first_location(self) -> None:
        body = "<p>synthetic</p>\n\nHTTP/1.1 200 OK\n"
        for version in VERSIONS:
            for newline in ("\r\n", "\n"):
                with self.subTest(version=version, newline=repr(newline)):
                    raw = newline.join((version + " 302 Found", "Location: /login", "Location: /home", "", body))
                    status, headers, parsed_body = parse_raw_response(raw.encode())
                    self.assertEqual(status, 302)
                    self.assertEqual(headers["location"], "/login")
                    self.assertEqual(parsed_body, body)

    def test_absent_capture_remains_unknown(self) -> None:
        for raw in (None, "", b"", "\n"):
            self.assertEqual(parse_raw_response(raw), (None, {}, ""))


if __name__ == "__main__":
    unittest.main()
