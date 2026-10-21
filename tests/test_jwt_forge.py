from __future__ import annotations

import base64
import hashlib
import hmac
import json
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
import socket
import sys
import tempfile
import unittest
from unittest.mock import patch
import urllib.request

from bugbounty_toolkit import cli
from bugbounty_toolkit.jwt_forge import forge_jwt


def _segment(value: dict[str, object]) -> str:
    encoded = json.dumps(value, separators=(",", ":")).encode("utf-8")
    return base64.urlsafe_b64encode(encoded).rstrip(b"=").decode("ascii")


def _token(header: dict[str, object] | None = None, claims: dict[str, object] | None = None) -> str:
    return f"{_segment(header or {'alg': 'RS256', 'typ': 'JWT', 'kid': 'test-key', 'jku': 'https://untrusted.invalid/jwks'})}.{_segment(claims or {'sub': 'test-user', 'role': 'user', 'admin': False})}.original-signature"


def _decode_segment(value: str) -> dict[str, object]:
    decoded = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    return json.loads(decoded)


class JwtForgeTests(unittest.TestCase):
    def test_generates_offline_none_algorithm_claim_and_header_variants(self):
        result = forge_jwt(_token())
        candidates = result["candidates"]
        self.assertEqual(result["network_requests_sent"], 0)
        self.assertEqual(result["candidate_count"], 5)
        self.assertIsInstance(candidates, list)
        typed_candidates = candidates
        self.assertEqual(
            {row["variant"] for row in typed_candidates},
            {
                "alg_none",
                "alg_none_claim_role",
                "alg_none_claim_admin",
                "alg_none_claim_is_admin",
                "rs256_to_hs256_signature_unchanged",
            },
        )
        unsigned = next(row["token"] for row in typed_candidates if row["variant"] == "alg_none")
        unsigned_parts = unsigned.split(".")
        self.assertEqual(unsigned_parts[2], "")
        self.assertEqual(_decode_segment(unsigned_parts[0]), {"alg": "none", "typ": "JWT"})
        changed_claim = next(row["token"] for row in typed_candidates if row["variant"] == "alg_none_claim_role")
        self.assertEqual(_decode_segment(changed_claim.split(".")[1])["role"], "admin")
        preserved = next(
            row["token"] for row in typed_candidates if row["variant"] == "rs256_to_hs256_signature_unchanged"
        )
        self.assertEqual(preserved.split(".")[2], "original-signature")
        self.assertNotIn("jku", _decode_segment(preserved.split(".")[0]))
        self.assertIn("not verified", " ".join(result["review_notes"]))
        self.assertTrue(result["what_to_test"])
        self.assertTrue(result["sensitive_output"])

    def test_signs_with_provided_and_common_weak_secrets_without_echoing_secret(self):
        private_value = "local-only-test-secret"
        result = forge_jwt(_token(), secret=private_value)
        candidates = result["candidates"]
        self.assertEqual(result["candidate_count"], 21)
        provided = next(row["token"] for row in candidates if row["variant"] == "hs256_provided_secret")
        header, payload, signature = provided.split(".")
        expected = hmac.new(private_value.encode(), f"{header}.{payload}".encode(), hashlib.sha256).digest()
        self.assertEqual(base64.urlsafe_b64decode(signature + "=" * (-len(signature) % 4)), expected)
        labels = {row["variant"] for row in candidates}
        for value in ("secret", "123456", "password"):
            self.assertIn(f"hs256_weak_secret_candidate:{value}", labels)
        serialized = json.dumps(result)
        self.assertNotIn(private_value, serialized)

    def test_public_key_confusion_is_local_and_uses_pem_bytes_as_hmac_key(self):
        public_key = b"-----BEGIN PUBLIC KEY-----\nZmFrZS1wdWJsaWMta2V5\n-----END PUBLIC KEY-----\n"
        result = forge_jwt(_token(), public_key=public_key)
        candidate = next(
            row["token"] for row in result["candidates"] if row["variant"] == "hs256_public_key_bytes_as_hmac_key"
        )
        header, payload, signature = candidate.split(".")
        expected = hmac.new(public_key, f"{header}.{payload}".encode(), hashlib.sha256).digest()
        self.assertEqual(base64.urlsafe_b64decode(signature + "=" * (-len(signature) % 4)), expected)
        self.assertEqual(result["candidate_count"], 9)

    def test_rejects_malformed_tokens_duplicate_keys_and_wrong_public_key_input(self):
        with self.assertRaisesRegex(ValueError, "three-part"):
            forge_jwt("not-a-token")
        duplicate_header = base64.urlsafe_b64encode(b'{"alg":"RS256","alg":"HS256"}').rstrip(b"=").decode()
        with self.assertRaisesRegex(ValueError, "duplicate"):
            forge_jwt(f"{duplicate_header}.{_segment({'sub': 'user'})}.sig")
        with self.assertRaisesRegex(ValueError, "PEM"):
            forge_jwt(_token(), public_key=b"not-a-key")
        with self.assertRaisesRegex(ValueError, "require an RS256"):
            forge_jwt(_token({"alg": "HS256"}), public_key=b"-----BEGIN PUBLIC KEY-----\nx\n-----END PUBLIC KEY-----")

    def test_cli_prints_candidates_and_does_not_use_network(self):
        with tempfile.TemporaryDirectory() as directory:
            input_path = Path(directory) / "token.txt"
            input_path.write_text(_token(), encoding="utf-8")
            output = StringIO()
            with (
                patch.object(sys, "argv", ["bbtk", "jwt-forge", "--input", str(input_path)]),
                patch.object(socket, "create_connection", side_effect=AssertionError("network call")) as connect,
                patch.object(urllib.request, "urlopen", side_effect=AssertionError("network call")) as urlopen,
                redirect_stdout(output),
            ):
                cli.main()
            data = json.loads(output.getvalue())
            self.assertEqual(data["network_requests_sent"], 0)
            self.assertEqual(data["candidate_count"], 5)
            connect.assert_not_called()
            urlopen.assert_not_called()

    def test_cli_can_save_candidates_to_local_json(self):
        with tempfile.TemporaryDirectory() as directory:
            input_path = Path(directory) / "token.txt"
            output_path = Path(directory) / "candidates.json"
            input_path.write_text(_token(), encoding="utf-8")
            output = StringIO()
            with (
                patch.object(
                    sys,
                    "argv",
                    ["bbtk", "jwt-forge", "--input", str(input_path), "--output", str(output_path)],
                ),
                redirect_stdout(output),
            ):
                cli.main()
            data = json.loads(output_path.read_text(encoding="utf-8"))
            self.assertEqual(data["network_requests_sent"], 0)
            self.assertIn("Offline analysis saved", output.getvalue())


if __name__ == "__main__":
    unittest.main()
