from __future__ import annotations

import json
import socket
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from bugbounty_toolkit.analysis.semantic_response_diff import (
    SCHEMA_VERSION,
    StoredResponse,
    diff_responses,
    fingerprint,
    is_protected_key,
    is_sensitive_key,
    naive_baseline_diff,
)
from labs.semantic_response_diff_eval.baseline import measure
from labs.semantic_response_diff_eval.evaluate import evaluate
from labs.semantic_response_diff_eval.example import create_example


class SemanticResponseDiffTests(unittest.TestCase):
    def setUp(self) -> None:
        for target in ((socket.socket, "connect"), (socket, "getaddrinfo")):
            guard = patch.object(*target, side_effect=AssertionError("Network prohibited"))
            guard.start()
            self.addCleanup(guard.stop)

    def test_schema_and_non_verdict(self) -> None:
        result = diff_responses(
            {"status_code": 200, "headers": {"content-type": "application/json"}, "body": '{"a":1}'},
            {"status_code": 200, "headers": {"content-type": "application/json"}, "body": '{"a":1}'},
        )
        self.assertEqual(result["schema_version"], SCHEMA_VERSION)
        self.assertTrue(result["structural_equality"])
        self.assertFalse(result["confirmed"])
        self.assertFalse(result["finding_confirmed"])
        self.assertIsNone(result["vulnerability_verdict"])
        json.dumps(result)  # serializable

    def test_timestamp_volatile_explicit_only(self) -> None:
        left = {
            "status_code": 200,
            "headers": {"content-type": "application/json"},
            "body": '{"id":1,"timestamp":"t1"}',
        }
        right = {
            "status_code": 200,
            "headers": {"content-type": "application/json"},
            "body": '{"id":1,"timestamp":"t2"}',
        }
        without = diff_responses(left, right)
        self.assertFalse(without["structural_equality"])
        with_rule = diff_responses(left, right, ignore_volatile=["timestamp"])
        self.assertTrue(with_rule["structural_equality"])
        self.assertTrue(any(item.startswith("ignore_value:timestamp:") for item in with_rule["normalizations_applied"]))

    def test_protected_id_never_ignored(self) -> None:
        left = {"status_code": 200, "headers": {"content-type": "application/json"}, "body": '{"id":1}'}
        right = {"status_code": 200, "headers": {"content-type": "application/json"}, "body": '{"id":2}'}
        result = diff_responses(left, right, ignore_volatile=["id"])
        self.assertFalse(result["structural_equality"])
        self.assertTrue(any(c["path"] == "/id" and c["authz_relevant"] for c in result["changes"]))
        self.assertFalse(any(item.startswith("ignore_value:id:") for item in result["normalizations_applied"]))

    def test_sensitive_values_not_leaked(self) -> None:
        secret = "super_secret_token_value_zz9"
        left = {
            "status_code": 200,
            "headers": {"content-type": "application/json", "authorization": f"Bearer {secret}"},
            "body": json.dumps({"token": secret, "id": 1}),
        }
        right = {
            "status_code": 200,
            "headers": {"content-type": "application/json", "authorization": f"Bearer {secret}x"},
            "body": json.dumps({"token": secret + "x", "id": 1}),
        }
        dumped = json.dumps(diff_responses(left, right))
        self.assertNotIn(secret, dumped)
        self.assertNotIn("Bearer", dumped)

    def test_array_reorder_vs_change(self) -> None:
        left = {"status_code": 200, "headers": {"content-type": "application/json"}, "body": '{"items":[1,2,3]}'}
        reorder = {"status_code": 200, "headers": {"content-type": "application/json"}, "body": '{"items":[3,2,1]}'}
        changed = {"status_code": 200, "headers": {"content-type": "application/json"}, "body": '{"items":[1,2,9]}'}
        kinds_r = {c["kind"] for c in diff_responses(left, reorder)["changes"]}
        kinds_c = {c["kind"] for c in diff_responses(left, changed)["changes"]}
        self.assertIn("array_reordered", kinds_r)
        self.assertIn("array_changed", kinds_c)

    def test_html_as_data(self) -> None:
        left = {
            "status_code": 403,
            "headers": {"content-type": "text/html"},
            "body": "<html><body><h1>Forbidden</h1></body></html>",
        }
        right = {
            "status_code": 403,
            "headers": {"content-type": "text/html"},
            "body": "<html><body><h1>Denied</h1><script>alert(1)</script></body></html>",
        }
        result = diff_responses(left, right)
        self.assertTrue(any(c["kind"] == "html_structure_changed" for c in result["changes"]))
        self.assertNotIn("alert(1)", json.dumps(result))

    def test_login_redirect_preserves_location(self) -> None:
        left = {"status_code": 200, "headers": {"content-type": "application/json"}, "body": "{}"}
        right = {
            "status_code": 302,
            "headers": {"content-type": "text/html", "location": "https://lab.test/login"},
            "body": "",
        }
        result = diff_responses(left, right)
        kinds = {c["kind"] for c in result["changes"]}
        self.assertIn("status_changed", kinds)
        self.assertIn("location_changed", kinds)
        self.assertTrue(any(c["authz_relevant"] for c in result["changes"]))
        self.assertFalse(result["behavioral_equivalence"])

    def test_type_change_and_key_diff(self) -> None:
        left = {"status_code": 200, "headers": {"content-type": "application/json"}, "body": '{"id":1}'}
        right = {
            "status_code": 200,
            "headers": {"content-type": "application/json"},
            "body": '{"id":"1","role":"admin"}',
        }
        result = diff_responses(left, right)
        kinds = {c["kind"] for c in result["changes"]}
        self.assertIn("type_changed", kinds)
        self.assertIn("key_added", kinds)

    def test_content_length_mismatch(self) -> None:
        body = '{"ok":true}'
        left = {
            "status_code": 200,
            "headers": {"content-type": "application/json", "content-length": "999"},
            "body": body,
        }
        right = {
            "status_code": 200,
            "headers": {"content-type": "application/json", "content-length": str(len(body))},
            "body": body,
        }
        result = diff_responses(left, right)
        self.assertTrue(any(c["kind"] == "content_length_mismatch" for c in result["changes"]))

    def test_limits_truncate_large_body(self) -> None:
        big = "A" * 5000
        left = {"status_code": 200, "headers": {"content-type": "text/plain"}, "body": big}
        right = {"status_code": 200, "headers": {"content-type": "text/plain"}, "body": "B" * 5000}
        result = diff_responses(left, right, max_body_bytes=100)
        self.assertTrue(result["left"]["body_truncated"] or result["right"]["body_truncated"])
        self.assertTrue(result["summary"]["body_truncated"])

    def test_malformed_and_duplicate_json(self) -> None:
        left = {"status_code": 200, "headers": {"content-type": "application/json"}, "body": '{"a":1}'}
        bad = {"status_code": 200, "headers": {"content-type": "application/json"}, "body": '{"a":1,}'}
        dup = {"status_code": 200, "headers": {"content-type": "application/json"}, "body": '{"a":1,"a":2}'}
        self.assertIn("body_kind_changed", {c["kind"] for c in diff_responses(left, bad)["changes"]})
        self.assertIn("body_kind_changed", {c["kind"] for c in diff_responses(left, dup)["changes"]})

    def test_assessment_attached_not_authoritative_verdict(self) -> None:
        left = {"status_code": 200, "headers": {"content-type": "application/json"}, "body": '{"success":true,"id":1}'}
        right = {"status_code": 403, "headers": {"content-type": "text/html"}, "body": "<html>Forbidden</html>"}
        result = diff_responses(left, right)
        self.assertIn("assessment", result["left"])
        self.assertIn("assessment", result["right"])
        self.assertIsNone(result["vulnerability_verdict"])
        # PR #52 classes may appear on sides but do not become confirmed findings.
        self.assertFalse(result["confirmed"])

    def test_stored_response_helpers(self) -> None:
        self.assertTrue(is_protected_key("owner_id"))
        self.assertTrue(is_sensitive_key("api_token"))
        self.assertEqual(fingerprint({"a": 1}), fingerprint({"a": 1}))
        stored = StoredResponse.from_mapping(
            {"status": "200", "headers": {"Content-Type": "application/json"}, "body_text": "{}"}
        )
        self.assertEqual(stored.status_code, 200)
        base = naive_baseline_diff(stored, stored)
        self.assertTrue(base["equal"])

    def test_origin_fingerprints_preserved(self) -> None:
        left = {
            "status_code": 200,
            "headers": {"content-type": "application/json"},
            "body": '{"a":1}',
            "origin_ref": "capture-a",
            "body_fingerprint": "abc",
        }
        right = {
            "status_code": 200,
            "headers": {"content-type": "application/json"},
            "body": '{"a":2}',
            "origin_ref": "capture-b",
            "body_fingerprint": "def",
        }
        result = diff_responses(left, right)
        self.assertEqual(result["left"]["origin_ref"], "capture-a")
        self.assertEqual(result["right"]["origin_ref"], "capture-b")
        self.assertEqual(result["left"]["body_fingerprint"], "abc")
        self.assertEqual(result["right"]["body_fingerprint"], "def")

    def test_lab_evaluate_and_baseline(self) -> None:
        baseline = measure()
        self.assertEqual(baseline["metrics"]["network_requests_sent"], 0)
        self.assertFalse(baseline["confirmed"])
        payload = evaluate()
        self.assertEqual(payload["metrics"]["unexpected_results"], 0)
        self.assertEqual(payload["metrics"]["secret_leaks"], 0)
        self.assertEqual(payload["metrics"]["network_requests_sent"], 0)
        self.assertEqual(payload["metrics"]["dangerous_normalizations"], 0)
        self.assertGreaterEqual(payload["metrics"]["precision_relevant_diff"], 0.99)
        self.assertGreaterEqual(payload["metrics"]["recall_field_changes"], 0.99)
        self.assertFalse(payload["confirmed"])

    def test_example_private_write(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "example"
            summary = create_example(root)
            self.assertFalse(summary["confirmed"])
            self.assertTrue((root / "diff.json").is_file())
            self.assertEqual((root / "diff.json").stat().st_mode & 0o777, 0o600)

    def test_header_and_sensitive_presence(self) -> None:
        left = {
            "status_code": 200,
            "headers": {"content-type": "application/json", "x-custom": "a", "date": "Tue"},
            "body": "{}",
        }
        right = {
            "status_code": 200,
            "headers": {
                "content-type": "application/json",
                "x-custom": "b",
                "x-extra": "1",
                "authorization": "Bearer z",
            },
            "body": "{}",
        }
        result = diff_responses(left, right)
        kinds = {c["kind"] for c in result["changes"]}
        self.assertIn("header_changed", kinds)
        self.assertIn("header_added", kinds)
        self.assertIn("sensitive_header_presence_changed", kinds)

    def test_opaque_text_and_bytes_body(self) -> None:
        left = {"status_code": 200, "headers": {"content-type": "text/plain"}, "body": "hello forbidden"}
        right = {"status_code": 200, "headers": {"content-type": "text/plain"}, "body": "hello success"}
        result = diff_responses(left, right)
        self.assertTrue(any(c["kind"] == "opaque_body_changed" for c in result["changes"]))
        stored = StoredResponse.from_mapping({"status_code": 200, "headers": {}, "body": b"{}", "origin": "bytes"})
        self.assertIn("{", stored.body)

    def test_html_identical_and_parse_resilience(self) -> None:
        body = "<html><body><p>x</p></body></html>"
        left = {"status_code": 200, "headers": {"content-type": "text/html"}, "body": body}
        right = {"status_code": 200, "headers": {"content-type": "text/html"}, "body": body}
        self.assertTrue(diff_responses(left, right)["structural_equality"])

    def test_schema_none_side_and_max_changes(self) -> None:
        left = {
            "status_code": 200,
            "headers": {"content-type": "application/json"},
            "body": '{"a":1,"b":2,"c":3,"d":4}',
        }
        right = {
            "status_code": 200,
            "headers": {"content-type": "application/json"},
            "body": '{"a":9,"b":8,"c":7,"d":6}',
        }
        result = diff_responses(left, right, max_changes=2)
        self.assertTrue(result["summary"]["output_truncated"])
        self.assertLessEqual(len(result["changes"]), 2)

    def test_invalid_content_length_and_status_cast(self) -> None:
        left = {
            "status_code": "201",
            "headers": {"content-type": "application/json", "content-length": "nope"},
            "body": "{}",
        }
        right = {
            "status_code": 200,
            "headers": {"content-type": "application/json", "content-length": "2"},
            "body": "{}",
        }
        result = diff_responses(left, right)
        self.assertTrue(any(c["kind"] == "status_changed" for c in result["changes"]))
        self.assertTrue(any(c["kind"] == "content_length_mismatch" for c in result["changes"]))


if __name__ == "__main__":
    unittest.main()
