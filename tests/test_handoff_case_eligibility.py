"""Offline tests for handoff→case eligibility classification and provenance."""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path

from bugbounty_toolkit.analysis.handoff_case_eligibility import (
    CODE_CASE_ELIGIBLE,
    CODE_NEEDS_MORE_EVIDENCE,
    CODE_NEEDS_RESPONSE,
    CODE_REJECT_GET_WITH_BODY,
    CODE_REJECT_HEADER_DIFF,
    CODE_REJECT_METHOD_MISMATCH,
    CODE_REJECT_MULTI_RESOURCE_DIFF,
    CODE_REJECT_NON_GET,
    CODE_REJECT_ORIGIN_MISMATCH_SIDES,
    CODE_REJECT_SAME_SESSION,
    CODE_REJECT_SESSION_ONLY,
    CODE_TECH_ORIGIN_OVERRIDE,
    _map_inspect_error,
    classify_capture_pair,
    classify_materialized_paths,
    origin_from_raw_request,
    provenance_origin,
)
from bugbounty_toolkit.analysis.object_handoff import propose_object_handoff
from bugbounty_toolkit.analysis.object_relationships import build_object_graph
from bugbounty_toolkit.idor_discovery import discover_idor, discovery_summary


HERE = Path(__file__).resolve().parents[1]
DEV = HERE / "labs" / "idor_handoff_case_eval" / "dev"
FROZEN = HERE / "labs" / "idor_handoff_case_eval" / "frozen"


def _raw(method: str, target: str, host: str, session: str, body: str = "") -> bytes:
    lines = [
        f"{method} {target} HTTP/1.1",
        f"Host: {host}",
        f"Authorization: Bearer {session}",
        "",
        body,
    ]
    return ("\r\n".join(lines)).encode("utf-8")


def _resp(body: dict) -> bytes:
    payload = json.dumps(body, sort_keys=True)
    return f"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{payload}".encode()


@unittest.skipUnless(os.name == "posix", "Secure private artifact I/O requires POSIX")
class HandoffCaseEligibilityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def _write(self, name: str, data: bytes) -> Path:
        path = self.root / name
        path.write_bytes(data)
        return path

    def test_compatible_origin_valid_get_is_case_eligible(self) -> None:
        owner = self._write(
            "o.http",
            _raw("GET", "/hd/widgets/60101", "127.0.0.1:8142", "owner"),
        )
        actor = self._write(
            "a.http",
            _raw("GET", "/hd/widgets/60102", "127.0.0.1:8142", "actor"),
        )
        ores = self._write(
            "or.http", _resp({"success": True, "data": {"id": 60101, "marker": "hcdev-widget-owner-aaa"}})
        )
        ares = self._write(
            "ar.http", _resp({"success": True, "data": {"id": 60102, "marker": "hcdev-widget-actor-bbb"}})
        )
        clf = classify_capture_pair(
            owner, actor, owner_response=ores, actor_response=ares, base_url="http://127.0.0.1:8142"
        )
        self.assertEqual(clf.status, "case_eligible")
        self.assertEqual(clf.code, CODE_CASE_ELIGIBLE)
        self.assertTrue(clf.case_eligible)
        self.assertFalse(clf.technical_error)
        d = discover_idor(
            "hc-test",
            owner,
            actor,
            base_url="http://127.0.0.1:8142",
            owner_response=ores,
            actor_response=ares,
            accounts_authorized=False,
        )
        self.assertEqual(len(d.proposal["candidates"]), 1)
        self.assertEqual(d.proposal["candidates"][0]["base_url"], "http://127.0.0.1:8142")
        self.assertFalse(d.proposal["confirmed"])

    def test_incompatible_caller_base_url_is_technical_error_not_rewrite(self) -> None:
        owner = self._write("o.http", _raw("GET", "/x/1", "127.0.0.1:8142", "owner"))
        actor = self._write("a.http", _raw("GET", "/x/2", "127.0.0.1:8142", "actor"))
        ores = self._write("or.http", _resp({"success": True, "data": {"id": 1, "marker": "owner-marker-aaa"}}))
        ares = self._write("ar.http", _resp({"success": True, "data": {"id": 2, "marker": "actor-marker-bbb"}}))
        clf = classify_capture_pair(
            owner, actor, owner_response=ores, actor_response=ares, base_url="http://127.0.0.1:8137"
        )
        self.assertEqual(clf.status, "technical_error")
        self.assertEqual(clf.code, CODE_TECH_ORIGIN_OVERRIDE)
        self.assertTrue(clf.technical_error)
        with self.assertRaises(ValueError) as ctx:
            discover_idor(
                "hc-test",
                owner,
                actor,
                base_url="http://127.0.0.1:8137",
                owner_response=ores,
                actor_response=ares,
                accounts_authorized=False,
            )
        self.assertIn("inconsistent origin", str(ctx.exception).lower())

    def test_different_ports_across_sides(self) -> None:
        owner = self._write("o.http", _raw("GET", "/hd/widgets/1", "127.0.0.1:8142", "owner"))
        actor = self._write("a.http", _raw("GET", "/hd/widgets/2", "127.0.0.1:8143", "actor"))
        ores = self._write("or.http", _resp({"success": True, "data": {"id": 1, "marker": "owner-marker-aaa"}}))
        ares = self._write("ar.http", _resp({"success": True, "data": {"id": 2, "marker": "actor-marker-bbb"}}))
        clf = classify_capture_pair(owner, actor, owner_response=ores, actor_response=ares, base_url=None)
        # Without base_url both default to https://host:port → sides disagree at inspect.
        self.assertIn(
            clf.code, {CODE_REJECT_ORIGIN_MISMATCH_SIDES, CODE_TECH_ORIGIN_OVERRIDE, CODE_REJECT_MULTI_RESOURCE_DIFF}
        )
        self.assertTrue(clf.technical_error or clf.legitimate_rejection)

    def test_multi_diff_and_non_get_and_session_only(self) -> None:
        # multi-diff
        owner = self._write("o.http", _raw("GET", "/t/1/s/11", "127.0.0.1:8142", "owner"))
        actor = self._write("a.http", _raw("GET", "/t/2/s/12", "127.0.0.1:8142", "actor"))
        ores = self._write("or.http", _resp({"success": True, "data": {"id": 11, "marker": "owner-marker-aaa"}}))
        ares = self._write("ar.http", _resp({"success": True, "data": {"id": 12, "marker": "actor-marker-bbb"}}))
        clf = classify_capture_pair(
            owner, actor, owner_response=ores, actor_response=ares, base_url="http://127.0.0.1:8142"
        )
        self.assertEqual(clf.code, CODE_REJECT_MULTI_RESOURCE_DIFF)
        self.assertTrue(clf.legitimate_rejection)

        # non-GET
        owner = self._write("o2.http", _raw("PUT", "/settings", "127.0.0.1:8142", "owner", body='{"a":1}'))
        actor = self._write("a2.http", _raw("PUT", "/settings", "127.0.0.1:8142", "actor", body='{"a":2}'))
        clf = classify_capture_pair(owner, actor, base_url="http://127.0.0.1:8142")
        self.assertIn(clf.code, {CODE_REJECT_NON_GET, CODE_REJECT_SESSION_ONLY})
        self.assertTrue(clf.legitimate_rejection)

        # session-only GET
        owner = self._write("o3.http", _raw("GET", "/profile", "127.0.0.1:8142", "owner"))
        actor = self._write("a3.http", _raw("GET", "/profile", "127.0.0.1:8142", "actor"))
        clf = classify_capture_pair(owner, actor, base_url="http://127.0.0.1:8142")
        self.assertEqual(clf.code, CODE_REJECT_SESSION_ONLY)

    def test_get_with_body_rejected(self) -> None:
        owner = self._write("o.http", _raw("GET", "/x/1", "127.0.0.1:8142", "owner", body='{"x":1}'))
        actor = self._write("a.http", _raw("GET", "/x/2", "127.0.0.1:8142", "actor", body='{"x":2}'))
        clf = classify_capture_pair(owner, actor, base_url="http://127.0.0.1:8142")
        self.assertEqual(clf.code, CODE_REJECT_GET_WITH_BODY)
        self.assertEqual(clf.status, "security_rejected")

    def test_missing_response_needs_more_evidence(self) -> None:
        owner = self._write("o.http", _raw("GET", "/n/1", "127.0.0.1:8142", "owner"))
        actor = self._write("a.http", _raw("GET", "/n/2", "127.0.0.1:8142", "actor"))
        ores = self._write("or.http", _resp({"success": True, "data": {"id": 1, "marker": "owner-marker-aaa"}}))
        clf = classify_capture_pair(
            owner, actor, owner_response=ores, actor_response=None, base_url="http://127.0.0.1:8142"
        )
        self.assertEqual(clf.code, CODE_NEEDS_RESPONSE)
        self.assertEqual(clf.status, "needs_more_evidence")

    def test_synthetic_secrets_absent_from_summary(self) -> None:
        owner = self._write(
            "o.http",
            _raw("GET", "/secrets/1", "127.0.0.1:8142", "owner") + b"",  # already terminated
        )
        # Rebuild with api key header
        owner.write_bytes(
            b"GET /secrets/1 HTTP/1.1\r\nHost: 127.0.0.1:8142\r\n"
            b"Authorization: Bearer owner\r\nX-Api-Key: SYNTHETIC_API_KEY_DO_NOT_LEAK\r\n\r\n"
        )
        actor = self._write(
            "a.http",
            b"GET /secrets/2 HTTP/1.1\r\nHost: 127.0.0.1:8142\r\n"
            b"Authorization: Bearer actor\r\nX-Api-Key: SYNTHETIC_API_KEY_DO_NOT_LEAK_B\r\n\r\n",
        )
        ores = self._write(
            "or.http",
            _resp(
                {
                    "success": True,
                    "data": {"id": 1, "token": "sk_live_SYNTHETIC_NOT_REAL_001", "marker": "owner-marker-aaa"},
                }
            ),
        )
        ares = self._write(
            "ar.http",
            _resp(
                {
                    "success": True,
                    "data": {"id": 2, "token": "sk_live_SYNTHETIC_NOT_REAL_002", "marker": "actor-marker-bbb"},
                }
            ),
        )
        d = discover_idor(
            "hc-test",
            owner,
            actor,
            base_url="http://127.0.0.1:8142",
            owner_response=ores,
            actor_response=ares,
            accounts_authorized=False,
        )
        summary = json.dumps(discovery_summary(d))
        self.assertNotIn("sk_live_", summary)
        self.assertNotIn("SYNTHETIC_API_KEY", summary)
        self.assertNotIn("Bearer", summary)

    def test_materialize_suggests_capture_provenance_origin(self) -> None:
        har = {
            "log": {
                "version": "1.2",
                "creator": {"name": "t", "version": "1"},
                "entries": [
                    {
                        "request": {
                            "method": "GET",
                            "url": "http://127.0.0.1:8142/hd/widgets/70101",
                            "headers": [{"name": "Authorization", "value": "Bearer o"}],
                        },
                        "response": {
                            "status": 200,
                            "content": {
                                "mimeType": "application/json",
                                "text": json.dumps({"data": {"id": 70101}}),
                            },
                        },
                    },
                    {
                        "request": {
                            "method": "GET",
                            "url": "http://127.0.0.1:8142/hd/widgets/70102",
                            "headers": [{"name": "Authorization", "value": "Bearer a"}],
                        },
                        "response": {
                            "status": 200,
                            "content": {
                                "mimeType": "application/json",
                                "text": json.dumps({"data": {"id": 70102}}),
                            },
                        },
                    },
                ],
            }
        }
        path = self.root / "c.har"
        path.write_text(json.dumps(har))
        key = b"k" * 32
        graph = build_object_graph("hc-mat", [path], key, authorized=True)
        mat = self.root / "pairs"
        doc = propose_object_handoff(graph, "hc-mat", key, verify_inputs=[path], limit=10, materialize_dir=mat)
        self.assertGreaterEqual(doc["materialized_pairs"], 1)
        row = doc["proposals"][0]
        self.assertEqual(row.get("provenance_origin"), "http://127.0.0.1:8142")
        self.assertIn("--base-url http://127.0.0.1:8142", row["suggested_discover_idor"])
        # Wrong caller base_url must not be written into the suggestion.
        doc2 = propose_object_handoff(
            graph,
            "hc-mat",
            key,
            verify_inputs=[path],
            limit=10,
            materialize_dir=mat,
            force=True,
            base_url="http://127.0.0.1:8137",
        )
        self.assertIn("--base-url http://127.0.0.1:8142", doc2["proposals"][0]["suggested_discover_idor"])
        self.assertNotIn("8137", doc2["proposals"][0]["suggested_discover_idor"])

    def test_dev_and_frozen_manifests(self) -> None:
        for root in (DEV, FROZEN):
            manifest = (root / "MANIFEST.sha256").read_text().splitlines()
            self.assertEqual(len(manifest), 2)
            for line in manifest:
                digest, name = line.split()
                actual = hashlib.sha256((root / name).read_bytes()).hexdigest()
                self.assertEqual(digest, actual, name)

    def test_corpus_generators_byte_identical(self) -> None:
        from labs.idor_handoff_case_eval.build_corpus import build_dev, build_frozen

        for builder, folder in ((build_frozen, FROZEN), (build_dev, DEV)):
            har, gt = builder()
            self.assertEqual(
                json.dumps(har, indent=1, sort_keys=True) + "\n",
                (folder / "captures.har").read_text(encoding="utf-8"),
            )
            self.assertEqual(
                json.dumps(gt, indent=1, sort_keys=True) + "\n",
                (folder / "ground_truth.json").read_text(encoding="utf-8"),
            )


class OriginHelperTests(unittest.TestCase):
    def test_origin_from_raw_absolute_and_host(self) -> None:
        abs_raw = "GET http://127.0.0.1:8142/x HTTP/1.1\r\nHost: ignored\r\n\r\n"
        self.assertEqual(origin_from_raw_request(abs_raw), "http://127.0.0.1:8142")
        rel = "GET /x HTTP/1.1\r\nHost: 127.0.0.1:8142\r\n\r\n"
        self.assertEqual(origin_from_raw_request(rel), "https://127.0.0.1:8142")
        self.assertIsNone(origin_from_raw_request("GET /x HTTP/1.1\r\n\r\n"))
        self.assertIsNone(origin_from_raw_request(""))

    def test_provenance_origin_agreement(self) -> None:
        a = "GET /a HTTP/1.1\r\nHost: 127.0.0.1:8142\r\n\r\n"
        b = "GET /b HTTP/1.1\r\nHost: 127.0.0.1:8142\r\n\r\n"
        c = "GET /c HTTP/1.1\r\nHost: 127.0.0.1:8143\r\n\r\n"
        self.assertEqual(provenance_origin(a, b), "https://127.0.0.1:8142")
        self.assertIsNone(provenance_origin(a, c))
        self.assertIsNone(provenance_origin("", ""))

    def test_map_inspect_error_branches(self) -> None:
        self.assertEqual(
            _map_inspect_error("same origin (scheme, host and port)"),
            ("technical_error", CODE_REJECT_ORIGIN_MISMATCH_SIDES),
        )
        self.assertEqual(
            _map_inspect_error("--base-url must match the origin"), ("technical_error", CODE_TECH_ORIGIN_OVERRIDE)
        )
        self.assertEqual(
            _map_inspect_error("This generator creates read cases and requires GET"),
            ("security_rejected", CODE_REJECT_NON_GET),
        )
        self.assertEqual(
            _map_inspect_error("GET captures with request bodies are unsupported"),
            ("security_rejected", CODE_REJECT_GET_WITH_BODY),
        )
        self.assertEqual(
            _map_inspect_error("Request methods differ: owner=GET, actor=POST"),
            ("security_rejected", CODE_REJECT_METHOD_MISMATCH),
        )
        self.assertEqual(
            _map_inspect_error("differences found at: path segment 2"),
            ("needs_more_evidence", CODE_REJECT_MULTI_RESOURCE_DIFF),
        )
        self.assertEqual(_map_inspect_error("probable same account"), ("needs_more_evidence", CODE_REJECT_SAME_SESSION))
        self.assertEqual(
            _map_inspect_error("differ outside the resource and session headers"),
            ("needs_more_evidence", CODE_REJECT_HEADER_DIFF),
        )
        self.assertEqual(_map_inspect_error("something novel"), ("needs_more_evidence", CODE_NEEDS_MORE_EVIDENCE))

    def test_classify_materialized_paths_missing_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            clf = classify_materialized_paths(Path(tmp), "missing-id")
            self.assertEqual(clf.status, "technical_error")


class AdversarialEvaluatorOriginTests(unittest.TestCase):
    def test_evaluator_uses_corpus_origin_not_hardcoded_port(self) -> None:
        source = (HERE / "labs" / "adversarial_idor_eval" / "evaluate.py").read_text(encoding="utf-8")
        self.assertNotIn('base_url="http://127.0.0.1:8137"', source)
        self.assertIn("corpus_origin", source)
        self.assertIn("classify_materialized_paths", source)


if __name__ == "__main__":
    unittest.main()
