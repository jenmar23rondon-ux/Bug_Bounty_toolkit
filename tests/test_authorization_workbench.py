from __future__ import annotations

import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from fastapi.testclient import TestClient

from bugbounty_toolkit.authorization_workbench import build_workbench
from bugbounty_toolkit.dashboard import create_app
from labs.authorization_workbench_eval.fixtures import populate


class WorkbenchTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.paths = populate(Path(self.temp.name))
        self.client = TestClient(
            create_app(self.paths.root, self.paths.program), base_url="http://127.0.0.1", client=("127.0.0.1", 1234)
        )
        self.addCleanup(self.client.close)

    def replace_capture(self, data: dict[str, object]) -> None:
        path = self.paths.evidence_dir / "synthetic.json"
        path.write_text(json.dumps(data), encoding="utf-8")
        lp = self.paths.program_dir / "ledger/evidence-ledger.json"
        ledger = json.loads(lp.read_text())
        ledger["evidence"][0]["sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
        lp.write_text(json.dumps(ledger))

    def test_states_alignment_read_only_and_no_network(self) -> None:
        ledger = self.paths.program_dir / "ledger/evidence-ledger.json"
        before = ledger.read_bytes()
        with patch("socket.socket.connect", side_effect=AssertionError("network forbidden")):
            result = build_workbench(self.paths, ["ev-lab@0", "ev-lab@1", "ev-lab@5"])
        self.assertEqual([c["response_state"] for c in result["columns"]], ["present", "denied_saved", "missing"])
        fields = {r["pointer"]: r for r in result["fields"]}
        self.assertEqual([c["state"] for c in fields["/nullable"]["cells"]], ["null", "absent", "unavailable"])
        self.assertEqual(fields["/empty"]["cells"][0]["state"], "empty_str")
        self.assertTrue(fields["/items/1"]["observed_difference"])
        self.assertFalse(fields["/items/0"]["observed_difference"])
        self.assertFalse(result["finding_confirmed"])
        self.assertEqual(ledger.read_bytes(), before)
        self.assertEqual(len(result["columns"]), 3)
        self.assertEqual(build_workbench(self.paths)["columns"], [])

    def test_saved_200_denial_and_public_do_not_imply_vulnerability(self) -> None:
        result = build_workbench(self.paths, ["ev-lab@2", "ev-lab@4"])
        self.assertEqual(result["columns"][0]["status_code"], 200)
        self.assertEqual(result["columns"][0]["response_state"], "denied_saved")
        self.assertIsNone(result["columns"][1]["saved_classification"])
        self.assertFalse(result["finding_confirmed"])
        self.assertEqual(len(result["columns"]), 2)

    def test_secrets_html_paths_and_arbitrary_property_names_withheld(self) -> None:
        # Construct per-run canaries; never persist literal secret values in Git or metrics.
        secret = "private-" + hashlib.sha256(self.temp.name.encode()).hexdigest()
        jwt = "eyJ" + secret.replace("-", "") + ".payload.signature"
        body = {
            secret: secret,
            "owner": secret,
            "cookie": secret,
            "9876": secret,
            "token": jwt,
            "path": "/home/example/private.json",
            "name": "<img src=x onerror=alert(1)>",
        }
        self.replace_capture(
            {
                "type": "authorization-workbench-lab",
                "authorized_captures": True,
                "captures": [
                    {"method": "GET", "status_code": 200, "body_available": True, "body_text": json.dumps(body)}
                ],
            }
        )
        output = json.dumps(build_workbench(self.paths, ["ev-lab@0"]))
        for value in (secret, jwt, "/home/example", "<img", "onerror", "cookie", "token", "9876"):
            self.assertNotIn(value, output)
        page = self.client.get("/authorization-workbench")
        self.assertEqual(page.status_code, 200)
        self.assertNotIn("innerHTML", page.text)
        self.assertNotIn("eval(", page.text)
        self.assertIn("textContent", page.text)

    def test_reference_tampering_symlinks_and_missing(self) -> None:
        path = self.paths.evidence_dir / "synthetic.json"
        original = path.read_bytes()
        path.write_bytes(original + b" ")
        self.assertEqual(build_workbench(self.paths)["catalog"], [])
        self.assertTrue(build_workbench(self.paths)["reference_issues"])
        path.unlink()
        self.assertEqual(build_workbench(self.paths)["catalog"], [])
        outside = Path(self.temp.name) / "outside.json"
        outside.write_bytes(original)
        path.symlink_to(outside)
        self.assertEqual(build_workbench(self.paths)["catalog"], [])
        with self.assertRaises(ValueError):
            build_workbench(self.paths, ["ev-lab@0"])

    def test_endpoint_selection_security_and_methods(self) -> None:
        for query in ("?a=ev-lab@0", "?c=ev-lab@1", "?a=ev-lab@0&b=ev-lab@0", "?a=../../x&b=x", "?a=x&b=y"):
            self.assertEqual(self.client.get("/api/authorization-workbench" + query).status_code, 400)
        self.assertEqual(self.client.get("/api/authorization-workbench?a=ev-lab@0&b=ev-lab@1").status_code, 200)
        for url in ("/authorization-workbench", "/api/authorization-workbench"):
            self.assertEqual(self.client.post(url).status_code, 405)
            self.assertEqual(self.client.get(url, headers={"host": "evil.example"}).status_code, 403)
            self.assertEqual(self.client.get(url, headers={"origin": "https://evil.example"}).status_code, 403)
            response = self.client.get(url)
            self.assertEqual(response.headers["cache-control"], "no-store")
            self.assertIn("object-src 'none'", response.headers["content-security-policy"])

    def test_har_and_predicate_only_native_formats(self) -> None:
        self.replace_capture(
            {
                "log": {
                    "entries": [
                        {
                            "request": {"method": "GET", "headers": [{"name": "cookie", "value": "private"}]},
                            "response": {"status": 200, "content": {"text": '{"success":true}'}},
                        }
                    ]
                }
            }
        )
        self.assertEqual(build_workbench(self.paths, ["ev-lab@0"])["columns"][0]["response_type"], "json")
        self.replace_capture(
            {
                "type": "access-control",
                "access_control_assessment": {"classification": "denied"},
                "steps": [{"status_code": 403, "application_success": False}, {"transport_error": True}],
            }
        )
        result = build_workbench(self.paths, ["ev-lab@0", "ev-lab@1"])
        self.assertEqual(result["fields"], [])
        self.assertEqual(result["columns"][0]["saved_predicates"], {"application_success": False})
        self.assertEqual(result["columns"][1]["response_state"], "missing")

    def test_bounds_unsupported_duplicate_json_and_missing_ledger(self) -> None:
        self.replace_capture(
            {
                "type": "authorization-workbench-lab",
                "authorized_captures": True,
                "captures": [
                    {"status_code": 200, "body_available": True, "body_text": '{"id":1,"id":2}'},
                    {"status_code": 200, "body_available": True, "body_text": json.dumps(list(range(1200)))},
                ],
            }
        )
        result = build_workbench(self.paths, ["ev-lab@0", "ev-lab@1"])
        self.assertEqual(result["fields"], [])
        self.assertTrue(all(c["body_state"] == "withheld" for c in result["columns"]))
        self.replace_capture({"unknown": True})
        self.assertEqual(build_workbench(self.paths)["catalog"], [])
        (self.paths.program_dir / "ledger/evidence-ledger.json").unlink()
        self.assertEqual(build_workbench(self.paths)["ledger_status"], "absent")

    def test_unsafe_paths_oversize_and_malformed_metadata(self) -> None:
        lp = self.paths.program_dir / "ledger/evidence-ledger.json"
        original = lp.read_text()
        for path in ("../../outside.json", "/tmp/outside.json"):
            ledger = json.loads(original)
            ledger["evidence"][0]["path"] = path
            lp.write_text(json.dumps(ledger))
            self.assertEqual(build_workbench(self.paths)["catalog"], [])
        lp.write_text(original)
        self.replace_capture(
            {
                "type": "authorization-workbench-lab",
                "authorized_captures": True,
                "captures": [
                    {"method": {}, "status_code": True, "assessment": {"classification": []}},
                    {"status_code": 200, "body_available": True, "body_text": "[" * 22 + "0" + "]" * 22},
                ],
            }
        )
        result = build_workbench(self.paths, ["ev-lab@0", "ev-lab@1"])
        self.assertEqual(result["columns"][0]["response_state"], "missing")
        self.assertEqual(result["columns"][1]["body_state"], "withheld")
        self.replace_capture({"data": "x" * 2_000_001})
        self.assertEqual(build_workbench(self.paths)["catalog"], [])

    def test_reason_is_saved_only_and_global_assessment_is_not_assigned_to_steps(self) -> None:
        self.replace_capture(
            {
                "type": "access-control",
                "access_control_assessment": {
                    "classification": "denied",
                    "reason": "Application-level success was false and no owner resource or private marker was observed.",
                },
                "steps": [{"status_code": 200, "application_success": True}, {"status_code": 403}],
            }
        )
        result = build_workbench(self.paths, ["ev-lab@0", "ev-lab@1"])
        self.assertEqual([c["response_state"] for c in result["columns"]], ["present", "present"])
        self.assertEqual(result["saved_assessments"][0]["classification"], "denied")
        self.assertTrue(result["saved_assessments"][0]["reason"].startswith("Application-level"))
        self.assertIsNone(result["columns"][0]["saved_classification"])
        self.assertNotIn("confirmed", result["saved_assessments"][0])

    def test_lab_metrics_and_distinct_redacted_values(self) -> None:
        from labs.authorization_workbench_eval.run import evaluate

        metrics = evaluate()
        self.assertEqual(metrics["canaries_exposed"], 0)
        self.assertEqual(metrics["missing_presented_as_denied"], 0)
        self.replace_capture(
            {
                "type": "authorization-workbench-lab",
                "authorized_captures": True,
                "captures": [
                    {"status_code": 200, "body_available": True, "body_text": json.dumps({"owner": value})}
                    for value in ("first-private", "second-private")
                ],
            }
        )
        rows = build_workbench(self.paths, ["ev-lab@0", "ev-lab@1"])["fields"]
        owner = next(row for row in rows if row["pointer"] == "/owner")
        self.assertTrue(owner["observed_difference"])
        self.assertEqual(owner["cells"][0], owner["cells"][1])

    def test_duplicate_ledger_ids_are_not_resolved_arbitrarily(self) -> None:
        lp = self.paths.program_dir / "ledger/evidence-ledger.json"
        ledger = json.loads(lp.read_text())
        ledger["evidence"].append(dict(ledger["evidence"][0]))
        lp.write_text(json.dumps(ledger))
        view = build_workbench(self.paths)
        self.assertEqual(view["catalog"], [])
        self.assertEqual(view["reference_issues"][0]["status"], "ambiguous_reference")
