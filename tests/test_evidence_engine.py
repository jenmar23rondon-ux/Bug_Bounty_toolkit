import base64
import json
from pathlib import Path
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from unittest.mock import patch

from bugbounty_toolkit import cli
from bugbounty_toolkit.analysis.evidence_engine import (
    MAX_INPUT_BYTES,
    correlate_evidence,
    correlations_from_bundle,
    import_evidence,
)


class EvidenceEngineTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def write_json(self, name, data):
        path = self.root / name
        path.write_text(json.dumps(data), encoding="utf-8")
        return path

    def test_har_anonymizes_accounts_and_correlates_templates_without_claiming_findings(self):
        har = self.write_json(
            "traffic.har",
            {
                "log": {
                    "entries": [
                        {
                            "startedDateTime": "2026-10-24T10:00:00Z",
                            "request": {
                                "method": "GET",
                                "url": "https://target.example/api/users/100?view=full",
                                "headers": [{"name": "Cookie", "value": "session=secret-cookie-a"}],
                            },
                            "response": {
                                "status": 200,
                                "headers": [{"name": "Content-Type", "value": "application/json"}],
                                "content": {"text": '{"id":100,"email":"a@example.test","token":"private-a"}'},
                            },
                        },
                        {
                            "startedDateTime": "2026-10-24T10:01:00Z",
                            "request": {
                                "method": "GET",
                                "url": "https://target.example/api/users/200?view=compact",
                                "headers": [{"name": "Cookie", "value": "session=secret-cookie-b"}],
                            },
                            "response": {
                                "status": 200,
                                "headers": [{"name": "Content-Type", "value": "application/json"}],
                                "content": {"text": '{"id":200,"email":"b@example.test","token":"private-b"}'},
                            },
                        },
                    ]
                }
            },
        )

        bundle = import_evidence([har])

        self.assertEqual(
            bundle["summary"],
            {
                "records_parsed": 2,
                "records_unique": 2,
                "duplicates_merged": 0,
                "correlation_groups": 1,
            },
        )
        records = bundle["records"]
        self.assertEqual({row["endpoint"] for row in records}, {"/api/users/{id}"})
        self.assertEqual({tuple(row["parameters"]) for row in records}, {("view",)})
        self.assertEqual(len({row["session_fingerprint"] for row in records}), 2)
        self.assertEqual(len({row["resource_fingerprint"] for row in records}), 2)
        serialized = json.dumps(bundle)
        for secret in ("secret-cookie", "private-a", "private-b", "a@example.test", "/users/100", "/users/200"):
            self.assertNotIn(secret, serialized)
        group = bundle["correlations"][0]
        self.assertEqual(group["distinct_sessions"], 2)
        self.assertEqual(group["distinct_resources"], 2)
        self.assertEqual(group["response_variants"], 2)
        self.assertFalse(group["finding_claimed"])

    def test_burp_xml_keeps_request_response_location_and_redacts_credentials(self):
        request = (
            "GET /api/items/900?access_token=qsecret HTTP/1.1\r\nHost: shop.example\r\nCookie: session=csecret\r\n\r\n"
        )
        response = 'HTTP/1.1 403 Forbidden\r\nContent-Type: application/json\r\n\r\n{"message":"denied"}'
        xml = self.root / "burp.xml"
        xml.write_text(
            "<items><item><url>https://shop.example/api/items/900?access_token=qsecret</url>"
            f'<request base64="true">{base64.b64encode(request.encode()).decode()}</request>'
            f'<response base64="true">{base64.b64encode(response.encode()).decode()}</response>'
            "</item></items>",
            encoding="utf-8",
        )

        bundle = import_evidence([xml])
        record = bundle["records"][0]

        self.assertEqual(record["source_tools"], ["burp"])
        self.assertEqual(record["method"], "GET")
        self.assertEqual(record["host"], "shop.example")
        self.assertEqual(record["endpoint"], "/api/items/{id}")
        self.assertEqual(record["status_code"], 403)
        self.assertEqual(record["parameters"], ["access_token"])
        self.assertEqual(record["sensitivity"], "sensitive")
        self.assertEqual(record["provenance"][0]["locator"], "/item[1]")
        serialized = json.dumps(bundle)
        for secret in ("qsecret", "csecret", "900"):
            self.assertNotIn(secret, serialized)

    def test_ffuf_json_semantically_deduplicates_and_preserves_both_sources(self):
        source = self.write_json(
            "ffuf.json",
            {
                "results": [
                    {"url": "https://target.example/admin", "status": 200, "length": 42},
                    {"url": "https://target.example/admin", "status": 200, "length": 42},
                ]
            },
        )

        bundle = import_evidence([source])
        record = bundle["records"][0]

        self.assertEqual(bundle["summary"]["records_parsed"], 2)
        self.assertEqual(bundle["summary"]["records_unique"], 1)
        self.assertEqual(record["source_tools"], ["ffuf"])
        self.assertEqual(len(record["provenance"]), 2)
        self.assertEqual(record["technical_evidence"]["response_length"], 42)

    def test_cross_format_dedup_keeps_each_source_and_provenance(self):
        sitemap = self.root / "routes.xml"
        sitemap.write_text(
            "<items><item><url>https://target.example/api/users/opaque-123</url></item></items>", encoding="utf-8"
        )
        notes = self.root / "notes.md"
        notes.write_text("Capture reference: https://target.example/api/users/opaque-123\n", encoding="utf-8")

        bundle = import_evidence([sitemap, notes])

        self.assertEqual(bundle["summary"]["records_parsed"], 2)
        self.assertEqual(bundle["summary"]["records_unique"], 1)
        record = bundle["records"][0]
        self.assertEqual(set(record["source_tools"]), {"burp", "document"})
        self.assertEqual(len(record["provenance"]), 2)
        self.assertEqual(record["endpoint"], "/api/users/{id}")
        self.assertNotIn("opaque-123", json.dumps(bundle))

    def test_nuclei_jsonl_and_toolkit_json_are_supported(self):
        nuclei = self.root / "nuclei.jsonl"
        nuclei.write_text(
            '{"template-id":"exposure-test","matched-at":"https://target.example/.well-known/info","info":{"severity":"low"}}\n',
            encoding="utf-8",
        )
        native = self.write_json(
            "toolkit.json",
            {
                "type": "xss",
                "results": [
                    {"url": "https://target.example/search?q=x", "status_code": 200, "classification": "possible"}
                ],
            },
        )

        bundle = import_evidence([nuclei, native])

        self.assertEqual(len(bundle["records"]), 2)
        self.assertEqual(
            set(bundle["records"][0]["source_tools"] + bundle["records"][1]["source_tools"]), {"nuclei", "xss"}
        )
        self.assertIn("template_id", bundle["records"][0]["technical_evidence"])
        self.assertIn("classification", bundle["records"][1]["technical_evidence"])

    def test_raw_http_request_and_response_extract_only_safe_metadata(self):
        request = self.root / "request.txt"
        request.write_bytes(
            "POST /api/items?owner_id=17 HTTP/1.1\r\n"
            "Host: target.example\r\n"
            "Cookie: session=raw-secret\r\n"
            "Content-Type: application/json\r\n\r\n"
            '{"name":"sample","password":"body-secret"}'.encode(),
        )
        response = self.root / "response.txt"
        response.write_bytes(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n"
            '{"id":17,"created_at":"2026-10-24T10:00:00Z","result":true}'.encode(),
        )

        bundle = import_evidence([request, response])
        request_row, response_row = bundle["records"]

        self.assertEqual(request_row["method"], "POST")
        self.assertEqual(request_row["host"], "target.example")
        self.assertEqual(request_row["parameters"], ["name", "owner_id", "password"])
        self.assertEqual(response_row["status_code"], 200)
        self.assertIsNone(response_row["host"])
        self.assertNotIn("raw-secret", json.dumps(bundle))
        self.assertNotIn("body-secret", json.dumps(bundle))

    def test_userinfo_and_malformed_host_are_not_persisted(self):
        source = self.root / "userinfo.txt"
        source.write_bytes(
            b"GET https://user:password@target.example/users/42 HTTP/1.1\r\nHost: ignored.example\r\n\r\n"
        )
        row = import_evidence([source])["records"][0]
        self.assertEqual(row["host"], "target.example")
        self.assertEqual(row["endpoint"], "/users/{id}")
        self.assertEqual(row["sensitivity"], "sensitive")
        self.assertNotIn("user:password", json.dumps(row))

    def test_burp_sitemap_dtd_and_invalid_base64_are_handled_safely(self):
        sitemap = self.root / "sitemap.xml"
        sitemap.write_text(
            "<items><item><url>https://target.example/api/public</url></item>"
            '<item><url>https://target.example/api/second</url><request base64="true">%%%bad%%</request></item></items>',
            encoding="utf-8",
        )
        bundle = import_evidence([sitemap])
        self.assertEqual(len(bundle["records"]), 2)
        self.assertEqual(bundle["records"][0]["technical_evidence"]["format"], "burp-sitemap")

        dtd = self.root / "dtd.xml"
        dtd.write_text('<!DOCTYPE items [<!ENTITY x "secret">]><items/>', encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "DTD/entity"):
            import_evidence([dtd])

    def test_har_cookie_arrays_base64_bodies_and_string_status(self):
        har = self.write_json(
            "cookies.har",
            {
                "log": {
                    "entries": [
                        {
                            "request": {
                                "method": "POST",
                                "url": "https://target.example/api/items?search=one",
                                "cookies": [{"name": "sid", "value": "hidden-session"}],
                                "postData": {
                                    "mimeType": "application/x-www-form-urlencoded",
                                    "text": "csrf=hidden&name=sample",
                                    "params": [{"name": "form_field"}],
                                },
                            },
                            "response": {
                                "status": "201",
                                "cookies": [{"name": "auth", "value": "hidden-response-cookie"}],
                                "content": {
                                    "encoding": "base64",
                                    "text": base64.b64encode(b"<html><body>ok</body></html>").decode(),
                                },
                            },
                        },
                        "not-an-entry",
                    ]
                }
            },
        )
        row = import_evidence([har])["records"][0]
        self.assertEqual(row["status_code"], 201)
        self.assertEqual(row["method"], "POST")
        self.assertEqual(set(row["parameters"]), {"search", "csrf", "name", "form_field"})
        self.assertEqual(row["sensitivity"], "sensitive")
        for secret in ("hidden-session", "hidden-response-cookie"):
            self.assertNotIn(secret, json.dumps(row))

    def test_nuclei_json_array_and_invalid_jsonl(self):
        nuclei = self.write_json(
            "findings.json",
            [
                {
                    "templateID": "test-template",
                    "matched-at": "https://target.example/status",
                    "info": {"severity": "info"},
                }
            ],
        )
        row = import_evidence([nuclei])["records"][0]
        self.assertEqual(row["source_tools"], ["nuclei"])
        self.assertEqual(row["technical_evidence"]["severity"], "info")

        invalid = self.root / "invalid.jsonl"
        invalid.write_text('{"template-id":\n', encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "line 1"):
            import_evidence([invalid])

    def test_native_report_document_formats_and_semantic_json_normalization(self):
        report = self.write_json(
            "report.json",
            {"findings": [{"title": "candidate", "target": "https://target.example/api/v1", "severity": "medium"}]},
        )
        html = self.root / "page.html"
        html.write_text(
            '<html><body><a href="https://target.example/page">Email test@example.test</a></body></html>',
            encoding="utf-8",
        )
        empty = self.root / "empty.txt"
        empty.write_text("", encoding="utf-8")
        first = self.write_json(
            "first.json",
            {
                "log": {
                    "entries": [
                        {
                            "request": {"method": "GET", "url": "https://target.example/status"},
                            "response": {
                                "status": 200,
                                "content": {"text": '{"ok":true,"timestamp":"2026-10-24T10:00:00Z"}'},
                            },
                        }
                    ]
                }
            },
        )
        second = self.write_json(
            "second.json",
            {
                "log": {
                    "entries": [
                        {
                            "request": {"method": "GET", "url": "https://target.example/status"},
                            "response": {
                                "status": 200,
                                "content": {"text": '{"ok":true,"timestamp":"2026-10-24T10:02:00Z"}'},
                            },
                        }
                    ]
                }
            },
        )

        bundle = import_evidence([report, html, empty, first, second])

        self.assertGreaterEqual(bundle["summary"]["records_parsed"], 5)
        self.assertIn("target.example", json.dumps(bundle))
        self.assertNotIn("test@example.test", json.dumps(bundle))
        self.assertEqual(bundle["summary"]["duplicates_merged"], 1)

    def test_input_validation_rejects_bad_formats_and_malformed_har_csv(self):
        source = self.write_json("source.json", {"ok": True})
        with self.assertRaisesRegex(ValueError, "Unsupported evidence format"):
            import_evidence([source], "yaml")
        malformed_har = self.write_json("malformed.har", {"log": "not-an-object"})
        with self.assertRaisesRegex(ValueError, "log.entries"):
            import_evidence([malformed_har])
        malformed_csv = self.root / "empty.csv"
        malformed_csv.write_text("", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "no header"):
            import_evidence([malformed_csv])
        missing = self.root / "missing.json"
        with self.assertRaisesRegex(ValueError, "Cannot read evidence input"):
            import_evidence([missing])

    def test_correlator_sanitizes_arbitrary_bundle_values(self):
        bundle = self.root / "unsafe-records.json"
        bundle.write_text(
            json.dumps(
                {
                    "type": "unified-evidence-bundle",
                    "records": [
                        {"host": "target.example", "endpoint": "/x", "method": "GET", "session_fingerprint": []},
                        {"host": "target.example", "endpoint": "/x", "method": "GET", "session_fingerprint": {}},
                    ],
                }
            ),
            encoding="utf-8",
        )
        result = correlations_from_bundle(bundle)
        self.assertEqual(result["summary"]["correlation_groups"], 1)

    def test_csv_and_markdown_extract_routes_without_storing_row_or_document_text(self):
        csv_path = self.root / "findings.csv"
        csv_path.write_text("url,method,status\nhttps://target.example/v1/users/42,GET,200\n", encoding="utf-8")
        markdown = self.root / "notes.md"
        markdown.write_text("Observed https://target.example/v1/users/43 and session=do-not-store\n", encoding="utf-8")

        bundle = import_evidence([csv_path, markdown])

        self.assertEqual(len(bundle["records"]), 2)
        serialized = json.dumps(bundle)
        self.assertNotIn("do-not-store", serialized)
        self.assertNotIn("/users/42", serialized)
        self.assertNotIn("/users/43", serialized)
        self.assertEqual({row["endpoint"] for row in bundle["records"]}, {"/v1/users/{id}"})

    def test_dry_run_does_not_write_and_existing_output_requires_force(self):
        source = self.write_json("ffuf.json", {"results": [{"url": "https://target.example/a", "status": 200}]})
        records_root = self.root / "records"
        args = cli.build_parser().parse_args(["evidence", "import", "sample", "--input", str(source), "--dry-run"])
        output = StringIO()
        with patch.object(cli, "RECORDS_ROOT", records_root), redirect_stdout(output):
            args.func(args)
        self.assertFalse((records_root / "sample").exists())
        self.assertIn("No target requests", output.getvalue())

        save_args = cli.build_parser().parse_args(["evidence", "import", "sample", "--input", str(source)])
        with patch.object(cli, "RECORDS_ROOT", records_root):
            with redirect_stdout(StringIO()):
                save_args.func(save_args)
            with self.assertRaisesRegex(ValueError, "already exists"):
                save_args.func(save_args)
            save_args.force = True
            with redirect_stdout(StringIO()):
                save_args.func(save_args)

    def test_correlate_command_reads_only_valid_bundle_and_is_dry_run_safe(self):
        source = self.write_json(
            "ffuf.json",
            {
                "results": [
                    {"url": "https://target.example/a", "status": 200},
                    {"url": "https://target.example/a", "status": 200},
                ]
            },
        )
        bundle = import_evidence([source])
        bundle_path = self.root / "bundle.json"
        bundle_path.write_text(json.dumps(bundle), encoding="utf-8")
        result = correlations_from_bundle(bundle_path)
        self.assertEqual(result["summary"]["records"], 1)
        self.assertEqual(result["summary"]["correlation_groups"], 0)

        invalid = self.root / "invalid.json"
        invalid.write_text("{}", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "not a unified evidence bundle"):
            correlations_from_bundle(invalid)

        records_root = self.root / "records"
        args = cli.build_parser().parse_args(
            ["evidence", "correlate", "sample", "--input", str(bundle_path), "--dry-run"]
        )
        with patch.object(cli, "RECORDS_ROOT", records_root), redirect_stdout(StringIO()):
            args.func(args)
        self.assertFalse((records_root / "sample").exists())

    def test_limits_and_malformed_inputs_fail_with_clear_errors(self):
        oversized = self.root / "large.txt"
        oversized.write_bytes(b"x" * (MAX_INPUT_BYTES + 1))
        with self.assertRaisesRegex(ValueError, "byte limit"):
            import_evidence([oversized])

        malformed = self.root / "broken.xml"
        malformed.write_text("<items>", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "Burp XML is malformed"):
            import_evidence([malformed])

        with self.assertRaisesRegex(ValueError, "between 1 and"):
            import_evidence([])

    def test_correlation_rejects_incomplete_endpoint_fields_without_crashing(self):
        self.assertEqual(correlate_evidence([{"host": "target.example", "endpoint": None, "method": "GET"}]), [])


if __name__ == "__main__":
    unittest.main()
