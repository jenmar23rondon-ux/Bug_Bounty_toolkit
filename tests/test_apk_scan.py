from __future__ import annotations

import json
from pathlib import Path
import struct
import tempfile
from types import SimpleNamespace
import unittest
from contextlib import redirect_stdout
from io import StringIO
from unittest.mock import patch
import zipfile

from bugbounty_toolkit import cli
from bugbounty_toolkit.analysis.evidence_review import review_evidence
from bugbounty_toolkit.analysis.live_review import review_evidence_file
from bugbounty_toolkit.apk_scan import ApkScanner, parse_android_manifest
from bugbounty_toolkit.core.scope_validator import ScopeValidator


def _u8_length(value: int) -> bytes:
    if value < 0x80:
        return bytes([value])
    return bytes([(value >> 8) | 0x80, value & 0xFF])


def _axml_string_pool(strings: list[str]) -> bytes:
    entries = []
    for item in strings:
        encoded = item.encode("utf-8")
        entries.append(_u8_length(len(item)) + _u8_length(len(encoded)) + encoded + b"\0")
    offsets = []
    cursor = 0
    for entry in entries:
        offsets.append(cursor)
        cursor += len(entry)
    header_size = 28
    strings_start = header_size + len(strings) * 4
    body = struct.pack("<IIIII", len(strings), 0, 0x100, strings_start, 0)
    body += b"".join(struct.pack("<I", value) for value in offsets) + b"".join(entries)
    return struct.pack("<HHI", 0x0001, header_size, 8 + len(body)) + body


def _axml_start(name_index: int, attrs: list[tuple[int, int]]) -> bytes:
    size = 36 + len(attrs) * 20
    body = struct.pack("<II", 0, 0xFFFFFFFF)
    body += struct.pack("<IIHHHHHH", 0xFFFFFFFF, name_index, 20, 20, len(attrs), 0, 0, 0)
    for key_index, value_index in attrs:
        body += struct.pack("<IIIHBBI", 0xFFFFFFFF, key_index, 0xFFFFFFFF, 8, 0, 3, value_index)
    return struct.pack("<HHI", 0x0102, 16, size) + body


def _axml_end(name_index: int) -> bytes:
    body = struct.pack("<II", 0, 0xFFFFFFFF) + struct.pack("<II", 0xFFFFFFFF, name_index)
    return struct.pack("<HHI", 0x0103, 16, 24) + body


def _binary_manifest() -> bytes:
    strings = [
        "manifest",
        "intent-filter",
        "action",
        "category",
        "data",
        "name",
        "scheme",
        "host",
        "pathPrefix",
        "android.intent.action.VIEW",
        "android.intent.category.BROWSABLE",
        "myapp",
        "links.example.test",
        "/items",
    ]
    index = {value: position for position, value in enumerate(strings)}
    chunks = [
        _axml_start(index["manifest"], []),
        _axml_start(index["intent-filter"], []),
        _axml_start(index["action"], [(index["name"], index["android.intent.action.VIEW"])]),
        _axml_end(index["action"]),
        _axml_start(index["category"], [(index["name"], index["android.intent.category.BROWSABLE"])]),
        _axml_end(index["category"]),
        _axml_start(
            index["data"],
            [
                (index["scheme"], index["myapp"]),
                (index["host"], index["links.example.test"]),
                (index["pathPrefix"], index["/items"]),
            ],
        ),
        _axml_end(index["data"]),
        _axml_end(index["intent-filter"]),
        _axml_end(index["manifest"]),
    ]
    pool = _axml_string_pool(strings)
    content = pool + b"".join(chunks)
    return struct.pack("<HHI", 0x0003, 8, 8 + len(content)) + content


class ApkScanTests(unittest.TestCase):
    def _apk(self, path: Path, manifest: bytes | None = None) -> Path:
        with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr(
                "AndroidManifest.xml",
                manifest
                or b"""<?xml version="1.0"?><manifest xmlns:android="http://schemas.android.com/apk/res/android">
                <application><activity><intent-filter>
                <action android:name="android.intent.action.VIEW"/>
                <category android:name="android.intent.category.BROWSABLE"/>
                <data android:scheme="sampleapp" android:host="links.example.test" android:pathPrefix="/items"/>
                </intent-filter></activity></application></manifest>""",
            )
            archive.writestr(
                "assets/config.properties",
                """
                api=https://api.example.test/v1/user?access_token=private-query-token
                mirror=https://outside.test/health
                firebase=https://demo.firebaseio.com/config.json
                google=AIzaSyAbcdefghijklmnopqrstuvwxyz123456
                stripe=sk_live_abcdefghijklmnop
                token="super-secret-token-123"
                contact=jane.doe@example.test
                """,
            )
        return path

    def test_zip_only_finds_urls_keys_firebase_deep_links_and_emails_safely(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            apk = self._apk(root / "app.apk")
            scope_file = root / "scope.txt"
            scope_file.write_text("*.example.test\n*.firebaseio.com\n", encoding="utf-8")
            scanner = ApkScanner(ScopeValidator(scope_file))
            with (
                patch("socket.create_connection", side_effect=AssertionError("APK scan must not use network")),
                patch("bugbounty_toolkit.apk_scan.subprocess.run", side_effect=AssertionError("decompiler is opt-in")),
            ):
                evidence = scanner.scan(apk)

        self.assertEqual(evidence["manifest_status"], "parsed")
        self.assertEqual(evidence["network_requests_sent"], 0)
        self.assertEqual(evidence["decompiler"]["status"], "not_requested")
        self.assertGreaterEqual(evidence["counts"]["endpoint"], 3)
        self.assertGreaterEqual(evidence["counts"]["secret"], 3)
        self.assertGreaterEqual(evidence["counts"]["firebase"], 1)
        self.assertEqual(evidence["counts"]["deep_link"], 1)
        self.assertEqual(evidence["counts"]["email"], 1)
        endpoint = next(
            row for row in evidence["results"] if row["type"] == "endpoint" and row["host"] == "api.example.test"
        )
        self.assertEqual(endpoint["scope"], "in_scope")
        self.assertNotIn("private-query-token", endpoint["value"])
        outside = next(row for row in evidence["results"] if row.get("host") == "outside.test")
        self.assertEqual(outside["scope"], "out_of_scope")
        secret = next(row for row in evidence["results"] if row["type"] == "secret")
        self.assertIn("...", secret["value_masked"])
        email = next(row for row in evidence["results"] if row["type"] == "email")
        self.assertEqual(email["value_masked"], "j***@example.test")
        serialized = json.dumps(evidence)
        for raw in (
            "AIzaSyAbcdefghijklmnopqrstuvwxyz123456",
            "sk_live_abcdefghijklmnop",
            "super-secret-token-123",
            "jane.doe@example.test",
        ):
            self.assertNotIn(raw, serialized)

    def test_binary_manifest_deep_link_parser(self):
        self.assertEqual(parse_android_manifest(_binary_manifest()), ["myapp://links.example.test/items"])

    def test_text_manifest_requires_view_and_browsable_filter(self):
        manifest = b"""<manifest xmlns:android="http://schemas.android.com/apk/res/android"><application>
        <activity><intent-filter><action android:name="android.intent.action.VIEW"/>
        <category android:name="android.intent.category.BROWSABLE"/>
        <data android:scheme="https" android:host="example.test" android:path="/open"/>
        </intent-filter><intent-filter><action android:name="android.intent.action.VIEW"/>
        <data android:scheme="ignored"/></intent-filter></activity></application></manifest>"""
        self.assertEqual(parse_android_manifest(manifest), ["https://example.test/open"])

    def test_decompile_is_explicit_and_missing_tools_fall_back_to_zip(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            apk = self._apk(root / "app.apk")
            scope_file = root / "scope.txt"
            scope_file.write_text("example.test\n", encoding="utf-8")
            scanner = ApkScanner(ScopeValidator(scope_file))
            with patch.object(scanner, "_decompiler", return_value=None):
                result = scanner.scan(apk, decompile=True)
        self.assertEqual(result["decompiler"]["status"], "unavailable")
        self.assertEqual(result["scan_mode"], "zip_only")
        self.assertTrue(result["warnings"])

    def test_opted_in_decompiler_is_timeout_limited_and_scanned(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            apk = self._apk(root / "app.apk")
            scope_file = root / "scope.txt"
            scope_file.write_text("*.example.test\n", encoding="utf-8")
            scanner = ApkScanner(ScopeValidator(scope_file))

            def fake_decompile(command: list[str], **kwargs: object) -> SimpleNamespace:
                output = Path(command[command.index("-d") + 1])
                output.mkdir()
                (output / "Extracted.java").write_text("https://api.example.test/from-source", encoding="utf-8")
                self.assertFalse(kwargs["shell"])
                self.assertEqual(kwargs["timeout"], 120)
                return SimpleNamespace(returncode=0)

            with (
                patch.object(scanner, "_decompiler", return_value=("jadx", "jadx.exe")),
                patch("bugbounty_toolkit.apk_scan.subprocess.run", side_effect=fake_decompile) as decompiler,
            ):
                evidence = scanner.scan(apk, decompile=True)
            decompiler.assert_called_once()

        self.assertEqual(evidence["decompiler"]["status"], "complete")
        self.assertEqual(evidence["scan_mode"], "zip_plus_decompiler")
        self.assertTrue(any(row.get("file") == "jadx/Extracted.java" for row in evidence["results"]))

    def test_cli_parser_and_local_evidence_output(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            apk = self._apk(root / "test-app.apk")
            records = root / "records"
            program_dir = records / "lab"
            program_dir.mkdir(parents=True)
            (program_dir / "scope.txt").write_text("example.test\n", encoding="utf-8")
            args = cli.build_parser().parse_args(["--records-root", str(records), "apk-scan", "lab", "--apk", str(apk)])
            output = StringIO()
            with redirect_stdout(output), patch.object(cli, "RECORDS_ROOT", records):
                args.func(args)
            evidence_files = list((program_dir / "evidence" / "apk-scan").glob("*.json"))
            self.assertEqual(len(evidence_files), 1)
            evidence = json.loads(evidence_files[0].read_text(encoding="utf-8"))
            self.assertEqual(evidence["type"], "apk-scan")
            self.assertIn("Nothing was contacted", output.getvalue())

    def test_cli_dry_run_validates_only_and_does_not_create_records(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            apk = self._apk(root / "test-app.apk")
            records = root / "records"
            program_dir = records / "lab"
            program_dir.mkdir(parents=True)
            (program_dir / "scope.txt").write_text("example.test\n", encoding="utf-8")
            args = cli.build_parser().parse_args(
                ["--records-root", str(records), "apk-scan", "lab", "--apk", str(apk), "--dry-run"]
            )
            output = StringIO()
            with (
                redirect_stdout(output),
                patch.object(cli, "RECORDS_ROOT", records),
                patch.object(ApkScanner, "scan", side_effect=AssertionError("dry-run must not scan")),
            ):
                args.func(args)
            self.assertFalse((program_dir / "toolkit.sqlite3").exists())
            self.assertIn("no requests sent", output.getvalue())

    def test_ai_exporter_contains_only_aggregate_pattern_metadata(self):
        data = {
            "type": "apk-scan",
            "classification": "candidate",
            "source": {"filename": "private-app.apk", "sha256": "abc"},
            "counts": {"secret": 1, "endpoint": 1},
            "scope_counts": {"in_scope": 1, "out_of_scope": 0},
            "secret_pattern_counts": {"google_api_key": 1},
            "results": [
                {
                    "type": "secret",
                    "classification": "candidate",
                    "value_masked": "AIza...1234",
                    "length_bucket": "33+",
                    "file": "classes.dex",
                }
            ],
        }
        packet = review_evidence(data)
        packet_text = json.dumps(packet)
        self.assertEqual(packet["secret_pattern_counts"], {"google_api_key": 1})
        self.assertEqual(packet["secret_length_buckets"], {"33+": 1})
        for private in ("private-app.apk", "AIza...1234", "classes.dex", "abc"):
            self.assertNotIn(private, packet_text)
        with tempfile.TemporaryDirectory() as directory:
            evidence_path = Path(directory) / "evidence.json"
            evidence_path.write_text(json.dumps(data), encoding="utf-8")
            with patch(
                "bugbounty_toolkit.analysis.live_review.review_with_ollama",
                return_value={"assessment": {"decision": "candidate"}},
            ) as model:
                result = review_evidence_file(evidence_path, "qwen2.5-coder:7b", 10)
            model_packet = model.call_args.args[0]
            self.assertEqual(model_packet["topic"], "apk-scan")
            self.assertEqual(result["status"], "available")
            self.assertNotIn("private-app.apk", json.dumps(model_packet))

    def test_cli_ai_options_are_opt_in_and_decompiler_plan_is_boolean(self):
        parser = cli.build_parser()
        args = parser.parse_args(["apk-scan", "lab", "--apk", "app.apk", "--ai-review", "--decompile"])
        self.assertTrue(args.ai_review)
        self.assertTrue(args.decompile)


if __name__ == "__main__":
    unittest.main()
