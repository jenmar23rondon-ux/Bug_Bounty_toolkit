"""Offline external importers never confirm a tool alert."""

from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
import io
import json
from pathlib import Path
import stat
import tempfile
import unittest
from typing import Any, cast
from unittest.mock import patch

import bugbounty_toolkit.cli as cli
from bugbounty_toolkit.analysis.evidence_engine import _ffuf, _nuclei_row
from bugbounty_toolkit.analysis.external_importers import (
    SCHEMA,
    _READER_SALT,
    import_external,
    import_external_paths,
)


def load(path: Path, tool: str | None = None) -> dict[str, Any]:
    return cast(dict[str, Any], import_external(path, tool=tool))


def load_many(paths: list[Path]) -> dict[str, Any]:
    return cast(dict[str, Any], import_external_paths(paths))


def _http(body: str = "welcome") -> tuple[str, str]:
    request = "GET http://127.0.0.1:9/search HTTP/1.1\r\nHost: 127.0.0.1:9\r\n\r\n"
    response = f"HTTP/1.1 200 X\r\nContent-Type: text/plain\r\nContent-Length: {len(body.encode())}\r\n\r\n{body}"
    return request, response


class ExternalImporterTests(unittest.TestCase):
    def test_critical_and_sqlmap_claims_stay_unconfirmed(self) -> None:
        request, response = _http()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            nuclei = root / "nuclei.jsonl"
            nuclei.write_text(
                json.dumps(
                    {
                        "template-id": "synthetic-critical",
                        "matched-at": "http://127.0.0.1:9/search",
                        "info": {"severity": "critical", "tags": ["xss"]},
                        "request": request,
                        "response": response,
                        "classification": "confirmed",
                        "access_confirmed": True,
                        "vulnerabilities_confirmed": 4,
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            log = root / "sqlmap.log"
            log.write_text(
                "sqlmap/1.8.4#stable\n"
                "[10:00:01] [INFO] GET parameter 'id' is vulnerable. Do you want to keep testing?\n",
                encoding="utf-8",
            )
            for path in (nuclei, log):
                report = load(path, tool="sqlmap" if path is log else "nuclei")
                self.assertIsNone(report["fatal"])
                self.assertEqual(report["vulnerabilities_confirmed"], 0)
                self.assertFalse(report["access_confirmed"])
                self.assertEqual(report["network_requests_sent"], 0)
                finding = report["findings"][0]
                self.assertIn(finding["status"], {"candidate", "needs_review", "abstain"})
                self.assertNotEqual(finding["status"], "confirmed")
                self.assertFalse(finding["access_confirmed"])
                self.assertEqual(finding["vulnerabilities_confirmed"], 0)
                self.assertEqual(finding["schema"], SCHEMA)
            self.assertEqual(load(nuclei)["findings"][0]["status"], "candidate")
            self.assertEqual(load(log, tool="sqlmap")["findings"][0]["status"], "needs_review")

    def test_malformed_sibling_is_diagnosed_and_kept(self) -> None:
        request, response = _http("ok")
        first = {
            "template-id": "synthetic-reflection",
            "matched-at": "http://127.0.0.1:9/search",
            "info": {"severity": "low", "tags": ["xss"]},
            "request": request,
            "response": response,
        }
        third = {
            "template-id": "synthetic-exposure",
            "matched-at": "http://127.0.0.1:9/health",
            "info": {"severity": "info", "tags": ["exposure"]},
            "request": request.replace("/search", "/health"),
            "response": response,
        }
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "rows.jsonl"
            path.write_text(json.dumps(first) + "\n" + '{"template-id":\n' + json.dumps(third) + "\n", encoding="utf-8")
            report = load(path)
        self.assertIsNone(report["fatal"])
        self.assertEqual([item["origin"]["record_index"] for item in report["findings"]], [1, 3])
        self.assertEqual(report["diagnostics"][0]["code"], "malformed_json")
        self.assertEqual(report["diagnostics"][0]["index"], 2)

    def test_secrets_payloads_and_entities_are_not_copied(self) -> None:
        request, response = _http()
        request = (
            "GET http://127.0.0.1:9/search HTTP/1.1\r\nHost: 127.0.0.1:9\r\n"
            "Cookie: a=alpha-secret-value\r\nCookie: a=beta-secret-value\r\n\r\n"
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            nuclei = root / "cookies.jsonl"
            nuclei.write_text(
                json.dumps(
                    {
                        "template-id": "synthetic-reflection",
                        "matched-at": "http://127.0.0.1:9/search",
                        "info": {"severity": "low", "tags": ["xss"]},
                        "request": request,
                        "response": response,
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            dtd = root / "zap.xml"
            dtd.write_text(
                '<!DOCTYPE zap [<!ENTITY leak "ENTITY-LEAK-MARKER">]>\n'
                '<OWASPZAPReport version="2.14.0"><site><alerts><alertitem>'
                "<alert>&leak;</alert></alertitem></alerts></site></OWASPZAPReport>\n",
                encoding="utf-8",
            )
            cookie_report = load(nuclei)
            dtd_report = load(dtd)
            cookie_blob = json.dumps(cookie_report)
            dtd_blob = json.dumps(dtd_report)
        self.assertNotIn("alpha-secret-value", cookie_blob)
        self.assertNotIn("beta-secret-value", cookie_blob)
        self.assertEqual(cookie_report["findings"][0]["status"], "abstain")
        self.assertIn("ambiguous_session", cookie_report["findings"][0]["evidence"]["ingestion_diagnostics"])
        self.assertEqual(dtd_report["fatal"], "xml_dtd_forbidden")
        self.assertNotIn("ENTITY-LEAK-MARKER", dtd_blob)
        self.assertEqual(dtd_report["findings"], [])

    def test_sqlmap_session_and_dump_are_not_loaded(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "output"
            root.mkdir()
            (root / "log").write_text(
                "sqlmap/1.8.4#stable\n"
                "[10:00:01] [INFO] GET parameter 'id' appears to be 'boolean-based blind' injectable\n",
                encoding="utf-8",
            )
            (root / "dump").mkdir()
            (root / "dump" / "users.csv").write_text("id,name\n1,secret-dump-row\n", encoding="utf-8")
            import sqlite3

            connection = sqlite3.connect(root / "session.sqlite")
            connection.execute("create table storage (value blob)")
            connection.execute("insert into storage values (?)", (b"\x80\x04not-unpickled",))
            connection.commit()
            connection.close()
            with patch("pickle.loads", side_effect=AssertionError("pickle")):
                report = load(root, tool="sqlmap")
        blob = json.dumps(report)
        self.assertNotIn("secret-dump-row", blob)
        self.assertNotIn("not-unpickled", blob)
        self.assertTrue(any(item["code"] == "session_pickle_refused" for item in report["diagnostics"]))
        self.assertTrue(any(item["code"] == "sqlmap_dump_skipped" for item in report["diagnostics"]))
        self.assertEqual(len(report["findings"]), 1)
        self.assertFalse(report["findings"][0]["access_confirmed"])

    def test_empty_oversized_and_unknown_inputs_do_not_crash(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            empty = root / "empty.jsonl"
            empty.write_bytes(b"")
            huge = root / "huge.json"
            huge.write_bytes(b"{" * 80)
            note = root / "note.txt"
            note.write_text("hello\n", encoding="utf-8")
            with patch("bugbounty_toolkit.analysis.external_importers.MAX_EXTERNAL_BYTES", 64):
                oversized = load(huge)
            empty_report = load(empty)
            unknown = load(note, tool="other")
            sibling = load_many([empty, note])
        self.assertEqual(empty_report["fatal"], "empty_input")
        self.assertEqual(oversized["fatal"], "oversized_input")
        self.assertEqual(unknown["fatal"], "unknown_tool")
        self.assertEqual(sibling["summary"]["inputs"], 2)
        self.assertEqual(sibling["summary"]["findings"], 0)
        self.assertEqual(sibling["vulnerabilities_confirmed"], 0)
        self.assertFalse(sibling["scope_modified"])
        self.assertFalse(sibling["rate_limit_modified"])
        self.assertTrue(sibling["human_approval_required"])
        self.assertEqual(sibling["network_requests_sent"], 0)

    def test_nuclei_and_ffuf_identity_comes_from_existing_readers(self) -> None:
        request, response = _http()
        with tempfile.TemporaryDirectory() as directory:
            nuclei = Path(directory) / "nuclei.jsonl"
            row = {
                "template-id": "synthetic-reflection",
                "matched-at": "http://127.0.0.1:9/search",
                "info": {"severity": "low", "tags": ["xss"]},
                "matcher-name": "body",
                "request": request,
                "response": response,
            }
            nuclei.write_text(json.dumps(row) + "\n", encoding="utf-8")
            ffuf = Path(directory) / "ffuf.json"
            ffuf_row = {"url": "http://127.0.0.1:9/admin", "status": 200, "length": 5, "words": 1, "lines": 1}
            ffuf.write_text(json.dumps({"commandline": "ffuf", "results": [ffuf_row]}), encoding="utf-8")
            nuclei_record = _nuclei_row(nuclei, row, "line:1", _READER_SALT)
            ffuf_record = _ffuf(ffuf, {"results": [ffuf_row]}, _READER_SALT)[0]
            nuclei_finding = load(nuclei)["findings"][0]
            ffuf_finding = load(ffuf)["findings"][0]
        self.assertEqual(nuclei_finding["hypothesis"]["template_id"], nuclei_record.technical_evidence["template_id"])
        self.assertEqual(nuclei_finding["hypothesis"]["severity_claimed"], nuclei_record.technical_evidence["severity"])
        self.assertEqual(nuclei_finding["traceability"]["reader"], "evidence_engine._nuclei_row")
        self.assertTrue(nuclei_finding["hypothesis"]["vulnerability_claimed"])
        self.assertEqual(ffuf_finding["evidence"]["response_length"], ffuf_record.technical_evidence["response_length"])
        self.assertEqual(ffuf_finding["evidence"]["status_code"], ffuf_record.status_code)
        self.assertEqual(ffuf_finding["traceability"]["reader"], "evidence_engine._ffuf")
        self.assertFalse(ffuf_finding["hypothesis"]["vulnerability_claimed"])
        self.assertEqual(ffuf_finding["status"], "candidate")

    def test_oversized_csv_line_is_diagnosed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "ffuf.csv"
            path.write_text("url,status_code\n" + ("http://127.0.0.1:9/a," + ("x" * 80)) + "\n", encoding="utf-8")
            with patch("bugbounty_toolkit.analysis.external_importers.MAX_RECORD_BYTES", 40):
                report = load(path, tool="ffuf")
        self.assertIsNone(report["fatal"])
        self.assertEqual(report["findings"], [])
        self.assertTrue(any(item["code"] == "record_too_large" for item in report["diagnostics"]))

    def test_import_does_not_open_a_socket_or_subprocess(self) -> None:
        source = Path(external_importers_source())
        text = source.read_text(encoding="utf-8")
        for banned in ("subprocess", "urlopen", "pickle.loads", "pickle.load", "import pickle", "socket.socket"):
            self.assertNotIn(banned, text)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "ffuf.json"
            path.write_text(json.dumps({"results": [{"url": "http://127.0.0.1:9/a", "status": 200}]}), encoding="utf-8")
            with (
                patch("socket.socket", side_effect=AssertionError("network")),
                patch("subprocess.run", side_effect=AssertionError("subprocess")),
            ):
                report = load(path)
        self.assertEqual(report["network_requests_sent"], 0)
        self.assertEqual(len(report["findings"]), 1)

    def test_cli_dry_run_writes_nothing_and_save_is_private(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "ffuf.json"
            source.write_text(
                json.dumps({"results": [{"url": "http://127.0.0.1:9/a", "status": 200, "length": 1}]}),
                encoding="utf-8",
            )
            records = root / "records"
            dry = cli.build_parser().parse_args(
                [
                    "evidence",
                    "external",
                    "sample",
                    "--input",
                    str(source),
                    "--tool",
                    "ffuf",
                    "--attest-local-artifacts",
                    "--dry-run",
                ]
            )
            output = io.StringIO()
            with patch.object(cli, "RECORDS_ROOT", records), redirect_stdout(output):
                dry.func(dry)
            self.assertFalse(records.exists())
            summary = json.loads(output.getvalue().splitlines()[0])
            self.assertEqual(summary["vulnerabilities_confirmed"], 0)
            self.assertEqual(summary["network_requests_sent"], 0)
            self.assertFalse(summary["scope_modified"])
            self.assertIn("No scanner was executed", output.getvalue())
            with self.assertRaises(SystemExit), redirect_stderr(io.StringIO()):
                cli.build_parser().parse_args(["evidence", "external", "sample", "--input", str(source)])
            save = cli.build_parser().parse_args(
                [
                    "evidence",
                    "external",
                    "sample",
                    "--input",
                    str(source),
                    "--attest-local-artifacts",
                    "--output",
                    str(root / "out" / "findings.json"),
                ]
            )
            with redirect_stdout(io.StringIO()):
                save.func(save)
            written = root / "out" / "findings.json"
            self.assertEqual(stat.S_IMODE(written.stat().st_mode), 0o600)
            document = json.loads(written.read_text(encoding="utf-8"))
            self.assertEqual(document["schema"], SCHEMA)
            self.assertEqual(document["vulnerabilities_confirmed"], 0)
            self.assertFalse(document["findings"][0]["access_confirmed"])
            with self.assertRaisesRegex(ValueError, "already exists"):
                with redirect_stdout(io.StringIO()):
                    save.func(save)


def external_importers_source() -> str:
    import bugbounty_toolkit.analysis.external_importers as module

    return module.__file__


if __name__ == "__main__":
    unittest.main()
