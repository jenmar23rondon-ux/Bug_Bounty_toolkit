"""Ingestion regressions for incomplete, malformed and mixed captures.

Synthetic loopback fixtures only. No network, no frozen-corpus edits, and no
assertion that a capture is a confirmed vulnerability.
"""

from __future__ import annotations

import base64
import gzip
import json
from pathlib import Path
import tempfile
from typing import Any, cast
import unittest
import zlib

from bugbounty_toolkit.analysis.authorization_denial import assess_pair_authorization
from bugbounty_toolkit.analysis.evidence_engine import import_evidence
from bugbounty_toolkit.analysis.capture_ingestion import (
    assess_ingested_pair,
    fallback_discovery_sources,
    ingest_capture,
)
from bugbounty_toolkit.analysis.object_relationships import _read_sources
from bugbounty_toolkit.burp_import import parse_captured_exchanges

PRIVATE = '{"ok":true,"data":{"id":"20","marker":"synthetic-owner-resource"}}'
CANARY = "CANARY-INGEST-SYNTHETIC"


def _har(entries: list[object]) -> bytes:
    return json.dumps(
        {"log": {"version": "1.2", "creator": {"name": "synth", "version": "0"}, "entries": entries}}
    ).encode()


def _entry(
    *,
    method: str = "GET",
    url: str = "http://127.0.0.1:9/api/orders/7",
    status: int = 200,
    body: str = PRIVATE,
    response_headers: list[dict[str, str]] | None = None,
    request_headers: list[dict[str, str]] | None = None,
    encoding: str | None = None,
    include_response: bool = True,
    http_version: str | None = None,
) -> dict[str, object]:
    entry: dict[str, object] = {
        "request": {
            "method": method,
            "url": url,
            "headers": request_headers
            or [
                {"name": "Host", "value": "127.0.0.1:9"},
                {"name": "Authorization", "value": "Bearer synthetic"},
            ],
            "postData": {"mimeType": "application/json", "text": ""},
        }
    }
    if http_version:
        entry["httpVersion"] = http_version
    if include_response:
        content: dict[str, object] = {"mimeType": "application/json", "text": body}
        if encoding:
            content["encoding"] = encoding
        entry["response"] = {
            "status": status,
            "headers": response_headers or [{"name": "Content-Type", "value": "application/json"}],
            "content": content,
        }
    return entry


def _request(version: str = "HTTP/1.1", cookie: str = "sid=owner") -> bytes:
    return (f"GET /api/orders/7 {version}\r\nHost: 127.0.0.1:9\r\nCookie: {cookie}\r\n\r\n").encode()


def _response(
    version: str = "HTTP/1.1",
    status: int = 200,
    body: str = PRIVATE,
    extra: str = "",
    raw_body: bytes | None = None,
    encoding: str | None = None,
    content_type: str = "application/json",
) -> bytes:
    payload = body.encode("utf-8") if raw_body is None else raw_body
    headers = f"{version} {status} X\r\nContent-Type: {content_type}\r\n{extra}"
    if encoding:
        headers += f"Content-Encoding: {encoding}\r\n"
    headers += f"Content-Length: {len(payload)}\r\n\r\n"
    return headers.encode() + payload


def _burp(items: list[bytes]) -> bytes:
    return b"<items>" + b"".join(items) + b"</items>"


def _item(request: bytes, response: bytes | None = None, status: str | None = None) -> bytes:
    parts = [
        b"<item><url><![CDATA[http://127.0.0.1:9/api/orders/7]]></url>",
        b'<request base64="true">' + base64.b64encode(request) + b"</request>",
    ]
    if response is not None:
        parts.append(b'<response base64="true">' + base64.b64encode(response) + b"</response>")
    if status is not None:
        parts.append(f"<status>{status}</status>".encode())
    parts.append(b"</item>")
    return b"".join(parts)


class CaptureIngestionTests(unittest.TestCase):
    def test_formats_cover_the_heterogeneous_cases_without_crashing(self) -> None:
        latin = "café-order".encode("latin-1")
        compressed = gzip.compress(PRIVATE.encode())
        cases = {
            "har": _har([_entry()]),
            "har-missing": _har([_entry(include_response=False)]),
            "har-gzip": _har(
                [
                    _entry(
                        body=base64.b64encode(compressed).decode(),
                        encoding="base64",
                        response_headers=[
                            {"name": "Content-Type", "value": "application/json"},
                            {"name": "Content-Encoding", "value": "gzip"},
                        ],
                    )
                ]
            ),
            "har-latin1": _har(
                [
                    _entry(
                        body=base64.b64encode(latin).decode(),
                        encoding="base64",
                        response_headers=[{"name": "Content-Type", "value": "text/plain; charset=iso-8859-1"}],
                    )
                ]
            ),
            "burp-h2": _burp([_item(_request("HTTP/2"), _response("HTTP/2", 403, '{"error":"no"}'))]),
            "burp-h3": _burp([_item(_request("HTTP/3"), _response("HTTP/3", 302, "", extra="Location: /login\r\n"))]),
            "raw-h2": _request("HTTP/2"),
            "raw-gzip": _response(raw_body=compressed, encoding="gzip"),
            "empty": b"",
            "truncated": b'{"log": {"entries": [',
            "dtd": b'<!DOCTYPE items [<!ENTITY leak "' + CANARY.encode() + b'">]><items>&leak;</items>',
        }
        for name, payload in cases.items():
            with self.subTest(name=name):
                report = ingest_capture(payload)
                encoded = json.dumps(report.summary())
                self.assertNotIn(CANARY, encoded)
                self.assertEqual(report.network_requests_sent, 0)
                self.assertEqual(report.vulnerabilities_confirmed, 0)
                self.assertNotIn("true", encoded)

    def test_missing_response_is_kept_and_not_invented(self) -> None:
        report = ingest_capture(_har([_entry(), _entry(include_response=False, url="http://127.0.0.1:9/api/orders/8")]))
        self.assertIsNone(report.fatal)
        self.assertEqual(report.exchanges[0].status_code, 200)
        missing = report.exchanges[1]
        self.assertFalse(missing.response_present)
        self.assertIsNone(missing.status_code)
        self.assertIsNone(missing.response_body)
        self.assertIn("response_missing", missing.diagnostics)
        self.assertEqual(missing.confidence_cap, "partial")

    def test_gzip_base64_and_charset_are_decoded_only_when_valid(self) -> None:
        compressed = gzip.compress(PRIVATE.encode())
        gzip_report = ingest_capture(
            _har(
                [
                    _entry(
                        body=base64.b64encode(compressed).decode(),
                        encoding="base64",
                        response_headers=[
                            {"name": "Content-Type", "value": "application/json"},
                            {"name": "Content-Encoding", "value": "gzip"},
                        ],
                    )
                ]
            )
        )
        self.assertEqual(gzip_report.exchanges[0].response_body, PRIVATE)
        self.assertEqual(gzip_report.exchanges[0].confidence_cap, "observed")

        deflated = zlib.compress(b"plain-deflate")
        deflate_report = ingest_capture(
            _response(raw_body=deflated, encoding="deflate", body="", content_type="text/plain")
        )
        self.assertEqual(deflate_report.exchanges[0].response_body, "plain-deflate")

        latin = ingest_capture(
            _har(
                [
                    _entry(
                        body=base64.b64encode("café-order".encode("latin-1")).decode(),
                        encoding="base64",
                        response_headers=[{"name": "Content-Type", "value": "text/plain; charset=iso-8859-1"}],
                    )
                ]
            )
        )
        self.assertEqual(latin.exchanges[0].response_body, "café-order")

        broken = ingest_capture(_har([_entry(body="!!!!", encoding="base64")]))
        self.assertIsNone(broken.exchanges[0].response_body)
        self.assertNotEqual(broken.exchanges[0].response_body, "")
        self.assertIn("response_base64_invalid", broken.exchanges[0].diagnostics)

        brotli = ingest_capture(_response(raw_body=b"not-brotli", encoding="br", content_type="application/json"))
        self.assertIsNone(brotli.exchanges[0].response_body)
        self.assertIn("content_encoding_br_undecoded", brotli.exchanges[0].diagnostics)
        self.assertEqual(brotli.exchanges[0].confidence_cap, "partial")

    def test_duplicate_session_headers_are_not_collapsed(self) -> None:
        report = ingest_capture(
            _har(
                [
                    _entry(
                        request_headers=[
                            {"name": "Host", "value": "127.0.0.1:9"},
                            {"name": "Cookie", "value": "sid=aaa"},
                            {"name": "Cookie", "value": "sid=bbb"},
                        ]
                    )
                ]
            )
        )
        exchange = report.exchanges[0]
        self.assertEqual(exchange.session_state, "ambiguous")
        self.assertNotIn("sid=aaa", dict(exchange.confident_request_headers).values())
        self.assertNotIn("sid=bbb", dict(exchange.confident_request_headers).values())
        self.assertEqual(exchange.request_headers[1][1], "sid=aaa")
        self.assertEqual(exchange.request_headers[2][1], "sid=bbb")
        self.assertIn("ambiguous_session", exchange.diagnostics)

    def test_identical_duplicate_headers_stay_observed(self) -> None:
        report = ingest_capture(_response(extra="Content-Type: application/json\r\n", content_type="application/json"))
        # The helper already writes one Content-Type; extra adds a second identical one.
        exchange = report.exchanges[0]
        self.assertIn("duplicate_header_identical", exchange.diagnostics)
        self.assertEqual(exchange.confidence_cap, "observed")
        self.assertEqual(exchange.status_code, 200)

    def test_disagreeing_locations_and_content_types_lower_confidence(self) -> None:
        locations = ingest_capture(b"HTTP/1.1 302 Found\r\nLocation: /login\r\nLocation: /home\r\n\r\n")
        exchange = locations.exchanges[0]
        self.assertEqual(exchange.locations, ("/login", "/home"))
        self.assertNotIn("location", {name.lower() for name, _ in exchange.confident_response_headers})
        self.assertIn("ambiguous_redirect", exchange.diagnostics)
        outcome = assess_pair_authorization(
            _response(), b"HTTP/1.1 302 Found\r\nLocation: /login\r\nLocation: /home\r\n\r\n"
        )
        self.assertEqual(outcome.outcome, "inconclusive")
        self.assertIsNot((outcome.annotation or {}).get("access_confirmed"), True)

        types = ingest_capture(
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Type: text/plain\r\n\r\n" + PRIVATE.encode()
        )
        self.assertEqual(types.exchanges[0].confidence_cap, "ambiguous")
        self.assertNotIn("content-type", {name.lower() for name, _ in types.exchanges[0].confident_response_headers})

    def test_malformed_status_content_length_and_contradictions_do_not_become_access(self) -> None:
        malformed = ingest_capture(b"HTTP/1.1 200.0 OK\r\nContent-Type: application/json\r\n\r\n" + PRIVATE.encode())
        self.assertIsNone(malformed.exchanges[0].status_code)
        self.assertEqual(malformed.exchanges[0].response_body, PRIVATE)
        self.assertEqual(
            assess_pair_authorization(_response(), b"HTTP/1.1 200.0 OK\r\n\r\n" + PRIVATE.encode()).outcome,
            "inconclusive",
        )

        mismatch = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 3\r\n\r\n" + PRIVATE.encode()
        parsed = ingest_capture(mismatch)
        self.assertIn("content_length_mismatch", parsed.exchanges[0].diagnostics)
        self.assertEqual(assess_pair_authorization(_response(), mismatch).outcome, "inconclusive")

        contradicted = ingest_capture(_burp([_item(_request(), _response(status=200), status="403")]))
        self.assertIsNone(contradicted.exchanges[0].status_code)
        self.assertIn("contradictory_status", contradicted.exchanges[0].diagnostics)
        pair = assess_ingested_pair(ingest_capture(_response()).exchanges[0], contradicted.exchanges[0])
        self.assertEqual(pair.outcome, "inconclusive")
        self.assertIsNot((pair.annotation or {}).get("access_confirmed"), True)

    def test_textual_http2_and_http3_exports_reach_authorization(self) -> None:
        denied = _burp([_item(_request("HTTP/2"), _response("HTTP/2", 403, ""))])
        report = ingest_capture(denied)
        self.assertEqual(report.exchanges[0].http_version, "HTTP/2")
        self.assertEqual(report.exchanges[0].status_code, 403)
        self.assertEqual(report.exchanges[0].method, "GET")
        owner = ingest_capture(_response("HTTP/2")).exchanges[0]
        actor = report.exchanges[0]
        self.assertEqual(assess_ingested_pair(owner, actor).outcome, "cross_account_denied")

        redirected = ingest_capture(_response("HTTP/3", 302, "", extra="Location: /login\r\n"))
        self.assertEqual(redirected.exchanges[0].status_code, 302)
        self.assertEqual(redirected.exchanges[0].locations, ("/login",))
        self.assertEqual(
            assess_pair_authorization(
                _response("HTTP/3"), _response("HTTP/3", 302, "", extra="Location: /login\r\n")
            ).outcome,
            "cross_account_denied",
        )

    def test_mixed_burp_keeps_the_valid_sibling_and_refuses_dtd(self) -> None:
        mixed = _burp([_item(_request(), _response()), b"<item><request>NOT-HTTP</request></item>"])
        report = ingest_capture(mixed)
        self.assertEqual(len(report.exchanges), 1)
        self.assertEqual(report.exchanges[0].status_code, 200)
        self.assertTrue(any(item.code == "incomplete_message" for item in report.diagnostics))

        dtd = ingest_capture(b'<!DOCTYPE items [<!ENTITY leak "SECRET">]><items>&leak;</items>')
        self.assertEqual(dtd.fatal, "xml_dtd_forbidden")
        self.assertEqual(dtd.exchanges, ())
        self.assertNotIn("SECRET", json.dumps(dtd.summary()))

        self.assertEqual(ingest_capture(b"").fatal, "empty_input")
        self.assertEqual(ingest_capture(b'{"log":').fatal, "json_invalid")

    def test_strict_discovery_path_is_unchanged_for_clean_http11(self) -> None:
        payload = _burp([_item(_request(), _response(body="{}"))])
        strict = parse_captured_exchanges(payload)
        self.assertEqual(len(strict), 1)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "clean.xml"
            path.write_bytes(payload)

            def _boom(*_args: object, **_kwargs: object) -> object:
                raise AssertionError("clean HTTP/1.1 capture must stay on the strict importer")

            from bugbounty_toolkit.analysis import capture_ingestion

            original = capture_ingestion.fallback_discovery_sources
            capture_ingestion.fallback_discovery_sources = _boom  # type: ignore[assignment]
            try:
                _data, sources, summary = _read_sources(path, None)
            finally:
                capture_ingestion.fallback_discovery_sources = original
        self.assertEqual(summary["mode"], "strict")
        self.assertEqual(sources[0].status_code, 200)
        self.assertEqual(sources[0].method, "GET")

    def test_http2_burp_is_recovered_for_discovery_without_confirmation(self) -> None:
        payload = _burp([_item(_request("HTTP/2"), _response("HTTP/2", 403, ""))])
        with self.assertRaises(ValueError):
            parse_captured_exchanges(payload)
        sources, summary = fallback_discovery_sources(payload, None)
        self.assertEqual(summary["mode"], "partial")
        self.assertEqual(sources[0].status_code, 403)
        self.assertEqual(summary["vulnerabilities_confirmed"], 0)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "http2.xml"
            path.write_bytes(payload)
            _data, recovered, recovered_summary = _read_sources(path, None)
        self.assertEqual(recovered[0].status_code, 403)
        self.assertEqual(recovered_summary["mode"], "partial")

    def test_redirect_without_location_is_diagnosed(self) -> None:
        report = ingest_capture(b"HTTP/1.1 302 Found\r\nContent-Length: 0\r\n\r\n")
        self.assertIn("redirect_missing_location", report.exchanges[0].diagnostics)
        self.assertEqual(report.exchanges[0].locations, ())
        self.assertEqual(report.exchanges[0].confidence_cap, "partial")

    def test_evidence_import_decodes_gzip_and_leaves_clean_requests_unchanged(self) -> None:
        compressed = gzip.compress(b'{"ok":true}')
        gzip_message = _response(raw_body=compressed, encoding="gzip", body="")
        request = _request()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            gzip_path = root / "gzip.http"
            request_path = root / "request.http"
            gzip_path.write_bytes(gzip_message)
            request_path.write_bytes(request)
            decoded = import_evidence([gzip_path])
            clean = import_evidence([request_path])
        decoded_records = cast(list[dict[str, Any]], decoded["records"])
        clean_records = cast(list[dict[str, Any]], clean["records"])
        clean_inputs = cast(list[dict[str, Any]], clean["inputs"])
        record = decoded_records[0]
        self.assertEqual(decoded["vulnerabilities_confirmed"], 0)
        self.assertEqual(record["status_code"], 200)
        technical = cast(dict[str, Any], record["technical_evidence"])
        self.assertEqual(technical["response_bytes"], len(b'{"ok":true}'))
        self.assertEqual(record["validation_status"], "parsed")
        self.assertEqual(clean_records[0]["validation_status"], "parsed")
        self.assertIsNone(clean_inputs[0].get("capture_import"))

    def test_chrome_http2_alias_does_not_drop_a_har_entry(self) -> None:
        report = ingest_capture(_har([_entry(http_version="HTTP/2.0")]))
        self.assertEqual(report.exchanges[0].http_version, "HTTP/2")
        self.assertIn("http_version_alias", report.exchanges[0].diagnostics)
        self.assertEqual(report.exchanges[0].confidence_cap, "observed")
        self.assertEqual(report.exchanges[0].status_code, 200)


if __name__ == "__main__":
    unittest.main()
