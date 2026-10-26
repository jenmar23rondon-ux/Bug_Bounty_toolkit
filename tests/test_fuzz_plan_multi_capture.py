"""fuzz-plan multi-format capture adapter: HAR / Burp XML / raw HTTP parity and isolation."""

from __future__ import annotations

import base64
import contextlib
import io
import json
import socket
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from bugbounty_toolkit.cli import build_parser
from bugbounty_toolkit.core.scope_validator import ScopeValidator
from bugbounty_toolkit.fuzzing.capture_adapter import (
    CAPTURE_ENTRY_REASONS,
    CaptureImportError,
    detect_capture_format,
    load_capture_for_planning,
)
from bugbounty_toolkit.fuzzing.context_planner import build_fuzz_plan, load_har_for_planning
from bugbounty_toolkit.fuzzing.wordlist_manager import register_collection

REPO = Path(__file__).resolve().parents[1]
LAB = REPO / "labs" / "context_fuzz_lab"
FIX = LAB / "fixtures"
HAR = FIX / "capture.har"
BURP = FIX / "capture.burp.xml"
ORIGIN = "http://127.0.0.1:8191"
SECRET = "SYNTH-SECRET"


@contextlib.contextmanager
def no_network():
    def blocked(*_args, **_kwargs):
        raise AssertionError("network attempted during offline capture import")

    with contextlib.ExitStack() as stack:
        stack.enter_context(patch.object(socket.socket, "connect", blocked))
        stack.enter_context(patch.object(socket.socket, "connect_ex", blocked))
        stack.enter_context(patch("socket.create_connection", blocked))
        stack.enter_context(patch("socket.getaddrinfo", blocked))
        yield


def _req(path: str, host: str = "127.0.0.1:8191", extra: str = "") -> str:
    return f"GET {path} HTTP/1.1\r\nHost: {host}\r\nAccept: application/json\r\n{extra}\r\n"


def _resp(body: str = "{}", status: int = 200, extra: str = "") -> str:
    return (
        f"HTTP/1.1 {status} OK\r\nContent-Type: application/json\r\n{extra}"
        f"Content-Length: {len(body.encode())}\r\n\r\n{body}"
    )


def _item(request: str | None, response: str | None, url: str, *, b64: bool = True) -> str:
    def node(tag: str, value: str) -> str:
        if b64:
            return f'<{tag} base64="true">{base64.b64encode(value.encode()).decode()}</{tag}>'
        return f"<{tag}><![CDATA[{value}]]></{tag}>"

    parts = [f"<url><![CDATA[{url}]]></url>"]
    if request is not None:
        parts.append(node("request", request))
    if response is not None:
        parts.append(node("response", response))
    return "<item>" + "".join(parts) + "</item>"


class MultiCaptureTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.collection = register_collection(self.root / "wl.json", "lab", LAB / "wordlists")
        scope_file = self.root / "scope.txt"
        scope_file.write_text(ORIGIN + "\n", encoding="utf-8")
        self.scope = ScopeValidator(scope_file)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def write(self, name: str, text: str) -> Path:
        path = self.root / name
        path.write_text(text, encoding="utf-8")
        return path

    def xml(self, *items: str) -> Path:
        return self.write("c.xml", "<items>" + "".join(items) + "</items>")

    def plan(self, path: Path, **kwargs):
        with no_network():
            return build_fuzz_plan("lab", path, collections=[self.collection], scope=self.scope, max_tests=20, **kwargs)

    # --- formats and parity -------------------------------------------------
    def test_detect_format(self) -> None:
        self.assertEqual(detect_capture_format(HAR.read_bytes()), "har")
        self.assertEqual(detect_capture_format(BURP.read_bytes()), "burp-xml")
        self.assertEqual(detect_capture_format((FIX / "raw" / "00.request.http").read_bytes()), "raw-http")
        with self.assertRaises(CaptureImportError) as ctx:
            detect_capture_format(b"hello world")
        self.assertEqual(ctx.exception.reason, "format_unknown")

    def test_explicit_format_mismatch_rejected(self) -> None:
        with self.assertRaises(CaptureImportError) as ctx:
            load_capture_for_planning(BURP, capture_format="har")
        self.assertEqual(ctx.exception.reason, "format_mismatch")

    def test_har_output_identical_through_adapter(self) -> None:
        legacy = self.plan(HAR).to_dict()
        via_auto = self.plan(HAR, capture_format="auto").to_dict()
        self.assertEqual(json.dumps(legacy, sort_keys=True), json.dumps(via_auto, sort_keys=True))
        self.assertEqual(load_har_for_planning(HAR).summary(), load_capture_for_planning(HAR).summary())

    def test_burp_xml_parity_with_har(self) -> None:
        har = self.plan(HAR).to_dict()
        burp = self.plan(BURP, capture_format="auto").to_dict()
        for key in (
            "hosts",
            "schemes",
            "route_prefixes",
            "observed_paths",
            "parameters",
            "technologies",
            "categories_needed",
            "methods",
        ):
            self.assertEqual(har["context"].get(key), burp["context"].get(key), key)
        self.assertEqual(
            [(t["url_template"], t["wordlist"]) for t in har["targets"]],
            [(t["url_template"], t["wordlist"]) for t in burp["targets"]],
        )
        imp = burp["context"]["capture_import"]
        self.assertEqual((imp["format"], imp["accepted"], imp["rejected"]), ("burp-xml", 9, 0))
        self.assertEqual(imp["provenance"]["paired_responses"], 9)
        self.assertEqual(imp["provenance"]["locators"], [f"/items/item[{i}]" for i in range(9)])

    def test_raw_http_parity_per_request(self) -> None:
        har_sources = load_har_for_planning(HAR).accepted
        for index, har_source in enumerate(har_sources):
            raw = load_capture_for_planning(
                FIX / "raw" / f"{index:02d}.request.http",
                response_path=FIX / "raw" / f"{index:02d}.response.http",
                origin=ORIGIN,
            )
            (source,) = raw.accepted
            self.assertEqual(source.url, har_source.url)
            self.assertEqual(source.method, har_source.method)
            self.assertEqual(source.status_code, har_source.status_code)
            self.assertEqual(set(source.parameters), set(har_source.parameters))
            self.assertEqual(source.response_body, har_source.response_body)

    def test_raw_requires_origin_and_never_rewrites(self) -> None:
        raw = FIX / "raw" / "00.request.http"
        with self.assertRaises(CaptureImportError) as ctx:
            load_capture_for_planning(raw)
        self.assertEqual(ctx.exception.reason, "raw_origin_required")
        with self.assertRaises(CaptureImportError) as ctx:
            load_capture_for_planning(raw, origin="http://other.example:8191")
        self.assertEqual(ctx.exception.entry_reason, "host_inconsistent")

    def test_request_without_response_not_invented(self) -> None:
        result = load_capture_for_planning(FIX / "raw" / "04.request.http", origin=ORIGIN)
        (source,) = result.accepted
        self.assertIsNone(source.status_code)
        self.assertEqual(source.response_body, "")
        self.assertEqual(result.summary()["provenance"]["requests_without_response"], 1)
        path = self.xml(_item(_req("/a"), None, ORIGIN + "/a"))
        self.assertIsNone(load_capture_for_planning(path).accepted[0].status_code)

    def test_response_file_only_for_raw(self) -> None:
        with self.assertRaises(CaptureImportError) as ctx:
            load_capture_for_planning(BURP, response_path=FIX / "raw" / "00.response.http")
        self.assertEqual(ctx.exception.reason, "response_without_raw_request")

    # --- adversarial -------------------------------------------------------
    def test_partial_recovery_isolates_items_with_codes(self) -> None:
        good = _item(_req("/api/v1/orders"), _resp(), ORIGIN + "/api/v1/orders")
        items = [
            good,
            _item(_resp(), _req("/x"), ORIGIN + "/x"),  # swapped
            _item(_req("/b", host="evil.example"), _resp(), ORIGIN + "/b"),  # host mismatch
            _item("GET /c HTTP/1.1\r\nHost: 127.0.0.1:8191\r\n", _resp(), ORIGIN + "/c"),  # incomplete
            '<item><url>http://127.0.0.1:8191/d</url><request base64="true">@@@not-b64@@@</request></item>',
            _item(None, _resp(), ORIGIN + "/e"),  # no request
            _item(_req("/f", extra="Accept: x\r\n"), _resp(), ORIGIN + "/f"),  # duplicate header
            _item(_req("/g"), _resp(extra="Content-Encoding: gzip\r\n"), ORIGIN + "/g"),
            _item(_req("/h"), "HTTP/1.1 200 OK\r\nContent-Length: 99\r\n\r\n{}", ORIGIN + "/h"),
            _item(_req("/i"), _resp(), "http://127.0.0.1:9999/i"),  # item url origin disagrees
            good,  # duplicate
        ]
        with no_network():
            result = load_capture_for_planning(self.xml(*items))
        summary = result.summary()
        self.assertEqual(summary["accepted"], 2)
        self.assertEqual(summary["duplicate_entries"], 1)
        codes = {row["index"]: row["reason"] for row in summary["rejected_entries"]}
        self.assertEqual(
            codes,
            {
                1: "request_line_invalid",
                2: "host_inconsistent",
                3: "request_incomplete",
                4: "request_base64_invalid",
                5: "request_missing",
                6: "request_headers_ambiguous",
                7: "response_encoding_unsupported",
                8: "response_length_mismatch",
                9: "host_inconsistent",
            },
        )
        for reason in codes.values():
            self.assertIn(reason, CAPTURE_ENTRY_REASONS)
        # Each accepted source keeps its own item's locator and response.
        self.assertEqual([s.locator for s in result.accepted], ["/items/item[0]", "/items/item[10]"])
        with self.assertRaises(CaptureImportError) as ctx:
            load_capture_for_planning(self.xml(*items), strict=True)
        self.assertEqual(ctx.exception.reason, "strict_entry_rejected")

    def test_never_pairs_across_items(self) -> None:
        items = [
            _item(_req("/one"), None, ORIGIN + "/one"),
            _item(_req("/two"), _resp('{"two": 1}', status=201), ORIGIN + "/two"),
        ]
        result = load_capture_for_planning(self.xml(*items))
        first, second = result.accepted
        self.assertIsNone(first.status_code)
        self.assertEqual(second.status_code, 201)
        self.assertIn("two", second.response_body)
        multiple = "<item><url>http://127.0.0.1:8191/z</url>" + _item(_req("/z"), _resp(), "")[6:-7]
        multiple += f'<response base64="true">{base64.b64encode(_resp().encode()).decode()}</response></item>'
        result = load_capture_for_planning(self.xml(multiple, items[1]))
        self.assertEqual(result.summary()["reasons"], {"item_messages_ambiguous": 1})

    def test_xml_global_failures_are_fatal(self) -> None:
        cases = {
            "xml_dtd_or_entity": '<?xml version="1.0"?><!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/passwd">]>'
            "<items><item>&e;</item></items>",
            "xml_malformed": "<items><item><request>",
            "xml_no_items": "<items></items>",
        }
        for reason, text in cases.items():
            with self.subTest(reason), self.assertRaises(CaptureImportError) as ctx:
                load_capture_for_planning(self.write("x.xml", text))
            self.assertEqual(ctx.exception.reason, reason)
        with self.assertRaises(CaptureImportError) as ctx:
            load_capture_for_planning(self.xml(_item(_resp(), None, ORIGIN + "/q")))
        self.assertEqual(ctx.exception.reason, "no_valid_entries")

    def test_over_limit_keeps_32_and_allow_truncate_semantics(self) -> None:
        items = [_item(_req(f"/p{i}"), _resp(), f"{ORIGIN}/p{i}") for i in range(33)]
        path = self.xml(*items)
        with self.assertRaises(CaptureImportError) as ctx:
            load_capture_for_planning(path)
        self.assertEqual(ctx.exception.reason, "entries_over_limit")
        result = load_capture_for_planning(path, allow_truncate=True)
        self.assertTrue(result.truncated)
        self.assertEqual(result.summary()["reasons"], {"over_entry_limit": 1})
        self.assertEqual(len(result.accepted), 32)

    def test_oversized_file_rejected(self) -> None:
        big = self.root / "big.xml"
        with big.open("wb") as handle:
            handle.truncate(32 * 1024 * 1024 + 1)
        with self.assertRaises(ValueError):
            load_capture_for_planning(big)

    def test_multiple_sessions_and_sensitive_params_never_leak(self) -> None:
        items = [
            _item(
                _req("/api/v1/orders?token=SYNTH-SECRET-q", extra=f"Cookie: sid={SECRET}-a\r\n"),
                _resp(),
                ORIGIN + "/api/v1/orders?token=SYNTH-SECRET-q",
            ),
            _item(
                _req("/api/v1/orders", extra=f"Authorization: Bearer {SECRET}-b\r\n"),
                _resp(f'{{"session": "{SECRET}-c"}}'),
                ORIGIN + "/api/v1/orders",
            ),
        ]
        plan = self.plan(self.xml(*items), capture_format="burp-xml")
        blob = json.dumps(plan.to_dict())
        self.assertNotIn(SECRET, blob)
        self.assertNotIn("Bearer", blob)
        self.assertEqual(plan.context.capture_import["accepted"], 2)
        summary = load_capture_for_planning(self.xml(*items)).summary()
        self.assertNotIn(SECRET, json.dumps(summary))
        self.assertNotIn("/api/v1/orders", json.dumps(summary))

    def test_burp_plan_targets_stay_in_scope(self) -> None:
        items = [
            _item(_req("/api/v1/x", host="out.example"), _resp(), "https://out.example/api/v1/x"),
            _item(_req("/api/v1/y"), _resp(), ORIGIN + "/api/v1/y"),
        ]
        plan = self.plan(self.xml(*items), capture_format="auto")
        for target in plan.targets:
            self.scope.require(target.url_template.replace("FUZZ", "probe"))
        self.assertFalse(plan.auto_execute)
        self.assertEqual(plan.network_requests_sent, 0)

    def test_cli_options(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["fuzz-plan", "p", "--capture", str(BURP), "--format", "burp-xml", "--dry-run"])
        self.assertEqual((args.capture_format, args.har), ("burp-xml", None))
        args = parser.parse_args(["fuzz-plan", "p", "--har", str(HAR)])
        self.assertEqual(args.capture, None)
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            parser.parse_args(["fuzz-plan", "p", "--har", str(HAR), "--capture", str(BURP)])
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            parser.parse_args(["fuzz-plan", "p"])


if __name__ == "__main__":
    unittest.main()
