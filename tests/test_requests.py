import json
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

from bugbounty_toolkit.core.http_client import HttpClient, RequestSpec
from bugbounty_toolkit.core.request_builder import parse_raw_http_request
from bugbounty_toolkit.core.scope_validator import ScopeValidator
from bugbounty_toolkit.core.rate_limiter import RateLimiter
from bugbounty_toolkit.requests_engine.replay import RequestReplayer
from bugbounty_toolkit.requests_engine.headers import parse_header_items, parse_cookie_items
from bugbounty_toolkit.reporting.evidence import write_evidence_json
from bugbounty_toolkit.utils.exceptions import RequestBuildError


class LabHandler(BaseHTTPRequestHandler):
    hits = []

    def do_GET(self):
        self.hits.append(self.path)
        if self.path == "/redirect":
            self.send_response(302)
            self.send_header("Location", "/excluded")
            self.end_headers()
            return
        self.send_response(404 if self.path == "/missing" else 200)
        self.send_header("Content-Type", "application/json; charset=not-a-real-codec")
        self.send_header("Set-Cookie", "session=private-cookie")
        self.end_headers()
        self.wfile.write(json.dumps({"path": self.path, "token": "private-response-token"}).encode())

    def do_POST(self):
        body = self.rfile.read(int(self.headers["Content-Length"]))
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


class RequestTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), LabHandler)
        cls.worker = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.worker.start()
        cls.base = f"http://127.0.0.1:{cls.server.server_port}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.worker.join()
        cls.server.server_close()

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        path = self.root / "scope.txt"
        path.write_text(self.base + "\n!" + self.base + "/excluded\n")
        self.scope = ScopeValidator(path)
        self.client = HttpClient(self.scope, rate_limiter=RateLimiter(10000))
        LabHandler.hits.clear()

    def tearDown(self):
        self.temp.cleanup()

    def test_redirect_is_recorded_without_second_request(self):
        record = self.client.send(RequestSpec("GET", self.base + "/redirect"))
        self.assertEqual(record.status_code, 302)
        self.assertEqual(LabHandler.hits, ["/redirect"])

    def test_out_of_scope_never_reaches_server(self):
        with self.assertRaises(ValueError):
            self.client.send(RequestSpec("GET", self.base + "/excluded"))
        self.assertEqual(LabHandler.hits, [])

    def test_http_error_and_invalid_charset_produce_evidence(self):
        record = self.client.send(RequestSpec("GET", self.base + "/missing"))
        self.assertEqual(record.status_code, 404)
        self.assertIn("private-response-token", record.body_text)

    def test_request_response_secrets_are_redacted(self):
        spec = RequestSpec("GET", self.base + "/search?access_token=private-query", {"Authorization": "Bearer private-header"})
        record, path = RequestReplayer(self.scope, self.client).send_and_save(spec, self.root / "evidence")
        saved = path.read_text()
        for secret in ("private-header", "private-cookie", "private-query", "private-response-token"):
            with self.subTest(secret=secret):
                self.assertNotIn(secret, saved)
        self.assertEqual(record.status_code, 200)

    def test_burp_replay_recalculates_content_length(self):
        raw = 'POST /echo HTTP/1.1\r\nHOST: old.example\r\nContent-Length: 9999\r\nContent-Type: application/json\r\n\r\n{"password": "private-body"}'
        spec = parse_raw_http_request(raw, self.base)
        record = self.client.send(spec)
        self.assertEqual(record.status_code, 200)
        self.assertNotIn("private-body", json.dumps(record.to_dict()))

    def test_host_mismatch_is_rejected(self):
        with self.assertRaises(ValueError):
            self.client.send(RequestSpec("GET", self.base, {"Host": "different.example"}))
        self.assertEqual(LabHandler.hits, [])

    def test_response_size_limit(self):
        self.client.max_response_bytes = 10
        record = self.client.send(RequestSpec("GET", self.base))
        self.assertTrue(record.body_truncated)
        self.assertEqual(record.body_size, 10)

    def test_headers_cookies_and_invalid_requests(self):
        self.assertEqual(parse_header_items(["Accept: text/html", "accept: application/json"]), {"accept": "application/json"})
        self.assertIn("session=value", parse_cookie_items(["session=value"]))
        for value in ("Invalid header", "X-Test: ok\r\nInjected: header"):
            with self.assertRaises(ValueError):
                parse_header_items([value])
        with self.assertRaises(RequestBuildError):
            parse_raw_http_request("GET / HTTP/1.1\nHost: one.example\nHOST: two.example\n\n")

    def test_unique_evidence_filenames(self):
        first = write_evidence_json(self.root, {"run": 1})
        second = write_evidence_json(self.root, {"run": 2})
        self.assertNotEqual(first, second)
        self.assertEqual(json.loads(first.read_text())["run"], 1)

    def test_rate_limiter_waits_and_rejects_zero(self):
        with self.assertRaises(ValueError):
            RateLimiter(0)
        limiter = RateLimiter(2)
        with patch("bugbounty_toolkit.core.rate_limiter.time.monotonic", side_effect=[10, 10, 10.1, 10.5]), patch("bugbounty_toolkit.core.rate_limiter.time.sleep") as sleep:
            limiter.wait()
            limiter.wait()
            self.assertAlmostEqual(sleep.call_args.args[0], 0.4)
