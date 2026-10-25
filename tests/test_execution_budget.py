from concurrent.futures import ThreadPoolExecutor
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch
from urllib.error import URLError

from bugbounty_toolkit.core.execution_budget import ExecutionBudget
from bugbounty_toolkit.core.http_client import HttpClient, RequestSpec
from bugbounty_toolkit.core.rate_limiter import RateLimiter
from bugbounty_toolkit.core.scope_validator import ScopeValidator
from bugbounty_toolkit.utils.exceptions import ToolkitError
from bugbounty_toolkit.xss.playwright_confirm import _BrowserRequestBudget, _origin


class FakeBrowserRequest:
    def __init__(self, url):
        self.url = url
        self.method = "GET"
        self.resource_type = "document"


class FakeBrowserRoute:
    def __init__(self, url):
        self.request = FakeBrowserRequest(url)
        self.continued = False
        self.aborted = False

    def continue_(self):
        self.continued = True

    def abort(self):
        self.aborted = True


class BudgetHandler(BaseHTTPRequestHandler):
    active = 0
    peak = 0
    lock = threading.Lock()

    def do_GET(self):
        with self.lock:
            type(self).active += 1
            type(self).peak = max(type(self).peak, type(self).active)
        time.sleep(0.03)
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"ok")
        with self.lock:
            type(self).active -= 1

    def log_message(self, *args):
        pass


class ExecutionBudgetTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), BudgetHandler)
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
        scope_path = Path(self.temp.name) / "scope.txt"
        scope_path.write_text(self.base + "\n", encoding="utf-8")
        self.scope = ScopeValidator(scope_path)
        BudgetHandler.active = 0
        BudgetHandler.peak = 0

    def tearDown(self):
        self.temp.cleanup()

    def client(self, budget):
        return HttpClient(self.scope, rate_limiter=RateLimiter(10000), execution_budget=budget)

    def test_request_cap_is_shared_by_clients_and_reports_summary(self):
        budget = ExecutionBudget(max_requests=1, max_concurrency=2)
        first = self.client(budget)
        second = self.client(budget)
        self.assertEqual(first.send(RequestSpec("GET", self.base)).status_code, 200)
        with self.assertRaisesRegex(ToolkitError, "request budget exhausted"):
            second.send(RequestSpec("GET", self.base))
        summary = budget.summary()
        self.assertEqual(summary.requests_started, 1)
        self.assertEqual(summary.responses_received, 1)
        self.assertEqual(summary.destinations, ("127.0.0.1",))
        self.assertEqual(summary.stop_reason, "request_budget_exhausted")

    def test_scope_rejection_does_not_consume_budget_or_add_destination(self):
        budget = ExecutionBudget(max_requests=1)
        with self.assertRaises(ValueError):
            self.client(budget).send(RequestSpec("GET", "https://outside.example/"))
        summary = budget.summary()
        self.assertEqual(summary.requests_started, 0)
        self.assertEqual(summary.destinations, ())

    def test_external_request_upper_bound_is_reserved_and_reported_separately(self):
        budget = ExecutionBudget(max_requests=4, max_concurrency=2)
        budget.reserve_external_requests(3, self.base + "/FUZZ", 2)
        self.client(budget).send(RequestSpec("GET", self.base))
        summary = budget.summary()
        self.assertEqual(summary.requests_started, 1)
        self.assertEqual(summary.external_requests_reserved, 3)
        self.assertEqual(summary.destinations, ("127.0.0.1",))
        with self.assertRaisesRegex(ToolkitError, "remaining run budget"):
            budget.reserve_external_requests(1, self.base + "/FUZZ", 1)

    def test_external_reservation_rejects_concurrency_above_run_limit(self):
        budget = ExecutionBudget(max_requests=4, max_concurrency=1)
        with self.assertRaisesRegex(ValueError, "concurrency exceeds"):
            budget.reserve_external_requests(1, self.base + "/FUZZ", 2)

    def test_shared_concurrency_cap_is_enforced(self):
        budget = ExecutionBudget(max_concurrency=1)
        clients = [self.client(budget), self.client(budget)]
        with ThreadPoolExecutor(max_workers=2) as pool:
            responses = list(pool.map(lambda client: client.send(RequestSpec("GET", self.base)), clients))
        self.assertEqual([response.status_code for response in responses], [200, 200])
        self.assertEqual(BudgetHandler.peak, 1)
        self.assertEqual(budget.summary().peak_concurrency, 1)

    def test_deadline_stops_before_an_additional_request(self):
        budget = ExecutionBudget(max_seconds=0.01)
        time.sleep(0.02)
        with self.assertRaisesRegex(ToolkitError, "time budget exhausted"):
            self.client(budget).send(RequestSpec("GET", self.base))
        self.assertEqual(budget.summary().requests_started, 0)
        self.assertEqual(budget.summary().stop_reason, "time_budget_exhausted")

    def test_transport_error_is_counted_without_leaking_exception_text(self):
        budget = ExecutionBudget(max_requests=2)
        client = self.client(budget)
        with patch.object(client.opener, "open", side_effect=URLError("private network detail")):
            with self.assertRaises(ToolkitError) as error:
                client.send(RequestSpec("GET", self.base))
        self.assertNotIn("private network detail", str(error.exception))
        summary = budget.summary()
        self.assertEqual(summary.requests_started, 1)
        self.assertEqual(summary.transport_errors, 1)
        self.assertEqual(summary.responses_received, 0)

    def test_timeout_is_reported_as_sanitized_transport_error(self):
        client = self.client(ExecutionBudget(max_requests=1))
        with patch.object(client.opener, "open", side_effect=URLError(TimeoutError("private timeout detail"))):
            with self.assertRaisesRegex(ToolkitError, "HTTP request failed: URLError") as error:
                client.send(RequestSpec("GET", self.base))
        self.assertNotIn("private timeout detail", str(error.exception))
        self.assertEqual(client.execution_budget.summary().transport_errors, 1)

    def test_playwright_requests_consume_the_shared_budget(self):
        budget = ExecutionBudget(max_requests=1, max_concurrency=1)
        router = _BrowserRequestBudget(self.scope, _origin(self.base), budget, RateLimiter(10000))
        route = FakeBrowserRoute(self.base + "/page")

        router.handle(route)

        self.assertTrue(route.continued)
        self.assertEqual(budget.summary().requests_started, 1)
        self.assertEqual(budget.summary().peak_concurrency, 1)
        router.finish(route.request, True)
        self.assertEqual(budget.summary().responses_received, 1)
        router.close()

    def test_playwright_budget_exhaustion_aborts_the_next_resource(self):
        budget = ExecutionBudget(max_requests=1)
        lease = budget.acquire(self.base)
        lease.start()
        lease.finish(True)
        lease.release()
        router = _BrowserRequestBudget(self.scope, _origin(self.base), budget, RateLimiter(10000))
        route = FakeBrowserRoute(self.base + "/asset.js")

        router.handle(route)

        self.assertTrue(route.aborted)
        self.assertFalse(route.continued)
        self.assertIsInstance(router.error, ToolkitError)
        self.assertEqual(budget.summary().requests_started, 1)

    def test_playwright_out_of_scope_subresource_is_aborted_without_budget_use(self):
        scope_file = Path(self.temp.name) / "scope-with-exclusion.txt"
        scope_file.write_text(self.base + "\n!" + self.base + "/blocked\n", encoding="utf-8")
        restricted_scope = ScopeValidator(scope_file)
        budget = ExecutionBudget(max_requests=1)
        router = _BrowserRequestBudget(restricted_scope, _origin(self.base), budget, RateLimiter(10000))
        route = FakeBrowserRoute(self.base + "/blocked/asset.js")

        router.handle(route)

        self.assertTrue(route.aborted)
        self.assertIsNone(router.error)
        self.assertEqual(budget.summary().requests_started, 0)
        router.close()


if __name__ == "__main__":
    unittest.main()
