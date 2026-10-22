from __future__ import annotations

import time
from dataclasses import dataclass, field
from http.client import HTTPMessage, HTTPException
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

from .rate_limiter import RateLimiter
from .execution_budget import ExecutionBudget
from .redaction import redact_headers, redact_text, redact_url
from .scope_validator import ScopeValidator
from .target import normalize_url
from ..utils.exceptions import ToolkitError


@dataclass
class RequestSpec:
    method: str
    url: str
    headers: dict[str, str] = field(default_factory=dict)
    params: dict[str, str] = field(default_factory=dict)
    body: str | bytes | None = None

    def prepared_url(self) -> str:
        parsed = urlsplit(normalize_url(self.url))
        if not self.params:
            return urlunsplit(parsed)
        query_items = parse_qsl(parsed.query, keep_blank_values=True)
        query_items.extend(self.params.items())
        return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, urlencode(query_items), ""))

    def body_bytes(self) -> bytes | None:
        if self.body is None or isinstance(self.body, bytes):
            return self.body
        return self.body.encode("utf-8")


@dataclass
class ResponseRecord:
    request: RequestSpec
    final_url: str
    status_code: int
    reason: str
    duration_ms: int
    headers: dict[str, str]
    body_text: str
    body_size: int
    body_truncated: bool = False
    set_cookies: tuple[str, ...] = ()

    def to_dict(self, body_limit: int = 8000) -> dict[str, object]:
        body = self.request.body_bytes()
        return {
            "request": {
                "method": self.request.method.upper(),
                "url": redact_url(self.request.prepared_url()),
                "headers": redact_headers(self.request.headers),
                "body": redact_text(body.decode("utf-8", errors="replace")) if body else None,
            },
            "response": {
                "url": redact_url(self.final_url),
                "status_code": self.status_code,
                "reason": self.reason,
                "duration_ms": self.duration_ms,
                "headers": redact_headers(self.headers),
                "body_size": self.body_size,
                "body_truncated": self.body_truncated,
                "body_preview": (redact_text(self.body_text) or "")[:body_limit],
            },
        }


class NoRedirects(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class HttpClient:
    def __init__(
        self,
        scope: ScopeValidator,
        timeout: float = 15.0,
        rate_limiter: RateLimiter | None = None,
        max_response_bytes: int = 1_000_000,
        execution_budget: ExecutionBudget | None = None,
    ):
        if timeout <= 0 or max_response_bytes <= 0:
            raise ValueError("Timeout and response size limit must be positive.")
        self.scope = scope
        self.timeout = timeout
        self.max_response_bytes = max_response_bytes
        self.rate_limiter = rate_limiter or RateLimiter()
        self.execution_budget = execution_budget
        if execution_budget is not None:
            self.rate_limiter.cancel_event = execution_budget.cancel_event
        self.opener = build_opener(NoRedirects())

    def send(self, request: RequestSpec) -> ResponseRecord:
        url = request.prepared_url()
        self.scope.require(url)
        headers = dict(request.headers)
        for key, value in list(headers.items()):
            if key.lower() == "host":
                if value.lower() != urlsplit(url).netloc.lower():
                    raise ValueError("Host header must match the request destination.")
                del headers[key]
            elif key.lower() in {"content-length", "transfer-encoding"}:
                del headers[key]
        headers.setdefault("User-Agent", "BugBountyToolkit/0.2 authorized-testing")
        lease = self.execution_budget.acquire(url) if self.execution_budget is not None else None
        request_started = False
        try:
            remaining = self.execution_budget.remaining_seconds() if self.execution_budget is not None else None
            if remaining is None:
                self.rate_limiter.wait()
            else:
                try:
                    self.rate_limiter.wait(max_wait=remaining)
                except ToolkitError as exc:
                    if "time budget" in str(exc).lower() and self.execution_budget is not None:
                        self.execution_budget.cancel("time_budget_exhausted")
                    raise
            if lease is not None:
                lease.start()
                request_started = True
                remaining = self.execution_budget.remaining_seconds()
            request_timeout = min(self.timeout, remaining) if remaining is not None else self.timeout
            req = Request(url=url, data=request.body_bytes(), headers=headers, method=request.method.upper())
            started = time.perf_counter()
            try:
                response = self.opener.open(req, timeout=request_timeout)
            except HTTPError as exc:
                response = exc
            except (URLError, OSError, HTTPException) as exc:
                raise ToolkitError(f"HTTP request failed: {type(exc).__name__}") from exc
            try:
                with response:
                    body = response.read(self.max_response_bytes + 1)
                    truncated = len(body) > self.max_response_bytes
                    record = self._record(
                        request,
                        response.url,
                        response.code,
                        response.reason,
                        response.headers,
                        body[: self.max_response_bytes],
                        started,
                        truncated,
                    )
            except (OSError, HTTPException) as exc:
                raise ToolkitError(f"HTTP response could not be read: {type(exc).__name__}") from exc
            if lease is not None:
                lease.finish(True)
                request_started = False
                self.execution_budget.observe_completion()
            return record
        except BaseException:
            if self.execution_budget is not None:
                self.execution_budget.observe_completion()
            if lease is not None and request_started:
                lease.finish(False)
                request_started = False
            raise
        finally:
            if lease is not None:
                lease.release()

    def _record(
        self,
        request: RequestSpec,
        final_url: str,
        status_code: int,
        reason: str,
        headers: HTTPMessage,
        body: bytes,
        started: float,
        truncated: bool,
    ) -> ResponseRecord:
        charset = headers.get_content_charset() or "utf-8"
        try:
            body_text = body.decode(charset, errors="replace")
        except LookupError:
            body_text = body.decode("utf-8", errors="replace")
        return ResponseRecord(
            request=request,
            final_url=final_url,
            status_code=status_code,
            reason=str(reason),
            duration_ms=int((time.perf_counter() - started) * 1000),
            headers={key.lower(): value for key, value in headers.items()},
            body_text=body_text,
            body_size=len(body),
            body_truncated=truncated,
            set_cookies=tuple(headers.get_all("Set-Cookie", [])),
        )
