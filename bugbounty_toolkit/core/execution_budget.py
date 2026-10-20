from __future__ import annotations

from dataclasses import dataclass
import math
import threading
import time
from urllib.parse import urlsplit

from ..utils.exceptions import ToolkitError


@dataclass(frozen=True)
class ExecutionSummary:
    requests_started: int
    responses_received: int
    transport_errors: int
    destinations: tuple[str, ...]
    elapsed_seconds: float
    max_requests: int | None
    max_seconds: float | None
    max_concurrency: int
    peak_concurrency: int
    stop_reason: str | None


class ExecutionBudget:
    """Share request, wall-clock and concurrency limits across in-scope requests."""

    def __init__(
        self,
        max_requests: int | None = None,
        max_seconds: float | None = None,
        max_concurrency: int = 5,
    ) -> None:
        if max_requests is not None and (type(max_requests) is not int or max_requests <= 0):
            raise ValueError("Run request budget must be a positive integer.")
        if max_seconds is not None and (
            isinstance(max_seconds, bool)
            or not isinstance(max_seconds, (int, float))
            or not math.isfinite(max_seconds)
            or max_seconds <= 0
        ):
            raise ValueError("Run time budget must be a finite positive number.")
        if type(max_concurrency) is not int or max_concurrency <= 0:
            raise ValueError("Run concurrency limit must be a positive integer.")
        self.max_requests = max_requests
        self.max_seconds = float(max_seconds) if max_seconds is not None else None
        self.max_concurrency = max_concurrency
        self.cancel_event = threading.Event()
        self._semaphore = threading.BoundedSemaphore(max_concurrency)
        self._lock = threading.Lock()
        self._started_at = time.monotonic()
        self._reserved = 0
        self._requests_started = 0
        self._responses_received = 0
        self._transport_errors = 0
        self._active = 0
        self._peak_concurrency = 0
        self._destinations: set[str] = set()
        self._stop_reason: str | None = None

    @property
    def enabled(self) -> bool:
        return self.max_requests is not None or self.max_seconds is not None

    def cancel(self, reason: str = "cancelled_by_user") -> None:
        with self._lock:
            if self._stop_reason is None:
                self._stop_reason = reason
        self.cancel_event.set()

    def _check_deadline(self) -> None:
        if self.cancel_event.is_set():
            reason = self._stop_reason or "cancelled"
            if reason == "request_budget_exhausted" and self.max_requests is not None:
                raise ToolkitError(f"Run request budget exhausted ({self._reserved}/{self.max_requests}).")
            if reason == "time_budget_exhausted" and self.max_seconds is not None:
                raise ToolkitError(f"Run time budget exhausted ({self.max_seconds:g}s).")
            raise ToolkitError(f"Run cancelled ({reason}).")
        if self.max_seconds is not None and time.monotonic() - self._started_at >= self.max_seconds:
            self.cancel("time_budget_exhausted")
            raise ToolkitError(f"Run time budget exhausted ({self.max_seconds:g}s).")

    def remaining_seconds(self) -> float | None:
        self._check_deadline()
        if self.max_seconds is None:
            return None
        return max(0.0, self.max_seconds - (time.monotonic() - self._started_at))

    def observe_completion(self) -> None:
        """Stop future dispatch after a response completes at or beyond the deadline."""
        if self.max_seconds is not None and time.monotonic() - self._started_at >= self.max_seconds:
            self.cancel("time_budget_exhausted")

    def acquire(self, url: str) -> _ExecutionLease:
        while not self._semaphore.acquire(timeout=0.05):
            self._check_deadline()
        try:
            self._check_deadline()
            host = urlsplit(url).hostname
            if not host:
                raise ValueError("A valid destination host is required for the run budget.")
            with self._lock:
                if self.max_requests is not None and self._reserved >= self.max_requests:
                    if self._stop_reason is None:
                        self._stop_reason = "request_budget_exhausted"
                    self.cancel_event.set()
                    raise ToolkitError(f"Run request budget exhausted ({self._reserved}/{self.max_requests}).")
                self._reserved += 1
                self._destinations.add(host.lower())
            return _ExecutionLease(self)
        except BaseException:
            self._semaphore.release()
            raise

    def _start(self) -> None:
        self._check_deadline()
        with self._lock:
            self._requests_started += 1
            self._active += 1
            self._peak_concurrency = max(self._peak_concurrency, self._active)

    def _finish(self, successful: bool) -> None:
        with self._lock:
            self._active -= 1
            if successful:
                self._responses_received += 1
            else:
                self._transport_errors += 1

    def _release_unstarted(self) -> None:
        with self._lock:
            self._reserved -= 1

    def summary(self) -> ExecutionSummary:
        with self._lock:
            return ExecutionSummary(
                requests_started=self._requests_started,
                responses_received=self._responses_received,
                transport_errors=self._transport_errors,
                destinations=tuple(sorted(self._destinations)),
                elapsed_seconds=max(0.0, time.monotonic() - self._started_at),
                max_requests=self.max_requests,
                max_seconds=self.max_seconds,
                max_concurrency=self.max_concurrency,
                peak_concurrency=self._peak_concurrency,
                stop_reason=self._stop_reason,
            )


class _ExecutionLease:
    def __init__(self, budget: ExecutionBudget) -> None:
        self._budget = budget
        self._started = False
        self._ever_started = False
        self._released = False

    def start(self) -> None:
        self._budget._start()
        self._started = True
        self._ever_started = True

    def finish(self, successful: bool) -> None:
        if self._started:
            self._budget._finish(successful)
            self._started = False

    def release(self) -> None:
        if self._released:
            return
        if not self._ever_started:
            self._budget._release_unstarted()
        self._budget._semaphore.release()
        self._released = True
