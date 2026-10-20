from __future__ import annotations

import time
import math
from threading import Event, Lock
from dataclasses import dataclass, field

from ..utils.exceptions import ToolkitError


@dataclass
class RateLimiter:
    requests_per_second: float = 1.0
    _last_request_at: float = field(default=0.0, init=False)
    cancel_event: Event | None = field(default=None, repr=False)
    _lock: Lock = field(default_factory=Lock, init=False, repr=False)

    def __post_init__(self) -> None:
        if not math.isfinite(self.requests_per_second) or self.requests_per_second <= 0:
            raise ValueError("Rate must be a finite positive number.")

    def wait(self, max_wait: float | None = None) -> None:
        # Serialize start slots, not HTTP responses; all workers share the same cadence.
        with self._lock:
            if self.cancel_event is not None and self.cancel_event.is_set():
                raise ToolkitError("Request schedule cancelled.")
            delay = 1.0 / self.requests_per_second - (time.monotonic() - self._last_request_at)
            if delay > 0:
                if max_wait is not None and delay > max_wait:
                    if self.cancel_event is None:
                        time.sleep(max_wait)
                    elif self.cancel_event.wait(max_wait):
                        raise ToolkitError("Request schedule cancelled.")
                    raise ToolkitError("Run time budget would expire before the next request slot.")
                if self.cancel_event is None:
                    time.sleep(delay)
                elif self.cancel_event.wait(delay):
                    raise ToolkitError("Request schedule cancelled.")
            if self.cancel_event is not None and self.cancel_event.is_set():
                raise ToolkitError("Request schedule cancelled.")
            self._last_request_at = time.monotonic()
