from __future__ import annotations

import time
import math
from dataclasses import dataclass, field


@dataclass
class RateLimiter:
    requests_per_second: float = 1.0
    _last_request_at: float = field(default=0.0, init=False)

    def __post_init__(self) -> None:
        if not math.isfinite(self.requests_per_second) or self.requests_per_second <= 0:
            raise ValueError("Rate must be a finite positive number.")

    def wait(self) -> None:
        interval = 1.0 / self.requests_per_second
        now = time.monotonic()
        delay = interval - (now - self._last_request_at)
        if delay > 0:
            time.sleep(delay)
        self._last_request_at = time.monotonic()
