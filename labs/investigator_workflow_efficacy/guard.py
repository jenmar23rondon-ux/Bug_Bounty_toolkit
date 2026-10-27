"""Count socket connects and refuse anything that is not literal loopback."""

from __future__ import annotations

import ipaddress
import socket
from typing import Any


def _host_of(address: object) -> str:
    if isinstance(address, tuple) and address:
        return str(address[0])
    return ""


def _loopback(host: str) -> bool:
    try:
        return bool(ipaddress.ip_address(host).is_loopback)
    except ValueError:
        return False


class LoopbackGuard:
    """Wrap ``socket.socket.connect``. Non-loopback attempts increment ``external`` and raise."""

    def __init__(self) -> None:
        self.external = 0
        self.loopback = 0
        self.attempts = 0
        self._original: Any = None

    def __enter__(self) -> LoopbackGuard:
        guard = self
        original = socket.socket.connect
        self._original = original

        def connect(self_sock: socket.socket, address: object) -> object:
            guard.attempts += 1
            host = _host_of(address)
            if _loopback(host):
                guard.loopback += 1
                return original(self_sock, address)  # type: ignore[arg-type]
            guard.external += 1
            raise OSError(f"non-loopback connect blocked: {host or address!r}")

        socket.socket.connect = connect  # type: ignore[method-assign, assignment]
        return self

    def __exit__(self, *exc: object) -> None:
        if self._original is not None:
            socket.socket.connect = self._original  # type: ignore[method-assign]
