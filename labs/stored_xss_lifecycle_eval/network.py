"""Measure loopback versus any other destination during a lab run.

The guard wraps ``socket.socket.connect`` in this process. A browser process
is not started on the mock path; child-process names are checked so a Chromium
launch cannot hide outside the counter.
"""

from __future__ import annotations

import ipaddress
import os
import socket
from pathlib import Path
from typing import Any, Callable


class NetworkGuard:
    def __init__(self) -> None:
        self.loopback_attempts = 0
        self.external_requests = 0
        self._original: Callable[..., Any] | None = None

    def __enter__(self) -> NetworkGuard:
        guard = self
        original = socket.socket.connect
        self._original = original

        def connect(sock: socket.socket, address: Any) -> None:
            _account(guard, address)
            original(sock, address)

        socket.socket.connect = connect  # type: ignore[method-assign, assignment]
        return self

    def __exit__(self, *_exc: object) -> None:
        if self._original is not None:
            socket.socket.connect = self._original  # type: ignore[method-assign]
            self._original = None


def _account(guard: NetworkGuard, address: object) -> None:
    host = address[0] if isinstance(address, tuple) and address else None
    if not isinstance(host, str):
        return
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        if host.lower() == "localhost":
            guard.loopback_attempts += 1
            return
        guard.external_requests += 1
        raise OSError("blocked non-loopback network attempt")
    if ip.is_loopback:
        guard.loopback_attempts += 1
        return
    guard.external_requests += 1
    raise OSError("blocked non-loopback network attempt")


def browser_process_names() -> list[str]:
    """Names of direct child processes. Chromium would show up here."""
    names: list[str] = []
    proc = Path("/proc")
    if not proc.is_dir():
        return names
    own = os.getpid()
    for entry in proc.iterdir():
        if not entry.name.isdigit():
            continue
        try:
            raw = (entry / "stat").read_text(encoding="utf-8")
            comm = (entry / "comm").read_text(encoding="utf-8").strip()
        except OSError:
            continue
        # stat: pid (comm) state ppid ...
        end = raw.rfind(")")
        if end < 0:
            continue
        rest = raw[end + 2 :].split()
        if len(rest) < 2:
            continue
        try:
            ppid = int(rest[1])
        except ValueError:
            continue
        if ppid == own:
            names.append(comm)
    return names


def browser_processes_observed(names: list[str] | None = None) -> int:
    found = names if names is not None else browser_process_names()
    needles = ("chrome", "chromium", "playwright", "headless_shell")
    return sum(1 for name in found if any(needle in name.lower() for needle in needles))
