"""Opt-in audit hook that records outbound socket connections from Python processes.

Loaded only when this directory is placed on PYTHONPATH by the offline lab
verifier and ``BBTK_CONNECT_AUDIT`` names a writable file. It never blocks or
alters traffic; it only appends one JSON line per non-loopback connect attempt
so the verifier can count external connection attempts made during a lab run.
Child Python processes inherit PYTHONPATH, so subprocess-based labs are covered.
Non-Python processes (ffuf, Chromium) are not observed by this hook.
"""

from __future__ import annotations

import ipaddress
import json
import os
import sys

_TARGET = os.environ.get("BBTK_CONNECT_AUDIT")


def _is_local(host: object) -> bool:
    if not isinstance(host, str):
        return False
    if host in {"localhost", ""}:
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _hook(event: str, args: tuple[object, ...]) -> None:
    if event not in {"socket.connect", "socket.getaddrinfo"} or not _TARGET:
        return
    if event == "socket.connect":
        address = args[1] if len(args) > 1 else None
        if isinstance(address, str):  # AF_UNIX path
            return
        host = address[0] if isinstance(address, tuple) and address else address
    else:
        host = args[0] if args else None
    if _is_local(host):
        return
    try:
        with open(_TARGET, "a", encoding="utf-8") as handle:
            handle.write(json.dumps({"event": event, "host": str(host), "pid": os.getpid()}) + "\n")
    except OSError:
        pass


if _TARGET:
    sys.addaudithook(_hook)
