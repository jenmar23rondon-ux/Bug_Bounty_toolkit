"""Loopback-only request decisions and external-socket measurement.

Page traffic is allowed only for literal loopback HTTP(S). Any other URL is
aborted. ``external_requests`` counts non-loopback HTTP(S) that were
*continued* plus non-loopback TCP/UDP sockets owned by the browser process.
Aborted probes stay in ``blocked_requests`` and do not increment
``external_requests``.
"""

from __future__ import annotations

import ipaddress
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit


def _hostname(url: str) -> str:
    host = urlsplit(url).hostname or ""
    return host.lower()


def is_loopback_host(host: str) -> bool:
    text = host.strip().lower()
    if text.startswith("[") and text.endswith("]"):
        text = text[1:-1]
    try:
        return bool(ipaddress.ip_address(text).is_loopback)
    except ValueError:
        return False


def is_allowed_loopback_http(url: str) -> bool:
    parsed = urlsplit(url)
    if parsed.scheme not in {"http", "https"}:
        return False
    if parsed.username is not None or parsed.password is not None:
        return False
    host = parsed.hostname
    if host is None:
        return False
    return is_loopback_host(host)


def is_external_network_url(url: str) -> bool:
    parsed = urlsplit(url)
    if parsed.scheme not in {"http", "https", "ws", "wss"}:
        return False
    host = parsed.hostname
    if host is None:
        return False
    return not is_loopback_host(host)


@dataclass
class RequestLedger:
    allowed_requests: int = 0
    blocked_requests: int = 0
    external_requests: int = 0
    blocked_external: int = 0
    websocket_blocked: int = 0
    decisions: list[dict[str, str]] = field(default_factory=list)

    def decide(self, url: str, *, websocket: bool = False) -> str:
        if websocket or not is_allowed_loopback_http(url):
            self.blocked_requests += 1
            if websocket:
                self.websocket_blocked += 1
            if is_external_network_url(url) or (websocket and not is_loopback_host(_hostname(url))):
                self.blocked_external += 1
            action = "block"
        else:
            self.allowed_requests += 1
            action = "allow"
        self.decisions.append({"url_scheme": urlsplit(url).scheme, "action": action})
        return action

    def note_continued_external(self) -> None:
        """Call only if a non-loopback request was actually continued."""
        self.external_requests += 1

    def apply_http(self, route: Any) -> str:
        url = str(route.request.url)
        action = self.decide(url)
        if action == "allow":
            route.continue_()
            return action
        if is_external_network_url(url):
            # Aborted external traffic must not be counted as a completed request.
            pass
        route.abort()
        return action

    def apply_websocket(self, websocket: Any) -> str:
        """Count and block a WebSocket without dialing the remote host.

        Sync Playwright deadlocks if ``WebSocketRoute.close()`` is called inside
        the route callback. The default route does not connect to the server, so
        returning without ``connect_to_server()`` keeps the socket on loopback
        control and never opens an external TCP connection.
        """
        url = str(getattr(websocket, "url", "") or "")
        return self.decide(url, websocket=True)


def _proc_ipv4(hex_ip: str) -> str:
    raw = bytes.fromhex(hex_ip)
    return ".".join(str(byte) for byte in reversed(raw))


def _proc_ipv6(hex_ip: str) -> str:
    groups: list[bytes] = []
    for index in range(0, 32, 8):
        groups.append(bytes.fromhex(hex_ip[index : index + 8])[::-1])
    return str(ipaddress.IPv6Address(b"".join(groups)))


def _parse_proc_net(path: Path) -> dict[str, str]:
    """Map socket inode → remote IP for non-listening sockets."""
    found: dict[str, str] = {}
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return found
    for line in lines[1:]:
        parts = line.split()
        if len(parts) < 10:
            continue
        rem = parts[2]
        state = parts[3]
        inode = parts[9]
        if state == "0A":  # listening
            continue
        ip_hex, _port = rem.split(":")
        if ip_hex == "00000000" or set(ip_hex) == {"0"}:
            continue
        try:
            remote = _proc_ipv4(ip_hex) if len(ip_hex) == 8 else _proc_ipv6(ip_hex)
        except ValueError:
            continue
        found[inode] = remote
    return found


def _socket_inodes(pid: int) -> set[str]:
    inodes: set[str] = set()
    fd_dir = Path(f"/proc/{pid}/fd")
    try:
        entries = list(fd_dir.iterdir())
    except OSError:
        return inodes
    for entry in entries:
        try:
            target = os.readlink(entry)
        except OSError:
            continue
        if target.startswith("socket:[") and target.endswith("]"):
            inodes.add(target[8:-1])
    return inodes


def descendant_pids(root: int) -> set[int]:
    seen: set[int] = set()

    def walk(pid: int) -> None:
        if pid in seen:
            return
        seen.add(pid)
        children_path = Path(f"/proc/{pid}/task/{pid}/children")
        try:
            text = children_path.read_text(encoding="utf-8")
        except OSError:
            return
        for token in text.split():
            if token.isdigit():
                walk(int(token))

    walk(root)
    return seen


def external_socket_count(root_pid: int) -> int:
    """Count non-loopback sockets owned by ``root_pid`` or its descendants."""
    inodes: set[str] = set()
    for pid in descendant_pids(root_pid):
        inodes.update(_socket_inodes(pid))
    if not inodes:
        return 0
    sockets: dict[str, str] = {}
    for name in ("tcp", "tcp6", "udp", "udp6"):
        sockets.update(_parse_proc_net(Path(f"/proc/net/{name}")))
    count = 0
    for inode in inodes:
        remote = sockets.get(inode)
        if remote is None:
            continue
        if is_loopback_host(remote):
            continue
        count += 1
    return count
