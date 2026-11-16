"""Canonical hosts and a fail-closed check before any target connection.

Alternate IP spellings (decimal, hex, short dotted form) are folded to one
address so a scope rule cannot be skipped by writing the same machine two
ways. DNS names that resolve to a non-public address are refused unless that
address is itself an explicit scope entry.
"""

from __future__ import annotations

import ipaddress
import re
import socket
from collections.abc import Callable
from typing import Protocol
from urllib.parse import urlsplit

from ..utils.exceptions import ToolkitError

_IP_PART = r"(?:0x[0-9a-fA-F]{1,8}|[0-9]{1,10})"
_IP_LIKE = re.compile(rf"(?i)^{_IP_PART}(?:\.{_IP_PART}){{0,3}}$")


class ScopeChecker(Protocol):
    def require(self, target: str) -> None:
        """Raise if the target is not explicitly authorized."""


def canonical_ip(host: str) -> str | None:
    """Return the canonical IP text, or None when the host is not an IP spelling."""
    text = host.strip().lower()
    if not text or "%" in text:
        return None
    if ":" in text:
        try:
            address = ipaddress.ip_address(text)
        except ValueError:
            return None
        mapped = getattr(address, "ipv4_mapped", None)
        if isinstance(mapped, ipaddress.IPv4Address):
            return str(mapped)
        return str(address)
    if _IP_LIKE.fullmatch(text) is None:
        return None
    try:
        packed = socket.inet_aton(text)
    except OSError:
        return None
    return socket.inet_ntoa(packed)


def _addresses_for(text: str) -> list[ipaddress.IPv4Address | ipaddress.IPv6Address]:
    cleaned = text.split("%", 1)[0]
    try:
        address = ipaddress.ip_address(cleaned)
    except ValueError:
        return []
    mapped = getattr(address, "ipv4_mapped", None)
    if isinstance(mapped, ipaddress.IPv4Address):
        return [mapped]
    if isinstance(address, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
        return [address]
    return []


def _is_public(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    return bool(address.is_global)


def _resolve(host: str) -> list[str]:
    try:
        infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise OSError(str(exc)) from exc
    found: list[str] = []
    for info in infos:
        sockaddr = info[4]
        if sockaddr:
            found.append(str(sockaddr[0]))
    return found


def refuse_unapproved_resolution(
    url: str,
    scope: ScopeChecker,
    resolver: Callable[[str], list[str]] | None = None,
) -> None:
    """Refuse a DNS name that resolves outside the public Internet unless each address is in scope.

    Literal IPs are not resolved. They already had to match scope as that exact address.
    """
    host = (urlsplit(url).hostname or "").rstrip(".").lower()
    if not host or canonical_ip(host) is not None:
        return
    lookup = resolver or _resolve
    try:
        answers = lookup(host)
    except OSError as exc:
        raise ToolkitError("Refusing to connect: the host did not resolve. No request was sent.") from exc
    if not answers:
        raise ToolkitError("Refusing to connect: the host did not resolve. No request was sent.")
    for item in answers:
        addresses = _addresses_for(item)
        if not addresses:
            raise ToolkitError("Refusing to connect: the resolver returned an unreadable address.")
        for address in addresses:
            if _is_public(address):
                continue
            try:
                scope.require(str(address))
            except ValueError as exc:
                raise ToolkitError(
                    "Refusing to connect: this name resolves to a non-public address that is not "
                    "an explicit scope entry. No request was sent."
                ) from exc
