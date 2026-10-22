"""Passive, signature-based subdomain takeover candidate checks."""

from __future__ import annotations

import importlib
import ipaddress
import re
from types import ModuleType
from typing import Any

SERVICE_SIGNATURES: dict[str, tuple[str, ...]] = {
    "Amazon S3": (r"(?:^|\.)(?:s3(?:[.-][a-z0-9-]+)?|s3-website(?:[.-][a-z0-9-]+)?)\.amazonaws\.com$",),
    "Heroku": (r"(?:^|\.)herokudns\.com$", r"(?:^|\.)herokuapp\.com$"),
    "GitHub Pages": (r"(?:^|\.)github\.io$",),
    "Netlify": (r"(?:^|\.)netlify\.app$",),
}
_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")
MAX_CNAME_RECORDS = 20


def normalize_dns_name(value: str) -> str:
    """Normalize a DNS hostname and reject URLs, IPs, and malformed labels."""
    name = value.strip().rstrip(".").encode("idna").decode("ascii").lower()
    if not name or len(name) > 253 or any(not _LABEL.fullmatch(label) for label in name.split(".")):
        raise ValueError("Host and CNAME values must be valid DNS names, not URLs or IP addresses.")
    try:
        ipaddress.ip_address(name)
    except ValueError:
        return name
    raise ValueError("Takeover checks require a DNS hostname, not an IP address.")


def match_services(cname: str) -> list[str]:
    """Return known provider names whose local CNAME signature matches."""
    normalized = normalize_dns_name(cname)
    return [
        provider
        for provider, patterns in SERVICE_SIGNATURES.items()
        if any(re.search(pattern, normalized) for pattern in patterns)
    ]


def analyze_cnames(host: str, cnames: list[str], dns_status: str, dns_queries_attempted: int = 0) -> dict[str, object]:
    """Analyze supplied CNAMEs without network access or provider claim checks."""
    normalized_host = normalize_dns_name(host)
    if len(cnames) > MAX_CNAME_RECORDS:
        raise ValueError(f"At most {MAX_CNAME_RECORDS} CNAME values can be analyzed at once.")
    normalized_cnames = list(dict.fromkeys(normalize_dns_name(value) for value in cnames))
    matches = []
    for cname in normalized_cnames:
        services = match_services(cname)
        if services:
            matches.append({"cname": cname, "services": services})
    return {
        "type": "takeover-check",
        "host": normalized_host,
        "cname_records": normalized_cnames,
        "provider_matches": matches,
        "classification": "possible_takeover" if matches else "not_observed",
        "unclaimed_status": "not_verified",
        "confirmed": False,
        "dns_status": dns_status,
        "dns_queries_attempted": dns_queries_attempted,
        "network_requests_sent": dns_queries_attempted,
        "http_requests_sent": 0,
        "known_limitations": [
            "A provider CNAME match is only a lead; it does not establish that the service resource is unclaimed.",
            "No HTTP requests, provider API calls, registration attempts or resource claims are performed.",
            "Signatures are local and may be incomplete or stale; verify ownership with the provider and program owner.",
        ],
    }


def resolve_cname_records(host: str, resolver_module: ModuleType | None = None) -> tuple[list[str], str, int]:
    """Optionally query one CNAME RRset through dnspython with a short timeout."""
    normalized_host = normalize_dns_name(host)
    if resolver_module is None:
        try:
            resolver_module = importlib.import_module("dns.resolver")
        except ModuleNotFoundError:
            return [], "dnspython_unavailable", 0

    try:
        resolver_factory: Any = getattr(resolver_module, "Resolver")
        resolver = resolver_factory()
        answer = resolver.resolve(normalized_host, "CNAME", lifetime=3.0)
    except Exception as exc:
        error_name = type(exc).__name__
        status = {"NoAnswer": "no_cname", "NXDOMAIN": "nxdomain"}.get(error_name, "resolver_error")
        if "Timeout" in error_name:
            status = "timeout"
        return [], status, 1

    try:
        records = [normalize_dns_name(str(record.target)) for record in answer]
    except (AttributeError, TypeError, ValueError):
        return [], "invalid_dns_answer", 1
    return list(dict.fromkeys(records)), "resolved" if records else "no_cname", 1
