"""Passive, signature-based subdomain takeover checks (never auto-confirmed)."""

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


def analyze_cnames(
    host: str,
    cnames: list[str],
    dns_status: str,
    dns_queries_attempted: int = 0,
    *,
    dangling: bool | None = None,
    unclaimed: bool | None = None,
    rejection_reason: str | None = None,
) -> dict[str, object]:
    """Analyze supplied CNAMEs without network access or provider claim checks.

    NEVER auto-confirmed. Max finding_state is candidate, and only when a dangling
    CNAME plus a known-service fingerprint is explicitly marked unclaimed in lab
    evidence. Otherwise inconclusive or not_observed.
    """
    from .core.checks import validate_rejection_reason

    if rejection_reason is not None:
        validate_rejection_reason(rejection_reason)
    normalized_host = normalize_dns_name(host)
    if len(cnames) > MAX_CNAME_RECORDS:
        raise ValueError(f"At most {MAX_CNAME_RECORDS} CNAME values can be analyzed at once.")
    normalized_cnames = list(dict.fromkeys(normalize_dns_name(value) for value in cnames))
    matches = []
    for cname in normalized_cnames:
        services = match_services(cname)
        if services:
            matches.append({"cname": cname, "services": services})
    if unclaimed is True:
        unclaimed_status = "unclaimed"
    elif unclaimed is False:
        unclaimed_status = "claimed"
    else:
        unclaimed_status = "not_verified"
    dangling_flag = bool(dangling) if dangling is not None else bool(matches)
    if rejection_reason is not None:
        classification = "possible_takeover" if matches else "not_observed"
        finding_state = "rejected"
    elif matches and dangling_flag and unclaimed_status == "unclaimed":
        classification = "possible_takeover"
        finding_state = "candidate"
    elif matches:
        # Fingerprint without verified unclaimed claim → inconclusive, not candidate.
        classification = "possible_takeover"
        finding_state = "inconclusive"
    else:
        classification = "not_observed"
        finding_state = "not_observed"
    return {
        "type": "takeover-check",
        "host": normalized_host,
        "cname_records": normalized_cnames,
        "provider_matches": matches,
        "classification": classification,
        "finding_state": finding_state,
        "dangling": dangling_flag if matches else False,
        "unclaimed_status": unclaimed_status,
        "confirmed": False,
        "confirmation_gap": None if finding_state == "candidate" else "no_second_proof" if matches else None,
        "rejection_reason": rejection_reason,
        "dns_status": dns_status,
        "dns_queries_attempted": dns_queries_attempted,
        "network_requests_sent": dns_queries_attempted,
        "http_requests_sent": 0,
        "known_limitations": [
            "CNAME takeover is never auto-confirmed by this toolkit.",
            "candidate requires dangling CNAME + known-service fingerprint + unclaimed lab evidence.",
            "A provider CNAME match alone is inconclusive until unclaimed status is proven offline.",
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
