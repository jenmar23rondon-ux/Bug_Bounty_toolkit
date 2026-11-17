"""Group recon assets and flag review leads. Leads are not confirmed vulnerabilities."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import re
from urllib.parse import urlsplit

from ..core.destinations import canonical_ip
from .models import Asset, Observation, ReconReport

_ADMIN_PATH = re.compile(
    r"/(?:admin|administrator|login|signin|phpmyadmin|wp-admin|cpanel|webmail|actuator)(?:/|$)",
    re.IGNORECASE,
)
_ADMIN_LABEL = re.compile(r"^(?:admin|administrator|phpmyadmin|cpanel|webmail|vpn|sso)$", re.IGNORECASE)
_STAGING_LABEL = re.compile(
    r"^(?:staging|stage|dev|development|test|testing|qa|uat|preprod|preview|sandbox|stg|nonprod)(?:\d+)?$",
    re.IGNORECASE,
)
_TECH_RULES: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"/wp-(?:admin|login|content|includes)(?:/|$)", re.IGNORECASE), "WordPress"),
    (re.compile(r"/phpmyadmin(?:/|$)", re.IGNORECASE), "phpMyAdmin"),
    (re.compile(r"/(?:actuator|jolokia)(?:/|$)", re.IGNORECASE), "Spring Boot Actuator"),
    (re.compile(r"/jenkins(?:/|$)", re.IGNORECASE), "Jenkins"),
    (re.compile(r"/grafana(?:/|$)", re.IGNORECASE), "Grafana"),
    (re.compile(r"/kibana(?:/|$)", re.IGNORECASE), "Kibana"),
)
_TECH_LABELS = {
    "jenkins": "Jenkins",
    "grafana": "Grafana",
    "kibana": "Kibana",
    "gitlab": "GitLab",
    "jira": "Jira",
}
_SENSITIVE_PORTS = {21, 22, 23, 25, 445, 1433, 3306, 3389, 5432, 5900, 6379, 9200, 11211, 27017}
_CATEGORY_ORDER = {
    "exposed-service": 0,
    "outdated-tech": 1,
    "admin-panel": 2,
    "staging-or-dev": 3,
}
_MAX_LEADS = 500


@dataclass(frozen=True)
class Lead:
    lead_id: str
    host: str
    category: str
    title: str
    detail: str
    confirmed: bool = False

    def to_dict(self) -> dict[str, object]:
        return {
            "id": self.lead_id,
            "host": self.host,
            "category": self.category,
            "title": self.title,
            "detail": self.detail,
            "confirmed": False,
        }


@dataclass(frozen=True)
class AssetGroup:
    kind: str
    key: str
    members: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        return {"kind": self.kind, "key": self.key, "members": list(self.members)}


def build_leads(report: ReconReport) -> list[Lead]:
    """Flag interesting targets. Every lead stays unconfirmed."""
    by_host: dict[str, list[Observation]] = {}
    for item in report.observations:
        by_host.setdefault(item.host, []).append(item)
    assets = {asset.host: asset for asset in report.assets}
    leads: list[Lead] = []
    for host in sorted(assets):
        asset = assets[host]
        observations = by_host.get(host, [])
        leads.extend(_host_leads(host, asset, observations))
    leads.sort(key=lambda lead: (_CATEGORY_ORDER.get(lead.category, 9), lead.host, lead.lead_id))
    return leads[:_MAX_LEADS]


def group_assets(report: ReconReport) -> list[AssetGroup]:
    """Group in-scope assets by host, observed IP, and technology hint."""
    groups: list[AssetGroup] = []
    for asset in sorted(report.assets, key=lambda item: item.host):
        groups.append(AssetGroup("host", asset.host, (asset.host,)))
    ip_members: dict[str, list[str]] = {}
    tech_members: dict[str, list[str]] = {}
    for item in report.observations:
        if item.kind == "ip":
            ip = canonical_ip(item.value) or ""
            if ip and item.host not in ip_members.setdefault(ip, []):
                ip_members[ip].append(item.host)
        if item.kind == "tech" and item.value.strip():
            name = item.value.strip()[:80]
            if item.host not in tech_members.setdefault(name, []):
                tech_members[name].append(item.host)
        if item.kind == "url":
            for name in _tech_from_url(item.value):
                if item.host not in tech_members.setdefault(name, []):
                    tech_members[name].append(item.host)
    for host in {asset.host for asset in report.assets}:
        for name in _tech_from_host(host):
            if host not in tech_members.setdefault(name, []):
                tech_members[name].append(host)
    for ip in sorted(ip_members):
        groups.append(AssetGroup("ip", ip, tuple(sorted(ip_members[ip]))))
    for name in sorted(tech_members):
        groups.append(AssetGroup("tech", name, tuple(sorted(tech_members[name]))))
    return groups


def _host_leads(host: str, asset: Asset, observations: list[Observation]) -> list[Lead]:
    found: list[Lead] = []
    urls = [_safe_url(url) for url in asset.urls]
    urls = [url for url in urls if url]
    admin_urls = [url for url in urls if _ADMIN_PATH.search(urlsplit(url).path or "")]
    admin_label = _matching_label(host, _ADMIN_LABEL)
    if admin_urls or admin_label:
        shown = ", ".join(admin_urls[:3]) or host
        found.append(
            _lead(
                "admin-panel",
                host,
                admin_label or "admin-path",
                "Possible admin or management path",
                "A hostname or historical URL resembles an administrative path "
                f"({shown}). The path was not requested. This is not a confirmed vulnerability.",
            )
        )
    staging = _matching_label(host, _STAGING_LABEL)
    if staging:
        found.append(
            _lead(
                "staging-or-dev",
                host,
                staging,
                "Staging or development hostname",
                f"The hostname label {staging!r} looks like a staging or development host. "
                "Confirm it is intentionally in scope. This is not a vulnerability.",
            )
        )
    exposed = sorted(asset.ports & _SENSITIVE_PORTS)
    if exposed:
        ports = ", ".join(str(port) for port in exposed)
        found.append(
            _lead(
                "exposed-service",
                host,
                ports,
                "Sensitive port listed by InternetDB",
                f"Shodan InternetDB lists port(s) {ports}. These ports were not probed. "
                "This is an unconfirmed exposure signal, not a confirmed vulnerability.",
            )
        )
    if asset.cves:
        cves = ", ".join(asset.cves)
        found.append(
            _lead(
                "outdated-tech",
                host,
                cves,
                "CVE identifiers listed by InternetDB",
                f"InternetDB lists {cves}. Treat that as a lead to review patch level. "
                "The identifiers are not confirmed vulnerabilities.",
            )
        )
    for item in observations:
        if item.kind == "tech" and item.value.strip() and item.detail.strip():
            product = item.value.strip()[:80]
            version = item.detail.strip()[:40]
            found.append(
                _lead(
                    "outdated-tech",
                    host,
                    f"{product}@{version}",
                    "Technology version recorded for review",
                    f"A source recorded {product} version {version}. "
                    "Check whether that version is still supported. It is not a confirmed vulnerability.",
                )
            )
    return found


def _lead(category: str, host: str, signature: str, title: str, detail: str) -> Lead:
    digest = hashlib.sha256(f"{category}|{host}|{signature}".encode()).hexdigest()[:12]
    return Lead(lead_id=f"lead-{digest}", host=host, category=category, title=title, detail=detail, confirmed=False)


def _matching_label(host: str, pattern: re.Pattern[str]) -> str:
    if canonical_ip(host) is not None:
        return ""
    labels = [label for label in host.split(".") if label]
    if len(labels) < 2:
        return ""
    for label in labels[:-1]:
        if pattern.fullmatch(label):
            return label.lower()
    return ""


def _tech_from_host(host: str) -> list[str]:
    names: list[str] = []
    if canonical_ip(host) is not None:
        return names
    for label in host.split(".")[:-1]:
        name = _TECH_LABELS.get(label.lower())
        if name and name not in names:
            names.append(name)
    return names


def _tech_from_url(url: str) -> list[str]:
    safe = _safe_url(url)
    if not safe:
        return []
    path = urlsplit(safe).path or ""
    names: list[str] = []
    for pattern, name in _TECH_RULES:
        if pattern.search(path) and name not in names:
            names.append(name)
    return names


def _safe_url(url: str) -> str:
    try:
        parts = urlsplit(url)
    except ValueError:
        return ""
    if parts.username or parts.password or parts.scheme not in {"http", "https"}:
        return ""
    return url.split("#", 1)[0][:300]
