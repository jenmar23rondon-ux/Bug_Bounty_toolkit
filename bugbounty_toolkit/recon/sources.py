"""Allowlisted passive providers. The target is a query parameter, never the request host."""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from urllib.parse import quote, urlsplit, urlunsplit
from urllib.request import Request, build_opener

from ..core.destinations import canonical_ip
from ..core.http_client import NoRedirects
from ..core.scope import normalize_host
from .models import Observation, SourcePlan

PROVIDER_HOSTS = frozenset(
    {
        "crt.sh",
        "api.certspotter.com",
        "web.archive.org",
        "otx.alienvault.com",
        "api.hackertarget.com",
        "urlscan.io",
        "internetdb.shodan.io",
        "api.securitytrails.com",
        "www.virustotal.com",
    }
)

_LABEL = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
_SINGLE_LABEL = re.compile(rf"^{_LABEL}$")
DOMAIN_NAME = re.compile(rf"^(?=.{{1,253}}$)(?:{_LABEL}\.)+{_LABEL}$")
_CVE = re.compile(r"^CVE-\d{4}-\d{4,7}$")
_MAX_BODY = 1_000_000
_MAX_ITEMS = 300


class ProviderRequestError(ValueError):
    """Raised before a socket opens when a passive URL is not an allowlisted provider."""


def is_domain_name(host: str) -> bool:
    try:
        normalized = normalize_host(host)
    except ValueError:
        return False
    return canonical_ip(normalized) is None and DOMAIN_NAME.fullmatch(normalized) is not None


def assert_provider_url(url: str) -> None:
    parsed = urlsplit(url)
    host = (parsed.hostname or "").rstrip(".").lower()
    if (
        parsed.scheme != "https"
        or host not in PROVIDER_HOSTS
        or parsed.username is not None
        or parsed.password is not None
        or parsed.port not in (None, 443)
    ):
        raise ProviderRequestError(
            "Refusing passive request: only HTTPS on port 443 to an allowlisted provider is permitted."
        )


def _https(host: str, path: str, query: str) -> str:
    if host not in PROVIDER_HOSTS:
        raise ProviderRequestError("Refusing passive request: provider host is not allowlisted.")
    return urlunsplit(("https", host, path, query, ""))


def _query(pairs: list[tuple[str, str]]) -> str:
    return "&".join(f"{quote(key, safe='')}={quote(value, safe='')}" for key, value in pairs)


def provider_plans(target: str, api_keys: Mapping[str, str] | None = None) -> list[SourcePlan]:
    """Build provider requests. API keys are headers and are omitted when unset."""
    keys = api_keys or {}
    host = normalize_host(target)
    plans: list[SourcePlan] = []
    if is_domain_name(host):
        domain = host
        plans.append(
            SourcePlan(
                "crtsh",
                _https("crt.sh", "/", _query([("q", f"%.{domain}"), ("output", "json")])),
            )
        )
        plans.append(
            SourcePlan(
                "certspotter",
                _https(
                    "api.certspotter.com",
                    "/v1/issuances",
                    _query([("domain", domain), ("include_subdomains", "true"), ("expand", "dns_names")]),
                ),
            )
        )
        plans.append(
            SourcePlan(
                "wayback",
                _https(
                    "web.archive.org",
                    "/cdx/search/cdx",
                    _query(
                        [
                            ("url", f"*.{domain}/*"),
                            ("output", "json"),
                            ("fl", "original"),
                            ("collapse", "urlkey"),
                            ("limit", "100"),
                        ]
                    ),
                ),
            )
        )
        plans.append(
            SourcePlan(
                "otx",
                _https("otx.alienvault.com", f"/api/v1/indicators/domain/{quote(domain, safe='')}/passive_dns", ""),
            )
        )
        plans.append(
            SourcePlan(
                "hackertarget",
                _https("api.hackertarget.com", "/hostsearch/", _query([("q", domain)])),
            )
        )
        plans.append(
            SourcePlan(
                "urlscan",
                _https("urlscan.io", "/api/v1/search/", _query([("q", f"domain:{domain}"), ("size", "100")])),
            )
        )
        trails = keys.get("securitytrails", "").strip()
        if trails:
            plans.append(
                SourcePlan(
                    "securitytrails",
                    _https("api.securitytrails.com", f"/v1/domain/{quote(domain, safe='')}/subdomains", ""),
                    headers=(("APIKEY", trails),),
                )
            )
        else:
            plans.append(
                SourcePlan(
                    "securitytrails",
                    _https("api.securitytrails.com", f"/v1/domain/{quote(domain, safe='')}/subdomains", ""),
                    skipped="Set SECURITYTRAILS_API_KEY to enable SecurityTrails. The key is sent as a header.",
                )
            )
        virus = keys.get("virustotal", "").strip()
        if virus:
            plans.append(
                SourcePlan(
                    "virustotal",
                    _https("www.virustotal.com", f"/api/v3/domains/{quote(domain, safe='')}/subdomains", ""),
                    headers=(("x-apikey", virus),),
                )
            )
        else:
            plans.append(
                SourcePlan(
                    "virustotal",
                    _https("www.virustotal.com", f"/api/v3/domains/{quote(domain, safe='')}/subdomains", ""),
                    skipped="Set VIRUSTOTAL_API_KEY to enable VirusTotal. The key is sent as a header.",
                )
            )
        plans.append(
            SourcePlan(
                "shodan-internetdb",
                "",
                skipped="InternetDB is queried only for an in-scope IPv4 address. Domain recon does not resolve DNS.",
            )
        )
    elif canonical_ip(host) is not None and ":" not in host:
        plans.append(SourcePlan("shodan-internetdb", _https("internetdb.shodan.io", f"/{quote(host, safe='')}", "")))
    else:
        plans.append(
            SourcePlan(
                "passive",
                "",
                skipped="Passive providers need a domain name, or Shodan InternetDB needs an IPv4 address.",
            )
        )
    for plan in plans:
        if plan.url and not plan.skipped:
            assert_provider_url(plan.url)
    return plans


def _loads(body: str) -> object:
    parsed: object = json.loads(body)
    return parsed


def _names_from_text(value: object) -> list[str]:
    if not isinstance(value, str):
        return []
    names: list[str] = []
    for part in value.replace(",", "\n").splitlines():
        cleaned = part.strip().lower().rstrip(".")
        if cleaned.startswith("*."):
            cleaned = cleaned[2:]
        if cleaned and cleaned not in names:
            names.append(cleaned)
    return names


def _host_observations(source: str, names: list[str]) -> list[Observation]:
    observations: list[Observation] = []
    for name in names[:_MAX_ITEMS]:
        if is_domain_name(name) or canonical_ip(name) is not None:
            observations.append(Observation(normalize_host(name), source, "host", normalize_host(name)))
    return observations


def _url_observations(source: str, urls: list[str]) -> list[Observation]:
    observations: list[Observation] = []
    for raw in urls[:_MAX_ITEMS]:
        try:
            parsed = urlsplit(raw.strip())
            if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password:
                continue
            host = normalize_host(parsed.hostname)
        except ValueError:
            continue
        observations.append(Observation(host, source, "url", raw.split("#", 1)[0][:2000]))
    return observations


def parse_source(source: str, body: str, parent: str = "") -> list[Observation]:
    """Parse one provider body. Raises ValueError with a short message and no response body."""
    if source == "hackertarget":
        lowered = body.lstrip().lower()
        if lowered.startswith(("error", "api ", "invalid")):
            raise ValueError("HackerTarget returned an error page.")
        observations: list[Observation] = []
        for line in body.splitlines():
            if not line.strip():
                continue
            name, separator, address = line.partition(",")
            hosts = _host_observations(source, [name.strip()])
            observations.extend(hosts)
            if not separator or not hosts:
                continue
            ip = canonical_ip(address.strip())
            if ip is not None:
                observations.append(Observation(hosts[0].host, source, "ip", ip))
        return observations
    if source == "crtsh":
        payload = _loads(body)
        if not isinstance(payload, list):
            raise ValueError("crt.sh response was not a JSON list.")
        certificate_names: list[str] = []
        for item in payload:
            if isinstance(item, dict):
                certificate_names.extend(_names_from_text(item.get("name_value")))
        return _host_observations(source, certificate_names)
    if source == "certspotter":
        payload = _loads(body)
        if not isinstance(payload, list):
            raise ValueError("Cert Spotter response was not a JSON list.")
        names = []
        for item in payload:
            if isinstance(item, dict):
                dns_names = item.get("dns_names")
                if isinstance(dns_names, list):
                    for name in dns_names:
                        names.extend(_names_from_text(name))
        return _host_observations(source, names)
    if source == "wayback":
        payload = _loads(body)
        if not isinstance(payload, list):
            raise ValueError("Wayback response was not a JSON list.")
        urls = [item[0] for item in payload[1:] if isinstance(item, list) and item and isinstance(item[0], str)]
        return _url_observations(source, urls) + _host_observations(
            source, [urlsplit(url).hostname or "" for url in urls]
        )
    if source == "otx":
        payload = _loads(body)
        if not isinstance(payload, dict):
            raise ValueError("AlienVault OTX response was not a JSON object.")
        records = payload.get("passive_dns")
        names = []
        if isinstance(records, list):
            for item in records:
                if isinstance(item, dict):
                    names.extend(_names_from_text(item.get("hostname")))
        return _host_observations(source, names)
    if source == "urlscan":
        payload = _loads(body)
        if not isinstance(payload, dict):
            raise ValueError("urlscan response was not a JSON object.")
        results = payload.get("results")
        page_urls: list[str] = []
        names = []
        if isinstance(results, list):
            for item in results:
                if not isinstance(item, dict):
                    continue
                page = item.get("page")
                task = item.get("task")
                if isinstance(page, dict):
                    names.extend(_names_from_text(page.get("domain")))
                    if isinstance(page.get("url"), str):
                        page_urls.append(page["url"])
                if isinstance(task, dict) and isinstance(task.get("url"), str):
                    page_urls.append(task["url"])
        return _url_observations(source, page_urls) + _host_observations(source, names)
    if source == "securitytrails":
        payload = _loads(body)
        if not isinstance(payload, dict):
            raise ValueError("SecurityTrails response was not a JSON object.")
        labels = payload.get("subdomains")
        names = []
        apex = parent if is_domain_name(parent) else ""
        if isinstance(labels, list) and apex:
            for label in labels:
                if isinstance(label, str) and _SINGLE_LABEL.fullmatch(label.strip().lower()):
                    names.append(f"{label.strip().lower()}.{apex}")
        return _host_observations(source, names)
    if source == "virustotal":
        payload = _loads(body)
        if not isinstance(payload, dict):
            raise ValueError("VirusTotal response was not a JSON object.")
        data = payload.get("data")
        names = []
        if isinstance(data, list):
            for item in data:
                if isinstance(item, dict):
                    names.extend(_names_from_text(item.get("id")))
        return _host_observations(source, names)
    if source == "shodan-internetdb":
        payload = _loads(body)
        if not isinstance(payload, dict):
            raise ValueError("Shodan InternetDB response was not a JSON object.")
        ip = payload.get("ip")
        host = normalize_host(ip) if isinstance(ip, str) else ""
        if canonical_ip(host) is None:
            raise ValueError("Shodan InternetDB response did not include an IP.")
        observations = [Observation(host, source, "host", host)]
        ports = payload.get("ports")
        if isinstance(ports, list):
            for port in ports[:_MAX_ITEMS]:
                if type(port) is int and 0 < port <= 65535:
                    observations.append(Observation(host, source, "port", str(port)))
        vulns = payload.get("vulns")
        if isinstance(vulns, list):
            for vuln in vulns[:_MAX_ITEMS]:
                if isinstance(vuln, str) and _CVE.fullmatch(vuln):
                    observations.append(Observation(host, source, "cve", vuln))
        hostnames = payload.get("hostnames")
        if isinstance(hostnames, list):
            observations.extend(_host_observations(source, [name for name in hostnames if isinstance(name, str)]))
        return observations
    raise ValueError("Unknown passive source.")


class PassiveHttpTransport:
    """Fetch provider URLs with a size cap and no redirects. The caller applies the rate limit."""

    def __init__(self, timeout: float = 15.0, max_bytes: int = _MAX_BODY):
        if timeout <= 0 or max_bytes <= 0:
            raise ValueError("Passive timeout and response size must be positive.")
        self.timeout = timeout
        self.max_bytes = max_bytes
        self.opener = build_opener(NoRedirects())

    def get_text(self, url: str, headers: Mapping[str, str] | None = None) -> str:
        assert_provider_url(url)
        request_headers = {"User-Agent": "BugBountyToolkit/0.3 authorized-research"}
        if headers:
            request_headers.update(dict(headers))
        request = Request(url, headers=request_headers, method="GET")
        try:
            response = self.opener.open(request, timeout=self.timeout)
        except OSError as exc:
            raise ValueError("Passive provider request failed.") from exc
        try:
            with response:
                body = response.read(self.max_bytes + 1)
        except OSError as exc:
            raise ValueError("Passive provider response could not be read.") from exc
        if len(body) > self.max_bytes:
            raise ValueError("Passive provider response exceeded the size cap.")
        return bytes(body).decode("utf-8", errors="replace")
