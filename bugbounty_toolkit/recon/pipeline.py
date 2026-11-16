"""Scope-checked recon: passive providers, optional tools, dedupe, and scoring."""

from __future__ import annotations

from collections.abc import Callable, Mapping
import json
from pathlib import Path
import re
from urllib.parse import urlsplit

from ..core.destinations import canonical_ip
from ..core.scope import ensure_in_scope, load_scope, normalize_host
from ..utils.exceptions import ExternalToolError
from .models import Asset, Observation, ReconReport
from .sources import is_domain_name, parse_source, provider_plans
from .tools import (
    ToolMissing,
    active_tool_argv,
    nuclei_argv,
    parse_nuclei_line,
    passive_tool_argv,
)

_SENSITIVE_PATH = re.compile(
    r"/(?:admin|login|signin|graphql|debug|backup|upload|phpmyadmin|actuator|server-status)(?:/|$)",
    re.IGNORECASE,
)
_SENSITIVE_PORTS = {21, 22, 23, 25, 445, 1433, 3306, 3389, 5432, 5900, 6379, 9200, 11211, 27017}
_MAX_OBSERVATIONS = 2000


class PassiveTransport:
    def get_text(self, url: str, headers: Mapping[str, str] | None = None) -> str:
        raise NotImplementedError


class RateLimit:
    def wait(self, max_wait: float | None = None) -> None:
        raise NotImplementedError


ToolRunner = Callable[[str, list[str]], str]


def authorize_recon_target(target: str, scope_file: Path) -> str:
    """Allow an in-scope name, or the apex of an in-scope wildcard. Exclusions win."""
    host = normalize_host(target)
    if canonical_ip(host) is None and not is_domain_name(host):
        raise ValueError("Recon target must be a domain name or an IP address.")
    rules = load_scope(scope_file)
    if not rules:
        raise ValueError("No scope rules found. Add an authorized domain first.")
    if any((not rule.allowed) and rule.matches(host) for rule in rules):
        raise ValueError("Target is excluded from configured scope.")
    if any(rule.allowed and rule.matches(host) for rule in rules):
        return host
    for rule in rules:
        if not rule.allowed:
            continue
        rule_host = normalize_host(rule.value)
        if rule_host.startswith("*.") and rule_host[2:] == host:
            return host
    raise ValueError(
        "Recon queries are limited to an in-scope name or the base of an in-scope wildcard such as *.example.com."
    )


def _redact(text: str, api_keys: Mapping[str, str]) -> str:
    cleaned = text
    for secret in api_keys.values():
        if secret:
            cleaned = cleaned.replace(secret, "[redacted]")
    return cleaned


def _in_scope(observation: Observation, scope_file: Path) -> bool:
    try:
        if observation.kind == "url":
            parsed = urlsplit(observation.value)
            if normalize_host(parsed.hostname or "") != observation.host:
                return False
            ensure_in_scope(observation.value, scope_file)
        else:
            ensure_in_scope(observation.host, scope_file)
    except ValueError:
        return False
    return True


def _dedupe(observations: list[Observation]) -> list[Observation]:
    seen: set[tuple[str, str, str, str]] = set()
    unique: list[Observation] = []
    for item in observations:
        if item.identity() in seen:
            continue
        seen.add(item.identity())
        unique.append(item)
        if len(unique) >= _MAX_OBSERVATIONS:
            break
    return unique


def _score(asset: Asset) -> None:
    points = 0
    reasons: list[str] = []
    if len(asset.sources) >= 2:
        points += 1
        reasons.append("Reported by more than one independent source.")
    if any(_SENSITIVE_PATH.search(urlsplit(url).path or "") for url in asset.urls):
        points += 2
        reasons.append("A historical URL includes a higher-sensitivity path. This is not proof of a vulnerability.")
    if asset.ports & _SENSITIVE_PORTS:
        points += 2
        reasons.append("Shodan InternetDB lists a sensitive port. The port was not probed.")
    if asset.cves:
        points += 2
        reasons.append("Shodan InternetDB lists CVE identifiers. They are not confirmed.")
    if asset.nuclei:
        points += 2
        reasons.append("Nuclei printed a template match. Treat it as unconfirmed scanner output.")
    asset.score = points
    asset.severity = "informational" if points <= 1 else "low" if points <= 3 else "medium"
    asset.reasons = reasons
    asset.confirmed = False


def correlate(observations: list[Observation]) -> list[Asset]:
    grouped: dict[str, Asset] = {}
    for item in observations:
        asset = grouped.get(item.host)
        if asset is None:
            asset = Asset(item.host)
            grouped[item.host] = asset
        asset.sources.add(item.source)
        if item.kind == "url" and item.value not in asset.urls:
            asset.urls.append(item.value)
        elif item.kind == "port":
            asset.ports.add(int(item.value))
        elif item.kind == "cve" and item.value not in asset.cves:
            asset.cves.append(item.value)
        elif item.kind == "nuclei" and item.value not in asset.nuclei:
            asset.nuclei.append(item.value)
    for asset in grouped.values():
        _score(asset)
    return sorted(grouped.values(), key=lambda asset: (-asset.score, asset.host))


def _filter(observations: list[Observation], scope_file: Path) -> tuple[list[Observation], int]:
    kept: list[Observation] = []
    dropped = 0
    for item in observations:
        if _in_scope(item, scope_file):
            kept.append(item)
        else:
            dropped += 1
    return kept, dropped


def _hosts_from(observations: list[Observation]) -> list[str]:
    hosts: list[str] = []
    for item in observations:
        if item.kind == "host" and (is_domain_name(item.host) or canonical_ip(item.host) is not None):
            if item.host not in hosts:
                hosts.append(item.host)
    return sorted(hosts)


def _observations_from_tool(name: str, text: str) -> list[Observation]:
    if name == "nuclei":
        found: list[Observation] = []
        for line in text.splitlines():
            parsed = parse_nuclei_line(line)
            if parsed is None:
                continue
            template, severity, url = parsed
            host = normalize_host(urlsplit(url).hostname or "")
            found.append(Observation(host, "nuclei", "url", url.split("#", 1)[0]))
            found.append(Observation(host, "nuclei", "nuclei", f"{template} ({severity})"))
        return found
    if name == "httpx":
        found = []
        for line in text.splitlines():
            token = line.strip().split(" ", 1)[0] if line.strip() else ""
            if token.startswith(("http://", "https://")):
                parts = urlsplit(token)
                if parts.hostname and not parts.username:
                    host = normalize_host(parts.hostname)
                    found.append(Observation(host, "httpx", "url", token.split("#", 1)[0][:2000]))
                    found.append(Observation(host, "httpx", "host", host))
        return found
    found = []
    for line in text.splitlines():
        token = line.strip().split(" ", 1)[0].lower().rstrip(".") if line.strip() else ""
        if token.startswith("*."):
            token = token[2:]
        if is_domain_name(token) or canonical_ip(token) is not None:
            host = normalize_host(token)
            found.append(Observation(host, name, "host", host))
    return found


def _run_tool(
    name: str,
    argv: list[str],
    runner: ToolRunner,
    observations: list[Observation],
    errors: list[str],
    api_keys: Mapping[str, str],
) -> None:
    try:
        text = runner(name, argv)
    except ToolMissing as exc:
        errors.append(str(exc))
        return
    except (OSError, ExternalToolError, ValueError):
        errors.append(f"{name} did not finish. No shell was used. Check that the binary accepts these arguments.")
        return
    observations.extend(_observations_from_tool(name, _redact(text, api_keys)))


def run_recon(
    target: str,
    scope_file: Path,
    *,
    transport: PassiveTransport | None = None,
    rate_limiter: RateLimit | None = None,
    tool_runner: ToolRunner | None = None,
    active: bool = False,
    nuclei: bool = False,
    confirm: bool = False,
    dry_run: bool = False,
    run_tools: bool = False,
    api_keys: Mapping[str, str] | None = None,
    severity: str = "medium,high,critical",
    rate: int = 1,
    timeout: int = 10,
    concurrency: int = 2,
    hosts_path: Path | None = None,
) -> ReconReport:
    """Collect in-scope names. Active binaries run only when requested and confirmed."""
    if nuclei and not active:
        raise ValueError("Nuclei probes the target. Pass --active --confirm --nuclei.")
    if not dry_run and (active or nuclei) and not confirm:
        raise ValueError("Active scanning is opt-in. Re-run with --active --confirm. Add --nuclei to include Nuclei.")
    keys = {name: value.strip() for name, value in (api_keys or {}).items() if value and value.strip()}
    for secret in keys.values():
        if any(char in secret for char in "\r\n\x00"):
            raise ValueError("API keys must be a single line. They are read from the environment, not from argv.")
    host = authorize_recon_target(target, scope_file)
    plans = provider_plans(host, keys)
    report = ReconReport(target=host, dry_run=dry_run, active=active, nuclei=nuclei, plans=plans)
    observations: list[Observation] = []
    if is_domain_name(host) or canonical_ip(host) is not None:
        try:
            ensure_in_scope(host, scope_file)
        except ValueError:
            pass
        else:
            observations.append(Observation(host, "target", "host", host))
    if dry_run:
        report.tool_argv = _planned_argv(host, active, nuclei, severity, rate, timeout, concurrency, hosts_path)
        report.observations = observations
        report.assets = correlate(observations)
        return report
    if transport is None or rate_limiter is None:
        raise ValueError("A passive transport and rate limiter are required unless --dry-run is set.")
    for plan in plans:
        if plan.skipped or not plan.url:
            continue
        rate_limiter.wait()
        try:
            body = transport.get_text(plan.url, dict(plan.headers))
        except ValueError:
            report.errors.append(f"{plan.source}: request failed before a usable response was saved.")
            continue
        report.requests_sent += 1
        try:
            observations.extend(parse_source(plan.source, _redact(body, keys), parent=host))
        except json.JSONDecodeError:
            report.errors.append(f"{plan.source}: response was not valid JSON.")
        except ValueError as exc:
            report.errors.append(f"{plan.source}: {_redact(str(exc), keys)[:200]}")
    kept, dropped = _filter(observations, scope_file)
    report.dropped += dropped
    observations = kept
    if run_tools:
        if tool_runner is None:
            raise ValueError("A tool runner is required when external binaries are enabled.")
        if is_domain_name(host):
            for name in ("subfinder", "amass"):
                argv = passive_tool_argv(name, host)
                report.tool_argv.append(argv)
                _run_tool(name, argv, tool_runner, observations, report.errors, keys)
            kept, dropped = _filter(observations, scope_file)
            report.dropped += dropped
            observations = kept
        if active:
            hosts = _hosts_from(observations)
            if not hosts:
                report.errors.append("Active probing was requested, but no in-scope hosts were available.")
            elif hosts_path is None:
                raise ValueError("Active probing needs a hosts file path inside the program directory.")
            else:
                hosts_path.parent.mkdir(parents=True, exist_ok=True)
                hosts_path.write_text("\n".join(hosts) + "\n", encoding="utf-8")
                for name in ("dnsx", "httpx"):
                    argv = active_tool_argv(name, str(hosts_path), rate, timeout)
                    report.tool_argv.append(argv)
                    _run_tool(name, argv, tool_runner, observations, report.errors, keys)
                if nuclei:
                    argv = nuclei_argv(str(hosts_path), rate, timeout, severity, concurrency)
                    report.tool_argv.append(argv)
                    _run_tool("nuclei", argv, tool_runner, observations, report.errors, keys)
                kept, dropped = _filter(observations, scope_file)
                report.dropped += dropped
                observations = kept
    report.observations = _dedupe(observations)
    report.assets = correlate(report.observations)
    return report


def _planned_argv(
    host: str,
    active: bool,
    nuclei: bool,
    severity: str,
    rate: int,
    timeout: int,
    concurrency: int,
    hosts_path: Path | None,
) -> list[list[str]]:
    planned: list[list[str]] = []
    if is_domain_name(host):
        planned.append(passive_tool_argv("subfinder", host))
        planned.append(passive_tool_argv("amass", host))
    if active:
        placeholder = str(hosts_path or "subdomains.txt")
        planned.append(active_tool_argv("dnsx", placeholder, rate, timeout))
        planned.append(active_tool_argv("httpx", placeholder, rate, timeout))
        if nuclei:
            planned.append(nuclei_argv(placeholder, rate, timeout, severity, concurrency))
    return planned
