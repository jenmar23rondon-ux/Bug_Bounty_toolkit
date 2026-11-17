from __future__ import annotations

from dataclasses import dataclass
import posixpath
from pathlib import Path
from urllib.parse import unquote, urlsplit

from .destinations import canonical_ip

# Wildcard bases that would authorize an entire public suffix or a shared hosting zone.
_PUBLIC_SUFFIXES = frozenset(
    {
        "com",
        "net",
        "org",
        "edu",
        "gov",
        "mil",
        "int",
        "io",
        "co",
        "uk",
        "us",
        "de",
        "fr",
        "nl",
        "ru",
        "br",
        "au",
        "jp",
        "cn",
        "in",
        "info",
        "biz",
        "xyz",
        "app",
        "dev",
        "sh",
        "me",
        "ai",
        "co.uk",
        "com.au",
        "com.br",
        "co.jp",
        "com.mx",
        "co.nz",
        "com.ar",
        "co.za",
        "com.tr",
        "com.cn",
        "github.io",
        "blogspot.com",
        "amazonaws.com",
        "azurewebsites.net",
        "cloudapp.net",
        "herokuapp.com",
        "pages.dev",
        "workers.dev",
        "netlify.app",
        "vercel.app",
        "ngrok.io",
    }
)


def normalize_host(target: str) -> str:
    parsed = urlsplit(target.strip() if "://" in target else f"//{target.strip()}")
    host = (parsed.hostname or "").rstrip(".").lower()
    if not host:
        return ""
    if "%" in host or "\\" in host:
        raise ValueError("Invalid host.")
    ip = canonical_ip(host)
    if ip is not None:
        return ip
    try:
        return host.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError("Invalid host.") from exc


def _reject_broad_wildcard(host: str) -> None:
    if not host.startswith("*."):
        return
    base = host[2:]
    if base.count(".") < 1 or base in _PUBLIC_SUFFIXES:
        raise ValueError(
            "Wildcard scope must name a private registrable domain, for example *.example.com. "
            "Wildcards of a public suffix are rejected."
        )


def normalized_path(path: str) -> str:
    for _ in range(5):
        decoded = unquote(path)
        if decoded == path:
            break
        path = decoded
    if "\\" in path:
        raise ValueError("Backslashes are not supported in scoped URL paths.")
    return "/" + posixpath.normpath("/" + path.lstrip("/")).lstrip("/")


@dataclass(frozen=True)
class ScopeRule:
    value: str
    allowed: bool = True

    def matches(self, target: str) -> bool:
        rule = urlsplit(self.value if "://" in self.value else f"//{self.value}")
        destination = urlsplit(target if "://" in target else f"//{target}")
        rule_host = normalize_host(self.value)
        host = normalize_host(target)
        if rule_host.startswith("*."):
            host_matches = host.endswith(f".{rule_host[2:]}")
        else:
            host_matches = bool(rule_host) and host == rule_host
        if not host_matches:
            return False
        if rule.scheme:
            if destination.scheme.lower() != rule.scheme.lower():
                return False
            default_port = 443 if rule.scheme == "https" else 80
            if (rule.port or default_port) != (destination.port or default_port):
                return False
        elif rule.port is not None and destination.port != rule.port:
            return False
        prefix = normalized_path(rule.path).rstrip("/")
        path = normalized_path(destination.path)
        # Exclusions are case-insensitive so /Admin cannot bypass !/admin.
        if not self.allowed:
            prefix = prefix.casefold()
            path = path.casefold()
        return not prefix or path == prefix or path.startswith(prefix + "/")


def validate_rule(value: str) -> None:
    parsed = urlsplit(value if "://" in value else f"//{value}")
    host = normalize_host(value)
    if not host or ("*" in host and not (host.startswith("*.") and "*" not in host[2:])):
        raise ValueError(f"Invalid scope rule: {value}")
    _reject_broad_wildcard(host)
    if parsed.scheme and parsed.scheme not in {"http", "https"}:
        raise ValueError(f"Invalid scope scheme: {value}")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("Scope rules cannot contain credentials, queries or fragments.")
    if parsed.port == 0:
        raise ValueError("Scope ports must be positive.")
    normalized_path(parsed.path)


def load_scope(scope_file: Path) -> list[ScopeRule]:
    if not scope_file.exists():
        return []
    rules: list[ScopeRule] = []
    for line in scope_file.read_text(encoding="utf-8").splitlines():
        clean = line.strip()
        if clean and not clean.startswith("#"):
            allowed = True
            if clean.startswith(("!", "-")):
                allowed = False
                clean = clean[1:].strip()
            validate_rule(clean)
            rules.append(ScopeRule(clean, allowed=allowed))
    return rules


def ensure_in_scope(target: str, scope_file: Path) -> None:
    rules = load_scope(scope_file)
    if not rules:
        raise ValueError("No scope rules found. Add an authorized domain first.")
    if any((not rule.allowed) and rule.matches(target) for rule in rules):
        raise ValueError("Target is excluded from configured scope.")
    if not any(rule.allowed and rule.matches(target) for rule in rules):
        raise ValueError("Target is outside configured scope.")
