from __future__ import annotations

from dataclasses import dataclass
import posixpath
from pathlib import Path
from urllib.parse import unquote, urlsplit


def normalize_host(target: str) -> str:
    parsed = urlsplit(target.strip() if "://" in target else f"//{target.strip()}")
    return (parsed.hostname or "").rstrip(".").lower().encode("idna").decode("ascii")


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
        return not prefix or path == prefix or path.startswith(prefix + "/")


def validate_rule(value: str) -> None:
    parsed = urlsplit(value if "://" in value else f"//{value}")
    host = normalize_host(value)
    if not host or ("*" in host and not (host.startswith("*.") and "*" not in host[2:])):
        raise ValueError(f"Invalid scope rule: {value}")
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
