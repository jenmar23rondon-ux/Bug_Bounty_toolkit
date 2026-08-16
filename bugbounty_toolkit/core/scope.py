from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse


@dataclass(frozen=True)
class ScopeRule:
    value: str

    def matches(self, target: str) -> bool:
        host = normalize_host(target)
        rule = self.value.lower().strip()
        if not host or not rule:
            return False
        return host == rule or host.endswith(f".{rule}")


def normalize_host(target: str) -> str:
    target = target.strip()
    parsed = urlparse(target if "://" in target else f"//{target}")
    host = parsed.hostname or target.split("/")[0]
    return host.lower().strip("[]")


def load_scope(scope_file: Path) -> list[ScopeRule]:
    if not scope_file.exists():
        return []
    rules: list[ScopeRule] = []
    for line in scope_file.read_text(encoding="utf-8").splitlines():
        clean = line.strip()
        if clean and not clean.startswith("#"):
            rules.append(ScopeRule(clean))
    return rules


def ensure_in_scope(target: str, scope_file: Path) -> None:
    rules = load_scope(scope_file)
    if not rules:
        raise ValueError("No scope rules found. Add an authorized domain first.")
    if not any(rule.matches(target) for rule in rules):
        raise ValueError(f"Target is outside configured scope: {target}")
