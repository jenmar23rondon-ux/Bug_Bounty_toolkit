from __future__ import annotations

from pathlib import Path

from .scope import ensure_in_scope, load_scope


class ScopeValidator:
    def __init__(self, scope_file: Path):
        self.scope_file = scope_file

    def require(self, target: str) -> None:
        ensure_in_scope(target, self.scope_file)

    def require_all(self, targets: list[str]) -> None:
        for target in targets:
            self.require(target)

    def summary(self) -> dict[str, list[str]]:
        rules = load_scope(self.scope_file)
        return {
            "allowed": [rule.value for rule in rules if rule.allowed],
            "excluded": [rule.value for rule in rules if not rule.allowed],
        }
