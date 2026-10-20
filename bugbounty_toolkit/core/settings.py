from __future__ import annotations

import math
from dataclasses import dataclass
from pathlib import Path

try:
    import yaml
except ModuleNotFoundError:  # Allows the offline doctor to report a missing base dependency.
    yaml = None


@dataclass(frozen=True)
class ExecutorSettings:
    requests_per_second: float = 1.0
    timeout: float = 15.0
    max_concurrency: int = 5
    max_tests: int = 100
    max_response_bytes: int = 1_000_000

    def __post_init__(self) -> None:
        for name in ("requests_per_second", "timeout"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or value <= 0:
                raise ValueError(f"{name} must be a finite positive number.")
        for name in ("max_concurrency", "max_tests", "max_response_bytes"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
                raise ValueError(f"{name} must be a positive integer.")


def load_settings(path: Path | None) -> ExecutorSettings:
    if path is None:
        return ExecutorSettings()
    if yaml is None:
        raise ValueError("PyYAML is required to read a settings file. Install the base package dependencies.")
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    if not isinstance(data, dict):
        raise ValueError("Settings must be a YAML mapping.")
    unknown = set(data) - set(ExecutorSettings.__dataclass_fields__)
    if unknown:
        raise ValueError(f"Unknown settings: {', '.join(sorted(map(str, unknown)))}")
    return ExecutorSettings(**data)
