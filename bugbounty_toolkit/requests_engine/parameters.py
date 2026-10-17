from __future__ import annotations

from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit


def with_parameter(url: str, name: str, value: str) -> str:
    parsed = urlsplit(url)
    query = [(key, current) for key, current in parse_qsl(parsed.query, keep_blank_values=True) if key != name]
    query.append((name, value))
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path or "/", urlencode(query), parsed.fragment))


def parse_parameter_items(items: list[str] | None) -> dict[str, str]:
    params: dict[str, str] = {}
    for item in items or []:
        if "=" in item:
            key, value = item.split("=", 1)
        else:
            key, value = item, ""
        key = key.strip()
        if not key:
            raise ValueError(f"Parameter name cannot be empty: {item}")
        params[key] = value
    return params


def load_parameter_names(path: Path) -> list[str]:
    if not path.exists():
        raise FileNotFoundError(path)
    names: list[str] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        clean = line.strip()
        if not clean or clean.startswith("#"):
            continue
        if "=" in clean:
            clean = clean.split("=", 1)[0].strip()
        if ":" in clean:
            clean = clean.split(":", 1)[0].strip()
        if clean and clean not in names:
            names.append(clean)
    return names
