"""YAML and TOML settings for `bbtk run`. Active confirmation is never read from a file."""

from __future__ import annotations

import importlib
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast

from .tools import parse_severity

LOG_LEVELS = ("debug", "info", "warning", "error")
FORMATS = ("markdown", "html", "json", "sarif", "dashboard")
_FIELDS = frozenset({"target", "active", "nuclei", "severity", "log_level", "formats"})


@dataclass(frozen=True)
class RunConfig:
    target: str = ""
    active: bool = False
    nuclei: bool = False
    severity: str = "medium,high,critical"
    log_level: str = "info"
    formats: tuple[str, ...] = FORMATS
    source: str = ""


def load_run_config(path: Path) -> RunConfig:
    """Load a flat recon config. Raises ValueError naming the file, line, and field."""
    try:
        text = path.read_text(encoding="utf-8")
    except UnicodeError as exc:
        raise ValueError(f"{path}: config files must be UTF-8 text.") from exc
    except OSError as exc:
        raise ValueError(f"{path}: could not be read ({exc.strerror or 'file error'}).") from exc
    if "\x00" in text:
        raise ValueError(f"{path}: config files must be plain text.")
    suffix = path.suffix.lower()
    try:
        if suffix == ".toml":
            raw = _parse_toml(text, path)
        elif suffix in {".yaml", ".yml", ""}:
            raw = _parse_yaml(text, path)
        else:
            stripped = text.lstrip()
            raw = (
                _parse_toml(text, path)
                if stripped.startswith(("target", "active", "formats")) and "=" in stripped
                else _parse_yaml(text, path)
            )
    except ValueError:
        raise
    except Exception as exc:
        raise ValueError(f"{path}: could not be parsed ({exc}).") from exc
    return _build(raw, path)


def _parse_yaml(text: str, path: Path) -> dict[str, object]:
    try:
        yaml_module: Any = importlib.import_module("yaml")
    except ModuleNotFoundError as exc:
        raise ValueError(f"{path}: PyYAML is required to read a YAML config.") from exc
    try:
        loaded = cast(object, yaml_module.safe_load(text))
    except Exception as exc:
        raise ValueError(f"{path}: YAML could not be parsed. {exc}") from exc
    if loaded is None:
        return {}
    if not isinstance(loaded, dict):
        raise ValueError(f"{path}: config must be a mapping of recon settings.")
    result: dict[str, object] = {}
    for key, value in loaded.items():
        if not isinstance(key, str):
            raise ValueError(f"{path}: setting names must be text.")
        result[key] = value
    return result


def _parse_toml(text: str, path: Path) -> dict[str, object]:
    values: dict[str, object] = {}
    for lineno, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("["):
            raise ValueError(f"{path}:{lineno}: only a flat recon config is supported. Remove tables.")
        if "=" not in line:
            raise ValueError(f"{path}:{lineno}: expected key = value.")
        key, raw_value = line.split("=", 1)
        name = key.strip()
        if not name.isidentifier():
            raise ValueError(f"{path}:{lineno}: invalid setting name {name!r}.")
        value, rest = _toml_value(raw_value.strip(), path, lineno)
        rest = rest.strip()
        if rest and not rest.startswith("#"):
            raise ValueError(f"{path}:{lineno}: unexpected text after the value.")
        if name in values:
            raise ValueError(f"{path}:{lineno}: {name} is set more than once.")
        values[name] = value
    return values


def _toml_value(text: str, path: Path, lineno: int) -> tuple[object, str]:
    if text.startswith("true"):
        return True, text[4:]
    if text.startswith("false"):
        return False, text[5:]
    if text.startswith('"'):
        return _toml_string(text, path, lineno)
    if text.startswith("["):
        return _toml_array(text, path, lineno)
    if text[:1].isdigit() or (text.startswith("-") and text[1:2].isdigit()):
        return _toml_int(text, path, lineno)
    raise ValueError(f"{path}:{lineno}: values must be true, false, a quoted string, or an array of strings.")


def _toml_int(text: str, path: Path, lineno: int) -> tuple[int, str]:
    index = 1 if text.startswith("-") else 0
    while index < len(text) and text[index].isdigit():
        index += 1
    if index == 0 or (text.startswith("-") and index == 1):
        raise ValueError(f"{path}:{lineno}: invalid number.")
    return int(text[:index]), text[index:]


def _toml_string(text: str, path: Path, lineno: int) -> tuple[str, str]:
    chars: list[str] = []
    index = 1
    while index < len(text):
        char = text[index]
        if char == '"':
            return "".join(chars), text[index + 1 :]
        if char == "\\":
            if index + 1 >= len(text):
                raise ValueError(f"{path}:{lineno}: unfinished escape in string.")
            escaped = text[index + 1]
            mapping = {"\\": "\\", '"': '"', "n": "\n", "t": "\t"}
            if escaped not in mapping:
                raise ValueError(f"{path}:{lineno}: unsupported escape \\{escaped}.")
            chars.append(mapping[escaped])
            index += 2
            continue
        if char == "\n":
            raise ValueError(f"{path}:{lineno}: strings must stay on one line.")
        chars.append(char)
        index += 1
    raise ValueError(f"{path}:{lineno}: string is missing a closing quote.")


def _toml_array(text: str, path: Path, lineno: int) -> tuple[list[str], str]:
    if "\n" in text.split("]", 1)[0]:
        raise ValueError(f"{path}:{lineno}: arrays must stay on one line.")
    body, separator, rest = text[1:].partition("]")
    if not separator:
        raise ValueError(f"{path}:{lineno}: array is missing a closing bracket.")
    items: list[str] = []
    remaining = body.strip()
    while remaining:
        if not remaining.startswith('"'):
            raise ValueError(f"{path}:{lineno}: array items must be quoted strings.")
        item, remaining = _toml_string(remaining, path, lineno)
        items.append(item)
        remaining = remaining.strip()
        if remaining.startswith(","):
            remaining = remaining[1:].strip()
            if not remaining:
                raise ValueError(f"{path}:{lineno}: trailing comma in array.")
        elif remaining:
            raise ValueError(f"{path}:{lineno}: expected a comma between array items.")
    return items, rest


def _build(raw: dict[str, object], path: Path) -> RunConfig:
    if "confirm" in raw:
        raise ValueError(
            f"{path}: confirm cannot be set in a config file. "
            "Pass --confirm on the command line so active probing stays opt-in."
        )
    unknown = sorted(set(raw) - _FIELDS)
    if unknown:
        supported = ", ".join(sorted(_FIELDS))
        raise ValueError(f"{path}: unknown setting {unknown[0]}. Supported settings: {supported}.")
    target = raw.get("target", "")
    if target is None:
        target = ""
    if not isinstance(target, str):
        raise ValueError(f"{path}: target must be a string.")
    active = _bool_field(raw.get("active", False), path, "active")
    nuclei = _bool_field(raw.get("nuclei", False), path, "nuclei")
    severity_value = raw.get("severity", "medium,high,critical")
    if not isinstance(severity_value, str):
        raise ValueError(f"{path}: severity must be a comma-separated string.")
    try:
        severity = parse_severity(severity_value)
    except ValueError as exc:
        raise ValueError(f"{path}: {exc}") from exc
    level = raw.get("log_level", "info")
    if not isinstance(level, str) or level.lower() not in LOG_LEVELS:
        names = ", ".join(LOG_LEVELS)
        raise ValueError(f"{path}: log_level must be one of {names}.")
    formats_value = raw.get("formats", list(FORMATS))
    formats = _formats(formats_value, path)
    return RunConfig(
        target=target.strip(),
        active=active,
        nuclei=nuclei,
        severity=severity,
        log_level=level.lower(),
        formats=formats,
        source=str(path),
    )


def _bool_field(value: object, path: Path, field: str) -> bool:
    if isinstance(value, bool):
        return value
    raise ValueError(f"{path}: {field} must be true or false, not {value!r}.")


def _formats(value: object, path: Path) -> tuple[str, ...]:
    if not isinstance(value, list) or not value:
        raise ValueError(f"{path}: formats must be a non-empty list. Choose from {', '.join(FORMATS)}.")
    chosen: list[str] = []
    for item in value:
        if not isinstance(item, str) or item not in FORMATS:
            raise ValueError(f"{path}: unknown format {item!r}. Choose from {', '.join(FORMATS)}.")
        if item not in chosen:
            chosen.append(item)
    return tuple(chosen)
