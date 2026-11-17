"""Import local HackerOne, Bugcrowd, CSV, or toolkit YAML scope. No network."""

from __future__ import annotations

import csv
import importlib
import io
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast

from ..core.scope import validate_rule

_MAX_BYTES = 1_000_000
_MAX_ASSETS = 500
_HOST_TYPES = frozenset(
    {
        "",
        "url",
        "domain",
        "wildcard",
        "ip",
        "ip_address",
        "api",
        "website",
        "api_endpoint",
        "other",
    }
)
_SKIP_TYPES = frozenset(
    {
        "cidr",
        "source_code",
        "downloadable_executables",
        "google_play_app_id",
        "apple_store_app_id",
        "hardware",
        "smart_contract",
        "ai_model",
        "ai_agent",
        "other_apk",
        "ios_app",
        "android_app",
    }
)
_TARGET_KEYS = ("uri", "url", "endpoint", "asset_identifier", "identifier", "asset", "host", "target", "name")


@dataclass(frozen=True)
class ImportedScope:
    source: str
    allowed: tuple[str, ...]
    excluded: tuple[str, ...]
    skipped: tuple[str, ...]


def parse_scope_file(path: Path, fmt: str = "auto") -> ImportedScope:
    """Read one local export. Raises ValueError with the file name and the reason."""
    if fmt not in {"auto", "yaml", "hackerone", "bugcrowd", "csv"}:
        raise ValueError("Scope format must be auto, yaml, hackerone, bugcrowd, or csv.")
    try:
        text = path.read_text(encoding="utf-8-sig")
    except UnicodeError as exc:
        raise ValueError(f"{path.name}: scope files must be UTF-8 text.") from exc
    except OSError as exc:
        raise ValueError(f"{path.name}: could not be read ({exc.strerror or 'file error'}).") from exc
    if "\x00" in text:
        raise ValueError(f"{path.name}: scope files must be plain text.")
    if len(text.encode("utf-8")) > _MAX_BYTES:
        raise ValueError(f"{path.name}: scope file is larger than {_MAX_BYTES} bytes.")
    selected = _detect_format(path, text) if fmt == "auto" else fmt
    if selected == "yaml":
        return _parse_yaml(text, path.name)
    if selected == "csv":
        return _parse_csv(text, path.name)
    try:
        payload: object = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError(f"{path.name}: is not valid JSON ({exc.msg}).") from exc
    explicit = None if fmt == "auto" else fmt
    return _parse_json(payload, path.name, explicit)


def _detect_format(path: Path, text: str) -> str:
    suffix = path.suffix.lower()
    if suffix in {".yaml", ".yml"}:
        return "yaml"
    if suffix == ".csv":
        return "csv"
    stripped = text.lstrip()
    if suffix == ".json" or stripped.startswith(("{", "[")):
        return "json"
    first = stripped.splitlines()[0] if stripped else ""
    if "," in first:
        return "csv"
    return "yaml"


def _parse_yaml(text: str, name: str) -> ImportedScope:
    try:
        yaml_module: Any = importlib.import_module("yaml")
    except ModuleNotFoundError as exc:
        raise ValueError(f"{name}: PyYAML is required to import a YAML scope file.") from exc
    try:
        data = cast(object, yaml_module.safe_load(text))
    except Exception as exc:
        raise ValueError(f"{name}: YAML could not be parsed ({exc}).") from exc
    if data is None:
        data = {}
    if not isinstance(data, dict) or set(data) - {"allowed", "excluded"}:
        raise ValueError("Scope YAML must contain allowed and excluded lists.")
    allowed: list[str] = []
    excluded: list[str] = []
    for key in ("allowed", "excluded"):
        values = data.get(key, [])
        if not isinstance(values, list) or not all(isinstance(value, str) for value in values):
            raise ValueError("Scope entries must be lists of strings.")
        bucket = allowed if key == "allowed" else excluded
        for value in values:
            validate_rule(value)
            bucket.append(value)
    if not allowed and not excluded:
        return ImportedScope("yaml", (), (), ())
    return _finish("yaml", allowed, excluded, [])


def _parse_csv(text: str, name: str) -> ImportedScope:
    try:
        rows = list(csv.DictReader(io.StringIO(text)))
    except csv.Error as exc:
        raise ValueError(f"{name}: CSV could not be parsed ({exc}).") from exc
    if not rows and text.strip():
        raise ValueError(f"{name}: CSV needs a header row with a target column.")
    if rows and not any(_csv_target(row) for row in rows):
        raise ValueError(
            f"{name}: missing a target column. Use one of identifier, asset_identifier, asset, target, host, uri, or url."
        )
    if len(rows) > _MAX_ASSETS:
        raise ValueError(f"{name}: more than {_MAX_ASSETS} rows. Split the export.")
    allowed: list[str] = []
    excluded: list[str] = []
    skipped: list[str] = []
    for index, row in enumerate(rows, start=2):
        raw = _csv_target(row)
        if not raw:
            skipped.append(f"row {index}: no target")
            continue
        try:
            eligible = _csv_eligible(row)
        except ValueError as exc:
            skipped.append(f"row {index}: {exc}")
            continue
        _collect(raw, eligible, _csv_type(row), allowed, excluded, skipped, f"row {index}")
    return _finish("csv", allowed, excluded, skipped, empty_error=f"{name}: no host scope rules were found.")


def _csv_target(row: dict[str, str | None]) -> str:
    folded = {((key or "").strip().lower()): (value or "").strip() for key, value in row.items()}
    for key in ("identifier", "asset_identifier", "asset", "target", "host", "uri", "url", "name"):
        if folded.get(key):
            return folded[key]
    return ""


def _csv_type(row: dict[str, str | None]) -> str:
    folded = {((key or "").strip().lower()): (value or "").strip() for key, value in row.items()}
    return folded.get("asset_type") or folded.get("type") or folded.get("category") or ""


def _csv_eligible(row: dict[str, str | None]) -> bool | None:
    folded = {((key or "").strip().lower()): (value or "").strip() for key, value in row.items()}
    for key in ("eligible_for_submission", "in_scope", "eligible", "scope"):
        if key in folded and folded[key] != "":
            return _truthy(folded[key])
    return None


def _truthy(value: str) -> bool:
    token = value.strip().lower()
    if token in {"1", "true", "yes", "y", "in", "in_scope", "eligible"}:
        return True
    if token in {"0", "false", "no", "n", "out", "out_of_scope", "ineligible"}:
        return False
    raise ValueError(f"Unrecognized scope flag {value!r}. Use yes/no, true/false, or in/out.")


def _parse_json(payload: object, name: str, explicit: str | None) -> ImportedScope:
    if explicit == "hackerone":
        return _from_hackerone(payload, name)
    if explicit == "bugcrowd":
        return _from_bugcrowd(payload, name)
    bugcrowd = isinstance(payload, dict) and ("target_groups" in payload or isinstance(payload.get("targets"), list))
    hackerone = _has_asset_identifier(payload) or _scope_lists(payload) is not None
    if bugcrowd and hackerone:
        raise ValueError(
            f"{name}: this JSON matches both HackerOne and Bugcrowd exports. Pass --format hackerone or --format bugcrowd."
        )
    if bugcrowd:
        return _from_bugcrowd(payload, name)
    if hackerone:
        return _from_hackerone(payload, name)
    if (
        isinstance(payload, dict)
        and set(payload) <= {"allowed", "excluded"}
        and ("allowed" in payload or "excluded" in payload)
    ):
        return _parse_yaml_like_json(payload, name)
    raise ValueError(
        f"{name}: could not read this as a HackerOne or Bugcrowd scope export. "
        "Pass --format hackerone or --format bugcrowd, or use a CSV with a target column."
    )


def _parse_yaml_like_json(payload: dict[str, object], name: str) -> ImportedScope:
    allowed: list[str] = []
    excluded: list[str] = []
    for key, bucket in (("allowed", allowed), ("excluded", excluded)):
        values = payload.get(key, [])
        if not isinstance(values, list) or not all(isinstance(value, str) for value in values):
            raise ValueError(f"{name}: allowed and excluded must be lists of strings.")
        for value in values:
            validate_rule(value)
            bucket.append(value)
    if not allowed and not excluded:
        return ImportedScope("json", (), (), ())
    return _finish("json", allowed, excluded, [])


def _has_asset_identifier(node: object) -> bool:
    if isinstance(node, dict):
        attributes = node.get("attributes")
        if isinstance(attributes, dict) and "asset_identifier" in attributes:
            return True
        if "asset_identifier" in node:
            return True
        return any(_has_asset_identifier(value) for value in node.values())
    if isinstance(node, list):
        return any(_has_asset_identifier(item) for item in node)
    return False


def _scope_lists(payload: object) -> tuple[list[object], list[object]] | None:
    if not isinstance(payload, dict):
        return None
    targets = payload.get("targets")
    if not isinstance(targets, dict):
        return None
    included = targets.get("in_scope", targets.get("inScope", []))
    excluded = targets.get("out_of_scope", targets.get("outOfScope", []))
    if not isinstance(included, list) or not isinstance(excluded, list):
        return None
    return included, excluded


def _from_hackerone(payload: object, name: str) -> ImportedScope:
    assets = _hackerone_assets(payload)
    if len(assets) > _MAX_ASSETS:
        raise ValueError(f"{name}: more than {_MAX_ASSETS} assets. Split the export.")
    if not assets:
        raise ValueError(f"{name}: no HackerOne structured scopes were found.")
    allowed: list[str] = []
    excluded: list[str] = []
    skipped: list[str] = []
    for index, (attributes, listed_in_scope) in enumerate(assets, start=1):
        identifier = attributes.get("asset_identifier")
        if not isinstance(identifier, str) or not identifier.strip():
            skipped.append(f"asset {index}: missing asset_identifier")
            continue
        asset_type = attributes.get("asset_type")
        kind = asset_type.strip() if isinstance(asset_type, str) else ""
        eligible = listed_in_scope
        if "eligible_for_submission" in attributes:
            flag = attributes.get("eligible_for_submission")
            if isinstance(flag, bool):
                eligible = flag
            else:
                skipped.append(f"asset {index}: eligible_for_submission must be true or false")
                continue
        _collect(identifier, eligible, kind, allowed, excluded, skipped, f"asset {index}")
    return _finish("hackerone", allowed, excluded, skipped, empty_error=f"{name}: no host scope rules were found.")


def _hackerone_assets(payload: object) -> list[tuple[dict[str, object], bool | None]]:
    found: list[tuple[dict[str, object], bool | None]] = []

    def walk(node: object, listed: bool | None) -> None:
        if isinstance(node, dict):
            attributes = node.get("attributes")
            if isinstance(attributes, dict) and "asset_identifier" in attributes:
                found.append((attributes, listed))
                return
            if "asset_identifier" in node and isinstance(node.get("asset_identifier"), str):
                found.append((node, listed))
                return
            lists = _scope_lists(node)
            if lists is not None:
                included, excluded = lists
                for item in included:
                    walk(item, True)
                for item in excluded:
                    walk(item, False)
                return
            for value in node.values():
                walk(value, listed)
        elif isinstance(node, list):
            for item in node:
                walk(item, listed)

    walk(payload, None)
    return found


def _from_bugcrowd(payload: object, name: str) -> ImportedScope:
    rows = _bugcrowd_rows(payload)
    if len(rows) > _MAX_ASSETS:
        raise ValueError(f"{name}: more than {_MAX_ASSETS} targets. Split the export.")
    if not rows:
        raise ValueError(f"{name}: no Bugcrowd targets were found.")
    allowed: list[str] = []
    excluded: list[str] = []
    skipped: list[str] = []
    for index, (row, group_in_scope) in enumerate(rows, start=1):
        identifier = ""
        for key in _TARGET_KEYS:
            value = row.get(key)
            if isinstance(value, str) and value.strip():
                identifier = value.strip()
                break
        if not identifier:
            skipped.append(f"target {index}: missing uri or name")
            continue
        kind = ""
        for key in ("category", "type", "asset_type"):
            value = row.get(key)
            if isinstance(value, str):
                kind = value
                break
        eligible = group_in_scope
        invalid_flag = False
        for key in ("in_scope", "inScope", "eligible_for_submission"):
            if key in row:
                flag = row.get(key)
                if isinstance(flag, bool):
                    eligible = flag
                else:
                    skipped.append(f"target {index}: {key} must be true or false")
                    invalid_flag = True
                break
        if invalid_flag:
            continue
        _collect(identifier, eligible, kind, allowed, excluded, skipped, f"target {index}")
    return _finish("bugcrowd", allowed, excluded, skipped, empty_error=f"{name}: no host scope rules were found.")


def _bugcrowd_rows(payload: object) -> list[tuple[dict[str, object], bool | None]]:
    rows: list[tuple[dict[str, object], bool | None]] = []
    if isinstance(payload, dict) and isinstance(payload.get("target_groups"), list):
        for group in payload["target_groups"]:
            if not isinstance(group, dict):
                continue
            in_scope = group.get("in_scope", group.get("inScope"))
            listed: bool | None = in_scope if isinstance(in_scope, bool) else None
            targets = group.get("targets")
            if isinstance(targets, list):
                for target in targets:
                    if isinstance(target, dict):
                        rows.append((target, listed))
        return rows
    targets_obj: object = payload.get("targets") if isinstance(payload, dict) else payload
    if isinstance(targets_obj, list):
        for target in targets_obj:
            if isinstance(target, dict):
                rows.append((target, None))
    return rows


def _collect(
    identifier: str,
    eligible: bool | None,
    asset_type: str,
    allowed: list[str],
    excluded: list[str],
    skipped: list[str],
    label: str,
) -> None:
    kind = asset_type.strip().lower().replace("-", "_").replace(" ", "_")
    text = identifier.strip()
    if _looks_like_cidr(text) or kind == "cidr":
        skipped.append(f"{label}: {text} is a CIDR range. Add each in-scope address on its own.")
        return
    if kind in _SKIP_TYPES:
        skipped.append(f"{label}: {kind or 'asset'} is not a host rule and was not imported.")
        return
    if kind and kind not in _HOST_TYPES and not _looks_like_host(text):
        skipped.append(f"{label}: asset type {kind} is not a host, URL, or wildcard.")
        return
    try:
        validate_rule(text)
    except ValueError as exc:
        skipped.append(f"{label}: {exc}")
        return
    if eligible is False:
        excluded.append(text)
    else:
        allowed.append(text)


def _looks_like_cidr(value: str) -> bool:
    if "/" not in value or "://" in value:
        return False
    base, _, prefix = value.partition("/")
    return bool(base) and prefix.isdigit() and "." not in prefix and ":" not in prefix


def _looks_like_host(value: str) -> bool:
    token = value.strip()
    if "://" in token or token.startswith("*."):
        return True
    return " " not in token and "." in token


def _finish(
    source: str,
    allowed: list[str],
    excluded: list[str],
    skipped: list[str],
    empty_error: str = "",
) -> ImportedScope:
    excluded_unique = tuple(dict.fromkeys(excluded))
    blocked = set(excluded_unique)
    allowed_unique = tuple(item for item in dict.fromkeys(allowed) if item not in blocked)
    if not allowed_unique and not excluded_unique:
        detail = "; ".join(skipped[:8]) or "nothing matched"
        prefix = empty_error or "No scope rules were produced."
        raise ValueError(f"{prefix} {detail}")
    return ImportedScope(source=source, allowed=allowed_unique, excluded=excluded_unique, skipped=tuple(skipped))
