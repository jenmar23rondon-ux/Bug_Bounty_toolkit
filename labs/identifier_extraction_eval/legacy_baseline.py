"""Before metrics: approximate what the legacy object_relationships extractor covers.

The legacy pipeline only inspects path, query and JSON bodies and only emits stringified
values for fields whose names match its id heuristics. Formats such as matrix parameters,
XML, form bodies and declared references are uncovered (recall 0 for those cases).
This baseline never mutates Object Discovery ranking and never touches PR #52.
"""

from __future__ import annotations

import json
import re
from typing import Any
from urllib.parse import parse_qsl, unquote, urlsplit

from bugbounty_toolkit.core.redaction import JWT_TOKEN
from bugbounty_toolkit.idor_discovery import SENSITIVE_FIELD

_ID_NAME = re.compile(r"(?:\A|[_-])(?:id|ids|uid|uuid|ref)\Z", re.I)
_UUID = re.compile(r"\A[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\Z")


def _id_name(name: str) -> bool:
    if SENSITIVE_FIELD.search(name):
        return False
    normalized = re.sub(r"([a-z])([A-Z])", r"\1_\2", name)
    return bool(_ID_NAME.search(normalized))


def _shape(value: Any) -> str:
    text = str(value)
    if isinstance(value, str) and _UUID.match(value):
        return "uuid"
    if text.lstrip("-").isdigit():
        return "numeric"
    return "opaque"


def _walk(node: Any, pointer: str, parent_name: str | None, out: list[dict[str, Any]]) -> None:
    if isinstance(node, dict):
        for key, value in node.items():
            child = f"{pointer}/{key}"
            if isinstance(value, (dict, list)):
                _walk(value, child, key, out)
            elif _id_name(key) and type(value) in {str, int}:
                if isinstance(value, str) and JWT_TOKEN.search(value):
                    continue
                out.append(
                    {
                        "value": str(value),
                        "value_type": "str",
                        "id_format": _shape(value),
                        "source": "json",
                        "locator": child,
                    }
                )
    elif isinstance(node, list):
        for index, value in enumerate(node):
            child = f"{pointer}/{index}"
            if isinstance(value, (dict, list)):
                _walk(value, child, parent_name, out)
            elif parent_name and _id_name(parent_name) and type(value) in {str, int}:
                out.append(
                    {
                        "value": str(value),
                        "value_type": "str",
                        "id_format": _shape(value),
                        "source": "json_array",
                        "locator": child,
                    }
                )


def legacy_extract(
    *,
    url: str | None = None,
    json_body: str | bytes | None = None,
    xml_body: str | bytes | None = None,
    form_body: str | bytes | None = None,
    declared_references: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    """Reproduce the formats the pre-wave-4 extractor covered (path/query/JSON only)."""
    del xml_body, form_body, declared_references  # intentionally uncovered
    out: list[dict[str, Any]] = []
    if url:
        parsed = urlsplit(url)
        segments = [seg for seg in (parsed.path or "/").split("/") if seg]
        for index, raw in enumerate(segments):
            base = unquote(raw).split(";")[0]
            if base.isdigit() or _UUID.match(base):
                out.append(
                    {
                        "value": base,
                        "value_type": "str",
                        "id_format": "uuid" if _UUID.match(base) else "numeric",
                        "source": "path",
                        "locator": f"/path/{index}",
                    }
                )
        for name, value in parse_qsl(parsed.query, keep_blank_values=True):
            if _id_name(name) and value and not JWT_TOKEN.search(value):
                out.append(
                    {
                        "value": value,
                        "value_type": "str",
                        "id_format": _shape(value),
                        "source": "query",
                        "locator": f"/query/{name}/0",
                    }
                )
    if isinstance(json_body, bytes):
        return out
    if json_body:
        try:
            data = json.loads(json_body)
        except ValueError:
            return out
        _walk(data, "", None, out)
    return out
