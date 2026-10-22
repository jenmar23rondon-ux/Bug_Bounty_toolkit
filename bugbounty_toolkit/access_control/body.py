"""Structured ID-field mutations. This module does not send requests."""

from __future__ import annotations

import copy
from dataclasses import dataclass
import json
import re
from urllib.parse import parse_qsl, urlencode

from .comparison import parse_json, pointer_parts


def id_name(name: str) -> bool:
    return name.lower() == "id" or name.endswith(("Id", "ID")) or bool(re.search(r"[_-]id$", name, re.I))


def numeric_fields(value, path: str = "") -> dict[str, int]:
    result = {}
    if isinstance(value, dict):
        for key, child in value.items():
            pointer = path + "/" + key.replace("~", "~0").replace("/", "~1")
            if type(child) is int and id_name(key):
                result[pointer] = child
            elif isinstance(child, (dict, list)):
                result.update(numeric_fields(child, pointer))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            result.update(numeric_fields(child, path + "/" + str(index)))
    return result


@dataclass(frozen=True)
class BodyDocument:
    media_type: str
    value: object

    @classmethod
    def parse(cls, body: str | bytes | None, content_type: str) -> BodyDocument:
        if body is None:
            raise ValueError("Body IDOR requires a captured body.")
        text = body.decode("utf-8") if isinstance(body, bytes) else body
        media = content_type.split(";", 1)[0].strip().lower()
        if media == "application/json":
            value = parse_json(text)
            if not isinstance(value, (dict, list)):
                raise ValueError("A JSON object or array is required.")
        elif media == "application/x-www-form-urlencoded":
            value = parse_qsl(text, keep_blank_values=True)
            names = [key for key, _ in value]
            if len(names) != len(set(names)):
                raise ValueError("Duplicate form fields are ambiguous and are not supported.")
        else:
            raise ValueError("Supported bodies are JSON and form-urlencoded; multipart is not rewritten.")
        return cls(media, value)

    def fields(self) -> dict[str, int]:
        if self.media_type == "application/json":
            return numeric_fields(self.value)
        return {
            "/" + key.replace("~", "~0").replace("/", "~1"): int(value)
            for key, value in self.value
            if id_name(key) and re.fullmatch(r"-?[0-9]{1,19}", value)
        }

    def replace(self, pointer: str, value: int) -> str:
        if pointer not in self.fields() or type(value) is not int or not -(2**63) <= value < 2**63:
            raise ValueError("Select an existing integer ID field and a signed 64-bit value.")
        parts = pointer_parts(pointer)
        if self.media_type == "application/x-www-form-urlencoded":
            key = parts[0]
            return urlencode([(name, str(value) if name == key else item) for name, item in self.value])
        document = copy.deepcopy(self.value)
        node = document
        for part in parts[:-1]:
            node = node[int(part)] if isinstance(node, list) else node[part]
        key = int(parts[-1]) if isinstance(node, list) else parts[-1]
        node[key] = value
        return json.dumps(document, ensure_ascii=True, allow_nan=False, separators=(",", ":"))

    def without_fields(self, fields: list[str]):
        document = self
        for pointer in fields:
            document = BodyDocument.parse(document.replace(pointer, 0), self.media_type)
        return document.value

    def variations(self, fields: list[str], values: list[int] | None = None):
        for pointer in fields:
            current = self.fields().get(pointer)
            if current is None:
                raise ValueError("An approved body field is missing or not an integer ID.")
            selected = values if values is not None else [current - 1, current + 1, current]
            for value in dict.fromkeys(selected):
                yield pointer, value, self.replace(pointer, value)
