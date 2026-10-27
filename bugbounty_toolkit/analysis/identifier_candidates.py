"""Offline structured object-identifier candidate extraction.

This module discovers *candidate* fields that may represent references to objects
across common capture encodings (URL path, query, matrix parameters, nested JSON,
JSON arrays, form-url-encoded bodies, bounded XML and XML attributes, and fields
explicitly declared as references). It is a discovery aid only:

* It never brute-forces or enumerates identifiers.
* It never determines ownership, visibility or authorization.
* It never replaces field values nor generates requests.
* It never auto-confirms a finding.
* It performs no network traffic of any kind.

The extractor preserves the original scalar type of every candidate value and an
exact locator (JSON Pointer, bounded XPath, or a stable path/query/matrix
reference) so downstream consumers can relocate the field without re-parsing.

An opt-in adapter (:func:`object_discovery_candidates`) exposes the candidates to
the existing Object Discovery pipeline without altering its ranking algorithm or
the PR #52 denial-assessment behaviour.
"""

from __future__ import annotations

from dataclasses import dataclass, field as dataclass_field
import json
import re
from typing import Any
from urllib.parse import parse_qsl, unquote, urlsplit
from xml.etree import ElementTree

from ..core.redaction import JWT_TOKEN
from ..idor_discovery import SENSITIVE_FIELD

# --- Bounds (defence-in-depth against hostile captures) -----------------------
MAX_INPUT_BYTES = 2 * 1024 * 1024
MAX_JSON_DEPTH = 24
MAX_JSON_NODES = 20_000
MAX_XML_BYTES = 256 * 1024
MAX_XML_ELEMENTS = 5_000
MAX_XML_DEPTH = 40
MAX_QUERY_FIELDS = 512
MAX_CANDIDATES = 4_096
MAX_VALUE_LEN = 256

# --- Identifier value shapes --------------------------------------------------
_UUID = re.compile(r"\A[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\Z")
_NUMERIC = re.compile(r"\A-?[0-9]{1,32}\Z")
# Opaque handles: mixed-case/alnum (and -,_) long enough to be non-trivial.
_OPAQUE = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9_-]{5,128}\Z")
# Short alphanumeric key, e.g. "AB12".
_ALNUM_KEY = re.compile(r"\A[A-Za-z0-9]{2,5}\Z")
# URL/payload signatures we must never treat as object references.
_SIGNATURE = re.compile(r"sig|signature|hmac|checksum|hash|digest|nonce|salt|mac|verifier", re.I)
# Names that identify a field as holding an object reference.
_ID_FIELD = re.compile(
    r"(?:\A|[_-])(?:id|ids|uid|uuid|guid|ref|reference|key|fk|pk|oid|gid|no|number|slug|handle|isbn|sku|ean|asin)\Z",
    re.I,
)
# Pagination / counter / cursor field names (excluded without strong evidence).
_PAGINATION = re.compile(
    r"\A(?:page|pages|per[_-]?page|page[_-]?size|offset|limit|skip|top|start|end|"
    r"index|count|total|size|length|rows|first|last|cursor|n)\Z",
    re.I,
)
# Timestamp-like field names (excluded without strong evidence).
_TIMESTAMP = re.compile(
    r"(?:\A|[_-])(?:time|timestamp|ts|date|datetime|created|updated|modified|"
    r"expires|expiry|iat|exp|nbf|epoch|millis|seconds)(?:[_-]|\Z)",
    re.I,
)
# A bare, unqualified identifier key such as "id" or "uuid".
_BARE_ID = re.compile(r"\A(?:id|ids|uid|uuid|guid|oid|pk|fk)\Z", re.I)

VALUE_FORMATS = ("numeric", "uuid", "opaque", "alnum_key", "nested_ref")
SOURCES = ("path", "query", "matrix", "json", "json_array", "xml", "xml_attr", "form", "declared")


class ExtractionError(ValueError):
    """Raised when an input is malformed or exceeds safety bounds."""


@dataclass(frozen=True)
class IdentifierCandidate:
    """A single candidate object reference with preserved type and exact locator."""

    value: Any
    value_type: str
    id_format: str
    source: str
    locator: str
    container: str
    field_name: str
    context: str | None = None
    confidence: str = "strong"

    def as_dict(self) -> dict[str, Any]:
        return {
            "value": self.value,
            "value_type": self.value_type,
            "id_format": self.id_format,
            "source": self.source,
            "locator": self.locator,
            "container": self.container,
            "field_name": self.field_name,
            "context": self.context,
            "confidence": self.confidence,
        }


@dataclass
class ExtractionResult:
    """Candidates plus structured diagnostics for inputs that could not be trusted."""

    candidates: list[IdentifierCandidate] = dataclass_field(default_factory=list)
    rejected: list[dict[str, str]] = dataclass_field(default_factory=list)
    uncertain: list[dict[str, str]] = dataclass_field(default_factory=list)

    def values(self) -> list[Any]:
        return [candidate.value for candidate in self.candidates]

    def as_dict(self) -> dict[str, Any]:
        return {
            "candidates": [candidate.as_dict() for candidate in self.candidates],
            "rejected": list(self.rejected),
            "uncertain": list(self.uncertain),
        }


def _is_secret_name(name: str) -> bool:
    return bool(SENSITIVE_FIELD.search(name) or _SIGNATURE.search(name))


def _looks_like_id_name(name: str) -> bool:
    normalized = re.sub(r"([a-z])([A-Z])", r"\1_\2", name)
    return bool(_ID_FIELD.search(normalized) or _BARE_ID.match(normalized))


def _is_excluded_name(name: str) -> bool:
    """Pagination, counters and timestamps are excluded unless strongly typed."""
    normalized = re.sub(r"([a-z])([A-Z])", r"\1_\2", name)
    if _PAGINATION.match(normalized):
        return True
    # `updated_by_id` names a reference, not a timestamp.
    return bool(_TIMESTAMP.search(normalized)) and not _ID_FIELD.search(normalized)


def _classify_value(value: Any) -> str | None:
    """Return the candidate id-format for a scalar, or None if it is not id-shaped."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return "numeric"
    if not isinstance(value, str):
        return None
    text = value.strip()
    if not text or len(text) > MAX_VALUE_LEN:
        return None
    if JWT_TOKEN.search(text):
        return None
    if _UUID.match(text):
        return "uuid"
    if _NUMERIC.match(text):
        return "numeric"
    if _ALNUM_KEY.match(text) and any(c.isalpha() for c in text) and any(c.isdigit() for c in text):
        return "alnum_key"
    has_alpha = any(c.isalpha() for c in text)
    if _OPAQUE.match(text) and has_alpha and (any(c.isdigit() for c in text) or len(text) >= 20):
        return "opaque"
    return None


def _value_type(value: Any) -> str:
    if isinstance(value, bool):
        return "bool"
    if isinstance(value, int):
        return "int"
    if isinstance(value, float):
        return "float"
    return "str"


def _consider(
    result: ExtractionResult,
    *,
    name: str,
    value: Any,
    source: str,
    locator: str,
    container: str,
    context: str | None,
    declared: bool = False,
) -> None:
    """Evaluate one field and record a candidate, a rejection, or uncertainty."""
    if _is_secret_name(name):
        result.rejected.append({"locator": locator, "reason": "secret_or_signature_name"})
        return
    id_format = _classify_value(value)
    if id_format is None:
        text = value if isinstance(value, str) else ""
        if text and JWT_TOKEN.search(text):
            result.rejected.append({"locator": locator, "reason": "jwt_token"})
        return
    name_is_id = declared or _looks_like_id_name(name)
    # A UUID is a candidate regardless of field name; bare numbers need an id-ish name.
    if id_format == "uuid":
        strong = True
    elif name_is_id:
        strong = True
    else:
        # Numbers / opaque strings in non-id fields are not assumed to be IDs.
        return
    if _is_excluded_name(name):
        # Pagination/timestamp/counter: keep only with strong evidence (UUID value).
        if id_format != "uuid":
            result.rejected.append({"locator": locator, "reason": "pagination_timestamp_or_counter"})
            return
        result.uncertain.append({"locator": locator, "reason": "strongly_typed_in_excluded_field"})
    result.candidates.append(
        IdentifierCandidate(
            value=value,
            value_type=_value_type(value),
            id_format=id_format,
            source=source,
            locator=locator,
            container=container,
            field_name=name,
            context=context,
            confidence="strong" if strong else "weak",
        )
    )


# --- Path / matrix ------------------------------------------------------------
def _extract_path(result: ExtractionResult, path: str) -> None:
    segments = [seg for seg in path.split("/") if seg != ""]
    for index, raw in enumerate(segments):
        decoded = unquote(raw)
        matrix = decoded.split(";")
        base = matrix[0]
        collection = unquote(segments[index - 1]).split(";")[0] if index else None
        shape = _classify_value(base)
        # A path segment is dynamic only when its shape carries id evidence (digits/UUID).
        if shape and not _VERSION.match(base) and (shape == "uuid" or any(c.isdigit() for c in base)):
            _consider(
                result,
                name=collection or "segment",
                value=base,
                source="path",
                locator=f"/path/{index}",
                container="/path",
                context=collection,
                declared=True,
            )
        for param in matrix[1:]:
            if "=" not in param:
                continue
            key, _, mvalue = param.partition("=")
            _consider(
                result,
                name=key,
                value=unquote(mvalue),
                source="matrix",
                locator=f"/path/{index};{key}",
                container=f"/path/{index}",
                context=base,
                declared=True,
            )


def _extract_query(result: ExtractionResult, query: str) -> None:
    try:
        pairs = parse_qsl(query, keep_blank_values=True, max_num_fields=MAX_QUERY_FIELDS)
    except ValueError as exc:
        result.rejected.append({"locator": "/query", "reason": f"malformed_query:{exc}"})
        return
    positions: dict[str, int] = {}
    for name, value in pairs:
        index = positions.get(name, 0)
        positions[name] = index + 1
        _consider(
            result,
            name=name,
            value=value,
            source="query",
            locator=f"/query/{name}/{index}",
            container="/query",
            context=None,
        )


def _extract_form(result: ExtractionResult, body: str) -> None:
    try:
        pairs = parse_qsl(body, keep_blank_values=True, max_num_fields=MAX_QUERY_FIELDS)
    except ValueError as exc:
        result.rejected.append({"locator": "/form", "reason": f"malformed_form:{exc}"})
        return
    positions: dict[str, int] = {}
    for name, value in pairs:
        index = positions.get(name, 0)
        positions[name] = index + 1
        _consider(
            result,
            name=name,
            value=value,
            source="form",
            locator=f"/form/{name}/{index}",
            container="/form",
            context=None,
        )


# --- JSON ---------------------------------------------------------------------
def _pointer_escape(token: str) -> str:
    return token.replace("~", "~0").replace("/", "~1")


def _walk_json(
    result: ExtractionResult, node: Any, pointer: str, depth: int, budget: list[int], container_name: str | None
) -> None:
    if depth > MAX_JSON_DEPTH:
        raise ExtractionError("JSON nesting exceeds the configured depth limit.")
    budget[0] += 1
    if budget[0] > MAX_JSON_NODES:
        raise ExtractionError("JSON exceeds the configured node limit.")
    if isinstance(node, dict):
        for key, value in node.items():
            child = f"{pointer}/{_pointer_escape(key)}"
            if isinstance(value, (dict, list)):
                _walk_json(result, value, child, depth + 1, budget, key)
            else:
                source = "json"
                _consider(
                    result,
                    name=key,
                    value=value,
                    source=source,
                    locator=child,
                    container=pointer or "/",
                    context=container_name,
                )
    elif isinstance(node, list):
        for index, value in enumerate(node):
            child = f"{pointer}/{index}"
            if isinstance(value, (dict, list)):
                _walk_json(result, value, child, depth + 1, budget, container_name)
            else:
                # Array of bare scalars under an id-ish container (e.g. "user_ids": [1,2]).
                name = container_name or ""
                _consider(
                    result,
                    name=name,
                    value=value,
                    source="json_array",
                    locator=child,
                    container=pointer or "/",
                    context=container_name,
                )


def _extract_json(result: ExtractionResult, body: str) -> None:
    text = body.strip()
    if not text:
        return
    # Detect repeated keys (json.loads silently keeps the last) so we can flag them.
    try:
        data = json.loads(text, object_pairs_hook=_reject_duplicate_keys)
    except ExtractionError as exc:
        # Repeated keys are ambiguous (parsers disagree on which value wins): reject.
        result.rejected.append({"locator": "/", "reason": str(exc)})
        return
    except (ValueError, RecursionError) as exc:
        result.rejected.append({"locator": "/", "reason": f"malformed_json:{exc}"})
        return
    try:
        _walk_json(result, data, "", 0, [0], None)
    except ExtractionError as exc:
        result.rejected.append({"locator": "/", "reason": str(exc)})


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    keys = [key for key, _ in pairs]
    if len(keys) != len(set(keys)):
        raise ExtractionError("duplicate_json_key")
    return dict(pairs)


# --- XML (bounded, no external entities) --------------------------------------
_VERSION = re.compile(r"\A[vV][0-9]{1,3}\Z")
_DOCTYPE = re.compile(r"<!DOCTYPE", re.I)
_ENTITY = re.compile(r"<!ENTITY", re.I)


def _xpath_of(trail: list[str]) -> str:
    return "/" + "/".join(trail)


def _walk_xml(result: ExtractionResult, element: Any, trail: list[str], counts: list[int], depth: int) -> None:
    if depth > MAX_XML_DEPTH:
        raise ExtractionError("XML nesting exceeds the configured depth limit.")
    counts[0] += 1
    if counts[0] > MAX_XML_ELEMENTS:
        raise ExtractionError("XML exceeds the configured element limit.")
    tag = element.tag if isinstance(element.tag, str) else "node"
    local = tag.split("}")[-1]
    trail = [*trail, local]
    xpath = _xpath_of(trail)
    for attr, value in element.attrib.items():
        attr_local = attr.split("}")[-1]
        _consider(
            result,
            name=attr_local,
            value=value,
            source="xml_attr",
            locator=f"{xpath}/@{attr_local}",
            container=xpath,
            context=local,
        )
    text = (element.text or "").strip()
    if text and len(element) == 0:
        _consider(
            result,
            name=local,
            value=text,
            source="xml",
            locator=xpath,
            container=_xpath_of(trail[:-1]) or "/",
            context=trail[-2] if len(trail) > 1 else None,
        )
    for child in element:
        _walk_xml(result, child, trail, counts, depth + 1)


def _extract_xml(result: ExtractionResult, body: str) -> None:
    text = body.strip()
    if not text:
        return
    if len(text.encode("utf-8", errors="replace")) > MAX_XML_BYTES:
        result.rejected.append({"locator": "/", "reason": "xml_exceeds_byte_limit"})
        return
    if _DOCTYPE.search(text) or _ENTITY.search(text):
        # Never resolve DTDs/external entities; reject rather than risk XXE.
        result.rejected.append({"locator": "/", "reason": "xml_doctype_or_entity_blocked"})
        return
    parser = ElementTree.XMLParser()
    try:
        root = ElementTree.fromstring(text, parser=parser)  # noqa: S314 - DOCTYPE/entity pre-blocked above
    except ElementTree.ParseError as exc:
        result.rejected.append({"locator": "/", "reason": f"malformed_xml:{exc}"})
        return
    try:
        _walk_xml(result, root, [], [0], 0)
    except ExtractionError as exc:
        result.rejected.append({"locator": "/", "reason": str(exc)})


# --- Declared references ------------------------------------------------------
def _extract_declared(result: ExtractionResult, declared: dict[str, Any]) -> None:
    for name, value in declared.items():
        _consider(
            result,
            name=name,
            value=value,
            source="declared",
            locator=f"/declared/{name}",
            container="/declared",
            context=None,
            declared=True,
        )


# --- Public entry points ------------------------------------------------------
def extract_candidates(
    *,
    url: str | None = None,
    json_body: str | bytes | None = None,
    xml_body: str | bytes | None = None,
    form_body: str | bytes | None = None,
    declared_references: dict[str, Any] | None = None,
) -> ExtractionResult:
    """Extract object-identifier candidates from one authorized capture.

    All inputs are optional; only the provided encodings are processed. The call
    never performs I/O and never mutates the inputs.
    """
    result = ExtractionResult()
    json_body = _decode(json_body, "json", result)
    xml_body = _decode(xml_body, "xml", result)
    form_body = _decode(form_body, "form", result)
    _guard_size(url, "url", result)
    _guard_size(json_body, "json", result)
    _guard_size(form_body, "form", result)
    if url:
        parsed = urlsplit(url)
        _extract_path(result, parsed.path or "/")
        if parsed.query:
            _extract_query(result, parsed.query)
    if form_body:
        _extract_form(result, form_body)
    if json_body:
        _extract_json(result, json_body)
    if xml_body:
        _extract_xml(result, xml_body)
    if declared_references:
        _extract_declared(result, declared_references)
    if len(result.candidates) > MAX_CANDIDATES:
        raise ExtractionError("Capture exceeds the per-message candidate limit.")
    return result


def _decode(value: str | bytes | None, label: str, result: ExtractionResult) -> str | None:
    """Decode bytes strictly as UTF-8; invalid encodings are rejected, never guessed."""
    if not isinstance(value, bytes):
        return value
    if len(value) > MAX_INPUT_BYTES:
        raise ExtractionError(f"{label} input exceeds the configured byte limit.")
    try:
        return value.decode("utf-8")
    except UnicodeDecodeError:
        result.rejected.append({"locator": f"/{label}", "reason": "invalid_encoding"})
        return None


def _guard_size(value: str | None, label: str, result: ExtractionResult) -> None:
    if value is not None and len(value.encode("utf-8", errors="replace")) > MAX_INPUT_BYTES:
        raise ExtractionError(f"{label} input exceeds the configured byte limit.")


def object_discovery_candidates(
    *,
    url: str | None = None,
    json_body: str | bytes | None = None,
    xml_body: str | bytes | None = None,
    form_body: str | bytes | None = None,
    declared_references: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    """Opt-in adapter: candidates as plain dicts for the Object Discovery pipeline.

    This exposes the extraction output without re-implementing or altering the
    existing object ranking. Consumers opt in by calling this function; default
    legacy behaviour is unchanged because nothing here is wired automatically.
    """
    result = extract_candidates(
        url=url,
        json_body=json_body,
        xml_body=xml_body,
        form_body=form_body,
        declared_references=declared_references,
    )
    return [candidate.as_dict() for candidate in result.candidates]
