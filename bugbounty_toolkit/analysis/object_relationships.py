"""Offline object-reference correlation, never an authorization or vulnerability oracle."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
import hashlib
import hmac
import json
from pathlib import Path
import re
import secrets
from typing import Any
from urllib.parse import parse_qsl, unquote, urlsplit

from ..access_control.comparison import parse_json, pointer_parts
from ..burp_import import MAX_EXCHANGE_BYTES, MAX_EXCHANGES, MAX_ITEM_BYTES, captured_response, parse_captured_exchanges
from ..case_generator import SESSION_HEADER
from ..core.private_files import atomic_private_write, local_path, read_private_input
from ..core.records import ProgramPaths
from ..core.redaction import JWT_TOKEN
from ..idor_discovery import SENSITIVE_FIELD, json_scalar_fields
from .api_workflow import graph_node_id, merge_relation
from .evidence_engine import CaptureSource, resource_path_segments
from .har_import import HarImportError, import_har
from .evidence_graph import MAX_GRAPH_EDGES, MAX_GRAPH_INPUT_BYTES, MAX_GRAPH_NODES

SCHEMA_VERSION = "1.0"
RANKING_VERSION = "2.0"
MAX_FILES = 16
MAX_TOTAL_BYTES = 64 * 1024 * 1024
MAX_CAPTURES = 256
MAX_OCCURRENCES = 64
COLLECTIONS = {
    word: singular
    for singular, plural in (
        ("user", "users"),
        ("order", "orders"),
        ("invoice", "invoices"),
        ("item", "items"),
        ("account", "accounts"),
        ("address", "addresses"),
        ("basket", "baskets"),
        ("cart", "carts"),
        ("document", "documents"),
        ("file", "files"),
        ("record", "records"),
        ("resource", "resources"),
        ("customer", "customers"),
        ("project", "projects"),
        ("organization", "organizations"),
        ("team", "teams"),
        ("tenant", "tenants"),
        ("product", "products"),
        ("wishlist", "wishlists"),
    )
    for word in (singular, plural)
}
SAFE_NAMES = set(COLLECTIONS) | {
    "api",
    "rest",
    "data",
    "results",
    "result",
    "response",
    "payload",
    "attributes",
    "relationships",
    "all",
    "count",
    "create",
    "current",
    "list",
    "me",
    "metadata",
    "new",
    "search",
    "self",
    "query",
    "get",
    "detail",
    "details",
    "update",
    "delete",
    "v1",
    "v2",
    "v3",
    "v4",
    "id",
    "uid",
    "uuid",
    "ids",
}
# Positive structural-evidence points (investigation priority for human review).
# Negative demotions follow; shared/public objects are demoted, never discarded.
POSITIVE_RULES = (
    ("request_reference", 20),
    ("also_in_response", 10),
    ("typed_foreign_key", 15),
    ("path_leaf_position", 15),
    ("cross_session_kind_peers", 20),
    ("multiple_session_contexts_leaf", 15),
    ("multiple_endpoints", 5),
    ("json_co_occurrence", 5),
    ("nested_path_context", 5),
)
NEGATIVE_RULES = (
    ("shared_path_parent_across_sessions", -35),
    ("unauthenticated_context", -15),
    ("response_only_no_request", -10),
)
# Back-compat alias for tests/importers that still import RULES.
RULES = POSITIVE_RULES
# Open-vocabulary resource kinds (P1). Structural wrappers / generic names are never a kind:
# an identifier whose only noun is one of these is INSUFFICIENT evidence and is not paired.
GENERIC_KIND_NAMES = frozenset(
    (SAFE_NAMES - set(COLLECTIONS))
    | {"ref", "refs", "key", "keys", "lookup", "value", "values", "obj", "object", "objects", "node", "nodes"}
    | {"meta", "info", "body", "content", "entry", "entries", "page", "pages", "limit"}
)
MAX_KIND_CHARS = 48
KIND_BASES = ("known_vocabulary", "path_collection", "typed_field_name", "collection_container")
LIMITATION = "References do not establish ownership, private data, account identity or unauthorized access."


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode()


def _ref(key: bytes, kind: str, *values: Any) -> str:
    digest = hmac.new(key, _canonical([kind, *values]), hashlib.sha256).hexdigest()[:32]
    return kind + "-" + digest


def _sign(graph: dict[str, Any], key: bytes) -> str:
    return hmac.new(key, _canonical({k: v for k, v in graph.items() if k != "integrity"}), hashlib.sha256).hexdigest()


def load_object_key(path: Path) -> bytes:
    key = read_private_input(path, 32, protected=True)
    if len(key) != 32:
        raise ValueError("The local HMAC key must contain exactly 32 random bytes.")
    return key


def _json_fields(body: str, headers: dict[str, str] | None) -> dict[str, Any]:
    content_type = next((v.lower() for k, v in (headers or {}).items() if k.lower() == "content-type"), "")
    if not body or ("json" not in content_type and not body.lstrip().startswith(("{", "["))):
        return {}
    return json_scalar_fields(parse_json(body), include_sensitive=True)


def _read_sources(
    path: Path, base_url: str | None, strict: bool = False, allow_truncate: bool = False
) -> tuple[bytes, list[CaptureSource], dict[str, Any]]:
    data = read_private_input(path, MAX_ITEM_BYTES)
    if data.lstrip().startswith(b"{"):
        result = import_har(
            data,
            strict=strict,
            max_bytes=MAX_ITEM_BYTES,
            max_message_bytes=MAX_EXCHANGE_BYTES,
            max_entries=MAX_EXCHANGES,
            allow_truncate=allow_truncate,
        )
        # Every per-entry check (URL, method, sizes, bodies) already ran in import_har.
        return data, result.accepted, result.summary()
    sources = []
    for index, exchange in enumerate(parse_captured_exchanges(data, base_url)):
        response = captured_response(exchange)
        request = exchange.request
        body = request.body_bytes()
        sources.append(
            CaptureSource(
                "burp",
                f"/items/{index}",
                request.prepared_url(),
                request.method,
                request.headers,
                body.decode("utf-8") if body else "",
                response.headers if response else {},
                response.body_text if response else "",
                response.status_code if response else None,
                None,
            )
        )
    summary = {
        "format": "burp",
        "mode": "strict",
        "entries_total": len(sources),
        "accepted": len(sources),
        "rejected": 0,
        "reasons": {},
        "rejected_entries": [],
        "truncated": False,
        "duplicate_entries": 0,
    }
    for source in sources:
        if not source.url or source.method not in {
            "GET",
            "HEAD",
            "POST",
            "PUT",
            "PATCH",
            "DELETE",
            "OPTIONS",
            "TRACE",
            "CONNECT",
        }:
            raise ValueError("Captured URL and HTTP method are required.")
        parsed = urlsplit(source.url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password:
            raise ValueError("Captured URLs must have an HTTP origin without embedded credentials.")
        if len(source.url) > 8192 or any(ord(char) < 32 for char in source.url):
            raise ValueError("Captured URL exceeds its structural limit.")
        if any(len(body.encode()) > MAX_EXCHANGE_BYTES for body in (source.request_body, source.response_body)):
            raise ValueError("Captured message exceeds the body byte limit.")
    return data, sources, summary


def _field_type(name: str, default: str) -> tuple[str, bool] | None:
    if SENSITIVE_FIELD.search(name):
        return None
    name = re.sub(r"([a-z])([A-Z])", r"\1_\2", name).lower()
    if name in {"id", "uid", "uuid", "ids"}:
        return default, False
    match = re.fullmatch(r"(.+?)_?(?:ids|uuid|uid|id)", name)
    if match and match[1].rstrip("_") in COLLECTIONS:
        return COLLECTIONS[match[1].rstrip("_")], True
    # Unknown identifier namespaces remain endpoint-qualified and are never named in exports.
    if match and re.search(r"_(?:ids|uuid|uid|id)$", name):
        return default + ":field:" + name, True
    return None


def _singular(word: str) -> str:
    if word.endswith("ies") and len(word) > 4:
        return word[:-3] + "y"
    if word.endswith(("sses", "xes", "ches", "shes", "zzes")):
        return word[:-2]
    if word.endswith("s") and not word.endswith(("ss", "us", "is")) and len(word) > 3:
        return word[:-1]
    return word


def resource_kind_noun(word: str) -> tuple[str, str] | None:
    """Open-vocabulary kind for one collection segment or typed-id stem, or None if insufficient.

    Returns (kind, basis_hint). Known nouns keep their existing canonical name. Generic wrappers,
    version tags, numbers, sensitive names and over-long tokens are INSUFFICIENT (None).
    """
    lower = re.sub(r"([a-z])([A-Z])", r"\1_\2", word).lower().strip("_")
    if lower in COLLECTIONS:
        return COLLECTIONS[lower], "known_vocabulary"
    if (
        not lower
        or len(lower) > MAX_KIND_CHARS
        or lower in GENERIC_KIND_NAMES
        or SENSITIVE_FIELD.search(lower)
        or not re.fullmatch(r"[a-z][a-z_]*[a-z]", lower)
        or re.fullmatch(r"v\d+", lower)
    ):
        return None
    noun = _singular(lower)
    if noun in GENERIC_KIND_NAMES or len(noun) < 2:
        return None
    return noun, "open_vocabulary"


def _field_kind(name: str) -> str | None:
    """Kind from a typed identifier field name (`ticket_id`, `claimId`, `shipment_ids`); bare ids -> None."""
    if SENSITIVE_FIELD.search(name):
        return None
    lower = re.sub(r"([a-z])([A-Z])", r"\1_\2", name).lower()
    match = re.fullmatch(r"(.+?)_?(?:ids|uuid|uid|id)", lower)
    if not match:
        return None
    found = resource_kind_noun(match[1].rstrip("_"))
    return found[0] if found else None


def _safe_name(name: str, key: bytes) -> str:
    lower = name.lower()
    typed = _field_type(name, "")
    if lower in SAFE_NAMES or (typed and typed[0] in set(COLLECTIONS.values())):
        return name
    return _ref(key, "name", name)


@dataclass(frozen=True)
class _Occurrence:
    kind: str
    value: str
    location: str
    pointer: str
    container: str
    typed: bool = False
    # Open-vocabulary kind (plain noun, internal only; exported keyed-hashed) and its evidence basis.
    resource_kind: str | None = None
    kind_basis: str | None = None


def _is_dynamic(segment: tuple[str, bool]) -> bool:
    return segment[1] and unquote(segment[0]).lower() not in SAFE_NAMES


def _path_data(path: str, key: bytes, origin: str) -> tuple[str, str, list[_Occurrence]]:
    segments = resource_path_segments(path, set(COLLECTIONS))
    template: list[str] = []
    occurrences: list[_Occurrence] = []
    context = "unknown:" + origin + ":" + path
    for index, (encoded, hinted) in enumerate(segments):
        segment = unquote(encoded)
        lower = segment.lower()
        if lower in COLLECTIONS:
            context = COLLECTIONS[lower]
        dynamic = hinted and lower not in SAFE_NAMES
        template.append("{id}" if dynamic else _safe_name(segment, key) if segment else "")
        if dynamic:
            previous = unquote(segments[index - 1][0]).lower() if index else ""
            kind = COLLECTIONS.get(previous, "unknown:" + origin + ":" + "/".join(template[:-1]))
            # The preceding segment names the collection only when it is itself a static segment.
            noun = resource_kind_noun(previous) if index and not _is_dynamic(segments[index - 1]) else None
            occurrences.append(
                _Occurrence(
                    kind,
                    segment,
                    "path",
                    f"/path/{index}",
                    "/path",
                    resource_kind=noun[0] if noun else None,
                    kind_basis="path_collection" if noun else None,
                )
            )
    return "/".join(template), context, occurrences


def _extract(source: CaptureSource, key: bytes, origin: str, credentials: set[str]) -> tuple[str, list[_Occurrence]]:
    parsed = urlsplit(source.url or "")
    template, default, occurrences = _path_data(parsed.path or "/", key, origin)
    # Unknown generic IDs are scoped to the normalized endpoint, not their captured value.
    if default.startswith("unknown:"):
        default = "unknown:" + origin + ":" + template
    positions: dict[str, int] = defaultdict(int)
    for name, value in parse_qsl(parsed.query, keep_blank_values=True, max_num_fields=128):
        index = positions[name]
        positions[name] += 1
        field = _field_type(name, default)
        if field:
            noun = _field_kind(name)
            occurrences.append(
                _Occurrence(
                    field[0],
                    value,
                    "query",
                    f"/query/{_safe_name(name, key)}/{index}",
                    "/query",
                    field[1],
                    noun,
                    "typed_field_name" if noun else None,
                )
            )
    for location, body, headers in (
        ("request_json", source.request_body, source.request_headers),
        ("response_json", source.response_body, source.response_headers),
    ):
        for pointer, value in _json_fields(body, headers).items():
            parts = pointer_parts(pointer)
            if any(SENSITIVE_FIELD.search(part) for part in parts):
                continue
            context = next(
                (COLLECTIONS[part.lower()] for part in reversed(parts[:-1]) if part.lower() in COLLECTIONS), default
            )
            name = parts[-2] if parts[-1].isdigit() and len(parts) > 1 else parts[-1]
            field = _field_type(name, context)
            if field and type(value) in {str, int}:
                # Numeric JSON keys may themselves be private IDs, not array indexes.
                safe = "/" + "/".join(_safe_name(p, key) for p in parts)
                container = pointer.rsplit("/", 1)[0]
                noun, basis = _field_kind(name), "typed_field_name"
                if noun is None and not field[1]:
                    # Bare `id`: only the IMMEDIATE named container may type it (`leases[*].id`).
                    parents = [part for part in parts[:-1] if not part.isdigit()]
                    found = resource_kind_noun(parents[-1]) if parents and parts[-1] == name else None
                    noun, basis = (found[0], "collection_container") if found else (None, "")
                occurrences.append(
                    _Occurrence(
                        field[0], str(value), location, safe, container, field[1], noun, basis if noun else None
                    )
                )
    occurrences = [
        o
        for o in occurrences
        if o.value and len(o.value) <= 256 and o.value not in credentials and not JWT_TOKEN.search(o.value)
    ]
    if len(occurrences) > MAX_OCCURRENCES:
        raise ValueError("Capture exceeds the per-message object-reference limit.")
    return template, occurrences


def _identity_namespace(occurrence: _Occurrence) -> str:
    """Stable object-identity namespace (resource-kind-lineage-v1).

    The legacy namespace (known noun or endpoint/field scoped ``unknown:...``) is kept and, when the
    inferred kind differs from it, the kind is appended as a disambiguator. This only ever SPLITS
    identities (equal raw IDs of different kinds stop colliding, e.g. ``tickets[*].id`` vs
    ``claims[*].id`` on one endpoint); it never creates a new union across endpoints or namespaces.
    """
    noun = occurrence.resource_kind
    # Path segments and typed field names already scope the legacy namespace by their own noun
    # (endpoint template / field name), so their historical object refs are kept byte-identical.
    if not noun or noun == occurrence.kind or occurrence.kind_basis != "collection_container":
        return occurrence.kind
    return occurrence.kind + "|kind:" + noun


def _kind_ref(key: bytes, program: str, origin: str, kind: str | None) -> str | None:
    """Keyed, origin-scoped kind reference. Known nouns stay readable; open nouns are HMAC-only."""
    if not kind:
        return None
    if kind in set(COLLECTIONS.values()):
        return "kind:" + kind
    return _ref(key, "kind", program, origin, kind)


def _credentials(source: CaptureSource) -> set[str]:
    result: set[str] = set()
    for headers in (source.request_headers, source.response_headers):
        for name, value in (headers or {}).items():
            if SESSION_HEADER.search(name) or SENSITIVE_FIELD.search(name):
                result.add(value)
                result.update(part.strip() for part in re.split(r"[\s;=,]+", value) if part.strip())
    for name, value in parse_qsl(urlsplit(source.url or "").query, max_num_fields=128):
        if SENSITIVE_FIELD.search(name):
            result.add(value)
    for body, headers in (
        (source.request_body, source.request_headers),
        (source.response_body, source.response_headers),
    ):
        for pointer, value in _json_fields(body, headers).items():
            if any(SENSITIVE_FIELD.search(part) for part in pointer_parts(pointer)):
                result.add(str(value))
    return result


def _session(source: CaptureSource, key: bytes, program: str, origin: str) -> str | None:
    values = sorted(
        (name.lower(), value) for name, value in (source.request_headers or {}).items() if SESSION_HEADER.search(name)
    )
    return _ref(key, "session", program, origin, values) if values else None


def build_object_graph(
    program: str,
    inputs: list[Path],
    key: bytes,
    *,
    authorized: bool,
    base_url: str | None = None,
    strict: bool = False,
    allow_truncate: bool = False,
) -> dict[str, Any]:
    """Read captures only. No DB, network, model calls, output files or executable cases.

    HAR files default to partial recovery: invalid entries are isolated and reported in
    ``capture_import``; ``strict=True`` keeps whole-file rejection for any invalid entry.
    """
    ProgramPaths(Path("."), program)
    if not authorized:
        raise ValueError("Declare authorization to analyze these local captures; this does not authorize active tests.")
    if len(key) != 32 or not 1 <= len(inputs) <= MAX_FILES:
        raise ValueError("Use a 32-byte key and between one and sixteen capture files.")
    if strict and allow_truncate:
        raise ValueError("Choose either strict import or explicit truncation, not both.")
    try:
        return _build(program, inputs, key, base_url, strict, allow_truncate)
    except (ValueError, UnicodeError, TypeError, KeyError, OverflowError, RecursionError) as exc:
        # Parser exceptions can contain raw input. Never propagate their text to the CLI.
        raise ValueError(_safe_failure(exc)) from exc


def _safe_failure(exc: BaseException) -> str:
    """Generic message plus, for HAR, only the enumerated file-fatal reason code."""
    message = "Offline captures are invalid, incomplete or exceed discovery limits; inspect locally."
    if isinstance(exc, HarImportError):
        return f"{message} (reason: {exc.reason})"
    return message


def _import_totals(rows: list[dict[str, Any]], mode: str) -> dict[str, Any]:
    reasons: dict[str, int] = defaultdict(int)
    for row in rows:
        for reason, count in row["reasons"].items():
            reasons[reason] += count
    return {
        "mode": mode,
        "entries_total": sum(row["entries_total"] for row in rows),
        "accepted": sum(row["accepted"] for row in rows),
        "rejected": sum(row["rejected"] for row in rows),
        "reasons": dict(sorted(reasons.items())),
        "truncated": any(row["truncated"] for row in rows),
        "duplicate_entries": sum(row["duplicate_entries"] for row in rows),
        "network_validation": "none",
    }


def _build(
    program: str,
    inputs: list[Path],
    key: bytes,
    base_url: str | None,
    strict: bool = False,
    allow_truncate: bool = False,
) -> dict[str, Any]:
    loaded: list[tuple[str, CaptureSource]] = []
    sources: dict[str, dict[str, Any]] = {}
    imports: dict[str, dict[str, Any]] = {}
    total_bytes = 0
    for path in inputs:
        data, captures, import_summary = _read_sources(path, base_url, strict, allow_truncate)
        total_bytes += len(data)
        if total_bytes > MAX_TOTAL_BYTES:
            raise ValueError("Capture set exceeds total byte limit.")
        source_id = _ref(key, "source", program, data.hex())
        sources[source_id] = {
            "id": source_id,
            "bytes": len(data),
            "captures": len(captures),
            "format": captures[0].tool,
        }
        imports[source_id] = import_summary
        loaded.extend((source_id, capture) for capture in captures)
        if len(loaded) > MAX_CAPTURES:
            raise ValueError("Capture set exceeds observation limit.")
    credentials: set[str] = set()
    for _, capture in loaded:
        credentials.update(_credentials(capture))
    nodes: dict[str, dict[str, Any]] = {}
    observations: dict[str, dict[str, Any]] = {}
    relations: dict[tuple[str, str, str], dict[str, object]] = {}

    for source_id, capture in loaded:
        parsed = urlsplit(capture.url or "")
        origin = _ref(
            key,
            "origin",
            program,
            parsed.scheme.lower(),
            (parsed.hostname or "").lower(),
            parsed.port or (443 if parsed.scheme == "https" else 80),
        )
        try:
            template, occurrences = _extract(capture, key, origin, credentials)
        except ValueError:
            # Per-entry object-reference overflow: isolate the HAR entry unless strict.
            row = imports[source_id]
            if strict or row["format"] != "har":
                raise
            index = int(capture.locator.rsplit("[", 1)[1].rstrip("]"))
            row["accepted"] -= 1
            sources[source_id]["captures"] -= 1
            row["rejected"] += 1
            row["reasons"]["object_reference_limit"] = row["reasons"].get("object_reference_limit", 0) + 1
            row["reasons"] = dict(sorted(row["reasons"].items()))
            row["rejected_entries"] = sorted(
                [*row["rejected_entries"], {"index": index, "reason": "object_reference_limit"}],
                key=lambda item: int(item["index"]),
            )
            continue
        endpoint = graph_node_id("endpoint", origin, capture.method or "", template)
        nodes[endpoint] = {
            "id": endpoint,
            "type": "Endpoint",
            "origin_ref": origin,
            "method": capture.method,
            "path_template": template,
        }
        session = _session(capture, key, program, origin)
        if session:
            nodes[session] = {"id": session, "type": "SessionContext", "account_identity": "unknown"}
        facts: list[dict[str, Any]] = []
        containers: dict[tuple[str, str], set[str]] = defaultdict(set)
        path_refs: list[str] = []
        for occurrence in occurrences:
            # Resource-kind lineage: equal raw IDs of different inferred kinds never share an object.
            identity = _identity_namespace(occurrence)
            object_id = _ref(key, "object", program, origin, identity, occurrence.value)
            # A known legacy type is only exported when the inferred kind does not contradict it
            # (`users[*].tickets[*].id` is a ticket reference, not a user). Contradiction -> unknown.
            type_hint = (
                occurrence.kind
                if occurrence.kind in set(COLLECTIONS.values()) and identity == occurrence.kind
                else "unknown"
            )
            nodes[object_id] = {
                "id": object_id,
                "type": "Object",
                "resource_type": type_hint,
                "type_basis": "field_or_collection_name_heuristic",
                "ownership": "unknown",
                "privacy": "unknown",
            }
            kind_ref = _kind_ref(key, program, origin, occurrence.resource_kind)
            field_id = graph_node_id("field", endpoint, occurrence.location, occurrence.pointer)
            nodes[field_id] = {
                "id": field_id,
                "type": "Field",
                "location": occurrence.location,
                "pointer_template": occurrence.pointer,
                "endpoint_ref": endpoint,
            }
            facts.append(
                {
                    "object_ref": object_id,
                    "field_ref": field_id,
                    "location": occurrence.location,
                    "typed": occurrence.typed,
                    # Inferred open-vocabulary kind: keyed hash only (no new names leak), or null when
                    # the evidence is insufficient (bare/generic/untyped ids). Never ownership.
                    "kind_ref": kind_ref,
                    "kind_basis": occurrence.kind_basis if kind_ref else "insufficient_evidence",
                }
            )
            if occurrence.location in {"request_json", "response_json"}:
                containers[(occurrence.location, occurrence.container)].add(object_id)
            if occurrence.location == "path":
                path_refs.append(object_id)
        facts = sorted({_canonical(fact): fact for fact in facts}.values(), key=_canonical)
        observation_id = _ref(key, "observation", program, endpoint, session, facts)
        provenance = {"source_ref": source_id, "locator": capture.locator}
        observation = observations.setdefault(
            observation_id,
            {
                "id": observation_id,
                "endpoint_ref": endpoint,
                "session_ref": session,
                "references": facts,
                "provenance": [],
            },
        )
        if provenance not in observation["provenance"]:
            observation["provenance"].append(provenance)

        def edge(relation: str, left: str, right: str, *, state: str = "observed", basis: str) -> None:
            merge_relation(
                relations,
                relation,
                left,
                right,
                [observation_id],
                [provenance],
                state=state,
                basis=basis,
                limitations=LIMITATION,
            )

        for fact in facts:
            edge("HAS_FIELD", endpoint, fact["field_ref"], basis="field_position")
            edge(
                "RETURNS_REFERENCE" if fact["location"] == "response_json" else "REFERENCES",
                fact["field_ref"],
                fact["object_ref"],
                basis="literal_typed_identifier",
            )
            if session:
                edge("SEEN_WITH_SESSION", fact["object_ref"], session, basis="captured_request_context")
        for group in containers.values():
            ordered = sorted(group)
            for index, left in enumerate(ordered):
                for right in ordered[index + 1 :]:
                    edge("CO_OCCURS", left, right, basis="same_json_container")
        for left, right in zip(path_refs, path_refs[1:]):
            if left != right:
                edge("PATH_CONTEXT", left, right, state="inferred", basis="nested_path_position_not_ownership")
        if len(nodes) > MAX_GRAPH_NODES or len(relations) > MAX_GRAPH_EDGES:
            raise ValueError("Object graph exceeds structural limits.")
    if any(row["accepted"] < 1 for row in imports.values()):
        raise HarImportError("no_valid_entries")
    for observation in observations.values():
        observation["provenance"].sort(key=_canonical)
    for relation in relations.values():
        provenance_rows = relation["provenance"]
        assert isinstance(provenance_rows, list)
        provenance_rows.sort(key=_canonical)
    graph: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "type": "api-object-relationship-graph",
        "program": program,
        "ranking_version": RANKING_VERSION,
        "key_id": _ref(key, "key", program),
        "sources": sorted(sources.values(), key=lambda row: row["id"]),
        "nodes": sorted(nodes.values(), key=lambda row: row["id"]),
        "relations": [relations[k] for k in sorted(relations)],
        "observations": sorted(observations.values(), key=lambda row: row["id"]),
        "summary": {
            "sources": len(sources),
            "observations": len(observations),
            "nodes": len(nodes),
            "relations": len(relations),
        },
        "capture_import": {
            **_import_totals(list(imports.values()), "strict" if strict else "partial"),
            "truncate_allowed": allow_truncate,
            "sources": [{"source_ref": ref, **imports[ref]} for ref in sorted(imports)],
        },
        "network_requests_sent": 0,
        "vulnerabilities_confirmed": 0,
        "captures_authorized_attestation": True,
        "limitation": LIMITATION,
    }
    graph["integrity"] = _sign(graph, key)
    if len(_canonical(graph)) > MAX_GRAPH_INPUT_BYTES:
        raise ValueError("Minimized graph exceeds export limit.")
    return graph


def read_object_graph(path: Path, program: str, key: bytes) -> dict[str, Any]:
    try:
        graph = parse_json(read_private_input(path, MAX_GRAPH_INPUT_BYTES).decode("utf-8"))
        validate_object_graph(graph, program, key)
        return dict(graph)
    except (ValueError, TypeError, UnicodeError, RecursionError) as exc:
        raise ValueError("Invalid object graph, unsupported version or mismatched local HMAC key.") from exc


def validate_object_graph(graph: Any, program: str, key: bytes) -> None:
    if (
        not isinstance(graph, dict)
        or graph.get("schema_version") != SCHEMA_VERSION
        or graph.get("type") != "api-object-relationship-graph"
    ):
        raise ValueError("Unsupported object graph schema.")
    if graph.get("program") != program or graph.get("key_id") != _ref(key, "key", program):
        raise ValueError("Object graph belongs to another program or HMAC key.")
    signature = graph.get("integrity")
    if not isinstance(signature, str) or not hmac.compare_digest(signature, _sign(graph, key)):
        raise ValueError("Object graph integrity verification failed.")
    if (
        graph.get("ranking_version") != RANKING_VERSION
        or graph.get("network_requests_sent") != 0
        or graph.get("vulnerabilities_confirmed") != 0
    ):
        raise ValueError("Invalid offline graph metadata.")
    for field, limit in (
        ("nodes", MAX_GRAPH_NODES),
        ("relations", MAX_GRAPH_EDGES),
        ("observations", MAX_CAPTURES),
        ("sources", MAX_FILES),
    ):
        if not isinstance(graph.get(field), list) or len(graph[field]) > limit:
            raise ValueError("Invalid object graph structure.")


def verify_object_sources(graph: dict[str, Any], inputs: list[Path], key: bytes) -> None:
    """Verify exact source bytes using keyed commitments, without publishing filenames."""
    if not 1 <= len(inputs) <= MAX_FILES:
        raise ValueError("Select between one and sixteen source files to verify.")
    refs = {_ref(key, "source", graph["program"], read_private_input(path, MAX_ITEM_BYTES).hex()) for path in inputs}
    if refs != {row["id"] for row in graph["sources"]}:
        raise ValueError("Source commitments do not match this graph.")


KIND_LINEAGE_VERSION = "resource-kind-lineage-v1"
EXPLICIT_KIND_BASES = frozenset({"path_collection", "typed_field_name"})
DERIVED_KIND_BASES = frozenset({"collection_container"})
KIND_STATUSES = ("explicit", "derived", "unknown", "ambiguous")


def kind_status(kind_refs: set[str], kind_bases: set[str]) -> str:
    """explicit (named by path/field), derived (container noun), unknown (no evidence) or ambiguous."""
    if len(kind_refs) > 1:
        return "ambiguous"
    if not kind_refs:
        return "unknown"
    return "explicit" if kind_bases & EXPLICIT_KIND_BASES else "derived"


def kind_lineage(
    kind_refs: set[str], kind_bases: set[str], observation_refs: set[str], namespace_refs: list[str]
) -> dict[str, Any]:
    """Exportable kind lineage for one object: keyed ids only, provenance by observation ref."""
    status = kind_status(kind_refs, kind_bases)
    return {
        "version": KIND_LINEAGE_VERSION,
        "kind_id": next(iter(kind_refs)) if len(kind_refs) == 1 else None,
        "status": status,
        "conflicting_kind_ids": sorted(kind_refs) if status == "ambiguous" else [],
        "bases": sorted(kind_bases),
        "namespace_refs": namespace_refs,
        "evidence_observation_refs": sorted(observation_refs),
        "ownership": "not_inferred_from_kind",
    }


def object_candidates(
    graph: dict[str, Any], program: str, key: bytes, *, limit: int = 100, min_score: int = 0
) -> dict[str, Any]:
    """Rank object references for human review using structural evidence only.

    Ranking prioritizes review depth; it never confirms ownership, privacy, or vulns.
    Shared/public objects may be demoted but are never auto-discarded.
    """
    validate_object_graph(graph, program, key)
    if not 1 <= limit <= 100 or not 0 <= min_score <= 100:
        raise ValueError("Candidate limit must be 1-100 and minimum score 0-100.")
    nodes = {node["id"]: node for node in graph["nodes"]}
    observations = list(graph["observations"])
    # Precompute path-parent / path-leaf roles from PATH_CONTEXT edges.
    path_parent_of: dict[str, set[str]] = defaultdict(set)  # parent -> evidence obs
    path_child_of: dict[str, set[str]] = defaultdict(set)  # child -> evidence obs
    co_of: dict[str, set[str]] = defaultdict(set)
    for relation in graph["relations"]:
        evidence = set(relation.get("evidence_refs") or [])
        if relation["relation"] == "PATH_CONTEXT":
            path_parent_of[relation["source"]].update(evidence)
            path_child_of[relation["target"]].update(evidence)
        elif relation["relation"] == "CO_OCCURS":
            co_of[relation["source"]].update(evidence)
            co_of[relation["target"]].update(evidence)

    # kind_ref -> session_ref -> distinct object_refs (for cross-session peer signal)
    kind_sessions: dict[str, dict[str, set[str]]] = defaultdict(lambda: defaultdict(set))
    for row in observations:
        session = row.get("session_ref") or ""
        for fact in row["references"]:
            kind = fact.get("kind_ref")
            if kind and session:
                kind_sessions[kind][session].add(fact["object_ref"])

    ep_origin = {
        node_id: str(node.get("origin_ref") or "") for node_id, node in nodes.items() if node["type"] == "Endpoint"
    }
    rows: list[dict[str, Any]] = []
    for object_id, node in nodes.items():
        if node["type"] != "Object":
            continue
        obs_rows = [row for row in observations if any(f["object_ref"] == object_id for f in row["references"])]
        request_refs: list[str] = []
        response_refs: list[str] = []
        typed_refs: list[str] = []
        kind_refs: set[str] = set()
        kind_bases: set[str] = set()
        kind_obs: set[str] = set()
        for row in obs_rows:
            facts = [fact for fact in row["references"] if fact["object_ref"] == object_id]
            if any(f["location"] != "response_json" for f in facts):
                request_refs.append(row["id"])
            if any(f["location"] == "response_json" for f in facts):
                response_refs.append(row["id"])
            if any(f["typed"] for f in facts):
                typed_refs.append(row["id"])
            for fact in facts:
                if fact.get("kind_ref"):
                    kind_refs.add(fact["kind_ref"])
                    kind_obs.add(row["id"])
                    if isinstance(fact.get("kind_basis"), str):
                        kind_bases.add(fact["kind_basis"])
        endpoints = sorted({row["endpoint_ref"] for row in obs_rows})
        sessions = sorted({row["session_ref"] for row in obs_rows if row["session_ref"]})
        all_refs = sorted(row["id"] for row in obs_rows)
        leaf_refs = sorted(path_child_of.get(object_id, set()) & set(all_refs))
        # Sole path identifier (no PATH_CONTEXT involving it) still counts as leaf-like when path-located.
        if not leaf_refs and not path_parent_of.get(object_id):
            path_only = [
                row["id"]
                for row in obs_rows
                if any(f["object_ref"] == object_id and f["location"] == "path" for f in row["references"])
            ]
            leaf_refs = path_only
        parent_refs = sorted(path_parent_of.get(object_id, set()) & set(all_refs))
        co_refs = sorted(co_of.get(object_id, set()) & set(all_refs))
        path_ctx_refs = sorted(
            (path_parent_of.get(object_id, set()) | path_child_of.get(object_id, set())) & set(all_refs)
        )

        # Cross-session kind peers: other object_refs sharing a kind_ref in a different session.
        peer_sessions = 0
        peer_objects: set[str] = set()
        # Conflicting kinds are AMBIGUOUS: no kind-based peer signal is derived from them.
        for kind in kind_refs if len(kind_refs) == 1 else ():
            for session, objs in kind_sessions.get(kind, {}).items():
                others = objs - {object_id}
                if others:
                    peer_objects.update(others)
                    peer_sessions += 1
        peer_refs = all_refs if peer_objects and peer_sessions >= 1 and sessions else []

        is_path_parent = bool(parent_refs)
        is_leaf = bool(leaf_refs) and not is_path_parent
        multi_session_leaf_refs = all_refs if len(sessions) > 1 and is_leaf else []
        multi_endpoint_refs = all_refs if len(endpoints) > 1 else []

        positive_evidence = [
            request_refs,
            response_refs if request_refs else [],
            typed_refs,
            leaf_refs if is_leaf else [],
            peer_refs,
            multi_session_leaf_refs,
            multi_endpoint_refs,
            co_refs,
            path_ctx_refs,
        ]
        breakdown: list[dict[str, Any]] = [
            {"rule": rule, "points": points, "polarity": "positive", "observation_refs": sorted(refs)}
            for (rule, points), refs in zip(POSITIVE_RULES, positive_evidence)
            if refs
        ]

        # Demotions — never discard; only lower priority for human review.
        shared_parent_refs = all_refs if is_path_parent and len(sessions) > 1 else []
        unauth_refs = all_refs if not sessions else []
        response_only_refs = (
            sorted(set(response_refs) - set(request_refs)) if not request_refs and response_refs else []
        )
        negative_evidence = [shared_parent_refs, unauth_refs, response_only_refs]
        for (rule, points), refs in zip(NEGATIVE_RULES, negative_evidence):
            if refs:
                breakdown.append(
                    {"rule": rule, "points": points, "polarity": "negative", "observation_refs": sorted(refs)}
                )

        raw = sum(part["points"] for part in breakdown)
        score = max(0, min(100, raw))

        uncertainty: list[str] = []
        if not request_refs:
            uncertainty.append("no_request_side_reference")
        if not kind_refs:
            uncertainty.append("insufficient_kind_evidence")
        elif len(kind_refs) > 1:
            uncertainty.append("ambiguous_kind_evidence")
        if is_path_parent and len(sessions) > 1:
            uncertainty.append("shared_parent_likely_requires_human_review")
        if not sessions:
            uncertainty.append("unauthenticated_or_missing_session_context")
        if response_only_refs:
            uncertainty.append("response_only_appearance")
        if not breakdown:
            uncertainty.append("insufficient_structural_evidence")

        order_reason_parts = [f"{part['rule']}({part['points']:+d})" for part in breakdown]
        order_reason = "; ".join(order_reason_parts) if order_reason_parts else "insufficient_evidence"
        if uncertainty:
            order_reason += " | uncertainty=" + ",".join(uncertainty)

        if score >= min_score:
            rows.append(
                {
                    "object_ref": object_id,
                    "resource_type": node["resource_type"],
                    # resource-kind-lineage-v1: stable (keyed) kind id + status + provenance. Never ownership.
                    "resource_kind": next(iter(kind_refs)) if len(kind_refs) == 1 else None,
                    "kind_lineage": kind_lineage(
                        kind_refs, kind_bases, kind_obs, sorted({ep_origin.get(e) or "" for e in endpoints} - {""})
                    ),
                    "score": score,
                    "score_breakdown": breakdown,
                    "score_raw": raw,
                    "order_reason": order_reason,
                    "uncertainty": uncertainty,
                    "endpoint_refs": endpoints,
                    "session_context_count": len(sessions),
                    "observation_refs": all_refs,
                    "ownership": "unknown",
                    "privacy": "unknown",
                    "confirmed": False,
                    "case_executable": False,
                    "researcher_review_required": True,
                    "evidence_class": "observation",
                }
            )
    rows.sort(key=lambda row: (-row["score"], row["object_ref"]))
    return {
        "schema_version": SCHEMA_VERSION,
        "type": "api-object-investigation-candidates",
        "program": program,
        "key_id": graph["key_id"],
        "graph_integrity": graph["integrity"],
        "ranking_version": RANKING_VERSION,
        "total_candidates": len(rows),
        "candidates": rows[:limit],
        "network_requests_sent": 0,
        "vulnerabilities_confirmed": 0,
        "limitation": LIMITATION,
        "next_step": "Review provenance and ownership locally, then use import discover-idor and explicit approve-idor separately.",
    }


def save_object_json(path: Path, document: dict[str, Any], *, force: bool = False) -> None:
    data = _canonical(document) + b"\n"
    if len(data) > MAX_GRAPH_INPUT_BYTES:
        raise ValueError("Offline object artifact exceeds the export byte limit.")
    atomic_private_write(path, data, force=force)


def discover_to_file(
    program: str,
    inputs: list[Path],
    key_path: Path,
    output: Path,
    *,
    authorized: bool,
    dry_run: bool = False,
    force: bool = False,
    base_url: str | None = None,
    strict: bool = False,
    allow_truncate: bool = False,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """CLI orchestration: ephemeral key for a first dry-run; publish only after validation."""
    key_path, output = local_path(key_path), local_path(output)
    if output == key_path or any(local_path(path) in {key_path, output} for path in inputs):
        raise ValueError("Keep outputs, captures and the HMAC key in separate files.")
    if output.exists() and not force and not dry_run:
        raise ValueError("Offline output already exists; select a new path or explicitly replace it.")
    key_exists = key_path.exists()
    key = load_object_key(key_path) if key_exists else secrets.token_bytes(32)
    graph = build_object_graph(
        program, inputs, key, authorized=authorized, base_url=base_url, strict=strict, allow_truncate=allow_truncate
    )
    candidates = object_candidates(graph, program, key)
    if not dry_run:
        if not key_exists:
            atomic_private_write(key_path, key)
        save_object_json(output, graph, force=force)
    return graph, candidates


def indexed_capture_sources(
    program: str,
    inputs: list[Path],
    key: bytes,
    *,
    base_url: str | None = None,
    strict: bool = False,
    allow_truncate: bool = False,
) -> dict[tuple[str, str], Any]:
    """Map (source_ref, locator) to CaptureSource for offline handoff. Read-only; no network."""
    ProgramPaths(Path("."), program)
    if len(key) != 32 or not 1 <= len(inputs) <= MAX_FILES:
        raise ValueError("Use a 32-byte key and between one and sixteen capture files.")
    try:
        index: dict[tuple[str, str], Any] = {}
        total_bytes = 0
        capture_count = 0
        for path in inputs:
            data, captures, _ = _read_sources(path, base_url, strict, allow_truncate)
            total_bytes += len(data)
            if total_bytes > MAX_TOTAL_BYTES:
                raise ValueError("Capture set exceeds total byte limit.")
            source_id = _ref(key, "source", program, data.hex())
            for capture in captures:
                capture_count += 1
                if capture_count > MAX_CAPTURES:
                    raise ValueError("Capture set exceeds observation limit.")
                index[(source_id, capture.locator)] = capture
        return index
    except (ValueError, UnicodeError, TypeError, KeyError, OverflowError, RecursionError) as exc:
        raise ValueError(_safe_failure(exc)) from exc
