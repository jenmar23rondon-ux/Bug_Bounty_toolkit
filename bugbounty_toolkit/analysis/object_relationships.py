"""Offline object-reference correlation, never an authorization or vulnerability oracle."""

from __future__ import annotations

import base64
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
from .evidence_engine import CaptureSource, har_capture_sources, resource_path_segments
from .evidence_graph import MAX_GRAPH_EDGES, MAX_GRAPH_INPUT_BYTES, MAX_GRAPH_NODES

SCHEMA_VERSION = "1.0"
RANKING_VERSION = "1.0"
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
RULES = (
    ("request_reference", 20),
    ("also_in_response", 15),
    ("multiple_endpoints", 15),
    ("multiple_session_contexts", 20),
    ("typed_foreign_key", 10),
    ("json_co_occurrence", 10),
    ("nested_path_context", 10),
)
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


def _read_sources(path: Path, base_url: str | None) -> tuple[bytes, list[CaptureSource]]:
    data = read_private_input(path, MAX_ITEM_BYTES)
    if data.lstrip().startswith(b"{"):
        document = parse_json(data.decode("utf-8"))
        log = document.get("log") if isinstance(document, dict) else None
        entries = log.get("entries") if isinstance(log, dict) else None
        if not isinstance(entries, list) or not entries or len(entries) > MAX_EXCHANGES:
            raise ValueError("Select a nonempty bounded HAR export, Burp XML or raw HTTP capture.")
        for entry in entries:
            if not isinstance(entry, dict):
                raise ValueError("Malformed HAR entry.")
            request, response = entry.get("request"), entry.get("response")
            if not isinstance(request, dict) or not isinstance(response, dict):
                raise ValueError("HAR entries must contain request and response objects.")
            post = request.get("postData", {})
            if not isinstance(post, dict) or not isinstance(post.get("text", ""), str):
                raise ValueError("Malformed HAR request body.")
            content = response.get("content", {})
            if not isinstance(content, dict) or not isinstance(content.get("text", ""), str):
                raise ValueError("Malformed HAR response content.")
            if content.get("encoding") not in (None, "base64"):
                raise ValueError("Unsupported HAR content encoding.")
            if content.get("encoding") == "base64":
                base64.b64decode(content.get("text", ""), validate=True).decode("utf-8")
        sources = har_capture_sources(document, MAX_EXCHANGES)
        if len(sources) != len(entries):
            raise ValueError("Incomplete HAR capture.")
    else:
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
    return data, sources


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
            occurrences.append(_Occurrence(kind, segment, "path", f"/path/{index}", "/path"))
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
            occurrences.append(
                _Occurrence(field[0], value, "query", f"/query/{_safe_name(name, key)}/{index}", "/query", field[1])
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
                occurrences.append(_Occurrence(field[0], str(value), location, safe, container, field[1]))
    occurrences = [
        o
        for o in occurrences
        if o.value and len(o.value) <= 256 and o.value not in credentials and not JWT_TOKEN.search(o.value)
    ]
    if len(occurrences) > MAX_OCCURRENCES:
        raise ValueError("Capture exceeds the per-message object-reference limit.")
    return template, occurrences


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
) -> dict[str, Any]:
    """Read captures only. No DB, network, model calls, output files or executable cases."""
    ProgramPaths(Path("."), program)
    if not authorized:
        raise ValueError("Declare authorization to analyze these local captures; this does not authorize active tests.")
    if len(key) != 32 or not 1 <= len(inputs) <= MAX_FILES:
        raise ValueError("Use a 32-byte key and between one and sixteen capture files.")
    try:
        return _build(program, inputs, key, base_url)
    except (ValueError, UnicodeError, TypeError, KeyError, OverflowError, RecursionError) as exc:
        # Parser exceptions can contain raw input. Never propagate their text to the CLI.
        raise ValueError(
            "Offline captures are invalid, incomplete or exceed discovery limits; inspect locally."
        ) from exc


def _build(program: str, inputs: list[Path], key: bytes, base_url: str | None) -> dict[str, Any]:
    loaded: list[tuple[str, CaptureSource]] = []
    sources: dict[str, dict[str, Any]] = {}
    total_bytes = 0
    for path in inputs:
        data, captures = _read_sources(path, base_url)
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
        template, occurrences = _extract(capture, key, origin, credentials)
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
            object_id = _ref(key, "object", program, origin, occurrence.kind, occurrence.value)
            type_hint = occurrence.kind if occurrence.kind in set(COLLECTIONS.values()) else "unknown"
            nodes[object_id] = {
                "id": object_id,
                "type": "Object",
                "resource_type": type_hint,
                "type_basis": "field_or_collection_name_heuristic",
                "ownership": "unknown",
                "privacy": "unknown",
            }
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


def object_candidates(
    graph: dict[str, Any], program: str, key: bytes, *, limit: int = 100, min_score: int = 0
) -> dict[str, Any]:
    validate_object_graph(graph, program, key)
    if not 1 <= limit <= 100 or not 0 <= min_score <= 100:
        raise ValueError("Candidate limit must be 1-100 and minimum score 0-100.")
    nodes = {node["id"]: node for node in graph["nodes"]}
    rows = []
    for object_id, node in nodes.items():
        if node["type"] != "Object":
            continue
        observations = [
            row for row in graph["observations"] if any(f["object_ref"] == object_id for f in row["references"])
        ]
        request_refs, response_refs, typed_refs = [], [], []
        for row in observations:
            facts = [fact for fact in row["references"] if fact["object_ref"] == object_id]
            if any(f["location"] != "response_json" for f in facts):
                request_refs.append(row["id"])
            if any(f["location"] == "response_json" for f in facts):
                response_refs.append(row["id"])
            if any(f["typed"] for f in facts):
                typed_refs.append(row["id"])
        endpoints = sorted({row["endpoint_ref"] for row in observations})
        sessions = sorted({row["session_ref"] for row in observations if row["session_ref"]})
        co_refs, path_refs = set(), set()
        for relation in graph["relations"]:
            if object_id not in (relation["source"], relation["target"]):
                continue
            if relation["relation"] == "CO_OCCURS":
                co_refs.update(relation["evidence_refs"])
            if relation["relation"] == "PATH_CONTEXT":
                path_refs.update(relation["evidence_refs"])
        all_refs = sorted(row["id"] for row in observations)
        evidence = [
            request_refs,
            response_refs if request_refs else [],
            all_refs if len(endpoints) > 1 else [],
            all_refs if len(sessions) > 1 else [],
            typed_refs,
            sorted(co_refs),
            sorted(path_refs),
        ]
        breakdown: list[dict[str, Any]] = [
            {"rule": rule, "points": points, "observation_refs": sorted(refs)}
            for (rule, points), refs in zip(RULES, evidence)
            if refs
        ]
        score = sum(row["points"] for row in breakdown)
        if score >= min_score:
            rows.append(
                {
                    "object_ref": object_id,
                    "resource_type": node["resource_type"],
                    "score": score,
                    "score_breakdown": breakdown,
                    "endpoint_refs": endpoints,
                    "session_context_count": len(sessions),
                    "observation_refs": all_refs,
                    "ownership": "unknown",
                    "privacy": "unknown",
                    "confirmed": False,
                    "case_executable": False,
                    "researcher_review_required": True,
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
) -> tuple[dict[str, Any], dict[str, Any]]:
    """CLI orchestration: ephemeral key for a first dry-run; publish only after validation."""
    key_path, output = local_path(key_path), local_path(output)
    if output == key_path or any(local_path(path) in {key_path, output} for path in inputs):
        raise ValueError("Keep outputs, captures and the HMAC key in separate files.")
    if output.exists() and not force and not dry_run:
        raise ValueError("Offline output already exists; select a new path or explicitly replace it.")
    key_exists = key_path.exists()
    key = load_object_key(key_path) if key_exists else secrets.token_bytes(32)
    graph = build_object_graph(program, inputs, key, authorized=authorized, base_url=base_url)
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
            data, captures = _read_sources(path, base_url)
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
        raise ValueError(
            "Offline captures are invalid, incomplete or exceed discovery limits; inspect locally."
        ) from exc
