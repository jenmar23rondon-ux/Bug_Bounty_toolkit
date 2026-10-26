"""Offline object-candidate → capture-pair handoff and efficacy lab.

Transforms ranked object-relationship candidates into reproducible owner/actor
capture-pair PROPOSALS for human review. Never writes access-check cases, never
sends HTTP, never approves, and never bypasses discover-idor / approve-idor gates.
"""

from __future__ import annotations

import hashlib
import json
import time
from collections import defaultdict
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from ..core.private_files import atomic_private_write, local_path
from ..core.records import ProgramPaths
from .evidence_engine import CaptureSource
from .object_relationships import (
    MAX_CAPTURES,
    MAX_FILES,
    SCHEMA_VERSION,
    indexed_capture_sources,
    load_object_key,
    object_candidates,
    read_object_graph,
    save_object_json,
    validate_object_graph,
    verify_object_sources,
    build_object_graph,
)

HANDOFF_VERSION = "1.0"
LAB_CORPUS_VERSION = "1.0"
MAX_PROPOSALS = 64
MAX_MATERIALIZE_BYTES = 1_000_000
REQUEST_LOCATIONS = frozenset({"path", "query", "request_json"})
KNOWN_COLLECTIONS = frozenset(
    {
        "user",
        "order",
        "invoice",
        "item",
        "account",
        "address",
        "basket",
        "cart",
        "document",
        "file",
        "record",
        "resource",
        "customer",
        "project",
        "organization",
        "team",
        "tenant",
        "product",
        "wishlist",
    }
)
LIMITATION = (
    "Handoff proposals are offline capture-pair suggestions only. They do not establish "
    "ownership, privacy, unauthorized access, or a vulnerability. Human review and the "
    "existing approve-idor attestations remain mandatory before any A/B validation."
)
HUMAN_GATE = (
    "Gate: review each proposal, export/confirm the owner and actor captures, run "
    "`import discover-idor`, complete all approve-idor attestations, then `approve-idor --approve`. "
    "object-handoff never writes case JSON, never calls access-check, and never auto-approves."
)

# Label categories used only by the synthetic efficacy lab.
POSITIVE_LABELS = frozenset({"vulnerable", "cross-tenant", "nested-json", "query"})
NEGATIVE_RANK_LABELS = frozenset({"public", "session-only", "single-session", "ambiguous"})
# Protected may yield a structural proposal but must never be confirmed.
PROTECTED_LABELS = frozenset({"protected"})


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode()


def _proposal_id(program: str, endpoint: str, owner_obj: str, actor_obj: str) -> str:
    digest = hashlib.sha256(_canonical([program, endpoint, owner_obj, actor_obj])).hexdigest()[:16]
    return "handoff-" + digest


def capture_to_raw_http(source: CaptureSource) -> tuple[bytes, bytes | None]:
    """Render a CaptureSource as raw HTTP request bytes and optional response bytes."""
    if not source.url or not source.method:
        raise ValueError("Capture is missing URL or method.")
    parsed = urlsplit(source.url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("Capture URL must be an HTTP(S) origin.")
    target = parsed.path or "/"
    if parsed.query:
        target = target + "?" + parsed.query
    header_items = [(str(name), str(value)) for name, value in (source.request_headers or {}).items()]
    if not any(name.lower() == "host" for name, _ in header_items):
        host = parsed.hostname
        if parsed.port:
            host = f"{host}:{parsed.port}"
        header_items.insert(0, ("Host", host))
    lines = [f"{source.method} {target} HTTP/1.1"]
    lines.extend(f"{name}: {value}" for name, value in header_items)
    request = ("\r\n".join(lines) + "\r\n\r\n" + (source.request_body or "")).encode("utf-8")
    if len(request) > MAX_MATERIALIZE_BYTES:
        raise ValueError("Materialized request exceeds the capture byte limit.")
    response: bytes | None = None
    if source.response_body or source.status_code is not None:
        status = 200 if source.status_code is None else int(source.status_code)
        resp_headers = [(str(n), str(v)) for n, v in (source.response_headers or {}).items()]
        if not any(n.lower() == "content-type" for n, _ in resp_headers) and source.response_body:
            resp_headers.append(("Content-Type", "application/json"))
        body = source.response_body or ""
        resp_lines = [f"HTTP/1.1 {status} OK"]
        resp_lines.extend(f"{n}: {v}" for n, v in resp_headers)
        response = ("\r\n".join(resp_lines) + "\r\n\r\n" + body).encode("utf-8")
        if len(response) > MAX_MATERIALIZE_BYTES:
            raise ValueError("Materialized response exceeds the capture byte limit.")
    return request, response


def _side_score(locations: set[str], typed: bool, resource_type: str) -> int:
    """Explainable handoff priority points for one capture side (not severity)."""
    score = 0
    if locations & REQUEST_LOCATIONS:
        score += 20
    # Path identifiers are the most common IDOR review starting point.
    if "path" in locations:
        score += 18
    elif "query" in locations:
        score += 14
    elif "request_json" in locations:
        score += 12
    if "response_json" in locations and locations & REQUEST_LOCATIONS:
        score += 10
    if typed:
        score += 8
    if resource_type in KNOWN_COLLECTIONS:
        score += 6
    return score


def _observation_object_sides(
    graph: dict[str, Any],
) -> dict[str, list[dict[str, Any]]]:
    """Group per-endpoint sides: one entry per (observation, object_ref) with request preference."""
    nodes = {node["id"]: node for node in graph["nodes"]}
    by_endpoint: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for observation in graph["observations"]:
        session = observation.get("session_ref")
        provenance = observation.get("provenance") or []
        if not session or not provenance:
            continue
        endpoint = observation["endpoint_ref"]
        # Aggregate locations per object within this observation.
        per_object: dict[str, dict[str, Any]] = {}
        for fact in observation.get("references") or []:
            object_ref = fact.get("object_ref")
            if not isinstance(object_ref, str):
                continue
            node = nodes.get(object_ref)
            if not node or node.get("type") != "Object":
                continue
            bucket = per_object.setdefault(
                object_ref,
                {
                    "object_ref": object_ref,
                    "resource_type": node.get("resource_type") or "unknown",
                    "locations": set(),
                    "typed": False,
                },
            )
            location = fact.get("location")
            if isinstance(location, str):
                bucket["locations"].add(location)
            if fact.get("typed"):
                bucket["typed"] = True
        for bucket in per_object.values():
            # Prefer request-side evidence for IDOR pair construction.
            if not (bucket["locations"] & REQUEST_LOCATIONS):
                continue
            for prov in provenance:
                if not isinstance(prov, dict):
                    continue
                source_ref = prov.get("source_ref")
                locator = prov.get("locator")
                if not isinstance(source_ref, str) or not isinstance(locator, str):
                    continue
                by_endpoint[endpoint].append(
                    {
                        "object_ref": bucket["object_ref"],
                        "resource_type": bucket["resource_type"],
                        "locations": set(bucket["locations"]),
                        "typed": bool(bucket["typed"]),
                        "session_ref": session,
                        "observation_ref": observation["id"],
                        "source_ref": source_ref,
                        "locator": locator,
                        "endpoint_ref": endpoint,
                    }
                )
    return by_endpoint


def _build_proposals(
    graph: dict[str, Any],
    program: str,
    *,
    candidate: str | None,
    limit: int,
) -> list[dict[str, Any]]:
    by_endpoint = _observation_object_sides(graph)
    path_linked: set[str] = set()
    for relation in graph.get("relations") or []:
        if relation.get("relation") == "PATH_CONTEXT":
            path_linked.add(relation.get("source", ""))
            path_linked.add(relation.get("target", ""))

    raw: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()
    for endpoint, sides in by_endpoint.items():
        # Group by resource_type then form cross-session, cross-object pairs.
        by_type: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for side in sides:
            by_type[side["resource_type"]].append(side)
        for resource_type, typed_sides in by_type.items():
            sessions = {side["session_ref"] for side in typed_sides}
            if len(sessions) < 2:
                continue
            # Deterministic order for pair enumeration.
            ordered = sorted(
                typed_sides,
                key=lambda row: (row["session_ref"], row["object_ref"], row["locator"], row["source_ref"]),
            )
            for index, owner in enumerate(ordered):
                for actor in ordered[index + 1 :]:
                    if owner["session_ref"] == actor["session_ref"]:
                        continue
                    if owner["object_ref"] == actor["object_ref"]:
                        continue
                    if candidate and candidate not in {owner["object_ref"], actor["object_ref"]}:
                        continue
                    left, right = sorted(
                        (owner, actor),
                        key=lambda row: (row["object_ref"], row["session_ref"], row["locator"]),
                    )
                    dedupe = (endpoint, left["object_ref"], right["object_ref"])
                    if dedupe in seen:
                        continue
                    seen.add(dedupe)
                    score = _side_score(left["locations"], left["typed"], resource_type) + _side_score(
                        right["locations"], right["typed"], resource_type
                    )
                    # Nested path context is an investigation hint, not ownership; small bonus only.
                    if left["object_ref"] in path_linked or right["object_ref"] in path_linked:
                        score += 2
                    # Soft cap keeps scores readable without fully flattening ties.
                    score = min(score, 120)
                    raw.append(
                        {
                            "id": _proposal_id(program, endpoint, left["object_ref"], right["object_ref"]),
                            "endpoint_ref": endpoint,
                            "resource_type": resource_type,
                            "score": score,
                            "owner": {
                                "object_ref": left["object_ref"],
                                "session_ref": left["session_ref"],
                                "observation_ref": left["observation_ref"],
                                "source_ref": left["source_ref"],
                                "locator": left["locator"],
                                "locations": sorted(left["locations"]),
                            },
                            "actor": {
                                "object_ref": right["object_ref"],
                                "session_ref": right["session_ref"],
                                "observation_ref": right["observation_ref"],
                                "source_ref": right["source_ref"],
                                "locator": right["locator"],
                                "locations": sorted(right["locations"]),
                            },
                            "confirmed": False,
                            "case_executable": False,
                            "researcher_review_required": True,
                            "human_gate": HUMAN_GATE,
                            "insufficient_evidence": False,
                        }
                    )

    # Diversified deterministic ranking: prefer higher score, then rotate resource types.
    def _sort_key(row: dict[str, Any]) -> tuple[int, int, str, str]:
        owner_locs = set(row["owner"]["locations"])
        # Prefer direct path/query object IDs over nested user companions when scores tie.
        direct = 0 if (("path" in owner_locs or "query" in owner_locs) and row["resource_type"] != "user") else 1
        return (-row["score"], direct, row["resource_type"], row["id"])

    raw.sort(key=_sort_key)
    selected: list[dict[str, Any]] = []
    seen_types: set[str] = set()
    deferred: list[dict[str, Any]] = []
    for row in raw:
        if row["resource_type"] not in seen_types:
            selected.append(row)
            seen_types.add(row["resource_type"])
        else:
            deferred.append(row)
        if len(selected) >= limit:
            break
    if len(selected) < limit:
        for row in deferred:
            selected.append(row)
            if len(selected) >= limit:
                break
    return selected[:limit]


def _suggested_command(
    program: str,
    owner_path: str,
    actor_path: str,
    *,
    owner_response: str | None = None,
    actor_response: str | None = None,
    base_url: str | None = None,
) -> str:
    parts = [
        "bbtk",
        "import",
        "discover-idor",
        program,
        "--owner",
        owner_path,
        "--actor",
        actor_path,
    ]
    if owner_response:
        parts.extend(["--owner-response", owner_response])
    if actor_response:
        parts.extend(["--actor-response", actor_response])
    if base_url:
        parts.extend(["--base-url", base_url])
    parts.append("--attest-authorized-accounts")
    parts.append("--dry-run")
    return " ".join(parts)


def _materialize_pair(
    directory: Path,
    proposal: dict[str, Any],
    index: dict[tuple[str, str], CaptureSource],
    *,
    force: bool,
) -> dict[str, str]:
    """Write private raw HTTP snapshots for one proposal. Never logs bodies or headers."""
    directory = local_path(directory)
    paths: dict[str, str] = {}
    for role in ("owner", "actor"):
        side = proposal[role]
        key = (side["source_ref"], side["locator"])
        if key not in index:
            raise ValueError("Proposal locator does not match the verified capture inputs.")
        request, response = capture_to_raw_http(index[key])
        req_path = directory / f"{proposal['id']}-{role}.http"
        atomic_private_write(req_path, request, force=force)
        paths[f"{role}_path"] = str(req_path)
        if response is not None:
            resp_path = directory / f"{proposal['id']}-{role}-response.http"
            atomic_private_write(resp_path, response, force=force)
            paths[f"{role}_response_path"] = str(resp_path)
    return paths


def propose_object_handoff(
    graph: dict[str, Any],
    program: str,
    key: bytes,
    *,
    candidate: str | None = None,
    verify_inputs: list[Path] | None = None,
    base_url: str | None = None,
    limit: int = 20,
    materialize_dir: Path | None = None,
    force: bool = False,
) -> dict[str, Any]:
    """Build offline capture-pair proposals. network_requests_sent is always 0."""
    ProgramPaths(Path("."), program)
    validate_object_graph(graph, program, key)
    if not 1 <= limit <= MAX_PROPOSALS:
        raise ValueError(f"Proposal limit must be 1-{MAX_PROPOSALS}.")
    if candidate is not None and not isinstance(candidate, str):
        raise ValueError("Candidate must be an object_ref string when provided.")
    inputs = list(verify_inputs or [])
    if inputs:
        if not 1 <= len(inputs) <= MAX_FILES:
            raise ValueError("Select between one and sixteen source files to verify.")
        verify_object_sources(graph, inputs, key)
    index: dict[tuple[str, str], CaptureSource] | None = None
    if materialize_dir is not None:
        if not inputs:
            raise ValueError("Materializing capture pairs requires --verify-input for every graph source.")
        index = indexed_capture_sources(program, inputs, key, base_url=base_url)

    # Explicit insufficient-evidence path when a candidate cannot form a pair.
    proposals = _build_proposals(graph, program, candidate=candidate, limit=limit)
    status = "proposals_ready"
    notes: list[str] = []
    if candidate and not proposals:
        status = "insufficient_evidence"
        notes.append(
            "The selected candidate lacks two distinct session contexts with different "
            "request-side object values on a shared endpoint template."
        )

    materialized = 0
    for proposal in proposals:
        owner_hint = f"<export {proposal['owner']['locator']} from verified capture>"
        actor_hint = f"<export {proposal['actor']['locator']} from verified capture>"
        owner_resp = None
        actor_resp = None
        if index is not None and materialize_dir is not None:
            paths = _materialize_pair(materialize_dir, proposal, index, force=force)
            owner_hint = paths["owner_path"]
            actor_hint = paths["actor_path"]
            owner_resp = paths.get("owner_response_path")
            actor_resp = paths.get("actor_response_path")
            materialized += 1
        proposal["suggested_discover_idor"] = _suggested_command(
            program,
            owner_hint,
            actor_hint,
            owner_response=owner_resp,
            actor_response=actor_resp,
            base_url=base_url,
        )
        # Redacted endpoint hint from graph nodes (path_template only; no host/IDs).
        endpoint_node = next((n for n in graph["nodes"] if n["id"] == proposal["endpoint_ref"]), None)
        proposal["endpoint_hint"] = {
            "method": endpoint_node.get("method") if endpoint_node else None,
            "path_template": endpoint_node.get("path_template") if endpoint_node else None,
        }

    document: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "type": "api-object-handoff-proposals",
        "handoff_version": HANDOFF_VERSION,
        "program": program,
        "key_id": graph["key_id"],
        "graph_integrity": graph["integrity"],
        "status": status,
        "notes": notes,
        "candidate_filter": candidate,
        "total_proposals": len(proposals),
        "proposals": proposals,
        "materialized_pairs": materialized,
        "network_requests_sent": 0,
        "vulnerabilities_confirmed": 0,
        "confirmed": False,
        "limitation": LIMITATION,
        "human_gate": HUMAN_GATE,
        "next_step": (
            "Review proposals and provenance locally. Run the suggested discover-idor command, "
            "complete approve-idor attestations, then approve-idor --approve. Never skip the gate."
        ),
    }
    return document


def handoff_to_file(
    program: str,
    graph_path: Path,
    key_path: Path,
    *,
    candidate: str | None = None,
    verify_inputs: list[Path] | None = None,
    output: Path | None = None,
    materialize_dir: Path | None = None,
    dry_run: bool = False,
    force: bool = False,
    base_url: str | None = None,
    limit: int = 20,
) -> dict[str, Any]:
    """CLI orchestration for object-handoff."""
    key_path = local_path(key_path)
    graph_path = local_path(graph_path)
    key = load_object_key(key_path)
    graph = read_object_graph(graph_path, program, key)
    write_materialize = None if dry_run else materialize_dir
    document = propose_object_handoff(
        graph,
        program,
        key,
        candidate=candidate,
        verify_inputs=verify_inputs,
        base_url=base_url,
        limit=limit,
        materialize_dir=write_materialize,
        force=force,
    )
    if dry_run:
        document = dict(document)
        document["dry_run"] = True
        return document
    if output is not None:
        output = local_path(output)
        if output in {key_path, graph_path} or (
            verify_inputs and any(local_path(path) == output for path in verify_inputs)
        ):
            raise ValueError("Handoff output must not replace the graph, key or source captures.")
        if materialize_dir is not None and local_path(materialize_dir) == output:
            raise ValueError("Handoff JSON output must be distinct from the materialize directory.")
        save_object_json(output, document, force=force)
    return document


def _load_lab_labels(path: Path) -> dict[str, Any]:
    raw = path.read_text(encoding="utf-8")
    if len(raw.encode("utf-8")) > 1_000_000:
        raise ValueError("Lab labels file exceeds size limit.")
    document = json.loads(raw)
    if not isinstance(document, dict) or document.get("corpus_version") != LAB_CORPUS_VERSION:
        raise ValueError("Unsupported lab corpus version.")
    labels = document.get("labels")
    if not isinstance(labels, list) or not labels or len(labels) > MAX_CAPTURES:
        raise ValueError("Lab labels must be a bounded nonempty list.")
    return document


def _enrich_labels(labels: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Attach resource_type for matching without mutating fixtures on disk semantics."""
    mapping = {
        "vuln-order": ("order", "vulnerable"),
        "protected-document": ("document", "protected"),
        "cross-tenant": ("organization", "cross-tenant"),
        "nested-json": ("account", "nested-json"),
        "query-id": ("invoice", "query"),
        "public": ("product", "public"),
        "single-session": ("cart", "single-session"),
        "ambiguous": ("unknown", "ambiguous"),
        "session-only": ("wishlist", "session-only"),
    }
    enriched = []
    for row in labels:
        item = dict(row)
        scenario = str(item.get("scenario") or "")
        if scenario in mapping:
            item.setdefault("resource_type", mapping[scenario][0])
            item.setdefault("category", mapping[scenario][1])
        enriched.append(item)
    return enriched


def _precision_at_k(ranked_types: list[str], positive_types: set[str], k: int) -> float:
    top = ranked_types[:k]
    if not top:
        return 0.0
    hits = sum(1 for resource in top if resource in positive_types)
    return hits / len(top)


def _primary_queue(
    proposals: list[dict[str, Any]],
    enriched: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Best proposal per labeled resource_type (investigation queue for lab metrics)."""
    labeled_types = {
        str(row["resource_type"])
        for row in enriched
        if row.get("resource_type") not in {None, "unknown"}
        and (
            row.get("category") in POSITIVE_LABELS
            or row.get("category") in PROTECTED_LABELS
            or row.get("expected_handoff") is True
        )
    }
    protected_types = {str(row["resource_type"]) for row in enriched if row.get("category") in PROTECTED_LABELS}
    best: dict[str, dict[str, Any]] = {}
    for row in proposals:
        resource = str(row["resource_type"])
        if resource not in labeled_types:
            continue
        prior = best.get(resource)
        if prior is None or (row["score"], row["id"]) > (prior["score"], prior["id"]):
            best[resource] = row
    # On score ties, keep protected resources after positive investigation targets.
    return sorted(
        best.values(),
        key=lambda row: (
            -row["score"],
            1 if row["resource_type"] in protected_types else 0,
            row["resource_type"],
            row["id"],
        ),
    )


def _compute_metrics(
    proposals: list[dict[str, Any]],
    baseline_types: list[str],
    labels: list[dict[str, Any]],
    *,
    elapsed_ms: float,
) -> dict[str, Any]:
    enriched = _enrich_labels(labels)
    positive_types = {
        str(row["resource_type"])
        for row in enriched
        if row.get("category") in POSITIVE_LABELS and row.get("resource_type") not in {None, "unknown"}
    }
    protected_types = {str(row["resource_type"]) for row in enriched if row.get("category") in PROTECTED_LABELS}
    negative_types = {
        str(row["resource_type"])
        for row in enriched
        if row.get("category") in NEGATIVE_RANK_LABELS and row.get("resource_type") not in {None, "unknown"}
    }
    queue = _primary_queue(proposals, enriched)
    ranked_types = [str(row["resource_type"]) for row in queue]
    proposed_types = {str(row["resource_type"]) for row in proposals}

    true_positives = sorted(positive_types & proposed_types)
    false_negatives = sorted(positive_types - proposed_types)
    # FP: proposals whose type only matches a negative-rank label (not also positive).
    false_positives = sorted((proposed_types & negative_types) - positive_types)

    recall = (len(true_positives) / len(positive_types)) if positive_types else 0.0
    per_relation: dict[str, dict[str, Any]] = {}
    for row in enriched:
        category = str(row.get("category") or "unknown")
        resource = str(row.get("resource_type") or "unknown")
        bucket = per_relation.setdefault(
            category,
            {"resource_type": resource, "proposed": False, "label_count": 0},
        )
        bucket["label_count"] += 1
        if resource in proposed_types:
            bucket["proposed"] = True

    vulnerable_ranks = [index + 1 for index, resource in enumerate(ranked_types) if resource == "order"]
    # Baseline: unique candidate resource types in object_candidates order, restricted to labeled types.
    labeled_for_baseline = positive_types | protected_types
    baseline_queue = [resource for resource in baseline_types if resource in labeled_for_baseline]
    baseline_vulnerable = [index + 1 for index, resource in enumerate(baseline_queue) if resource == "order"]

    confirmed = [row for row in proposals if row.get("confirmed")]
    return {
        "precision_at_1": round(_precision_at_k(ranked_types, positive_types, 1), 4),
        "precision_at_3": round(_precision_at_k(ranked_types, positive_types, 3), 4),
        "precision_at_5": round(_precision_at_k(ranked_types, positive_types, 5), 4),
        "recall": round(recall, 4),
        "true_positives": true_positives,
        "false_positives": false_positives,
        "false_negatives": false_negatives,
        "fp_count": len(false_positives),
        "fn_count": len(false_negatives),
        "per_relation": per_relation,
        "primary_queue_resource_types": ranked_types,
        "vulnerable_in_top3": any(rank <= 3 for rank in vulnerable_ranks),
        "vulnerable_ranks": vulnerable_ranks,
        "baseline_vulnerable_ranks": baseline_vulnerable,
        "baseline_precision_at_3": round(_precision_at_k(baseline_queue, positive_types, 3), 4),
        "baseline_raw_top5_types": baseline_types[:5],
        "handoff_top5_types": [str(row["resource_type"]) for row in proposals[:5]],
        "baseline_includes_negative_top5": any(resource in negative_types for resource in baseline_types[:5]),
        "handoff_includes_negative": bool(false_positives),
        "protected_types_seen": sorted(protected_types & proposed_types),
        "confirmed_findings": len(confirmed),
        "processing_ms": round(elapsed_ms, 3),
        "disclaimer": (
            "Synthetic lab metrics measure candidate-pair ranking efficacy only. "
            "They do not claim real bug-bounty vulnerability confirmation performance. "
            "Precision@k uses the primary queue (best proposal per labeled resource_type)."
        ),
    }


def run_object_discovery_lab(
    corpus_root: Path,
    *,
    split: str = "eval",
    limit: int = 10,
    dry_run: bool = False,
) -> dict[str, Any]:
    """Reproducible offline efficacy lab over the versioned synthetic corpus."""
    if split not in {"dev", "eval", "all"}:
        raise ValueError("Lab split must be dev, eval or all.")
    root = Path(corpus_root)
    splits = ["dev", "eval"] if split == "all" else [split]
    started = time.perf_counter()
    reports: list[dict[str, Any]] = []
    for name in splits:
        folder = root / name
        captures = folder / "captures.har"
        labels_path = folder / "labels.json"
        if not captures.is_file() or not labels_path.is_file():
            raise ValueError(f"Lab split '{name}' is missing captures.har or labels.json.")
        label_doc = _load_lab_labels(labels_path)
        labels = label_doc["labels"]
        # Ephemeral key: lab results use resource_type matching, not stable HMAC refs across runs.
        key = hashlib.sha256(f"bbtk-object-lab-{name}-{LAB_CORPUS_VERSION}".encode()).digest()
        program = f"object-lab-{name}"
        graph = build_object_graph(program, [captures], key, authorized=True)
        candidates = object_candidates(graph, program, key, limit=100)
        # Baseline: resource_type order from existing candidate ranking (pre-handoff).
        baseline_types = [str(row["resource_type"]) for row in candidates["candidates"]]
        # Deduplicate baseline types preserving order for @k comparability.
        baseline_unique: list[str] = []
        for resource in baseline_types:
            if resource not in baseline_unique:
                baseline_unique.append(resource)
        handoff = propose_object_handoff(
            graph,
            program,
            key,
            verify_inputs=[captures],
            limit=limit,
        )
        elapsed_ms = (time.perf_counter() - started) * 1000.0
        metrics = _compute_metrics(
            handoff["proposals"],
            baseline_unique,
            labels if isinstance(labels, list) else [],
            elapsed_ms=elapsed_ms,
        )
        reports.append(
            {
                "split": name,
                "corpus_version": label_doc.get("corpus_version"),
                "observations": graph["summary"]["observations"],
                "baseline_candidates": candidates["total_candidates"],
                "handoff_proposals": handoff["total_proposals"],
                "metrics": metrics,
                "network_requests_sent": 0,
                "vulnerabilities_confirmed": 0,
                "confirmed": False,
            }
        )
        if dry_run:
            # Dry-run still computes metrics in memory; no files written by this function.
            pass
    primary = next(row for row in reports if row["split"] == (split if split != "all" else "eval"))
    return {
        "schema_version": SCHEMA_VERSION,
        "type": "api-object-discovery-efficacy-lab",
        "handoff_version": HANDOFF_VERSION,
        "corpus_version": LAB_CORPUS_VERSION,
        "split": split,
        "dry_run": dry_run,
        "reports": reports,
        "primary": primary,
        "network_requests_sent": 0,
        "vulnerabilities_confirmed": 0,
        "confirmed": False,
        "limitation": LIMITATION,
        "human_gate": HUMAN_GATE,
        "disclaimer": primary["metrics"]["disclaimer"],
    }


def default_lab_root() -> Path:
    return Path(__file__).resolve().parents[2] / "labs" / "object_discovery_lab"
