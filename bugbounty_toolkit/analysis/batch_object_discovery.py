"""Read-only campaign consumer. Graphs and rankings remain independent per batch.

Original, hash-verified HAR entries are staged privately in <=32-entry fragments;
the public object builder still enforces every existing parser and graph limit.
No normalized fingerprint is interpreted as an account or object identity.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from pathlib import Path
import re
import tempfile
from typing import Any

from ..burp_import import MAX_EXCHANGES, MAX_ITEM_BYTES
from ..core.private_files import atomic_private_write, read_private_input
from .batch_capture_pipeline import CampaignError, CampaignPlan, HARD_MAX_TOTAL_RECORDS, SCHEMA
from .evidence_engine import MAX_INPUT_BYTES
from .evidence_graph import MAX_GRAPH_EDGES, MAX_GRAPH_INPUT_BYTES, MAX_GRAPH_NODES
from .har_import import load_har_entries
from .har_provenance import path_ref
from .object_relationships import MAX_CAPTURES, MAX_FILES, MAX_TOTAL_BYTES, build_object_graph, object_candidates

RESULT_SCHEMA = "bbtk.batch-object-discovery/1"
LOCATOR = re.compile(r"/log/entries\[(\d+)\]")


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def _seal(value: dict[str, Any], key: bytes) -> str:
    return hmac.new(key, b"batch-object-discovery/1\0" + _canonical(value), hashlib.sha256).hexdigest()


def _read(path: Path) -> tuple[bytes, Any]:
    raw = read_private_input(path, MAX_INPUT_BYTES * 4)
    return raw, json.loads(raw)


def discover_campaign(
    plan: CampaignPlan,
    state_dir: Path,
    key: bytes,
    *,
    authorized: bool,
    max_entries: int,
    previous: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Return a replacement snapshot; never append old results on resume.

    ``previous`` is an optional private snapshot. Only authenticated partitions with
    the same source/bundle/limit binding can be reused. No campaign files are written.
    HAR only: unsupported formats are explicitly pending, never silently reimported.
    A batch beyond an existing object stage limit is refused as a whole.
    """
    if not authorized or len(key) != 32:
        raise CampaignError("object_authorization_or_key_required")
    plan.limits.validate()
    if plan.har_mode not in {"partial", "strict"}:
        raise CampaignError("validated_har_mode_required")
    if type(max_entries) is not int or not 1 <= max_entries <= min(
        plan.limits.max_total_records, HARD_MAX_TOTAL_RECORDS
    ):
        raise CampaignError("object_global_limit_invalid")
    _, state = _read(state_dir / "campaign-state.json")
    if (
        not isinstance(state, dict)
        or any(
            state.get(k) != v
            for k, v in (
                ("schema", SCHEMA),
                ("campaign_id", plan.campaign_id),
                ("manifest_sha256", plan.manifest_sha256),
                ("manifest", plan.manifest()),
            )
        )
        or not isinstance(state.get("batches"), dict)
    ):
        raise CampaignError("object_campaign_mismatch")
    old = {
        p["batch_id"]: p
        for p in (previous or {}).get("partitions", [])
        if isinstance(p, dict) and isinstance(p.get("batch_id"), str)
    }
    partitions: list[dict[str, Any]] = []
    coverage: list[dict[str, Any]] = []
    committed = 0
    reserved = 0
    reused = 0
    graph_nodes = graph_edges = graph_bytes = 0
    graph_limit_reached = False
    for batch in plan.batches:
        outcome = state["batches"].get(batch.batch_id, {})
        row: dict[str, Any] = {
            "batch_id": batch.batch_id,
            "state": "pending",
            "processed": 0,
            "entries_imported": outcome.get("records_parsed"),
        }
        coverage.append(row)
        if outcome.get("state") != "completed":
            row["reason"] = "campaign_batch_not_completed"
            continue
        if outcome.get("output_sha256") is None:
            row.update(state="rejected", reason="no_validated_bundle")
            continue
        if graph_limit_reached:
            row.update(reason="global_graph_limit_reached")
            continue
        try:
            raw, bundle = _read(state_dir / "batches" / f"{batch.batch_id}.json")
            if hashlib.sha256(raw).hexdigest() != outcome["output_sha256"]:
                raise CampaignError("bundle_hash_mismatch")
            count = outcome["records_parsed"]
            if type(count) is not int or not 0 <= count <= plan.limits.max_records_per_batch:
                raise CampaignError("batch_record_limit")
            reserved += count
            if reserved > min(max_entries, plan.limits.max_total_records):
                row.update(state="pending", reason="global_limit_reached")
                continue
            if not isinstance(bundle, dict) or bundle.get("summary", {}).get("records_parsed") != count:
                raise CampaignError("bundle_accounting_mismatch")
            # Read once into bounded memory, then use those immutable bytes throughout.
            inputs: dict[str, bytes] = {}
            source_bytes = 0
            for name in batch.files:
                if outcome.get("files", {}).get(name, {}).get("state") != "imported":
                    continue
                if outcome["files"][name].get("format") != "har":
                    raise CampaignError("unsupported_object_campaign_format")
                source_bytes += plan.file(name).size
                if source_bytes > min(batch.bytes, MAX_TOTAL_BYTES):
                    raise CampaignError("object_source_byte_limit")
                data = read_private_input(plan.root / name, MAX_INPUT_BYTES)
                if hashlib.sha256(data).hexdigest() != plan.file(name).sha256:
                    raise CampaignError("source_hash_mismatch")
                inputs[name] = data
            if sum(map(len, inputs.values())) > min(batch.bytes, MAX_TOTAL_BYTES):
                raise CampaignError("object_source_byte_limit")
            binding = {
                "campaign_id": plan.campaign_id,
                "manifest_sha256": plan.manifest_sha256,
                "batch_id": batch.batch_id,
                "bundle_sha256": outcome["output_sha256"],
                "max_entries": max_entries,
                "schema": RESULT_SCHEMA,
            }
            cached = old.get(batch.batch_id)
            partition = None
            was_reused = False
            if isinstance(cached, dict):
                unsigned = {k: v for k, v in cached.items() if k != "integrity"}
                if cached.get("binding") == binding and hmac.compare_digest(
                    str(cached.get("integrity", "")), _seal(unsigned, key)
                ):
                    partition = cached
                    was_reused = True
            if partition is None:
                partition = _discover_batch(plan, batch.batch_id, inputs, bundle, binding, key)
            if partition["entries_processed"] != count:
                raise CampaignError("bundle_locator_accounting_mismatch")
            nodes = len(partition["graph"]["nodes"])
            edges = len(partition["graph"]["relations"])
            size = len(_canonical(partition))
            if (
                graph_nodes + nodes > MAX_GRAPH_NODES
                or graph_edges + edges > MAX_GRAPH_EDGES
                or graph_bytes + size > MAX_GRAPH_INPUT_BYTES
            ):
                graph_limit_reached = True
                row.update(reason="global_graph_limit_reached")
                continue
            graph_nodes += nodes
            graph_edges += edges
            graph_bytes += size
            partitions.append(partition)
            committed += partition["entries_processed"]
            if was_reused:
                reused += partition["entries_processed"]
            row.update(state="processed", processed=partition["entries_processed"])
        except CampaignError as exc:
            row.update(state="rejected", reason=exc.reason)
        except (ValueError, KeyError, TypeError, IndexError, RecursionError):
            # Never export parser messages, source values, or local paths.
            row.update(state="rejected", reason="validation_or_object_stage_limit")
    omitted = sum(f.state.startswith("omitted") for f in plan.files)
    partial_graphs = any(p["graph"]["capture_import"]["rejected"] for p in partitions)
    complete = all(r["state"] == "processed" for r in coverage) and not omitted and not partial_graphs
    # Importer's rejected entries/files remain visible even for a completed batch.
    rejected_files = sum(
        f.get("state") == "rejected_file" for b in state["batches"].values() for f in b.get("files", {}).values()
    )
    rejected_entries = sum(
        f.get("har", {}).get("entries_rejected", 0)
        for b in state["batches"].values()
        for f in b.get("files", {}).values()
    )
    complete = complete and not rejected_files and not rejected_entries
    file_coverage = []
    processed_locators: dict[str, int] = {}
    for partition in partitions:
        for mapping in partition["provenance"]:
            ref = mapping["file_ref"]
            processed_locators[ref] = processed_locators.get(ref, 0) + 1
    for file in plan.files:
        owner = next((b.batch_id for b in plan.batches if file.relpath in b.files), None)
        ref = path_ref(file.relpath)
        file_coverage.append(
            {
                "file_ref": ref,
                "file_sha256": file.sha256,
                "batch_id": owner,
                "plan_state": file.state,
                "entries_processed": processed_locators.get(ref, 0),
                "import_state": state["batches"]
                .get(owner, {})
                .get("files", {})
                .get(file.relpath, {})
                .get("state", "pending"),
            }
        )
    return {
        "schema": RESULT_SCHEMA,
        "campaign_id": plan.campaign_id,
        "manifest_sha256": plan.manifest_sha256,
        "complete": complete,
        "status": "complete" if complete else "partial",
        "coverage": coverage,
        "files": file_coverage,
        "entries_processed": committed,
        "entries_accepted_at_discovery": sum(p["graph"]["capture_import"]["accepted"] for p in partitions),
        "entries_rejected_at_discovery": sum(p["graph"]["capture_import"]["rejected"] for p in partitions),
        "entries_rejected_at_import": rejected_entries,
        "files_rejected_at_import": rejected_files,
        "files_omitted": omitted,
        "duplicate_files_omitted": sum(f.state == "duplicate_file" for f in plan.files),
        "entries_reprocessing_avoided": reused,
        "partitions": partitions,
        "cross_batch_graph_merge": "not_performed",
        "ambiguous_joins": "cross_batch_identity_not_established" if len(partitions) > 1 else None,
        "global_ranking_guaranteed": len(partitions) == 1 and complete,
        "ranking_scope": "per_batch",
        "limits": {
            "entries": max_entries,
            "graph_nodes": MAX_GRAPH_NODES,
            "graph_edges": MAX_GRAPH_EDGES,
            "partition_bytes": MAX_GRAPH_INPUT_BYTES,
        },
        "graph_totals": {"nodes": graph_nodes, "edges": graph_edges, "partition_bytes": graph_bytes},
        "network_requests_sent": 0,
        "vulnerabilities_confirmed": 0,
    }


def _discover_batch(
    plan: CampaignPlan,
    batch_id: str,
    inputs: dict[str, bytes],
    bundle: dict[str, Any],
    binding: dict[str, Any],
    key: bytes,
) -> dict[str, Any]:
    selected: dict[str, set[int]] = {name: set() for name in inputs}
    paths = {str((plan.root / name).resolve()): name for name in inputs}
    for record in bundle["records"]:
        for prov in record["provenance"]:
            name = paths.get(prov["source_path"])
            match = LOCATOR.fullmatch(prov["locator"])
            if name is None or match is None:
                raise CampaignError("unsupported_or_inconsistent_provenance")
            selected[name].add(int(match[1]))
    total = sum(map(len, selected.values()))
    if not 1 <= total <= min(MAX_CAPTURES, plan.limits.max_records_per_batch):
        raise CampaignError("object_capture_limit")
    mappings: list[dict[str, Any]] = []
    with tempfile.TemporaryDirectory(prefix="bbtk-object-") as directory:
        fragments: list[Path] = []
        for name, indices in selected.items():
            entries = load_har_entries(inputs[name], max_bytes=MAX_INPUT_BYTES)
            ordered = sorted(indices)
            for start in range(0, len(ordered), MAX_EXCHANGES):
                chunk = ordered[start : start + MAX_EXCHANGES]
                if len(fragments) >= MAX_FILES:
                    raise CampaignError("object_fragment_limit")
                data = _canonical({"log": {"version": "1.2", "entries": [entries[i] for i in chunk]}})
                if len(data) > MAX_ITEM_BYTES:
                    raise CampaignError("object_fragment_bytes")
                path = Path(directory) / f"{len(fragments)}.har"
                atomic_private_write(path, data)
                # Public builder provides the source reference without relying on its HMAC internals.
                single = build_object_graph(plan.program, [path], key, authorized=True)
                source_ref = single["sources"][0]["id"]
                for offset, index in enumerate(chunk):
                    mappings.append(
                        {
                            "source_ref": source_ref,
                            "locator": f"/log/entries[{offset}]",
                            "campaign_id": plan.campaign_id,
                            "batch_id": batch_id,
                            "file_ref": path_ref(name),
                            "file_sha256": plan.file(name).sha256,
                            "original_locator": f"/log/entries[{index}]",
                        }
                    )
                fragments.append(path)
        if sum(p.stat().st_size for p in fragments) > MAX_TOTAL_BYTES:
            raise CampaignError("object_fragment_total_bytes")
        graph = build_object_graph(plan.program, fragments, key, authorized=True)
    result = {
        "batch_id": batch_id,
        "binding": binding,
        "entries_processed": total,
        "graph": graph,
        "candidates": object_candidates(graph, plan.program, key),
        "provenance": mappings,
        "graph_scope": "independent_batch",
    }
    result["integrity"] = _seal(result, key)
    return result
