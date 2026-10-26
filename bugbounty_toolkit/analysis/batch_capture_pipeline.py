"""Bounded, resumable, offline batch ingestion of *pre-split* local capture files.

Scope and contract (see docs/batch-capture-ingestion.md):

- No new HTTP parser. Every batch is one ordinary ``evidence_engine.import_evidence`` call, so
  HAR (resilient ``partial``/``strict``/``compat``), Burp XML and raw HTTP keep their existing
  parsers, per-file limits (``MAX_INPUT_BYTES``) and per-import limits (``MAX_INPUT_FILES``,
  ``MAX_RECORDS``). Batch limits may only be *equal or lower* than those stage limits.
- Batching never evades campaign totals: explicit ``max_total_*`` budgets are required, capped by
  hard ceilings, and checked *before* a batch is committed. A batch that would exceed a budget
  is blocked (never truncated) and the campaign stays ``partial_limit_reached``.
- Not streaming: HAR files are still decoded whole by the existing importer. Large captures
  must be split beforehand into files that fit the existing per-file limits.
- Batch bundles are independent partial graphs. Salted fingerprints differ per import, so
  records are never merged across batches; cross-batch duplicates are only *reported* (whole
  file SHA-256 and HAR entry SHA-256), never deduplicated.
- State and outputs live in a private (0700, owner-only, no symlink) directory and are
  published atomically with mode 0600. Inputs are never copied; only the normalized bundles the
  importer already produces are stored, once per batch.
- Resume requires the same schema, program, limits, mode and file list. Changed inputs are
  refused unless ``allow_source_changes``; then only batches whose content-addressed id still
  matches (and whose stored output digest verifies) are reused.
- Summaries contain counts, reason codes, digests and path references only.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import time
from typing import Any, Callable
import xml.etree.ElementTree as ET

from ..core.private_files import atomic_private_write, local_path, read_private_input
from . import evidence_engine
from .har_import import HarImportError
from .har_provenance import HAR_MODES

SCHEMA = "bbtk.batch-capture-campaign/1"
SUPPORTED_FORMATS = ("har", "burp-xml", "http")
# New explicit campaign ceilings (budgets above these are refused, not clamped).
HARD_MAX_TOTAL_FILES = 1_000
HARD_MAX_TOTAL_BYTES = 1024 * 1024 * 1024
HARD_MAX_TOTAL_RECORDS = 100_000
BATCH_STATES = ("pending", "completed", "failed", "blocked_by_campaign_limit")
FILE_STATES = ("planned", "duplicate_file", "omitted_file_limit", "omitted_campaign_limit")
CAMPAIGN_STATES = ("complete", "incomplete", "partial_limit_reached")
_PROGRAM = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
_SHA = re.compile(r"^[a-f0-9]{64}$")


class CampaignError(ValueError):
    """Refusal with an enumerated ``reason`` code; messages never echo capture content."""

    def __init__(self, reason: str, detail: str = "") -> None:
        super().__init__(f"Batch campaign refused: {reason}{(' (' + detail + ')') if detail else ''}")
        self.reason = reason


@dataclass(frozen=True)
class CampaignLimits:
    """All limits are explicit. Per-batch values may not exceed the existing stage limits."""

    max_files_per_batch: int
    max_bytes_per_batch: int
    max_records_per_batch: int
    max_total_files: int
    max_total_bytes: int
    max_total_records: int

    def validate(self) -> None:
        bounds = {
            "max_files_per_batch": evidence_engine.MAX_INPUT_FILES,
            "max_bytes_per_batch": evidence_engine.MAX_INPUT_BYTES * evidence_engine.MAX_INPUT_FILES,
            "max_records_per_batch": evidence_engine.MAX_RECORDS,
            "max_total_files": HARD_MAX_TOTAL_FILES,
            "max_total_bytes": HARD_MAX_TOTAL_BYTES,
            "max_total_records": HARD_MAX_TOTAL_RECORDS,
        }
        for name, ceiling in bounds.items():
            value = getattr(self, name)
            if type(value) is not int or not 1 <= value <= ceiling:
                raise CampaignError("limit_invalid", name)
        if self.max_files_per_batch > self.max_total_files or self.max_records_per_batch > self.max_total_records:
            raise CampaignError("limit_invalid", "per-batch limit above campaign total")

    def as_dict(self) -> dict[str, int]:
        return {
            "max_files_per_batch": self.max_files_per_batch,
            "max_bytes_per_batch": self.max_bytes_per_batch,
            "max_records_per_batch": self.max_records_per_batch,
            "max_total_files": self.max_total_files,
            "max_total_bytes": self.max_total_bytes,
            "max_total_records": self.max_total_records,
            "max_bytes_per_file": evidence_engine.MAX_INPUT_BYTES,
        }


@dataclass(frozen=True)
class PlannedFile:
    relpath: str
    sha256: str
    size: int
    state: str
    duplicate_of: str | None = None


@dataclass(frozen=True)
class Batch:
    batch_id: str
    files: tuple[str, ...]
    bytes: int


@dataclass
class CampaignPlan:
    root: Path
    program: str
    har_mode: str
    format_name: str
    limits: CampaignLimits
    campaign_id: str
    manifest_sha256: str
    files: list[PlannedFile]
    batches: list[Batch] = field(default_factory=list)

    def file(self, relpath: str) -> PlannedFile:
        return next(item for item in self.files if item.relpath == relpath)

    def manifest(self) -> dict[str, Any]:
        return {
            "schema": SCHEMA,
            "campaign_id": self.campaign_id,
            "manifest_sha256": self.manifest_sha256,
            "program": self.program,
            "har_mode": self.har_mode,
            "format": self.format_name,
            "limits": self.limits.as_dict(),
            "files": [
                {
                    "relpath": f.relpath,
                    "sha256": f.sha256,
                    "size": f.size,
                    "state": f.state,
                    "duplicate_of": f.duplicate_of,
                }
                for f in self.files
            ],
            "batches": [{"batch_id": b.batch_id, "files": list(b.files), "bytes": b.bytes} for b in self.batches],
        }


def _digest(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _hash_file(path: Path) -> tuple[str, int]:
    data = read_private_input(path, evidence_engine.MAX_INPUT_BYTES)
    return hashlib.sha256(data).hexdigest(), len(data)


def _resolve_input(root: Path, relpath: str) -> Path:
    candidate = Path(relpath)
    if candidate.is_absolute() or not relpath or ".." in candidate.parts or "\\" in relpath:
        raise CampaignError("input_path_external")
    path = local_path(root / candidate)
    try:
        info = os.lstat(path)
    except OSError as exc:
        raise CampaignError("input_missing") from exc
    if not stat.S_ISREG(info.st_mode):
        raise CampaignError("input_not_regular_file")
    if os.path.commonpath([str(path), str(root)]) != str(root):
        raise CampaignError("input_path_external")
    return path


def plan_campaign(
    root: Path,
    relpaths: list[str],
    *,
    program: str,
    limits: CampaignLimits,
    har_mode: str = "partial",
    format_name: str = "auto",
) -> CampaignPlan:
    """Hash every input and build a deterministic, content-addressed batch plan (no parsing)."""
    if not isinstance(program, str) or not _PROGRAM.match(program):
        raise CampaignError("program_invalid")
    if har_mode not in HAR_MODES:
        raise CampaignError("har_mode_invalid")
    if format_name not in ("auto", *SUPPORTED_FORMATS):
        raise CampaignError("format_invalid")
    limits.validate()
    root = local_path(root)
    if not root.is_dir():
        raise CampaignError("root_invalid")
    names = sorted(set(relpaths))
    if len(names) != len(relpaths):
        raise CampaignError("input_listed_twice")
    if not names or len(names) > limits.max_total_files:
        raise CampaignError("total_file_limit", f"{len(names)} files")
    identity = {
        "schema": SCHEMA,
        "program": program,
        "har_mode": har_mode,
        "format": format_name,
        "limits": limits.as_dict(),
        "files": names,
    }
    campaign_id = _digest(identity)[:24]
    files: list[PlannedFile] = []
    first_by_sha: dict[str, str] = {}
    total_bytes = 0
    for relpath in names:
        path = _resolve_input(root, relpath)
        size = os.lstat(path).st_size
        if size > evidence_engine.MAX_INPUT_BYTES:
            files.append(PlannedFile(relpath, "", size, "omitted_file_limit"))
            continue
        sha, size = _hash_file(path)
        if sha in first_by_sha:
            files.append(PlannedFile(relpath, sha, size, "duplicate_file", first_by_sha[sha]))
            continue
        if total_bytes + size > limits.max_total_bytes or size > limits.max_bytes_per_batch:
            files.append(PlannedFile(relpath, sha, size, "omitted_campaign_limit"))
            continue
        first_by_sha[sha] = relpath
        total_bytes += size
        files.append(PlannedFile(relpath, sha, size, "planned"))
    batches: list[Batch] = []
    current: list[PlannedFile] = []

    def close() -> None:
        if current:
            members = [(f.relpath, f.sha256) for f in current]
            batch_id = _digest({"campaign": campaign_id, "files": members})[:24]
            batches.append(Batch(batch_id, tuple(f.relpath for f in current), sum(f.size for f in current)))
            current.clear()

    for item in files:
        if item.state != "planned":
            continue
        if current and (
            len(current) >= limits.max_files_per_batch
            or sum(f.size for f in current) + item.size > limits.max_bytes_per_batch
        ):
            close()
        current.append(item)
    close()
    manifest_sha = _digest({"identity": identity, "files": [(f.relpath, f.sha256, f.size, f.state) for f in files]})
    return CampaignPlan(root, program, har_mode, format_name, limits, campaign_id, manifest_sha, files, batches)


# --- private state directory -------------------------------------------------------------


def _private_dir(path: Path) -> Path:
    path = local_path(path)
    try:
        os.makedirs(path, mode=0o700, exist_ok=True)
        info = os.lstat(path)
    except OSError as exc:
        raise CampaignError("state_dir_unusable") from exc
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o077:
        raise CampaignError("state_dir_not_private")
    return path


def _read_json(path: Path) -> Any:
    return json.loads(read_private_input(path, evidence_engine.MAX_INPUT_BYTES * 4))


def _write_json(path: Path, value: Any) -> str:
    data = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    atomic_private_write(path, data, force=True)
    return hashlib.sha256(data).hexdigest()


# --- batch execution ---------------------------------------------------------------------

Importer = Callable[[list[Path], str, str], dict[str, Any]]


def _default_importer(paths: list[Path], format_name: str, har_mode: str) -> dict[str, Any]:
    return evidence_engine.import_evidence(paths, format_name, har_mode)


def _error_code(exc: BaseException) -> str:
    """Enumerated code only (the importer's messages may name files, so they are not echoed)."""
    cause: BaseException | None = exc
    for _ in range(4):
        if isinstance(cause, HarImportError):
            return f"har:{cause.reason}"
        cause = cause.__cause__ if cause is not None else None
    return "input_rejected:" + type(exc).__name__


def _burp_items(path: Path) -> int | None:
    """Count declared Burp ``<item>`` elements (accounting only; the importer still parses)."""
    raw = read_private_input(path, evidence_engine.MAX_INPUT_BYTES)
    if re.search(rb"<!\s*(?:DOCTYPE|ENTITY)\b", raw, re.I):
        return None
    try:
        root = ET.fromstring(raw)
    except (ET.ParseError, ValueError, RecursionError):
        return None
    return sum(1 for node in root.iter() if isinstance(node.tag, str) and node.tag.rsplit("}", 1)[-1] == "item")


def _run_batch(plan: CampaignPlan, batch: Batch, importer: Importer) -> tuple[dict[str, Any], dict[str, Any] | None]:
    """Run one batch. Returns (outcome, bundle). Fatal files are isolated, never repaired."""
    started = time.perf_counter()
    paths: dict[str, Path] = {}
    for relpath in batch.files:
        path = _resolve_input(plan.root, relpath)
        if _hash_file(path)[0] != plan.file(relpath).sha256:
            return {"state": "failed", "error": "source_changed_since_plan", "files": {}}, None
        paths[relpath] = path
    file_errors: dict[str, str] = {}
    usable = list(batch.files)
    bundle: dict[str, Any] | None = None
    while usable:
        try:
            bundle = importer([paths[r] for r in usable], plan.format_name, plan.har_mode)
            break
        except (ValueError, RecursionError) as exc:
            if len(usable) == 1:
                file_errors[usable[0]] = _error_code(exc)
                usable = []
                break
            # Isolate: probe each file alone; only files that fail alone are excluded.
            survivors = []
            for relpath in usable:
                try:
                    importer([paths[relpath]], plan.format_name, plan.har_mode)
                    survivors.append(relpath)
                except (ValueError, RecursionError) as single:
                    file_errors[relpath] = _error_code(single)
            if survivors == usable:  # combined-only failure (e.g. combined record limit)
                return {"state": "failed", "error": "combined_import_rejected:" + _error_code(exc), "files": {}}, None
            usable = survivors
    for relpath, path in paths.items():  # TOCTOU guard: inputs must not change during import
        if _hash_file(path)[0] != plan.file(relpath).sha256:
            return {"state": "failed", "error": "source_changed_during_batch", "files": {}}, None
    by_path = {str(path.resolve()): relpath for relpath, path in paths.items()}
    files: dict[str, Any] = {r: {"state": "rejected_file", "error": e} for r, e in file_errors.items()}
    records = 0
    if bundle is not None:
        records = int(bundle["summary"]["records_parsed"])
        for row in bundle["inputs"]:
            relpath = by_path[row["source_path"]]
            info: dict[str, Any] = {
                "state": "imported",
                "format": row["format"],
                "records_parsed": row["records_parsed"],
            }
            account = row.get("capture_import")
            if isinstance(account, dict):
                info["har"] = {
                    k: account[k]
                    for k in (
                        "entries_declared",
                        "entries_accepted",
                        "entries_rejected",
                        "rejections_by_reason",
                        "rejected_entries",
                        "duplicate_entries",
                        "omitted_by_limits",
                        "truncated",
                    )
                }
                info["entry_sha256"] = sorted(set(account.get("entry_sha256", {}).values()))
            if row["format"] == "burp-xml":
                declared = _burp_items(paths[relpath])
                info["burp_items_declared"] = declared
                info["burp_items_not_emitted"] = None if declared is None else max(0, declared - row["records_parsed"])
            files[relpath] = info
    outcome = {
        "state": "completed",
        "error": None,
        "files": files,
        "records_parsed": records,
        "records_unique": len(bundle["records"]) if bundle else 0,
        "elapsed_ms": round((time.perf_counter() - started) * 1000, 3),
    }
    if records > plan.limits.max_records_per_batch:
        return {"state": "failed", "error": "batch_record_limit", "files": {}}, None
    return outcome, bundle


def _load_state(plan: CampaignPlan, state_dir: Path, allow_source_changes: bool) -> dict[str, Any]:
    state_path = state_dir / "campaign-state.json"
    if not state_path.exists():
        return {"batches": {}, "events": []}
    try:
        state = _read_json(state_path)
    except (ValueError, UnicodeError) as exc:
        raise CampaignError("state_corrupt") from exc
    if not isinstance(state, dict) or state.get("schema") != SCHEMA:
        raise CampaignError("schema_mismatch")
    if state.get("campaign_id") != plan.campaign_id:
        raise CampaignError("campaign_mismatch", "program, limits, mode or file list differ")
    if state.get("manifest_sha256") != plan.manifest_sha256:
        if not allow_source_changes:
            old = {f["relpath"]: f["sha256"] for f in state.get("manifest", {}).get("files", [])}
            changed = sorted(r for r, s in ((f.relpath, f.sha256) for f in plan.files) if old.get(r) != s)
            raise CampaignError("source_changed", f"{len(changed)} input(s) changed")
        state.setdefault("events", []).append(
            {"event": "source_changes_accepted", "previous": state["manifest_sha256"]}
        )
    batches = state.get("batches")
    if not isinstance(batches, dict):
        raise CampaignError("state_corrupt")
    return {"batches": batches, "events": list(state.get("events", []))}


def run_campaign(
    plan: CampaignPlan,
    state_dir: Path,
    *,
    max_batches: int | None = None,
    allow_source_changes: bool = False,
    importer: Importer = _default_importer,
) -> dict[str, Any]:
    """Execute pending batches in plan order, persisting state after each batch.

    ``max_batches`` bounds the work of one invocation (deliberate interruption). Completed
    batches with a verified output digest are reused, never re-run.
    """
    state_dir = _private_dir(state_dir)
    outputs = _private_dir(state_dir / "batches")
    loaded = _load_state(plan, state_dir, allow_source_changes)
    previous: dict[str, Any] = loaded["batches"]
    events: list[dict[str, Any]] = loaded["events"]
    batches: dict[str, Any] = {}
    stats = {"reused": 0, "executed": 0, "reprocessed_output_altered": 0, "invalidated_by_source_change": 0}
    for old_id, old in previous.items():
        if old_id not in {b.batch_id for b in plan.batches} and old.get("state") == "completed":
            stats["invalidated_by_source_change"] += 1
    committed = 0
    run_count = 0
    blocked = False

    def save() -> None:
        _write_json(
            state_dir / "campaign-state.json",
            {
                "schema": SCHEMA,
                "campaign_id": plan.campaign_id,
                "manifest_sha256": plan.manifest_sha256,
                "manifest": plan.manifest(),
                "batches": batches,
                "events": events[-200:],
            },
        )

    for batch in plan.batches:
        old = previous.get(batch.batch_id)
        if isinstance(old, dict) and old.get("state") == "completed" and old.get("output_sha256") is None:
            batches[batch.batch_id] = old  # every file rejected; nothing stored, nothing to verify
            stats["reused"] += 1
            continue
        if isinstance(old, dict) and old.get("state") == "completed" and _SHA.match(str(old.get("output_sha256"))):
            try:
                data = read_private_input(outputs / f"{batch.batch_id}.json", evidence_engine.MAX_INPUT_BYTES * 4)
                intact = hashlib.sha256(data).hexdigest() == old["output_sha256"]
            except ValueError:
                intact = False
            if intact and committed + int(old["records_parsed"]) <= plan.limits.max_total_records:
                batches[batch.batch_id] = old
                committed += int(old["records_parsed"])
                stats["reused"] += 1
                continue
            if not intact:
                stats["reprocessed_output_altered"] += 1
                events.append({"event": "output_altered", "batch_id": batch.batch_id})
        if blocked or (max_batches is not None and run_count >= max_batches):
            batches[batch.batch_id] = {"state": "blocked_by_campaign_limit" if blocked else "pending"}
            continue
        if committed >= plan.limits.max_total_records:
            blocked = True
            batches[batch.batch_id] = {"state": "blocked_by_campaign_limit"}
            continue
        run_count += 1
        stats["executed"] += 1
        outcome, bundle = _run_batch(plan, batch, importer)
        if bundle is not None and committed + int(outcome["records_parsed"]) > plan.limits.max_total_records:
            blocked = True
            outcome = {"state": "blocked_by_campaign_limit", "error": "campaign_record_limit", "files": {}}
            bundle = None
        if bundle is not None:
            outcome["output_sha256"] = _write_json(outputs / f"{batch.batch_id}.json", bundle)
            committed += int(outcome["records_parsed"])
        elif outcome["state"] == "completed":  # every file rejected: completed with no output
            outcome["output_sha256"] = None
        batches[batch.batch_id] = outcome
        save()  # durable after every batch: an interruption loses at most the running batch
    save()
    return campaign_summary(plan, batches, stats, state_dir)


def campaign_summary(
    plan: CampaignPlan, batches: dict[str, Any], stats: dict[str, int], state_dir: Path | None = None
) -> dict[str, Any]:
    """Content-free consolidated view. Never merges partial graphs across batches."""
    from .har_provenance import path_ref

    by_state = {s: 0 for s in BATCH_STATES}
    for item in batches.values():
        by_state[item["state"]] = by_state.get(item["state"], 0) + 1
    file_states = {s: 0 for s in (*FILE_STATES, "imported", "rejected_file")}
    for f in plan.files:
        if f.state != "planned":
            file_states[f.state] += 1
    reasons: dict[str, int] = {}
    entry_counts = dict.fromkeys(("entries_declared", "entries_accepted", "entries_rejected", "duplicate_entries"), 0)
    entry_owner: dict[str, set[str]] = {}
    entry_files: dict[str, set[str]] = {}
    file_errors: list[dict[str, str]] = []
    burp_not_emitted = 0
    records = 0
    for batch_id, item in batches.items():
        records += int(item.get("records_parsed", 0)) if item["state"] == "completed" else 0
        for relpath, info in item.get("files", {}).items():
            file_states[info["state"]] += 1
            if info["state"] == "rejected_file":
                file_errors.append({"ref": path_ref(relpath), "error": info["error"]})
            har = info.get("har")
            if isinstance(har, dict):
                for key in entry_counts:
                    entry_counts[key] += int(har[key])
                for reason, count in har["rejections_by_reason"].items():
                    reasons[reason] = reasons.get(reason, 0) + int(count)
            for digest in info.get("entry_sha256", []):
                entry_owner.setdefault(digest, set()).add(batch_id)
                entry_files.setdefault(digest, set()).add(relpath)
            burp_not_emitted += int(info.get("burp_items_not_emitted") or 0)
    omitted = file_states["omitted_file_limit"] + file_states["omitted_campaign_limit"]
    if by_state["blocked_by_campaign_limit"] or omitted:
        status = "partial_limit_reached"
    elif by_state["pending"] or by_state["failed"] or len(batches) != len(plan.batches):
        status = "incomplete"
    else:
        status = "complete"
    warnings = []
    if file_states["rejected_file"]:
        warnings.append("some_input_files_rejected")
    if burp_not_emitted:
        warnings.append("burp_items_not_emitted")
    if reasons:
        warnings.append("har_entries_rejected")
    return {
        "schema": SCHEMA,
        "campaign_id": plan.campaign_id,
        "manifest_sha256": plan.manifest_sha256,
        "program": plan.program,
        "har_mode": plan.har_mode,
        "status": status,
        "complete": status == "complete",
        "limits": plan.limits.as_dict(),
        "batches_total": len(plan.batches),
        "batches_by_state": by_state,
        "files_declared": len(plan.files),
        "files_by_state": file_states,
        "file_errors": sorted(file_errors, key=lambda e: e["ref"]),
        "records_parsed": records,
        "har_entries": entry_counts,
        "har_rejections_by_reason": dict(sorted(reasons.items())),
        "burp_items_not_emitted": burp_not_emitted,
        "cross_batch_duplicate_har_entries": sum(len(owners) - 1 for owners in entry_owner.values()),
        "cross_file_duplicate_har_entries": sum(len(files) - 1 for files in entry_files.values()),
        "cross_batch_graph_merge": "not_performed",
        "resume": dict(stats),
        "warnings": warnings,
        "outputs_private": state_dir is not None,
        "contains_capture_content": False,
        "network_requests_sent": 0,
        "vulnerabilities_confirmed": 0,
    }


def batch_bundle_paths(plan: CampaignPlan, state_dir: Path) -> list[Path]:
    """Paths of completed batch bundles in plan order (each an independent partial graph)."""
    return [
        state_dir / "batches" / f"{b.batch_id}.json"
        for b in plan.batches
        if (state_dir / "batches" / f"{b.batch_id}.json").exists()
    ]
