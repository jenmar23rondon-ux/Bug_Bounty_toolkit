"""Structured, content-free HAR capture-import provenance for unified evidence bundles.

This module does not parse HTTP on its own: every per-entry decision comes from the resilient
importer (``har_import.entry_reason`` / ``har_import.import_har``) and every record is still
decoded by ``evidence_engine.har_entry_source``. It only *accounts* for what happened to each
original entry and verifies that the produced records agree with that account.

Summaries contain indices, counts, enumerated reason codes and SHA-256 digests only: never
URLs, headers, cookies, tokens, bodies or object identifiers.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import re
from typing import Any, Iterable, Mapping

from .har_import import ENTRY_REASONS, HarImportResult, entry_fingerprint, entry_reason, has_duplicate_keys

CAPTURE_IMPORT_SCHEMA = "bbtk.har-capture-import/1"
HAR_MODES = ("compat", "partial", "strict")
_LOCATOR = re.compile(r"^/log/entries\[(\d+)\]$")
_SHA256 = re.compile(r"^[a-f0-9]{64}$")


def entry_digest(entry: Any) -> str:
    """SHA-256 of one entry's canonical JSON; reproducible from the original file only."""
    return hashlib.sha256(
        json.dumps(entry, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    ).hexdigest()


def locator_index(locator: object) -> int | None:
    match = _LOCATOR.match(locator) if isinstance(locator, str) else None
    return int(match.group(1)) if match else None


@dataclass
class HarAccount:
    """Per-entry outcome of one HAR file (internal; ``summary`` is the public view)."""

    mode: str
    entries_declared: int
    rejected: dict[int, str]
    emitted: list[int]
    duplicate_entries: int
    digests: dict[int, str]
    source_sha256: str
    limits: dict[str, int]
    container_duplicate_keys: bool = False
    omitted_by_limits: int = 0
    truncated: bool = False

    def summary(self) -> dict[str, Any]:
        reasons: dict[str, int] = {}
        for reason in self.rejected.values():
            reasons[reason] = reasons.get(reason, 0) + 1
        emitted = set(self.emitted)
        accepted = self.entries_declared - self.omitted_by_limits - len(self.rejected)
        return {
            "schema": CAPTURE_IMPORT_SCHEMA,
            "format": "har",
            "mode": self.mode,
            "importer": "bugbounty_toolkit.analysis.har_import",
            "source_sha256": self.source_sha256,
            "entries_declared": self.entries_declared,
            "entries_processed": self.entries_declared - self.omitted_by_limits,
            "entries_accepted": accepted,
            "entries_rejected": len(self.rejected),
            "rejections_by_reason": dict(sorted(reasons.items())),
            "rejected_entries": [
                {"index": index, "reason": reason, "emitted_as_record": index in emitted}
                for index, reason in sorted(self.rejected.items())
            ],
            "duplicate_entries": self.duplicate_entries,
            "omitted_by_limits": self.omitted_by_limits,
            "truncated": self.truncated,
            "container_duplicate_keys": self.container_duplicate_keys,
            "limits": dict(sorted(self.limits.items())),
            "records_emitted": len(self.emitted),
            "emitted_entry_indices": sorted(self.emitted),
            "entry_sha256": {str(index): self.digests[index] for index in sorted(self.digests)},
        }


def _digest_map(entries: list[Any], indices: Iterable[int]) -> dict[int, str]:
    return {index: entry_digest(entries[index]) for index in indices}


def account_compat(
    document: Any,
    entries: list[Any],
    emitted: list[int],
    raw: bytes,
    *,
    limits: dict[str, int],
    max_message_bytes: int,
) -> HarAccount:
    """Classify every entry with the resilient validator without changing legacy records."""
    rejected: dict[int, str] = {}
    seen: set[str] = set()
    duplicates = 0
    for index, entry in enumerate(entries):
        reason, _ = entry_reason(entry, index, max_message_bytes)
        if reason is not None:
            rejected[index] = reason
            continue
        fingerprint = entry_fingerprint(entry)
        duplicates += fingerprint in seen
        seen.add(fingerprint)
    log = document.get("log") if isinstance(document, dict) else None
    return HarAccount(
        mode="compat",
        entries_declared=len(entries),
        rejected=rejected,
        emitted=list(emitted),
        duplicate_entries=duplicates,
        digests=_digest_map(entries, emitted),
        source_sha256=hashlib.sha256(raw).hexdigest(),
        limits=limits,
        container_duplicate_keys=has_duplicate_keys(document) or has_duplicate_keys(log),
    )


def account_resilient(result: HarImportResult, entries: list[Any], raw: bytes, *, limits: dict[str, int]) -> HarAccount:
    emitted = [index for index in (locator_index(source.locator) for source in result.accepted) if index is not None]
    return HarAccount(
        mode=result.mode,
        entries_declared=result.entries_total,
        rejected=dict(result.rejected),
        emitted=emitted,
        duplicate_entries=result.duplicates,
        digests=_digest_map(entries, emitted),
        source_sha256=hashlib.sha256(raw).hexdigest(),
        limits=limits,
        truncated=result.truncated,
    )


def _issue(issues: list[dict[str, str]], code: str, ref: str) -> None:
    issues.append({"code": code, "ref": ref})


def _validate_summary(summary: Mapping[str, Any], ref: str, issues: list[dict[str, str]]) -> None:
    ints = (
        "entries_declared",
        "entries_processed",
        "entries_accepted",
        "entries_rejected",
        "duplicate_entries",
        "omitted_by_limits",
        "records_emitted",
    )
    if summary.get("schema") != CAPTURE_IMPORT_SCHEMA:
        _issue(issues, "schema_unknown", ref)
        return
    if any(type(summary.get(key)) is not int or summary[key] < 0 for key in ints):
        _issue(issues, "count_malformed", ref)
        return
    if summary.get("mode") not in {"compat", "partial", "strict"}:
        _issue(issues, "mode_unknown", ref)
    if not isinstance(summary.get("source_sha256"), str) or not _SHA256.match(summary["source_sha256"]):
        _issue(issues, "source_hash_malformed", ref)
    declared, processed = summary["entries_declared"], summary["entries_processed"]
    if processed + summary["omitted_by_limits"] != declared:
        _issue(issues, "processed_count_mismatch", ref)
    if summary["entries_accepted"] + summary["entries_rejected"] != processed:
        _issue(issues, "accepted_rejected_mismatch", ref)
    if summary["duplicate_entries"] > summary["entries_accepted"]:
        _issue(issues, "duplicate_count_exceeds_accepted", ref)
    if bool(summary.get("truncated")) != (summary["omitted_by_limits"] > 0):
        _issue(issues, "truncation_flag_mismatch", ref)
    rows = summary.get("rejected_entries")
    reasons = summary.get("rejections_by_reason")
    if not isinstance(rows, list) or not isinstance(reasons, dict):
        _issue(issues, "rejections_malformed", ref)
        return
    rejected: dict[int, str] = {}
    flagged_emitted: set[int] = set()
    for row in rows:
        if (
            not isinstance(row, dict)
            or type(row.get("index")) is not int
            or row.get("reason") not in ENTRY_REASONS
            or not isinstance(row.get("emitted_as_record"), bool)
        ):
            _issue(issues, "rejected_entry_malformed", ref)
            continue
        if row["index"] in rejected or not 0 <= row["index"] < declared:
            _issue(issues, "rejected_index_invalid", ref)
        rejected[row["index"]] = row["reason"]
        if row["emitted_as_record"]:
            flagged_emitted.add(row["index"])
    if len(rejected) != summary["entries_rejected"]:
        _issue(issues, "rejected_count_mismatch", ref)
    tally: dict[str, int] = {}
    for reason in rejected.values():
        tally[reason] = tally.get(reason, 0) + 1
    if tally != reasons:
        _issue(issues, "reason_tally_mismatch", ref)
    emitted = summary.get("emitted_entry_indices")
    digests = summary.get("entry_sha256")
    if not isinstance(emitted, list) or any(type(item) is not int for item in emitted) or not isinstance(digests, dict):
        _issue(issues, "emitted_malformed", ref)
        return
    if len(set(emitted)) != len(emitted) or any(not 0 <= item < declared for item in emitted):
        _issue(issues, "emitted_index_invalid", ref)
    if len(emitted) != summary["records_emitted"]:
        _issue(issues, "records_emitted_mismatch", ref)
    if set(emitted) & set(rejected) != flagged_emitted:
        _issue(issues, "emitted_flag_mismatch", ref)
    if summary.get("mode") != "compat" and flagged_emitted:
        _issue(issues, "rejected_entry_emitted", ref)
    if set(digests) != {str(item) for item in emitted} or any(
        not isinstance(value, str) or not _SHA256.match(value) for value in digests.values()
    ):
        _issue(issues, "entry_digest_mismatch", ref)


def validate_capture_provenance(bundle: Mapping[str, Any]) -> dict[str, Any]:
    """Check that capture-import summaries agree with the records actually produced.

    Bundles without any ``capture_import`` section (created before this schema) are reported as
    ``status: absent`` and are not invalid.
    """
    issues: list[dict[str, str]] = []
    inputs = bundle.get("inputs")
    records = bundle.get("records")
    if not isinstance(inputs, list) or not isinstance(records, list):
        return {"status": "invalid", "valid": False, "issues": [{"code": "bundle_malformed", "ref": "bundle"}]}
    locators: dict[str, list[str]] = {}
    for record in records:
        for item in record.get("provenance", []) if isinstance(record, dict) else []:
            if isinstance(item, dict) and isinstance(item.get("source_path"), str):
                locators.setdefault(item["source_path"], []).append(str(item.get("locator")))
    checked = 0
    emitted_total = 0
    expected_by_path: dict[str, set[int]] = {}
    har_without_summary = False
    for position, row in enumerate(inputs):
        if not isinstance(row, dict):
            _issue(issues, "input_malformed", f"inputs[{position}]")
            continue
        summary = row.get("capture_import")
        if summary is None:
            har_without_summary = har_without_summary or row.get("format") == "har"
            continue
        ref = f"inputs[{position}].capture_import"
        if not isinstance(summary, dict):
            _issue(issues, "summary_malformed", ref)
            continue
        checked += 1
        before = len(issues)
        _validate_summary(summary, ref, issues)
        emitted = summary.get("emitted_entry_indices")
        if isinstance(emitted, list) and all(type(item) is int for item in emitted):
            expected_by_path.setdefault(str(row.get("source_path")), set()).update(emitted)
        if len(issues) != before:
            continue
        if row.get("records_parsed") != summary["records_emitted"]:
            _issue(issues, "records_parsed_mismatch", ref)
        emitted_total += summary["records_emitted"]
    for path, expected in sorted(expected_by_path.items()):
        produced = [locator_index(locator) for locator in locators.get(path, [])]
        if any(index is None for index in produced):
            _issue(issues, "foreign_locator", path_ref(path))
        if {index for index in produced if index is not None} != expected:
            _issue(issues, "record_locators_mismatch", path_ref(path))
    if checked and har_without_summary:
        _issue(issues, "summary_missing", "inputs")
    if not checked:
        return {"status": "absent", "valid": True, "issues": []}
    summary_block = bundle.get("summary")
    if isinstance(summary_block, dict) and all(
        isinstance(row, dict) and isinstance(row.get("capture_import"), dict) for row in inputs
    ):
        if summary_block.get("records_parsed") != emitted_total:
            _issue(issues, "bundle_records_parsed_mismatch", "summary")
    return {"status": "checked", "valid": not issues, "issues": issues, "inputs_checked": checked}


def path_ref(path: str) -> str:
    """Issue reference for a source path without echoing it (paths can contain private names)."""
    return "source:" + hashlib.sha256(path.encode()).hexdigest()[:12]


def verify_capture_sources(bundle: Mapping[str, Any], files: Mapping[str, Path]) -> dict[str, Any]:
    """Recompute file and entry digests from local files (``source_path`` -> path). Offline only."""
    from .har_import import decode_har_document

    issues: list[dict[str, str]] = []
    for position, row in enumerate(bundle.get("inputs", [])):
        summary = row.get("capture_import") if isinstance(row, dict) else None
        if not isinstance(summary, dict):
            continue
        ref = f"inputs[{position}].capture_import"
        path = files.get(str(row.get("source_path")))
        if path is None:
            _issue(issues, "source_unavailable", ref)
            continue
        raw = path.read_bytes()
        if hashlib.sha256(raw).hexdigest() != summary.get("source_sha256"):
            _issue(issues, "source_hash_mismatch", ref)
            continue
        document = decode_har_document(raw.decode("utf-8-sig"))
        entries = document["log"]["entries"]
        for key, value in dict(summary.get("entry_sha256", {})).items():
            index = int(key)
            if not 0 <= index < len(entries) or entry_digest(entries[index]) != value:
                _issue(issues, "entry_hash_mismatch", f"{ref}.entry_sha256[{key}]")
    return {"valid": not issues, "issues": issues}


def capture_origin_summary(bundle: Mapping[str, Any]) -> dict[str, Any]:
    """Bundle-level, content-free capture-origin section for reports and the Evidence Ledger."""
    totals = dict.fromkeys(
        (
            "inputs",
            "entries_declared",
            "entries_accepted",
            "entries_rejected",
            "duplicate_entries",
            "omitted_by_limits",
            "records_emitted",
        ),
        0,
    )
    reasons: dict[str, int] = {}
    sources = []
    for row in bundle.get("inputs", []):
        summary = row.get("capture_import") if isinstance(row, dict) else None
        if not isinstance(summary, dict):
            continue
        totals["inputs"] += 1
        for key in tuple(totals)[1:]:
            totals[key] += int(summary.get(key, 0))
        for reason, count in summary.get("rejections_by_reason", {}).items():
            reasons[reason] = reasons.get(reason, 0) + int(count)
        sources.append({"source_sha256": summary.get("source_sha256"), "mode": summary.get("mode"), "format": "har"})
    return {
        "schema": CAPTURE_IMPORT_SCHEMA,
        **totals,
        "rejections_by_reason": dict(sorted(reasons.items())),
        "sources": sources,
        "records_unique": len(bundle.get("records", [])),
        # Bundle-wide (all inputs): emitted records that deduplication merged into another record.
        "records_merged_by_deduplication": int(dict(bundle.get("summary", {})).get("duplicates_merged", 0)),
        "contains_capture_content": False,
    }
