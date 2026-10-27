"""Offline evidence-integrity and coverage ledger for human review.

The ledger records which surfaces were investigated, which candidates were
raised, which local evidence files back each candidate (with SHA-256 and
provenance), and the human review state of every candidate.

Design rules (enforced by :func:`validate_ledger`):

* States are distinct: ``candidate``, ``requires_validation``, ``rejected`` and
  ``confirmed``. Nothing in this module ever produces ``confirmed`` on its own;
  only :func:`review_candidate` with an explicit human reviewer can, and the
  validator rejects confirmations whose basis is a heuristic, pattern match,
  model opinion or automatic tool verdict.
* A confirmation must be reviewed by someone other than whoever raised the
  candidate (independent review, no AI agent required).
* Rejections record a reason; blocked surfaces and ``requires_validation``
  candidates record the exact blocker.
* Evidence is referenced by program-relative path and digest; when the
  program directory is available, digests are re-verified and code/surface
  fingerprints are compared so changed code invalidates prior evidence.

The module performs no network requests and never executes tests.
"""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
from collections import Counter
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any, Mapping

from ..core.records import utc_now
from .evidence_review import review_evidence

SCHEMA_VERSION = "bbtk-evidence-ledger/1"
SUPPORTED_SCHEMA_VERSIONS = frozenset({SCHEMA_VERSION})
MAX_LEDGER_BYTES = 4 * 1024 * 1024
MAX_RECORDS = 5000
MAX_EVIDENCE_BYTES = 64 * 1024 * 1024

SURFACE_STATUSES = ("investigated", "reviewed", "pending", "blocked", "out_of_scope")
CANDIDATE_STATES = ("candidate", "requires_validation", "rejected", "confirmed")
REJECTION_REASONS = (
    "not_reproducible",
    "expected_behavior",
    "control_invalid",
    "insufficient_impact",
    "out_of_scope",
    "duplicate",
    "evidence_invalidated",
    "false_positive",
    "other",
)
REVIEW_METHODS = ("human_manual", "human_lab_reproduction", "human_code_review")
AUTOMATIC_BASES = frozenset(
    {"heuristic", "pattern_match", "match", "model", "ai", "llm", "automatic", "tool_verdict", "scanner"}
)
ALLOWED_TRANSITIONS: dict[str, frozenset[str]] = {
    "candidate": frozenset({"requires_validation", "rejected"}),
    "requires_validation": frozenset({"rejected", "confirmed", "candidate"}),
    "rejected": frozenset({"candidate"}),
    "confirmed": frozenset({"requires_validation", "rejected"}),
}
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_LEGACY_POSITIVE = frozenset({"candidate", "confirmed", "VULNERABLE", "possible", "possible_csrf", "reflected"})

LEDGER_SCHEMA: dict[str, Any] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "$id": "https://github.com/jenmar23rondon-ux/Bug_Bounty_toolkit/docs/schemas/evidence-ledger-v1.schema.json",
    "title": "bbtk evidence verification and coverage ledger",
    "type": "object",
    "additionalProperties": False,
    "required": ["schema_version", "program", "surfaces", "evidence", "candidates"],
    "properties": {
        "schema_version": {"const": SCHEMA_VERSION},
        "program": {"type": "string", "pattern": "^[A-Za-z0-9][A-Za-z0-9_-]{0,79}$"},
        "updated_at": {"type": "string"},
        "surfaces": {
            "type": "array",
            "maxItems": MAX_RECORDS,
            "items": {
                "type": "object",
                "additionalProperties": False,
                "required": ["surface_id", "kind", "ref", "status"],
                "properties": {
                    "surface_id": {"type": "string", "pattern": _ID.pattern},
                    "kind": {"enum": ["endpoint", "workflow", "source_file", "component", "asset"]},
                    "ref": {"type": "string", "minLength": 1, "maxLength": 300},
                    "status": {"enum": list(SURFACE_STATUSES)},
                    "blocker": {"type": "string", "maxLength": 500},
                    "reason": {"type": "string", "maxLength": 500},
                    "fingerprint": {"type": "string", "maxLength": 128},
                    "investigation_id": {"type": "string", "pattern": _ID.pattern},
                    "notes": {"type": "string", "maxLength": 2000},
                },
            },
        },
        "evidence": {
            "type": "array",
            "maxItems": MAX_RECORDS,
            "items": {
                "type": "object",
                "additionalProperties": False,
                "required": ["evidence_id", "path", "sha256", "provenance"],
                "properties": {
                    "evidence_id": {"type": "string", "pattern": _ID.pattern},
                    "path": {"type": "string", "maxLength": 240},
                    "sha256": {"type": "string", "pattern": _SHA256.pattern},
                    "surface_fingerprint": {"type": "string", "maxLength": 128},
                    "provenance": {
                        "type": "object",
                        "additionalProperties": False,
                        "required": ["tool", "captured_at"],
                        "properties": {
                            "tool": {"type": "string", "maxLength": 80},
                            "captured_at": {"type": "string", "maxLength": 40},
                            "bundle_id": {"type": "string", "pattern": _ID.pattern},
                            "investigation_id": {"type": "string", "pattern": _ID.pattern},
                            "graph_node_ids": {"type": "array", "items": {"type": "string"}, "maxItems": 100},
                            "registered_object_refs": {
                                "type": "array",
                                "items": {"type": "string", "maxLength": 200},
                                "maxItems": 100,
                            },
                            "depends_on": {
                                "type": "array",
                                "items": {"type": "string", "pattern": _ID.pattern},
                                "maxItems": 100,
                            },
                        },
                    },
                },
            },
        },
        "candidates": {
            "type": "array",
            "maxItems": MAX_RECORDS,
            "items": {
                "type": "object",
                "additionalProperties": False,
                "required": ["candidate_id", "surface_id", "category", "state", "evidence_refs", "raised_by"],
                "properties": {
                    "candidate_id": {"type": "string", "pattern": _ID.pattern},
                    "surface_id": {"type": "string", "pattern": _ID.pattern},
                    "category": {"type": "string", "minLength": 1, "maxLength": 80},
                    "title": {"type": "string", "maxLength": 200},
                    "state": {"enum": list(CANDIDATE_STATES)},
                    "evidence_refs": {"type": "array", "items": {"type": "string"}, "maxItems": 100},
                    "raised_by": {"type": "string", "minLength": 1, "maxLength": 80},
                    "dedup_key": {"type": "string", "maxLength": 300},
                    "duplicate_of": {"type": "string", "pattern": _ID.pattern},
                    "finding_id": {"type": "string", "maxLength": 100},
                    "blockers": {"type": "array", "items": {"type": "string", "maxLength": 500}, "maxItems": 20},
                    "rejection": {
                        "type": "object",
                        "additionalProperties": False,
                        "required": ["reason", "detail"],
                        "properties": {
                            "reason": {"enum": list(REJECTION_REASONS)},
                            "detail": {"type": "string", "minLength": 1, "maxLength": 1000},
                        },
                    },
                    "review": {
                        "type": "object",
                        "additionalProperties": False,
                        "required": ["reviewer", "method", "basis", "reviewed_at"],
                        "properties": {
                            "reviewer": {"type": "string", "minLength": 1, "maxLength": 80},
                            "method": {"type": "string", "maxLength": 40},
                            "basis": {"type": "string", "minLength": 1, "maxLength": 1000},
                            "reviewed_at": {"type": "string", "maxLength": 40},
                        },
                    },
                    "history": {"type": "array", "maxItems": 200, "items": {"type": "object"}},
                },
            },
        },
    },
}


class LedgerError(ValueError):
    """Raised when a ledger operation would break evidence integrity."""


def _issue(severity: str, code: str, ref: str, message: str) -> dict[str, str]:
    return {"severity": severity, "code": code, "ref": ref, "message": message}


def _safe_relpath(value: object) -> str | None:
    if not isinstance(value, str) or not value or len(value) > 240 or "\\" in value:
        return None
    path = PurePosixPath(value)
    if path.is_absolute() or PureWindowsPath(value).drive or any(part in {"", ".", ".."} for part in path.parts):
        return None
    return path.as_posix()


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def new_ledger(program: str) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "program": program,
        "updated_at": utc_now(),
        "surfaces": [],
        "evidence": [],
        "candidates": [],
    }


def load_ledger(path: Path) -> dict[str, Any]:
    if not path.is_file():
        raise LedgerError(f"Ledger file does not exist: {path}")
    if path.stat().st_size > MAX_LEDGER_BYTES:
        raise LedgerError("Ledger file exceeds the 4 MiB limit.")
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise LedgerError(f"Ledger is not valid JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise LedgerError("Ledger root must be a JSON object.")
    return data


def save_ledger(path: Path, ledger: Mapping[str, Any], *, program_dir: Path | None = None) -> dict[str, Any]:
    """Validate then write; refuses to persist a ledger with errors."""
    result = validate_ledger(ledger, program_dir=program_dir)
    if not result["valid"]:
        codes = sorted({item["code"] for item in result["issues"] if item["severity"] == "error"})
        raise LedgerError("Ledger has validation errors and was not saved: " + ", ".join(codes))
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(ledger, indent=2, sort_keys=True, ensure_ascii=True) + "\n", encoding="utf-8")
    tmp.replace(path)
    return result


# ---------------------------------------------------------------- structural


def _check_object(value: object, schema: Mapping[str, Any], ref: str, issues: list[dict[str, str]]) -> None:
    """Minimal zero-dependency JSON-schema subset check used by the ledger schema."""
    if "const" in schema and value != schema["const"]:
        issues.append(_issue("error", "schema_version_unsupported", ref, f"Expected {schema['const']!r}."))
        return
    if "enum" in schema and value not in schema["enum"]:
        issues.append(_issue("error", "invalid_enum", ref, f"Value {value!r} not in {schema['enum']}."))
        return
    kind = schema.get("type")
    if kind == "object":
        if not isinstance(value, dict):
            issues.append(_issue("error", "invalid_type", ref, "Expected an object."))
            return
        for key in schema.get("required", []):
            if key not in value:
                issues.append(_issue("error", "missing_field", f"{ref}.{key}", "Required field is missing."))
        props = schema.get("properties", {})
        for key, item in value.items():
            if key not in props:
                if schema.get("additionalProperties") is False:
                    issues.append(_issue("error", "unknown_field", f"{ref}.{key}", "Field is not allowed."))
                continue
            _check_object(item, props[key], f"{ref}.{key}", issues)
    elif kind == "array":
        if not isinstance(value, list):
            issues.append(_issue("error", "invalid_type", ref, "Expected an array."))
            return
        if len(value) > schema.get("maxItems", MAX_RECORDS):
            issues.append(_issue("error", "too_many_items", ref, "Array exceeds its limit."))
            return
        for index, item in enumerate(value):
            _check_object(item, schema.get("items", {}), f"{ref}[{index}]", issues)
    elif kind == "string":
        if not isinstance(value, str):
            issues.append(_issue("error", "invalid_type", ref, "Expected a string."))
            return
        if len(value) < schema.get("minLength", 0) or len(value) > schema.get("maxLength", 10_000):
            issues.append(_issue("error", "invalid_length", ref, "String length out of bounds."))
        pattern = schema.get("pattern")
        if pattern and not re.fullmatch(pattern, value):
            issues.append(_issue("error", "invalid_format", ref, "String does not match the required format."))


# ---------------------------------------------------------------- semantic


def _graph_node_ids(program_dir: Path | None) -> set[str] | None:
    if program_dir is None:
        return None
    db = program_dir / "toolkit.sqlite3"
    if not db.is_file():
        return None
    connection = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
    try:
        tables = {row[0] for row in connection.execute("select name from sqlite_master where type='table'")}
        if "graph_nodes" not in tables:
            return None
        return {str(row[0]) for row in connection.execute("select node_id from graph_nodes")}
    finally:
        connection.close()


def _investigation_ids(program_dir: Path | None) -> set[str] | None:
    if program_dir is None:
        return None
    db = program_dir / "toolkit.sqlite3"
    if not db.is_file():
        return None
    connection = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
    try:
        tables = {row[0] for row in connection.execute("select name from sqlite_master where type='table'")}
        if "investigation_memory" not in tables:
            return None
        return {str(row[0]) for row in connection.execute("select investigation_id from investigation_memory")}
    finally:
        connection.close()


def _finding_ids(program_dir: Path | None) -> set[str] | None:
    if program_dir is None:
        return None
    db = program_dir / "toolkit.sqlite3"
    if not db.is_file():
        return None
    connection = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
    try:
        tables = {row[0] for row in connection.execute("select name from sqlite_master where type='table'")}
        if "findings" not in tables:
            return None
        return {str(row[0]) for row in connection.execute("select id from findings")}
    finally:
        connection.close()


def _unique(rows: list[Any], key: str, kind: str, issues: list[dict[str, str]]) -> dict[str, dict[str, Any]]:
    index: dict[str, dict[str, Any]] = {}
    for row in rows:
        if not isinstance(row, dict) or not isinstance(row.get(key), str):
            continue
        if row[key] in index:
            issues.append(_issue("error", f"duplicate_{kind}_id", row[key], f"{kind} ID appears more than once."))
            continue
        index[row[key]] = row
    return index


def validate_ledger(ledger: Mapping[str, Any], *, program_dir: Path | None = None) -> dict[str, Any]:
    """Return ``{valid, issues, summary}``. Never mutates the ledger and never contacts the network."""
    issues: list[dict[str, str]] = []
    _check_object(dict(ledger) if isinstance(ledger, Mapping) else ledger, LEDGER_SCHEMA, "$", issues)
    if any(
        item["code"] in {"schema_version_unsupported", "invalid_type"} and item["ref"] in {"$", "$.schema_version"}
        for item in issues
    ):
        return {"valid": False, "issues": issues, "summary": {}}
    surfaces = _unique(list(ledger.get("surfaces") or []), "surface_id", "surface", issues)
    evidence = _unique(list(ledger.get("evidence") or []), "evidence_id", "evidence", issues)
    candidates = _unique(list(ledger.get("candidates") or []), "candidate_id", "candidate", issues)
    graph_ids = _graph_node_ids(program_dir)
    investigations = _investigation_ids(program_dir)
    findings = _finding_ids(program_dir)

    for sid, srow in surfaces.items():
        status = srow.get("status")
        if status in {"pending", "blocked"} and not str(srow.get("blocker") or "").strip():
            issues.append(_issue("error", "blocker_missing", sid, f"Surface marked {status} must state its blocker."))
        if status == "out_of_scope" and not str(srow.get("reason") or "").strip():
            issues.append(_issue("error", "scope_reason_missing", sid, "Out-of-scope surface must state why."))
        inv = srow.get("investigation_id")
        if isinstance(inv, str) and investigations is not None and inv not in investigations:
            issues.append(_issue("error", "broken_investigation_ref", sid, "Investigation ID not in local memory."))

    stale: set[str] = set()
    for eid, record in evidence.items():
        rel = _safe_relpath(record.get("path"))
        if rel is None:
            issues.append(_issue("error", "evidence_path_unsafe", eid, "Evidence path must be program-relative."))
        elif program_dir is not None:
            target = program_dir / rel
            if not target.is_file():
                issues.append(_issue("error", "evidence_missing", eid, "Evidence file does not exist."))
                stale.add(eid)
            elif target.stat().st_size > MAX_EVIDENCE_BYTES:
                issues.append(_issue("error", "evidence_too_large", eid, "Evidence file exceeds 64 MiB."))
            elif file_sha256(target) != record.get("sha256"):
                issues.append(
                    _issue("error", "evidence_digest_mismatch", eid, "Evidence changed after it was recorded.")
                )
                stale.add(eid)
        raw_prov = record.get("provenance")
        provenance: dict[str, Any] = raw_prov if isinstance(raw_prov, dict) else {}
        for node in provenance.get("graph_node_ids") or []:
            if graph_ids is not None and node not in graph_ids:
                issues.append(_issue("error", "broken_graph_ref", eid, f"Graph node {node} not in local graph."))
        inv = provenance.get("investigation_id")
        if isinstance(inv, str) and investigations is not None and inv not in investigations:
            issues.append(_issue("error", "broken_investigation_ref", eid, "Investigation ID not in local memory."))

    seen_keys: dict[str, str] = {}
    for cid, cand in candidates.items():
        state = cand.get("state")
        refs = [r for r in cand.get("evidence_refs") or [] if isinstance(r, str)]
        surface = surfaces.get(str(cand.get("surface_id")))
        if surface is None:
            issues.append(_issue("error", "broken_surface_ref", cid, "Candidate references an unknown surface."))
        elif surface.get("status") == "out_of_scope" and state != "rejected":
            issues.append(_issue("error", "state_incompatible", cid, "Active candidate on an out-of-scope surface."))
        elif surface.get("status") == "pending" and state == "confirmed":
            issues.append(_issue("error", "state_incompatible", cid, "Confirmed candidate on a pending surface."))
        finding_id = cand.get("finding_id")
        if isinstance(finding_id, str) and findings is not None and finding_id not in findings:
            issues.append(_issue("error", "broken_finding_ref", cid, "finding_id is not in the program findings."))
        for ref in refs:
            if ref not in evidence:
                issues.append(_issue("error", "broken_evidence_ref", cid, f"Evidence {ref} is not recorded."))
        valid_refs = [r for r in refs if r in evidence]
        fresh_refs = [r for r in valid_refs if r not in stale]
        if surface is not None and surface.get("fingerprint"):
            for ref in valid_refs:
                captured = evidence[ref].get("surface_fingerprint")
                if captured and captured != surface["fingerprint"]:
                    stale.add(ref)
                    if ref in fresh_refs:
                        fresh_refs.remove(ref)
                    sev = "error" if state == "confirmed" else "warning"
                    issues.append(
                        _issue(
                            sev,
                            "evidence_invalidated_by_change",
                            cid,
                            f"Evidence {ref} was captured against a different code/surface fingerprint.",
                        )
                    )
        if state != "rejected" and not valid_refs:
            sev = "warning" if state == "candidate" else "error"
            issues.append(_issue(sev, "evidence_incomplete", cid, "Candidate has no verifiable evidence reference."))
        if state == "requires_validation" and not [b for b in cand.get("blockers") or [] if str(b).strip()]:
            issues.append(_issue("error", "blocker_missing", cid, "requires_validation must name the unresolved fact."))
        if state == "rejected":
            rejection = cand.get("rejection")
            if not isinstance(rejection, dict) or not str(rejection.get("detail") or "").strip():
                issues.append(_issue("error", "rejection_reason_missing", cid, "Rejected candidate must state why."))
            elif rejection.get("reason") == "duplicate" and cand.get("duplicate_of") not in candidates:
                issues.append(_issue("error", "broken_duplicate_ref", cid, "duplicate_of must name a known candidate."))
        elif cand.get("rejection"):
            issues.append(_issue("error", "state_incompatible", cid, "Only rejected candidates carry a rejection."))
        if state == "confirmed":
            review = cand.get("review")
            if not isinstance(review, dict):
                issues.append(_issue("error", "auto_confirmation_blocked", cid, "Confirmation lacks a human review."))
            else:
                method = str(review.get("method", "")).lower()
                basis_words = set(re.findall(r"[a-z_]+", str(review.get("basis", "")).lower()))
                if method not in REVIEW_METHODS or method in AUTOMATIC_BASES:
                    issues.append(
                        _issue(
                            "error",
                            "auto_confirmation_blocked",
                            cid,
                            f"Review method {method!r} is not a human review method.",
                        )
                    )
                if basis_words and basis_words <= AUTOMATIC_BASES:
                    issues.append(
                        _issue(
                            "error",
                            "auto_confirmation_blocked",
                            cid,
                            "Confirmation basis is only a heuristic/automatic verdict.",
                        )
                    )
                if str(review.get("reviewer", "")).strip().lower() == str(cand.get("raised_by", "")).strip().lower():
                    issues.append(
                        _issue(
                            "error",
                            "review_not_independent",
                            cid,
                            "Reviewer must differ from whoever raised the candidate.",
                        )
                    )
                if str(review.get("reviewer", "")).strip().lower() in AUTOMATIC_BASES | {"bbtk", "ollama", "agent"}:
                    issues.append(_issue("error", "auto_confirmation_blocked", cid, "Reviewer must be a human."))
            if not fresh_refs:
                issues.append(
                    _issue(
                        "error",
                        "evidence_incomplete",
                        cid,
                        "Confirmed candidate needs at least one current, digest-verified evidence file.",
                    )
                )
            if cand.get("blockers"):
                issues.append(_issue("error", "state_incompatible", cid, "Confirmed candidate still lists blockers."))
        if state != "rejected":
            key = str(cand.get("dedup_key") or f"{cand.get('surface_id')}|{str(cand.get('category', '')).lower()}")
            if key in seen_keys:
                issues.append(
                    _issue(
                        "error",
                        "duplicate_candidate",
                        cid,
                        f"Same dedup key as {seen_keys[key]}; reject one as duplicate.",
                    )
                )
            else:
                seen_keys[key] = cid

    errors = [i for i in issues if i["severity"] == "error"]
    summary = summarize_ledger(ledger, stale_evidence=stale)
    return {
        "type": "evidence-ledger-validation",
        "schema_version": SCHEMA_VERSION,
        "valid": not errors,
        "error_count": len(errors),
        "warning_count": len(issues) - len(errors),
        "issues": issues,
        "summary": summary,
        "network_requests_sent": 0,
        "auto_confirmations": 0,
    }


def summarize_ledger(ledger: Mapping[str, Any], *, stale_evidence: set[str] | None = None) -> dict[str, Any]:
    surfaces = [s for s in ledger.get("surfaces") or [] if isinstance(s, dict)]
    candidates = [c for c in ledger.get("candidates") or [] if isinstance(c, dict)]
    status = Counter(str(s.get("status")) for s in surfaces)
    total = len(surfaces)
    done = status["investigated"] + status["reviewed"]
    in_scope = total - status["out_of_scope"]
    return {
        "surfaces_total": total,
        "surface_status": {key: status.get(key, 0) for key in SURFACE_STATUSES},
        "coverage_ratio": round(done / in_scope, 4) if in_scope else 0.0,
        "candidate_states": {
            key: Counter(str(c.get("state")) for c in candidates).get(key, 0) for key in CANDIDATE_STATES
        },
        "evidence_records": len([e for e in ledger.get("evidence") or [] if isinstance(e, dict)]),
        "stale_evidence": sorted(stale_evidence or set()),
        "rejection_reasons": dict(
            Counter(str((c.get("rejection") or {}).get("reason")) for c in candidates if c.get("state") == "rejected")
        ),
    }


# ---------------------------------------------------------------- mutation helpers


def _find(rows: list[dict[str, Any]], key: str, value: str) -> dict[str, Any] | None:
    return next((row for row in rows if row.get(key) == value), None)


def upsert_surface(ledger: dict[str, Any], surface: Mapping[str, Any]) -> dict[str, Any]:
    row = {k: v for k, v in surface.items() if v is not None}
    existing = _find(ledger["surfaces"], "surface_id", str(row.get("surface_id")))
    if existing is None:
        ledger["surfaces"].append(row)
    else:
        existing.clear()
        existing.update(row)
    ledger["updated_at"] = utc_now()
    return row


def registration_snapshot(path: Path) -> dict[str, list[str]]:
    """Capture object identity and dependency refs while the file still matches its digest.

    ``registered_object_refs`` is present (possibly empty) only when the file parses as a
    JSON object. A later digest mismatch can then tell "named no objects" from "never
    snapshotted". The current file bytes are not consulted again after a mismatch.
    """
    try:
        if path.stat().st_size > 262_144:
            return {}
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError):
        return {}
    if not isinstance(data, dict):
        return {}
    objects: list[str] = []
    proposal = data.get("proposal")
    if isinstance(proposal, dict):
        for side in ("owner", "actor"):
            side_row = proposal.get(side)
            if isinstance(side_row, dict) and isinstance(side_row.get("object_ref"), str):
                objects.append(side_row["object_ref"])
    control = data.get("control") if isinstance(data.get("control"), dict) else {}
    extra = control.get("object_refs") if isinstance(control, dict) else None
    if isinstance(extra, list):
        objects.extend(item for item in extra if isinstance(item, str))
    depends_raw = control.get("depends_on") if isinstance(control, dict) else None
    if not isinstance(depends_raw, list):
        depends_raw = data.get("depends_on")
    depends = (
        [item for item in depends_raw if isinstance(item, str) and _ID.fullmatch(item)]
        if isinstance(depends_raw, list)
        else []
    )
    cleaned = sorted({item for item in objects if item and len(item) <= 200 and "\n" not in item})
    out: dict[str, list[str]] = {"registered_object_refs": cleaned[:100]}
    if depends:
        out["depends_on"] = sorted(set(depends))[:100]
    return out


def add_evidence(
    ledger: dict[str, Any],
    program_dir: Path,
    evidence_id: str,
    rel_path: str,
    *,
    tool: str,
    surface_fingerprint: str | None = None,
    bundle_id: str | None = None,
    investigation_id: str | None = None,
    graph_node_ids: list[str] | None = None,
) -> dict[str, Any]:
    rel = _safe_relpath(rel_path)
    if rel is None:
        raise LedgerError("Evidence path must be relative to the program directory.")
    target = program_dir / rel
    if not target.is_file():
        raise LedgerError(f"Evidence file does not exist: {rel}")
    if _find(ledger["evidence"], "evidence_id", evidence_id):
        raise LedgerError("Evidence ID already recorded; evidence records are append-only.")
    provenance: dict[str, Any] = {"tool": tool, "captured_at": utc_now()}
    if bundle_id:
        provenance["bundle_id"] = bundle_id
    if investigation_id:
        provenance["investigation_id"] = investigation_id
    if graph_node_ids:
        provenance["graph_node_ids"] = list(graph_node_ids)
    # Frozen at registration. Evaluation must not re-read object identity from a
    # file whose digest no longer matches this row.
    provenance.update(registration_snapshot(target))
    row: dict[str, Any] = {
        "evidence_id": evidence_id,
        "path": rel,
        "sha256": file_sha256(target),
        "provenance": provenance,
    }
    if surface_fingerprint:
        row["surface_fingerprint"] = surface_fingerprint
    ledger["evidence"].append(row)
    ledger["updated_at"] = utc_now()
    return row


def add_candidate(
    ledger: dict[str, Any],
    candidate_id: str,
    surface_id: str,
    category: str,
    raised_by: str,
    evidence_refs: list[str],
    *,
    title: str | None = None,
    dedup_key: str | None = None,
    finding_id: str | None = None,
) -> dict[str, Any]:
    """New candidates always start in ``candidate``; there is no parameter to start confirmed."""
    if _find(ledger["candidates"], "candidate_id", candidate_id):
        raise LedgerError("Candidate ID already exists.")
    row: dict[str, Any] = {
        "candidate_id": candidate_id,
        "surface_id": surface_id,
        "category": category,
        "state": "candidate",
        "evidence_refs": list(evidence_refs),
        "raised_by": raised_by,
        "history": [{"state": "candidate", "at": utc_now(), "by": raised_by}],
    }
    for key, value in (("title", title), ("dedup_key", dedup_key), ("finding_id", finding_id)):
        if value:
            row[key] = value
    ledger["candidates"].append(row)
    ledger["updated_at"] = utc_now()
    return row


def review_candidate(
    ledger: dict[str, Any],
    candidate_id: str,
    new_state: str,
    reviewer: str,
    *,
    method: str | None = None,
    basis: str | None = None,
    rejection_reason: str | None = None,
    rejection_detail: str | None = None,
    blockers: list[str] | None = None,
    duplicate_of: str | None = None,
    human_attestation: bool = False,
) -> dict[str, Any]:
    """Apply one explicit human review decision. Confirmation requires ``human_attestation=True``."""
    cand = _find(ledger["candidates"], "candidate_id", candidate_id)
    if cand is None:
        raise LedgerError("Unknown candidate.")
    current = str(cand.get("state"))
    if new_state not in CANDIDATE_STATES:
        raise LedgerError("Unknown target state.")
    if new_state not in ALLOWED_TRANSITIONS.get(current, frozenset()):
        raise LedgerError(f"Transition {current} -> {new_state} is not allowed.")
    if not reviewer or reviewer.strip().lower() in AUTOMATIC_BASES | {"bbtk", "ollama", "agent"}:
        raise LedgerError("A named human reviewer is required.")
    if new_state == "confirmed":
        if not human_attestation:
            raise LedgerError("Confirmation requires an explicit human attestation (--i-reviewed-the-evidence).")
        if method not in REVIEW_METHODS:
            raise LedgerError(f"Confirmation method must be one of {REVIEW_METHODS}.")
        if not basis:
            raise LedgerError("Confirmation must describe the observed, reproducible basis.")
    if new_state == "rejected" and (rejection_reason not in REJECTION_REASONS or not rejection_detail):
        raise LedgerError("Rejection requires --reason and --detail.")
    if new_state == "requires_validation" and not blockers:
        raise LedgerError("requires_validation needs at least one --blocker naming the unresolved fact.")
    cand["state"] = new_state
    cand.pop("rejection", None)
    cand.pop("duplicate_of", None)
    if new_state == "rejected":
        cand["rejection"] = {"reason": rejection_reason, "detail": rejection_detail}
        if duplicate_of:
            cand["duplicate_of"] = duplicate_of
    if new_state == "requires_validation":
        cand["blockers"] = list(blockers or [])
    elif new_state == "confirmed":
        cand.pop("blockers", None)
    cand["review"] = {
        "reviewer": reviewer,
        "method": method or "human_manual",
        "basis": basis or rejection_detail or "; ".join(blockers or []) or "state change",
        "reviewed_at": utc_now(),
    }
    cand.setdefault("history", []).append({"state": new_state, "at": utc_now(), "by": reviewer, "from": current})
    ledger["updated_at"] = utc_now()
    return cand


def import_native_evidence(
    ledger: dict[str, Any],
    program_dir: Path,
    rel_path: str,
    surface_id: str,
    *,
    raised_by: str = "bbtk-import",
    evidence_id: str | None = None,
) -> dict[str, Any]:
    """Register native tool evidence and raise at most one candidate from it.

    Legacy tool labels such as ``confirmed`` or ``VULNERABLE`` are downgraded:
    the candidate starts as ``candidate`` and the label is kept only as a note.
    """
    rel = _safe_relpath(rel_path)
    if rel is None:
        raise LedgerError("Evidence path must be relative to the program directory.")
    target = program_dir / rel
    try:
        data = json.loads(target.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise LedgerError(f"Evidence is not readable JSON: {exc}") from exc
    packet = review_evidence(data)  # existing allowlisted minimizer; raises on unsupported input
    eid = evidence_id or "ev-" + file_sha256(target)[:16]
    if _find(ledger["evidence"], "evidence_id", eid) is None:
        add_evidence(ledger, program_dir, eid, rel, tool=str(packet["topic"]))
    labels = set(packet.get("classifications", {})) | {str(packet.get("access_result", ""))}
    positive = sorted(labels & _LEGACY_POSITIVE)
    result: dict[str, Any] = {
        "evidence_id": eid,
        "topic": packet["topic"],
        "legacy_labels": positive,
        "candidate_id": None,
        "auto_confirmed": False,
    }
    if positive:
        cid = f"cand-{packet['topic']}-{eid[3:]}"
        if _find(ledger["candidates"], "candidate_id", cid) is None:
            add_candidate(
                ledger,
                cid,
                surface_id,
                str(packet["topic"]),
                raised_by,
                [eid],
                title=f"Tool labels {positive} require human review",
            )
        result["candidate_id"] = cid
    return result


# Effective eligibility (idor-evidence-correctness-v3) ------------------------------------
# Gap kinds that prevent a recorded ``requires_validation`` candidate from being treated as
# reviewable *now*. The ledger history is never rewritten; this is a derived, read-only view.
EFFECTIVE_BLOCKING_GAPS = frozenset(
    {
        "invalid_evidence",
        "stale_evidence",
        "insufficient_capture",
        "blocked_by_scope",
        "duplicate_candidate",
        "contradictory_observation",
        "session_control",
        "access_proof",
    }
)
EFFECTIVE_NON_REVIEWABLE_STATUSES = frozenset(
    {"integrity_blocked", "blocked", "duplicate", "stop_recommended", "abstain"}
)


def effective_eligibility(
    ledger: Mapping[str, Any], plan_candidates: list[Mapping[str, Any]] | None
) -> list[dict[str, Any]]:
    """Derive the *current* reviewability of every candidate without mutating the ledger.

    ``plan_candidates`` are the per-candidate results of the evidence-gap planner (status and
    gaps already reflect digest checks, broken references, expiry, scope, origin, session
    control and access proof). A candidate is ``effective_reviewable`` only when the ledger
    records ``requires_validation`` **and** no current blocker applies. Missing human
    attestations are not blockers here: ``requires_validation`` already means a human decides.
    """
    by_id = {str(row.get("candidate_id")): row for row in plan_candidates or [] if isinstance(row, Mapping)}
    out: list[dict[str, Any]] = []
    for cand in ledger.get("candidates") or []:
        if not isinstance(cand, Mapping):
            continue
        cid = str(cand.get("candidate_id"))
        state = str(cand.get("state"))
        row = by_id.get(cid) or {}
        status = str(row.get("status") or "unknown")
        blockers = sorted(
            {
                str(g.get("kind"))
                for g in row.get("gaps") or []
                if isinstance(g, Mapping) and g.get("kind") in EFFECTIVE_BLOCKING_GAPS
            }
        )
        if status in EFFECTIVE_NON_REVIEWABLE_STATUSES:
            blockers = sorted({*blockers, f"status:{status}"})
        reviewable = state == "requires_validation" and not blockers
        if state in {"rejected", "confirmed"}:
            effective = state
        elif state == "requires_validation" and blockers:
            effective = "blocked"
        else:
            effective = state
        out.append(
            {
                "candidate_id": cid,
                "ledger_state": state,
                "effective_state": effective,
                "effective_reviewable": reviewable,
                "blockers": blockers,
                "ledger_modified": False,
            }
        )
    return out


def render_markdown(ledger: Mapping[str, Any], validation: Mapping[str, Any]) -> str:
    summary = validation.get("summary") or summarize_ledger(ledger)
    lines = [
        f"# Evidence ledger — {ledger.get('program')}",
        "",
        f"Schema `{ledger.get('schema_version')}` · valid: **{validation.get('valid')}** · "
        f"errors {validation.get('error_count', 0)} · warnings {validation.get('warning_count', 0)}",
        "",
        "## Coverage",
        "",
        "| status | surfaces |",
        "|---|---|",
    ]
    lines += [f"| {k} | {v} |" for k, v in summary.get("surface_status", {}).items()]
    lines += [
        "",
        f"Coverage ratio (investigated+reviewed / in-scope): {summary.get('coverage_ratio')}",
        "",
        "## Candidates",
        "",
        "| id | surface | category | state | evidence | note |",
        "|---|---|---|---|---|---|",
    ]
    for cand in ledger.get("candidates") or []:
        note = ""
        if cand.get("state") == "rejected":
            note = f"{(cand.get('rejection') or {}).get('reason')}: {(cand.get('rejection') or {}).get('detail')}"
        elif cand.get("blockers"):
            note = "blocked: " + "; ".join(cand["blockers"])
        lines.append(
            f"| {cand.get('candidate_id')} | {cand.get('surface_id')} | {cand.get('category')} | "
            f"{cand.get('state')} | {', '.join(cand.get('evidence_refs') or []) or '—'} | {note} |"
        )
    blocked = [s for s in ledger.get("surfaces") or [] if s.get("status") in {"blocked", "pending"}]
    if blocked:
        lines += ["", "## Open surfaces", ""]
        lines += [f"- `{s.get('surface_id')}` ({s.get('status')}): {s.get('blocker')}" for s in blocked]
    if validation.get("issues"):
        lines += ["", "## Validation issues", ""]
        lines += [f"- **{i['severity']}** `{i['code']}` {i['ref']}: {i['message']}" for i in validation["issues"]]
    lines += [
        "",
        "_Offline human-review ledger. No state here was set automatically; `confirmed` "
        "requires an independent human reviewer and current digest-verified evidence._",
        "",
    ]
    return "\n".join(lines)
