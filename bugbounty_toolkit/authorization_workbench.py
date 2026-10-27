"""Offline, read-only projections of ledger-bound HTTP captures. No access classifier."""

from __future__ import annotations

import hashlib
import json
import re
from collections import Counter
from pathlib import Path
from typing import Any

from .access_control.comparison import parse_json
from .core.records import ProgramPaths
from .dashboard_triage import load_ledger_view

MAX_BYTES = 2_000_000
MAX_FIELDS = 1000
MAX_CAPTURES = 100
# Other property names use opaque ordinal labels; arbitrary keys can themselves be secrets.
PUBLIC_KEYS = frozenset(
    "id owner owner_id resource resource_id role roles success error message data items name status shared public value count nested enabled empty nullable".split()
)
CLASSES = frozenset(
    {"denied", "legitimate_access", "insufficient_evidence", "possible_unauthorized_access", "inconclusive"}
)
# Display-only allowlist of public engine explanations; never used to decide a state.
SAFE_REASONS = frozenset(
    {
        "Application-level success was false and no owner resource or private marker was observed.",
        "The crossed response does not establish either private-data access or an application-level denial.",
        "Every tested crossed direction matched its explicit application-denial predicate.",
        "All tested restricted roles met the configured application-denial predicate.",
        "Positive role controls or restricted-role denial evidence were incomplete or contradictory.",
    }
)


def _saved_reason(value: object) -> str:
    if value is None:
        return "No saved explanation."
    return (
        value
        if isinstance(value, str) and value in SAFE_REASONS
        else "Free text withheld; inspect saved predicates in the private artifact."
    )


PREDICATES = (
    "application_success",
    "resource_match",
    "private_match",
    "owner_resource_match",
    "owner_private_match",
    "denial_match",
    "controls_valid",
)


def _read(paths: ProgramPaths, row: dict[str, Any]) -> dict[str, Any]:
    rel = row.get("path")
    if not isinstance(rel, str) or Path(rel).is_absolute() or ".." in Path(rel).parts:
        raise ValueError("unsafe_reference")
    root = paths.program_dir.resolve()
    target = paths.program_dir / rel
    if any(p.is_symlink() for p in (paths.program_dir, *target.parents, target)):
        raise ValueError("unsafe_reference")
    if not target.resolve().is_relative_to(root):
        raise ValueError("unsafe_reference")
    with target.open("rb") as handle:
        raw = handle.read(MAX_BYTES + 1)
    if len(raw) > MAX_BYTES:
        raise ValueError("capture_too_large")
    if hashlib.sha256(raw).hexdigest() != row.get("sha256"):
        raise ValueError("altered_reference")
    data = parse_json(raw.decode("utf-8"))
    if not isinstance(data, dict):
        raise ValueError("unsupported_capture")
    return data


def _captures(data: dict[str, Any]) -> list[dict[str, Any]]:
    """Native predicate-only evidence and HAR retain their existing semantics."""
    if data.get("type") == "access-control":
        steps = data.get("steps")
        return (
            [dict(s, method=None, body_available=False) for s in steps[:MAX_CAPTURES] if isinstance(s, dict)]
            if isinstance(steps, list)
            else []
        )
    log = data.get("log")
    if isinstance(log, dict) and isinstance(log.get("entries"), list):
        out = []
        for entry in log["entries"][:MAX_CAPTURES]:
            if not isinstance(entry, dict):
                continue
            req, resp = entry.get("request"), entry.get("response")
            req = req if isinstance(req, dict) else {}
            resp = resp if isinstance(resp, dict) else {}
            content = resp.get("content")
            content = content if isinstance(content, dict) else {}
            out.append(
                {
                    "method": req.get("method"),
                    "status_code": resp.get("status"),
                    "body_text": content.get("text") if content.get("encoding") is None else None,
                    "mime_type": content.get("mimeType"),
                    "body_available": isinstance(content.get("text"), str) and content.get("encoding") is None,
                }
            )
        return out
    if data.get("type") == "authorization-workbench-lab" and data.get("authorized_captures") is True:
        captures = data.get("captures")
        return [c for c in captures[:MAX_CAPTURES] if isinstance(c, dict)] if isinstance(captures, list) else []
    return []


def _fields(value: Any) -> dict[tuple[str, ...], Any]:
    result: dict[tuple[str, ...], Any] = {}

    def visit(item: Any, path: tuple[str, ...], depth: int) -> None:
        if depth > 20 or len(result) >= MAX_FIELDS:
            raise ValueError("field_limit")
        result[path] = item
        if isinstance(item, dict):
            for key, child in item.items():
                visit(child, (*path, key), depth + 1)
        elif isinstance(item, list):
            for index, child in enumerate(item):
                visit(child, (*path, str(index)), depth + 1)

    visit(value, (), 0)
    return result


def _kind(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, (str, dict, list)) and not value:
        return "empty_" + type(value).__name__
    return type(value).__name__


def build_workbench(paths: ProgramPaths, selections: list[str] | None = None) -> dict[str, Any]:
    """Select existing evidence-id@index records; never infer account identities."""
    view = load_ledger_view(paths)
    ledger = view.get("ledger") or {}
    catalog: list[dict[str, Any]] = []
    private: dict[str, dict[str, Any]] = {}
    problems = []
    saved_assessments = []
    evidence = ledger.get("evidence")
    evidence = evidence if isinstance(evidence, list) else []
    counts = Counter(
        row.get("evidence_id") for row in evidence if isinstance(row, dict) and isinstance(row.get("evidence_id"), str)
    )
    for row in evidence[:MAX_CAPTURES]:
        if not isinstance(row, dict):
            continue
        eid = row.get("evidence_id")
        if not isinstance(eid, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", eid):
            continue
        if counts[eid] != 1:
            problems.append({"evidence_id": eid, "status": "ambiguous_reference"})
            continue
        try:
            data = _read(paths, row)
            assessment = data.get("access_control_assessment")
            if isinstance(assessment, dict):
                classification = assessment.get("classification")
                saved_assessments.append(
                    {
                        "evidence_id": eid,
                        "classification": classification
                        if isinstance(classification, str) and classification in CLASSES
                        else None,
                        "reason": _saved_reason(assessment.get("reason")),
                        "predicates": {p: assessment[p] for p in PREDICATES if type(assessment.get(p)) is bool},
                    }
                )
            for index, capture in enumerate(_captures(data)):
                key = f"{eid}@{index}"
                status = capture.get("status_code")
                present = type(status) is int and 100 <= status <= 599
                method = capture.get("method")
                saved = capture.get("assessment")
                saved = saved if isinstance(saved, dict) else {}
                classification = saved.get("classification")
                public = {
                    "selection": key,
                    "evidence_id": eid,
                    "sha256": row["sha256"],
                    "capture_index": index,
                    "method": method
                    if isinstance(method, str)
                    and method in {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}
                    else None,
                    "status_code": status if present else None,
                    "response_state": ("denied_saved" if classification == "denied" else "present")
                    if present
                    else "missing",
                    "saved_classification": classification
                    if isinstance(classification, str) and classification in CLASSES
                    else None,
                    "saved_reason": _saved_reason(saved.get("reason")),
                    "saved_predicates": {p: capture[p] for p in PREDICATES if type(capture.get(p)) is bool},
                    "response_type": "unavailable",
                    "source_format": "har"
                    if isinstance(data.get("log"), dict)
                    else "native_predicates"
                    if data.get("type") == "access-control"
                    else "authorized_lab",
                    "body_state": "unavailable",
                }
                fields = None
                if present and capture.get("body_available") is True and isinstance(capture.get("body_text"), str):
                    try:
                        body = parse_json(capture["body_text"])
                        fields = _fields(body)
                        public.update(response_type="json", body_state="available")
                    except ValueError:
                        mime = capture.get("mime_type")
                        public.update(
                            response_type=mime
                            if isinstance(mime, str) and mime in {"text/html", "text/plain", "application/json"}
                            else "non_json_or_limited",
                            body_state="withheld",
                        )
                catalog.append(public)
                private[key] = {"public": public, "fields": fields}
        except (OSError, ValueError, RecursionError):
            problems.append({"evidence_id": eid, "status": "unusable_reference"})
    selected = selections or []
    if len(selected) > 3 or len(set(selected)) != len(selected) or any(k not in private for k in selected):
        raise ValueError("Choose up to three distinct existing captures.")
    columns = [private[k]["public"] for k in selected]
    field_maps = [private[k]["fields"] for k in selected]
    pointers = sorted({p for m in field_maps if m is not None for p in m})
    aliases: dict[tuple[str, ...], str] = {}
    for pointer in pointers:
        if not pointer:
            aliases[pointer] = ""
        else:
            key = pointer[-1]
            parents = [
                mapping[pointer[:-1]] for mapping in field_maps if mapping is not None and pointer[:-1] in mapping
            ]
            array_index = bool(parents) and all(isinstance(parent, list) for parent in parents)
            segment = key if key in PUBLIC_KEYS or array_index else f"field-{len(aliases)}"
            aliases[pointer] = aliases[pointer[:-1]] + "/" + segment
    rows = []
    for pointer in pointers:
        cells = []
        signatures = []
        for mapping in field_maps:
            if mapping is None:
                cells.append({"state": "unavailable"})
            elif pointer not in mapping:
                cells.append({"state": "absent"})
                signatures.append(("absent", ""))
            else:
                item = mapping[pointer]
                kind = _kind(item)
                cells.append({"state": kind, "value": "[withheld]"})
                # Compare privately, before display minimization; no body hashes leave this function.
                signatures.append((kind, json.dumps(item, sort_keys=True, ensure_ascii=True)))
        rows.append(
            {"pointer": aliases[pointer] or "/", "cells": cells, "observed_difference": len(set(signatures)) > 1}
        )
    return {
        "type": "authorization-comparison-workbench",
        "read_only": True,
        "network_requests_sent": 0,
        "model_calls": 0,
        "finding_confirmed": False,
        "saved_assessments": saved_assessments,
        "catalog": catalog,
        "columns": columns,
        "fields": rows,
        "reference_issues": problems,
        "ledger_status": view["status"],
        "pending_controls": [
            "Human review of ownership, roles, public/shared resource expectations and missing captures."
        ],
        "notice": "Saved classifications and predicates are observations from existing engines. HTTP 200 and body differences do not establish unauthorized access. Text and scalar values are withheld; arrays align by index. Choose A/B/C explicitly; absent C is never fabricated.",
    }
