"""Minimized lifecycle evidence. Raw HTML and payloads are not stored."""

from __future__ import annotations

import hashlib
import json
import re
from typing import Mapping

_LEAKS = (
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bsk-[A-Za-z0-9_-]{12,}"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}"),
    re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}"),
    re.compile(r"(?i)\bBBTK[-_]CANARY[-_]"),
    re.compile(r"(?i)\bCANARY[-_][A-Za-z0-9_-]{8,}"),
    re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/-]+=*"),
    re.compile(r"(?i)\bauthorization\s*[:=]"),
    re.compile(r"(?i)\bset-cookie\s*:"),
    re.compile(r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"),
)


def integrity_sha256(payload: Mapping[str, object]) -> str:
    body = {key: value for key, value in payload.items() if key != "integrity_sha256"}
    raw = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def count_secret_leaks(text: str) -> int:
    return sum(len(pattern.findall(text)) for pattern in _LEAKS)


def count_confirmed(value: object) -> int:
    """Count boolean confirmation flags. The classification string ``confirmed`` is not a flag."""
    found = 0
    if isinstance(value, dict):
        for key, item in value.items():
            if key in {"finding_confirmed", "confirmed", "pipeline_confirms_finding"} and item is True:
                found += 1
            else:
                found += count_confirmed(item)
    elif isinstance(value, list):
        for item in value:
            found += count_confirmed(item)
    return found


def build_case_evidence(
    *,
    case_id: str,
    observed: Mapping[str, object],
    cleanup_ok: bool,
    execution_observed: object,
    browser_error: str | None,
) -> dict[str, object]:
    storage_id = observed.get("storage_id")
    record: dict[str, object] = {
        "case_id": case_id,
        "write_status": observed.get("write_status"),
        "storage_id": storage_id if isinstance(storage_id, str) else None,
        "view_status": observed.get("view_status"),
        "render_context": observed.get("render_context"),
        "marker_present": bool(observed.get("marker_in_html")),
        "execution_observed": execution_observed,
        "csp": {
            "restrictive_for_inline": bool(observed.get("csp_restrictive")),
            "directives": observed.get("csp_directives") or [],
        },
        "sanitize_path": observed.get("sanitize_path"),
        "actor": {
            "writer": observed.get("actor_writer"),
            "viewer": observed.get("actor_viewer"),
        },
        "cleanup_status": "cleared" if cleanup_ok else "residue",
        "browser_error": browser_error,
        "finding_confirmed": False,
        "human_review_required": True,
        "storage_sha256": observed.get("storage_sha256"),
        "note": (
            "Write success is not stored XSS. A marker in HTML is not execution. "
            "finding_confirmed stays false pending human review."
        ),
    }
    record["integrity_sha256"] = integrity_sha256(record)
    return record
