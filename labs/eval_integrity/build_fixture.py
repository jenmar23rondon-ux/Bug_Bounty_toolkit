"""Deterministic synthetic capture for the end-to-end contract test (loopback origin only).

Authored before any pipeline run; regenerate only into a temporary directory and compare.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

ORIGIN = "http://127.0.0.1:8141"
VERSION = "e2e-contract-1.0"
# Synthetic canaries: they must never appear in any pipeline output.
CANARIES = ("tok-alice-CANARY-7f3a", "tok-bob-CANARY-91c2", "tok-carol-CANARY-5d0e")


def _ex(path: str, token: str | None, resp: Any | None, *, method: str = "GET") -> dict[str, Any]:
    headers = [{"name": "Authorization", "value": "Bearer " + token}] if token else []
    request: dict[str, Any] = {"method": method, "url": ORIGIN + path, "headers": headers}
    text = "" if resp is None else json.dumps(resp, sort_keys=True)
    return {
        "request": request,
        "response": {"status": 200, "content": {"mimeType": "application/json", "text": text}},
    }


def _entries() -> list[dict[str, Any]]:
    alice, bob, carol = CANARIES
    incomplete = _ex("/api/notes/77", carol, {"note_id": 77})
    del incomplete["request"]["method"]
    return [
        _ex("/api/invoices/5001", alice, {"invoice_id": 5001, "total": 3}),
        _ex("/api/invoices/5002", bob, {"invoice_id": 5002, "total": 4}),
        _ex("/api/reports/9001", alice, {"report_id": 9001}),
        _ex("/api/projects/3101", carol, {"project_id": 3101, "name": "p"}),
        _ex("/api/projects/3102", bob, {"project_id": 3102, "name": "q"}),
        incomplete,
    ]


SCENARIOS: list[dict[str, Any]] = [
    {
        "id": "E01",
        "description": "Same invoice endpoint template seen from two synthetic sessions.",
        "entries": [0, 1],
        "expected_eligibility": "proposals_ready",
        "expected_pair_types": ["invoice"],
        "forbidden_pair_types": [],
        "ambiguous_types": [],
        "expected_confirmed": False,
    },
    {
        "id": "E02",
        "description": "Single-session report view: not eligible for a pair, must be a structured rejection.",
        "entries": [2],
        "expected_eligibility": "insufficient_evidence",
        "expected_pair_types": [],
        "forbidden_pair_types": ["report"],
        "ambiguous_types": [],
        "expected_confirmed": False,
    },
    {
        "id": "E03",
        "description": "Project endpoint template seen from two other sessions (cross-pairing guard).",
        "entries": [3, 4],
        "expected_eligibility": "proposals_ready",
        "expected_pair_types": ["project"],
        "forbidden_pair_types": [],
        "ambiguous_types": [],
        "expected_confirmed": False,
    },
    {
        "id": "E04",
        "description": "Incomplete request (no method): importer must reject it, not repair it.",
        "entries": [5],
        "expected_eligibility": "rejected_at_import",
        "expected_pair_types": [],
        "forbidden_pair_types": [],
        "ambiguous_types": [],
        "expected_confirmed": False,
    },
]


def build(out: Path) -> None:
    out.mkdir(parents=True, exist_ok=True)
    har = {
        "log": {"version": "1.2", "creator": {"name": "bbtk-e2e-contract", "version": VERSION}, "entries": _entries()}
    }
    gt = {"corpus_version": VERSION, "origin": ORIGIN, "scenarios": SCENARIOS}
    files = {
        "captures.har": json.dumps(har, indent=1, sort_keys=True) + "\n",
        "ground_truth.json": json.dumps(gt, indent=1, sort_keys=True) + "\n",
    }
    for name, text in files.items():
        (out / name).write_text(text, encoding="utf-8")
    manifest = "".join(f"{hashlib.sha256(t.encode()).hexdigest()}  {n}\n" for n, t in sorted(files.items()))
    (out / "MANIFEST.sha256").write_text(manifest, encoding="utf-8")


if __name__ == "__main__":  # pragma: no cover - manual regeneration into an explicit path only
    import sys

    build(Path(sys.argv[1]))
