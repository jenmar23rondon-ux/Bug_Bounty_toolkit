from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path


def utc_stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")


def write_evidence_json(destination: Path, data: dict[str, object], prefix: str = "evidence") -> Path:
    destination.mkdir(parents=True, exist_ok=True)
    path = destination / f"{utc_stamp()}-{prefix}.json"
    path.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")
    return path
