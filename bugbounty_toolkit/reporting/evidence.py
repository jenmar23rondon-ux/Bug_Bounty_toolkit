from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4


def utc_stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")


def write_evidence_json(destination: Path, data: dict[str, object], prefix: str = "evidence") -> Path:
    destination.mkdir(parents=True, exist_ok=True)
    path = destination / f"{utc_stamp()}-{uuid4().hex}-{prefix}.json"
    with path.open("x", encoding="utf-8") as handle:
        json.dump(data, handle, indent=2, sort_keys=True)
    return path
