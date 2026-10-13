from __future__ import annotations

import json
from pathlib import Path

from .deduplicator import deduplicate_results


def parse_ffuf_results(path: Path) -> list[dict[str, object]]:
    if not path.exists():
        raise FileNotFoundError(path)
    data = json.loads(path.read_text(encoding="utf-8") or "{}")
    parsed: list[dict[str, object]] = []
    for result in data.get("results", []):
        parsed.append(
            {
                "url": result.get("url"),
                "status": result.get("status"),
                "length": result.get("length"),
                "words": result.get("words"),
                "lines": result.get("lines"),
                "redirectlocation": result.get("redirectlocation"),
                "input": result.get("input"),
            }
        )
    return deduplicate_results(parsed)
