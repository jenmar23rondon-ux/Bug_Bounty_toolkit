"""Evaluate the frozen response-control corpus without issuing requests."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from bugbounty_toolkit.analysis.authorization_denial import assess_pair_authorization

ROOT = Path(__file__).resolve().parent
RESOURCE = {"data": {"id": "SYNTH-17", "marker": "synthetic-private"}}


def evaluate() -> dict[str, Any]:
    raw = (ROOT / "cases.json").read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    if digest != (ROOT / "MANIFEST.sha256").read_text().split()[0]:
        raise ValueError("Independent corpus digest mismatch")
    rows = []
    for case in json.loads(raw)["cases"]:

        def response(role: str) -> str:
            body = case.get(role + "_body", RESOURCE)
            body = body if isinstance(body, str) else json.dumps(body)
            headers = "".join(f"{key}: {value}\r\n" for key, value in case.get(role + "_headers", {}).items())
            return f"HTTP/1.1 {case.get(role + '_status', 200)} Synthetic\r\n{headers}\r\n{body}"

        outcome = assess_pair_authorization(response("owner"), response("actor"))
        rows.append({"id": case["id"], "expected": case["expected"], "actual": outcome.outcome})
    return {
        "corpus_sha256": digest,
        "cases": len(rows),
        "correct": sum(row["actual"] == row["expected"] for row in rows),
        "false_positive_access": sum(
            row["actual"] == "possible_access" and row["expected"] != "possible_access" for row in rows
        ),
        "false_negative_access": sum(
            row["actual"] != "possible_access" and row["expected"] == "possible_access" for row in rows
        ),
        "abstentions": sum(row["actual"] == "inconclusive" for row in rows),
        "rows": rows,
    }


if __name__ == "__main__":
    print(json.dumps(evaluate(), indent=2, sort_keys=True))
