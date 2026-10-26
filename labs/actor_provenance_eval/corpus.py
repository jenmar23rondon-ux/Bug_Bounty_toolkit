"""Frozen synthetic scenarios. Credentials are generated at runtime, never serialized."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from typing import Any

from bugbounty_toolkit.analysis.evidence_engine import CaptureSource, EvidenceRecord, _record

KEY = b"synthetic-local-evaluation-key-0001"
PROGRAM = "actor-lab"


def corpus() -> tuple[list[EvidenceRecord], dict[str, Any], list[str | None]]:
    # label, human account alias, cookie context, color, expected account alias
    cases = [
        ("owner", "a", "a1", "red", "a"),
        ("second_account", "b", "b1", "blue", None),
        ("owner", "a", "a2", "red", "a"),  # same account, different session
        ("owner", "a", "a3", "red", "a"),  # rotated session
        ("unknown", None, "b1", "red", None),  # wrong Pwnfox color
        ("anonymous", None, None, None, None),
        ("unknown", None, None, None, None),
        ("role_a", "c", "duplicate", None, None),
        ("role_b", "d", "duplicate", None, None),  # incompatible declarations
        ("owner", "a", "a4", "blue", "a"),
        ("second_account", "a", "b2", None, None),  # contradictory label
    ]
    records = []
    labels = []
    truth = []
    for index, (label, account, cookie, color, expected) in enumerate(cases):
        # A runtime canary only; fixtures/reports never include its plaintext.
        headers = {"Cookie": "sid=" + "BBTK" + "_CANARY_" + cookie} if cookie else {}
        source = CaptureSource(
            "har",
            f"/log/entries[{index}]",
            "https://synthetic.invalid/items/1",
            "GET",
            request_headers=headers,
            response_headers={"Set-Cookie": "sid=rotated"} if index == 3 else {},
            captured_at=f"2026-01-01T00:{index:02d}:00Z",
        )
        record = _record(source, Path("capture.har"), KEY)
        records.append(replace(record, evidence_id=f"fixture-{index}"))
        row: dict[str, object] = {
            "source_path": record.provenance[0].source_path,
            "locator": source.locator,
            "label": label,
        }
        if account:
            row.update(account=account, declared_by_human=True)
        if color:
            row["pwnfox_color"] = color
        labels.append(row)
        truth.append(expected)
    return (
        records,
        {"schema": "bbtk.actor-labels/1", "program": PROGRAM, "labels": labels, "distinct_accounts": [["a", "b"]]},
        truth,
    )
