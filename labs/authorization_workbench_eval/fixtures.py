"""Synthetic captures; no server, credentials, private canaries or requests."""

from __future__ import annotations

import json
import secrets
from pathlib import Path
from typing import Any

from bugbounty_toolkit.analysis.access_assessment import assess_access_control_data
from bugbounty_toolkit.analysis.evidence_ledger import add_evidence, new_ledger, save_ledger
from bugbounty_toolkit.core.records import ProgramPaths


def populate(root: Path) -> ProgramPaths:
    paths = ProgramPaths(root, "workbench-lab")
    paths.evidence_dir.mkdir(parents=True)
    bodies: list[tuple[int | None, Any, str | None]] = [
        (
            200,
            {"success": True, "owner": "A", "role": "owner", "nullable": None, "empty": "", "items": [1, 2]},
            "legitimate_access",
        ),
        (403, {"success": False, "error": "Denied", "items": [1, 3]}, "denied"),
        (200, {"success": False, "error": "Denied"}, "denied"),
        (403, {"error": {"message": "Forbidden"}}, "denied"),
        (200, {"public": True, "shared": True, "roles": ["reader", "editor"]}, None),
        (None, None, None),
        (200, {"data": "x" * 100_000, "items": list(range(100))}, None),
        (200, '<script>throw Error("must never execute")</script>', None),
    ]
    denial = assess_access_control_data(
        {
            "accounts_authorized": True,
            "resource_private": True,
            "expected_cross_access": "deny",
            "checks": {
                "owner_resource": "a",
                "actor_resource": "b",
                "owner_marker": "private-a",
                "actor_marker": "private-b",
            },
        },
        {
            "type": "access-control",
            "mode": "read",
            "controls_valid": True,
            "steps": [
                {"step": "owner_control", "application_success": True, "resource_match": True, "private_match": True},
                {"step": "actor_control", "application_success": True, "resource_match": True, "private_match": True},
                {
                    "step": "cross_read",
                    "application_success": False,
                    "owner_resource_match": False,
                    "owner_private_match": False,
                },
            ],
        },
    )
    captures = []
    for status, body, classification in bodies:
        captures.append(
            {
                "method": "GET",
                "status_code": status,
                "body_available": status is not None,
                "body_text": json.dumps(body) if not isinstance(body, str) else body,
                "assessment": denial if classification == "denied" else {"classification": classification},
            }
        )
    private_marker = secrets.token_hex(24)
    captures.append(
        {
            "method": "GET",
            "status_code": 200,
            "body_available": True,
            "body_text": json.dumps(
                {
                    "token": "eyJ" + secrets.token_hex(20) + ".payload.signature",
                    "owner": private_marker,
                    private_marker: "/home/synthetic/private.json",
                }
            ),
        }
    )
    path = paths.evidence_dir / "synthetic.json"
    path.write_text(
        json.dumps({"type": "authorization-workbench-lab", "authorized_captures": True, "captures": captures}),
        encoding="utf-8",
    )
    ledger = new_ledger(paths.program)
    add_evidence(ledger, paths.program_dir, "ev-lab", "evidence/synthetic.json", tool="synthetic-lab")
    save_ledger(paths.program_dir / "ledger/evidence-ledger.json", ledger, program_dir=paths.program_dir)
    return paths
