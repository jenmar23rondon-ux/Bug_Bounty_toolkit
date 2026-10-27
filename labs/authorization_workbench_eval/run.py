"""Reproducible offline metrics. Run: python -m labs.authorization_workbench_eval.run."""

from __future__ import annotations

import json
from pathlib import Path
import statistics
import tempfile
import time
from typing import Any
from unittest.mock import patch

from fastapi.testclient import TestClient

from bugbounty_toolkit.authorization_workbench import build_workbench
from bugbounty_toolkit.dashboard import create_app
from .fixtures import populate


def evaluate() -> dict[str, Any]:
    with tempfile.TemporaryDirectory() as directory:
        paths = populate(Path(directory))
        artifact = json.loads((paths.evidence_dir / "synthetic.json").read_text())
        canary_body = json.loads(artifact["captures"][8]["body_text"])
        ledger = paths.program_dir / "ledger/evidence-ledger.json"
        before = ledger.read_bytes()
        with patch("socket.socket.connect", side_effect=AssertionError("external traffic forbidden")):
            with TestClient(
                create_app(paths.root, paths.program), base_url="http://127.0.0.1", client=("127.0.0.1", 1234)
            ) as client:
                durations = []
                result = None
                for _ in range(25):
                    start = time.perf_counter()
                    response = client.get("/api/authorization-workbench?a=ev-lab@0&b=ev-lab@1&c=ev-lab@5")
                    response.raise_for_status()
                    result = response.json()
                    durations.append((time.perf_counter() - start) * 1000)
                assert result is not None
                canary_view = json.dumps(build_workbench(paths, ["ev-lab@0", "ev-lab@8"]))
                exposed = sum(value in canary_view for value in (canary_body["token"], canary_body["owner"]))
                assert exposed == 0
                assert ledger.read_bytes() == before
                fields = {r["pointer"]: r for r in result["fields"]}
                assert fields["/items/0"]["observed_difference"] is False
                assert fields["/items/1"]["observed_difference"] is True
                assert all(c["sha256"] == result["catalog"][0]["sha256"] for c in result["columns"])
                assert result["columns"][2]["response_state"] == "missing"
                large = build_workbench(paths, ["ev-lab@0", "ev-lab@6"])
                assert len(large["fields"]) > 100
                html = build_workbench(paths, ["ev-lab@0", "ev-lab@7"])
                assert html["columns"][1]["body_state"] == "withheld"
        return {
            "samples": 25,
            "endpoint_projection_median_ms": round(statistics.median(durations), 3),
            "aligned_fields": len(fields),
            "alignment_oracle_checks": 4,
            "alignment_oracle_failures": 0,
            "false_difference_oracle_checks": 2,
            "false_differences": 0,
            "lost_sha256_references": 0,
            "canaries_exposed": exposed,
            "missing_presented_as_denied": 0,
            "ledger_changed": False,
            "network_requests_sent": 0,
            "steps_to_locate_difference": 4,
            "steps_definition": "Select A, select B, select optional C, compare. Difference rows are highlighted by default. This is an interaction count, not a human timing study.",
        }


if __name__ == "__main__":
    print(json.dumps(evaluate(), indent=2))
