"""Reproducible offline evaluation; only aggregate metrics may be shared."""

from __future__ import annotations

import json
from pathlib import Path
import secrets
import socket
import tempfile
from typing import Any
from unittest.mock import patch

from bugbounty_toolkit.access_control.comparison import exact
from bugbounty_toolkit.analysis.request_variation_plan import build_plan, save_plan, validate_plan
from bugbounty_toolkit.core.private_files import atomic_private_write

from .fixtures import CORPUS_VERSION, corpus


def evaluate() -> dict[str, Any]:
    metrics = dict.fromkeys(
        (
            "structurally_correct_variations",
            "accidental_field_changes",
            "correctly_rejected_cases",
            "types_preserved",
            "duplicates_generated",
            "duplicates_skipped",
            "unauthorized_variations",
            "network_requests_sent",
            "secrets_in_plans",
            "origin_rewrites",
            "unexpected_results",
        ),
        0,
    )
    results = []
    with (
        tempfile.TemporaryDirectory() as directory,
        patch.object(socket.socket, "connect", side_effect=AssertionError("Network prohibited in this lab")),
        patch.object(socket, "getaddrinfo", side_effect=AssertionError("DNS prohibited in this lab")),
    ):
        root = Path(directory)
        capture, config_path, scope = root / "capture.http", root / "declaration.json", root / "scope.txt"
        atomic_private_write(scope, b"https://lab.test\n")
        # A runtime secret is deliberately absent from fixture files, reports and Git.
        private_value = secrets.token_hex(24)
        for row in corpus():
            raw = row["raw"].replace("[REDACTED]", private_value).encode()
            config = row["declaration"]
            atomic_private_write(capture, raw, force=True)
            atomic_private_write(config_path, json.dumps(config).encode(), force=True)
            plan = build_plan(capture, config_path, scope)
            variants = plan["variants"]
            codes = [item["code"] for item in plan["incompatible"]]
            expected = row["expected_code"]
            correct = codes == [expected] and not variants if expected else len(variants) == 1 and not codes
            metrics["unexpected_results"] += int(not correct)
            metrics["correctly_rejected_cases"] += int(bool(expected) and correct)
            metrics["duplicates_skipped"] += plan["duplicates_skipped"]
            metrics["duplicates_generated"] += len(variants) - len({item["id"] for item in variants})
            metrics["secrets_in_plans"] += int(private_value in json.dumps(plan))
            metrics["accidental_field_changes"] += int(capture.read_bytes() != raw)
            for variant in variants:
                diff = variant["diff"]
                target = next(item for item in config["resources"] if item["name"] == variant["resource_ref"])
                source = next(item for item in config["resources"] if item["name"] == config["source"])
                structurally_correct = (
                    variant["fields_changed"] == 1
                    and diff["selector"] == config["selector"]
                    and exact(diff["before"], source["value"])
                    and exact(diff["after"], target["value"])
                )
                metrics["structurally_correct_variations"] += int(structurally_correct)
                metrics["accidental_field_changes"] += int(not structurally_correct)
                metrics["types_preserved"] += int(type(diff["before"]) is type(diff["after"]))
                metrics["unauthorized_variations"] += int(target["synthetic"] is not True)
            assert validate_plan(plan, capture, config_path, scope)
            output = root / row["name"] / "plan.json"
            save_plan(capture, config_path, scope, output)
            assert output.stat().st_mode & 0o777 == 0o600
            assert output.parent.stat().st_mode & 0o777 == 0o700
            results.append({"scenario": row["name"], "passed": correct, "variants": len(variants), "codes": codes})
    return {
        "schema_version": "bbtk-request-variation-eval/1",
        "corpus_version": CORPUS_VERSION,
        "scenarios": len(results),
        "metrics": metrics,
        "results": results,
        "confirmed": False,
    }


if __name__ == "__main__":
    result = evaluate()
    print(json.dumps(result, indent=2, sort_keys=True))
    raise SystemExit(1 if result["metrics"]["unexpected_results"] else 0)
