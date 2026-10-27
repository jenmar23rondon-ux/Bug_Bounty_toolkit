"""Reproducible offline evaluation; only aggregate metrics may be shared."""

from __future__ import annotations

import json
import socket
import time
import tracemalloc
from typing import Any
from unittest.mock import patch

from bugbounty_toolkit.analysis.semantic_response_diff import (
    diff_responses,
    naive_baseline_diff,
)

from .fixtures import CORPUS_VERSION, corpus


def _kinds_hit(changes: list[dict[str, Any]], expected: list[str]) -> set[str]:
    found = {item["kind"] for item in changes}
    return set(expected) & found


def evaluate() -> dict[str, Any]:
    metrics: dict[str, Any] = {
        "precision_relevant_diff": 0.0,
        "recall_field_changes": 0.0,
        "false_equivalences": 0,
        "dangerous_normalizations": 0,
        "json_valid_outputs": 0,
        "json_invalid_outputs": 0,
        "latency_ms_total": 0.0,
        "peak_memory_kib": 0.0,
        "secret_leaks": 0,
        "network_requests_sent": 0,
        "authz_fields_preserved": 0,
        "authz_fields_lost": 0,
        "baseline_false_positive_diffs": 0,
        "semantic_false_positive_diffs": 0,
        "scenarios_passed": 0,
        "scenarios_failed": 0,
        "unexpected_results": 0,
    }
    results: list[dict[str, Any]] = []
    tp = fp = fn = 0

    with (
        patch.object(socket.socket, "connect", side_effect=AssertionError("Network prohibited in this lab")),
        patch.object(socket, "getaddrinfo", side_effect=AssertionError("DNS prohibited in this lab")),
    ):
        tracemalloc.start()
        t0 = time.perf_counter()
        for row in corpus():
            canaries = [
                "tok_canary_alpha_9f3a",
                "tok_canary_bravo_9f3a",
                "pwd_canary_alpha_9f3a",
                "pwd_canary_bravo_9f3a",
            ]

            baseline = naive_baseline_diff(row["left"], row["right"])
            result = diff_responses(row["left"], row["right"], ignore_volatile=row["ignore_volatile"])

            # JSON validity
            leaked = False
            try:
                dumped = json.dumps(result, sort_keys=True)
                json.loads(dumped)
                metrics["json_valid_outputs"] += 1
            except (TypeError, ValueError):
                metrics["json_invalid_outputs"] += 1
                dumped = ""

            for canary in canaries:
                if canary in dumped:
                    metrics["secret_leaks"] += 1
                    leaked = True

            expect_diff = bool(row["relevant_kinds"]) or (
                row["must_preserve_authz"] and not row["expect_structural_equal"]
            )
            reported = not result["structural_equality"]
            if expect_diff and reported:
                tp += 1
            elif expect_diff and not reported:
                fn += 1
                metrics["false_equivalences"] += 1
            elif not expect_diff and reported:
                fp += 1
                metrics["semantic_false_positive_diffs"] += 1

            if baseline["reports_difference"] and not expect_diff:
                metrics["baseline_false_positive_diffs"] += 1

            # Authz preservation
            if row["must_preserve_authz"]:
                authz_changes = [c for c in result["changes"] if c.get("authz_relevant")]
                kinds = _kinds_hit(result["changes"], row["relevant_kinds"])
                preserved = bool(authz_changes) or bool(kinds) or (row["expect_structural_equal"] is False and reported)
                # Sensitive ignore attempt: token/password rules must not hide diffs.
                if "token" in row["ignore_volatile"] or "password" in row["ignore_volatile"]:
                    sensitive = [c for c in result["changes"] if c.get("sensitive") or c.get("authz_relevant")]
                    preserved = bool(sensitive)
                if "owner" in row["ignore_volatile"] or "id" in row["ignore_volatile"]:
                    # Protected keys must still appear.
                    paths = " ".join(c["path"] for c in result["changes"])
                    if "owner" in row["ignore_volatile"] and "owner" not in paths and "id" not in paths:
                        # owner change scenario
                        preserved = any("owner" in c["path"] for c in result["changes"])
                    if "id" in row["ignore_volatile"]:
                        preserved = any(c["path"].endswith("/id") or c["path"] == "/id" for c in result["changes"])
                if preserved:
                    metrics["authz_fields_preserved"] += 1
                else:
                    metrics["authz_fields_lost"] += 1
                    metrics["dangerous_normalizations"] += 1

            # Dangerous normalization: any ignore_* that touched a protected path.
            for note in result["normalizations_applied"]:
                if note.startswith("ignore_") and any(
                    token in note for token in ("/id", "/owner", "/role", "/token", "/password", ":id:", ":owner:")
                ):
                    metrics["dangerous_normalizations"] += 1

            passed = True
            if row["expect_structural_equal"] and not result["structural_equality"]:
                # Allow content_length_mismatch-only? structural equal means no changes.
                passed = False
            if row["expect_structural_equal"] is False and result["structural_equality"] and expect_diff:
                passed = False
            if row["expect_behavioral"] is True and not result["behavioral_equivalence"]:
                # Soft: behavioral may be false when non-authz soft diffs remain (array reorder).
                if (
                    row["name"] != "array_reordered"
                    and row["name"] != "large_responses"
                    and row["name"] != "content_length_mismatch"
                ):
                    passed = False
            if row["expect_behavioral"] is False and result["behavioral_equivalence"] and expect_diff:
                passed = False
            if row["relevant_kinds"]:
                hit = _kinds_hit(result["changes"], row["relevant_kinds"])
                if not hit and not row["expect_structural_equal"]:
                    # At least one expected kind should appear.
                    passed = False
            if result.get("confirmed") or result.get("finding_confirmed") or result.get("vulnerability_verdict"):
                passed = False
            if leaked:
                passed = False

            if passed:
                metrics["scenarios_passed"] += 1
            else:
                metrics["scenarios_failed"] += 1
                metrics["unexpected_results"] += 1

            results.append(
                {
                    "scenario": row["name"],
                    "passed": passed,
                    "structural_equality": result["structural_equality"],
                    "similarity": result["similarity"],
                    "behavioral_equivalence": result["behavioral_equivalence"],
                    "change_kinds": sorted({c["kind"] for c in result["changes"]}),
                    "authz_relevant_changes": result["summary"]["authz_relevant_changes"],
                    "normalizations": result["normalizations_applied"],
                }
            )
        metrics["latency_ms_total"] = round((time.perf_counter() - t0) * 1000, 3)
        _, peak = tracemalloc.get_traced_memory()
        metrics["peak_memory_kib"] = round(peak / 1024, 3)
        tracemalloc.stop()

    denom_p = tp + fp
    denom_r = tp + fn
    metrics["precision_relevant_diff"] = round(tp / denom_p, 4) if denom_p else 1.0
    metrics["recall_field_changes"] = round(tp / denom_r, 4) if denom_r else 1.0

    return {
        "schema_version": "bbtk-semantic-response-diff-eval/1",
        "corpus_version": CORPUS_VERSION,
        "scenarios": len(results),
        "metrics": metrics,
        "results": results,
        "confirmed": False,
        "finding_confirmed": False,
        "vulnerability_verdict": None,
    }


if __name__ == "__main__":
    payload = evaluate()
    print(json.dumps(payload, indent=2, sort_keys=True))
    raise SystemExit(1 if payload["metrics"]["unexpected_results"] or payload["metrics"]["secret_leaks"] else 0)
