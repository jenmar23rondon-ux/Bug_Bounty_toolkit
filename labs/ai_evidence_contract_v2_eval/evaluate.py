"""Score schema v2 packets against the frozen synthetic corpus.

CI mode is in-process. It does not open sockets, call a model, or confirm findings.
Real model quality is NOT_MEASURED.

    python -m labs.ai_evidence_contract_v2_eval.evaluate --split dev
    python -m labs.ai_evidence_contract_v2_eval.evaluate --split final --write-results
"""

from __future__ import annotations

import argparse
import json
import socket
from pathlib import Path
from typing import Any
from unittest.mock import patch

from bugbounty_toolkit.analysis.ai_evidence_contract_v2 import (
    aggregate_metrics,
    build_contract_packet,
    measure_semantic_completeness,
    normalize_dual_advisory,
    scan_secret_material,
)
from bugbounty_toolkit.analysis.multi_review import build_evidence_bundle

from labs.ai_evidence_contract_v2_eval.corpus import build_split, verify

LAB = Path(__file__).resolve().parent
RESULT_SCHEMA = "bbtk.ai-evidence-contract-v2-eval.v1"
NOT_MEASURED = (
    {
        "item": "real_local_model_quality",
        "reason": "CI uses in-process fixtures only. No Ollama, LM Studio, or other model host was contacted.",
    },
    {
        "item": "human_reviewer_agreement",
        "reason": "No human study was run. Advisory output is not a classification.",
    },
    {
        "item": "p08_local_llm_quality_eval_rerun",
        "reason": "labs/local_llm_quality_eval is owned by another change and was not executed or modified.",
    },
)


def _rate(rows: list[dict[str, Any]], family: str) -> dict[str, Any]:
    selected = [row for row in rows if row["family"] == family]
    summary = aggregate_metrics(selected)
    return {
        "cases": summary["cases"],
        "v2_known_fact_preservation": summary["known_fact_preservation"],
        "v1_known_fact_preservation": summary["v1_known_fact_preservation"],
        "v2_unknown_preservation": summary["unknown_preservation"],
    }


def _gate_checks() -> dict[str, Any]:
    """Structural consensus gates. Not a model measurement."""
    packet = build_contract_packet(build_split("dev")["cases"][0]["evidence"])
    refs = {row["ref"] for row in packet["observations"]}
    analysis = {
        "decision": "candidate",
        "claims": [{"statement": "Cited.", "kind": "evidence", "refs": [next(iter(refs))]}],
        "missing_controls": [],
    }
    critique = {"decision": "candidate", "contradictions": [], "unsupported_claims": [], "missing_controls": []}
    disabled = normalize_dual_advisory(analysis, critique, packet, [], refs, enabled=False)
    shared = normalize_dual_advisory(analysis, critique, packet, [], refs, enabled=True)
    return {
        "opt_in_disabled_decision": disabled["advisory_decision"],
        "shared_resource_blocks_candidate": shared["advisory_decision"] == "inconclusive",
        "finding_confirmed": disabled["finding_confirmed"] or shared["finding_confirmed"],
        "tools_available": disabled["tools_available"] or shared["tools_available"],
        "ledger_modified": disabled["evidence_ledger_modified"] or shared["evidence_ledger_modified"],
    }


def evaluate(split: str) -> dict[str, Any]:
    if split not in {"dev", "final"}:
        raise ValueError("split must be dev or final")
    problems = verify(LAB)
    if problems:
        raise RuntimeError("corpus freeze check failed: " + ",".join(problems))
    attempts = {"network": 0, "external": 0}

    def _refuse_connect(self: socket.socket, address: object) -> None:
        attempts["network"] += 1
        host = address[0] if isinstance(address, tuple) and address else ""
        if str(host) not in {"127.0.0.1", "::1"}:
            attempts["external"] += 1
        raise RuntimeError("ai_evidence_contract_v2_eval refuses sockets")

    with patch.object(socket.socket, "connect", _refuse_connect):
        cases = build_split(split)["cases"]
        rows: list[dict[str, Any]] = []
        secret_leaks = 0
        for case in cases:
            packet = build_contract_packet(case["evidence"])
            bundle = build_evidence_bundle(case["evidence"])
            measured = measure_semantic_completeness(
                packet,
                case,
                bundle["observations"],
                bundle,
            )
            materials = [item for item in case["secret_material"] if isinstance(item, str)]
            leaks = scan_secret_material(packet, materials) or scan_secret_material(bundle, materials)
            if leaks or measured["privacy_leak"]:
                secret_leaks += 1
            rows.append(
                {
                    "id": case["id"],
                    "family": case["family"],
                    **measured,
                }
            )
        summary = aggregate_metrics(rows)
        families = sorted({row["family"] for row in rows})
        result: dict[str, Any] = {
            "schema_version": RESULT_SCHEMA,
            "split": split,
            "mode": "mock_in_process",
            "simulated": True,
            "notice": "Structural contract metrics only. NOT a local model score.",
            "cases": summary["cases"],
            "v1": {
                "known_fact_preservation": summary["v1_known_fact_preservation"],
                "semantic_loss": summary["v1_semantic_loss"],
                "unknown_preservation": summary["v1_unknown_preservation"],
                "privacy_leak_rate": summary["v1_privacy_leak_rate"],
                "schema_valid_rate": summary["v1_schema_valid_rate"],
            },
            "v2": {
                "known_fact_preservation": summary["known_fact_preservation"],
                "semantic_loss": summary["semantic_loss"],
                "unknown_preservation": summary["unknown_preservation"],
                "unknown_coerced": summary["unknown_coerced"],
                "privacy_leak_rate": summary["privacy_leak_rate"],
                "schema_valid_rate": summary["schema_valid_rate"],
            },
            "by_family": {family: _rate(rows, family) for family in families},
            "dual_advisory_gate_checks": _gate_checks(),
            "external_requests": attempts["external"],
            "network_attempts": attempts["network"],
            "secret_leaks": secret_leaks,
            "finding_confirmed": False,
            "finding_confirmed_true_count": sum(1 for row in rows if row["finding_confirmed"] is True),
            "not_measured": NOT_MEASURED,
        }
        leaked_now = scan_secret_material(
            result,
            [item for case in cases for item in case["secret_material"] if isinstance(item, str)],
        )
        if leaked_now:
            secret_leaks += 1
            result["secret_leaks"] = secret_leaks
        return result


def write_result(split: str, result: dict[str, Any]) -> Path:
    path = LAB / "results" / f"mock-{split}.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Score the AI evidence contract v2 lab offline.")
    parser.add_argument("--split", choices=("dev", "final", "all"), default="dev")
    parser.add_argument("--write-results", action="store_true")
    args = parser.parse_args(argv)
    splits = ("dev", "final") if args.split == "all" else (args.split,)
    for split in splits:
        result = evaluate(split)
        if args.write_results:
            write_result(split, result)
        print(
            json.dumps(
                {
                    "split": split,
                    "v1": result["v1"],
                    "v2": result["v2"],
                    "secret_leaks": result["secret_leaks"],
                    "external_requests": result["external_requests"],
                },
                sort_keys=True,
            )
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
