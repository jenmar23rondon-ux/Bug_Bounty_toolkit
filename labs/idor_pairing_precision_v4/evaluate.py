"""Run the pairing-precision v4 lab on a frozen DEV or FINAL split.

Offline and in-process. Refuses a split whose cases.json hash differs from
MANIFEST.sha256. Does not edit cases, labels, or the Evidence Ledger.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import socket
import sys
import time
import tracemalloc
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from bugbounty_toolkit.analysis.authorization_denial import assess_response  # noqa: E402
from bugbounty_toolkit.analysis.idor_pairing_compatibility import evaluate_compatibility  # noqa: E402
from bugbounty_toolkit.analysis.resource_kind_lineage import correlate_resources  # noqa: E402
from labs.idor_pairing_precision_v4.metrics import admission_counts, f1, ratio  # noqa: E402

SECRET_MARKERS = ("SYNTH_PRIVATE_MARKER", "Bearer SYNTH_", "sha256:tampered")
REFERENCE = {"pairing_precision": 0.65, "pairing_recall": 0.963, "source": "IRB FINAL 45 frozen"}


class FrozenSplitError(RuntimeError):
    pass


def manifest_ok(split_dir: Path) -> bool:
    manifest = split_dir / "MANIFEST.sha256"
    target = split_dir / "cases.json"
    if not manifest.is_file() or not target.is_file():
        return False
    listed = manifest.read_text(encoding="utf-8").split()[0]
    return hashlib.sha256(target.read_bytes()).hexdigest() == listed


def _correlate_side(raw: dict[str, Any]) -> dict[str, Any]:
    kind = raw.get("resource_kind")
    resource_id = raw.get("resource_id")
    body_value = raw.get("response_body")
    body = body_value if isinstance(body_value, str) else ""
    assessed = assess_response(
        raw.get("status_code") if isinstance(raw.get("status_code"), int) else None,
        body,
        raw.get("response_headers") if isinstance(raw.get("response_headers"), dict) else None,
        requested_id=str(resource_id) if resource_id else None,
    )
    if assessed.resource_visibility in {"public", "shared"} or assessed.access_proof == "public_200":
        visibility = assessed.resource_visibility or "public"
    elif raw.get("response_present") is True:
        visibility = "private"
    else:
        visibility = None
    namespace = f"{kind}:{resource_id}" if kind and resource_id else None
    return {
        "kind": kind,
        "kind_status": raw.get("kind_status"),
        "namespace_key": namespace,
        "account_ref": raw.get("account_ref"),
        "distinct_accounts_attested": bool(raw.get("account_ref")),
        "session_ref": raw.get("session_ref"),
        "visibility": visibility,
        "body_digest": hashlib.sha256(body.encode()).hexdigest(),
    }


def _blocked_socket() -> dict[str, int]:
    attempts = {"count": 0}

    def guard(*_args: object, **_kwargs: object) -> object:
        attempts["count"] += 1
        raise OSError("network disabled during offline evaluation")

    socket.socket.connect = guard  # type: ignore[method-assign, assignment]
    socket.socket.connect_ex = guard  # type: ignore[method-assign, assignment]
    socket.create_connection = guard  # type: ignore[assignment]
    socket.getaddrinfo = guard  # type: ignore[assignment]
    return attempts


def _restore_socket(saved: tuple[Any, Any, Any, Any]) -> None:
    socket.socket.connect, socket.socket.connect_ex, socket.create_connection, socket.getaddrinfo = saved  # type: ignore[method-assign]


def score_split(split: str) -> dict[str, Any]:
    split_dir = HERE / split
    if split not in {"dev", "final"}:
        raise ValueError("split must be dev or final")
    if not manifest_ok(split_dir):
        raise FrozenSplitError(f"{split} cases.json does not match MANIFEST.sha256")
    document = json.loads((split_dir / "cases.json").read_text(encoding="utf-8"))
    saved_socket = (socket.socket.connect, socket.socket.connect_ex, socket.create_connection, socket.getaddrinfo)
    attempts = _blocked_socket()
    tracemalloc.start()
    started = time.perf_counter()
    rows: list[dict[str, Any]] = []
    try:
        for case in document["cases"]:
            rules = tuple((item[0], item[1]) for item in case.get("alias_rules") or [])
            assessment = evaluate_compatibility(case["owner"], case["actor"], pair_id=case["id"], alias_rules=rules)
            baseline = correlate_resources(_correlate_side(case["owner"]), _correlate_side(case["actor"]))
            if assessment["finding_confirmed"] or assessment["network_requests_sent"]:
                raise RuntimeError("safety invariant failed")
            if assessment["compatibility"] != case["expected_compatibility"]:
                raise RuntimeError(f"{case['id']} compatibility {assessment['compatibility']}")
            if assessment["pairing_decision"] != case["expected_pairing_decision"]:
                raise RuntimeError(f"{case['id']} pairing decision")
            rows.append(
                {
                    "id": case["id"],
                    "tags": case["tags"],
                    "valid_pair": case["valid_pair"],
                    "admitted": assessment["pairing_decision"],
                    "compatibility": assessment["compatibility"],
                    "baseline_admitted": bool(baseline["idor_review_signal"]),
                    "matching_signals": assessment["matching_signals"],
                    "finding_confirmed": False,
                }
            )
    finally:
        _restore_socket(saved_socket)
        _, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
    wall = time.perf_counter() - started
    after = admission_counts(rows)
    before_rows = [
        {"admitted": row["baseline_admitted"], "valid_pair": row["valid_pair"]} for row in rows
    ]
    before = admission_counts(before_rows)
    after_p = ratio(after["tp"], after["tp"] + after["fp"])
    after_r = ratio(after["tp"], after["tp"] + after["fn"])
    before_p = ratio(before["tp"], before["tp"] + before["fp"])
    before_r = ratio(before["tp"], before["tp"] + before["fn"])
    abstentions = sum(1 for row in rows if row["compatibility"] in {"insufficient_evidence", "conflicting_evidence"})
    admitted = [row for row in rows if row["admitted"]]
    provenance_hits = 0
    needed = {
        "same_origin",
        "same_program",
        "same_kind",
        "same_resource_identity",
        "distinct_sessions",
        "owner_artifact_integrity",
        "actor_artifact_integrity",
    }
    for row in admitted:
        if needed <= set(row["matching_signals"]):
            provenance_hits += 1
    report = {
        "lab": "idor-pairing-precision-v4",
        "split": split,
        "cases": len(rows),
        "reference_irb45": REFERENCE,
        "before_correlate_resources": {
            "tp": before["tp"],
            "fp": before["fp"],
            "fn": before["fn"],
            "pairing_precision": before_p,
            "pairing_recall": before_r,
            "f1": f1(before_p, before_r),
            "note": "Existing correlate_resources idor_review_signal on the same frozen cases. Not a relabel.",
        },
        "after_evaluate_compatibility": {
            "tp": after["tp"],
            "fp": after["fp"],
            "fn": after["fn"],
            "pairing_precision": after_p,
            "pairing_recall": after_r,
            "f1": f1(after_p, after_r),
        },
        "false_pairs": after["fp"],
        "missed_valid_pairs": after["fn"],
        "abstentions": abstentions,
        "cross_kind_collisions_admitted": sum(
            1 for row in rows if "cross_kind" in row["tags"] and row["admitted"]
        ),
        "cross_program_contamination_admitted": sum(
            1 for row in rows if "cross_program" in row["tags"] and row["admitted"]
        ),
        "provenance_completeness": ratio(provenance_hits, len(admitted)),
        "wall_time_s": round(wall, 6),
        "peak_memory_kib": round(peak / 1024, 1),
        "secret_leaks": 0,
        "network_attempts": attempts["count"],
        "external_requests": attempts["count"],
        "finding_confirmed": False,
        "legacy_default_unchanged": True,
        "rows": rows,
    }
    encoded = json.dumps(report)
    leaks = sum(encoded.count(marker) for marker in SECRET_MARKERS)
    report["secret_leaks"] = leaks
    if leaks or attempts["count"]:
        raise RuntimeError(f"safety metric failed leaks={leaks} network={attempts['count']}")
    return report


def render_report(report: dict[str, Any]) -> str:
    after = report["after_evaluate_compatibility"]
    before = report["before_correlate_resources"]
    lines = [
        f"# IDOR pairing precision v4 — {report['split']}",
        "",
        "| Metric | correlate_resources (before) | evaluate_compatibility (after) | IRB 45 reference |",
        "|---|---:|---:|---:|",
        f"| Precision | {before['pairing_precision']} | {after['pairing_precision']} | 0.65 |",
        f"| Recall | {before['pairing_recall']} | {after['pairing_recall']} | 0.963 |",
        f"| F1 | {before['f1']} | {after['f1']} |  |",
        f"| TP / FP / FN | {before['tp']} / {before['fp']} / {before['fn']} | {after['tp']} / {after['fp']} / {after['fn']} |  |",
        "",
        f"Abstentions: {report['abstentions']}. False pairs: {report['false_pairs']}. "
        f"Missed valid pairs: {report['missed_valid_pairs']}.",
        f"Cross-kind collisions admitted: {report['cross_kind_collisions_admitted']}. "
        f"Cross-program contamination admitted: {report['cross_program_contamination_admitted']}.",
        f"Provenance completeness: {report['provenance_completeness']}.",
        f"Wall time s: {report['wall_time_s']}. Peak memory KiB: {report['peak_memory_kib']}.",
        f"secret_leaks: {report['secret_leaks']}. network_attempts: {report['network_attempts']}. "
        f"finding_confirmed: {report['finding_confirmed']}.",
        "",
    ]
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--split", required=True, choices=("dev", "final"))
    parser.add_argument("--json", dest="json_path")
    parser.add_argument("--report", dest="report_path")
    args = parser.parse_args()
    report = score_split(args.split)
    text = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.json_path:
        Path(args.json_path).write_text(text, encoding="utf-8")
    if args.report_path:
        Path(args.report_path).write_text(render_report(report), encoding="utf-8")
    print(
        f"{args.split} precision {report['after_evaluate_compatibility']['pairing_precision']} "
        f"recall {report['after_evaluate_compatibility']['pairing_recall']} "
        f"leaks {report['secret_leaks']} network {report['network_attempts']}"
    )


if __name__ == "__main__":
    main()
