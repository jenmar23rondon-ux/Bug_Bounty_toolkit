"""Run the pairing-precision v4 lab and the read-only IRB FINAL re-evaluation.

FINAL refuses to run unless ``final/MANIFEST.sha256`` matches ``final/cases.json``.
Network connects are blocked. ``finding_confirmed`` stays false.
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

from bugbounty_toolkit import __version__  # noqa: E402
from bugbounty_toolkit.analysis.idor_pairing_precision import evaluate_compatibility  # noqa: E402
from labs.idor_pairing_precision_v4 import SCHEMA  # noqa: E402
from labs.idor_pairing_precision_v4 import irb_reeval  # noqa: E402
from labs.idor_pairing_precision_v4.metrics import classification_counts, f1, ratio  # noqa: E402

CANARIES = ("SYNTH_CANARY_PAIRING_V4", "IRBCANARY", "AKIA", "-----BEGIN PRIVATE KEY-----")
REFERENCE_PRECISION = 0.65
REFERENCE_RECALL = 0.963


class FrozenCorpusError(RuntimeError):
    pass


def verify_manifest(split: str) -> str:
    directory = HERE / split
    manifest = (directory / "MANIFEST.sha256").read_text(encoding="utf-8").split()
    digest = hashlib.sha256((directory / "cases.json").read_bytes()).hexdigest()
    if not manifest or manifest[0] != digest:
        raise FrozenCorpusError(f"{split} cases.json does not match MANIFEST.sha256")
    return digest


def load_cases(split: str) -> list[dict[str, Any]]:
    document = json.loads((HERE / split / "cases.json").read_text(encoding="utf-8"))
    cases = document.get("cases")
    if not isinstance(cases, list):
        raise ValueError("cases.json has no cases")
    return cases


def naive_pairing_decision(case: dict[str, Any]) -> bool:
    """Id-only baseline: equal final path segments, ignoring kind, denial and namespace."""

    def last(path: object) -> str | None:
        if not isinstance(path, str):
            return None
        parts = [part for part in path.split("?")[0].split("/") if part]
        return parts[-1] if parts else None

    left = last((case.get("owner") or {}).get("path"))
    right = last((case.get("actor") or {}).get("path"))
    return bool(left and left == right)


def score_case(case: dict[str, Any]) -> dict[str, Any]:
    assessment = evaluate_compatibility(
        case["owner"],
        case["actor"],
        context=case.get("context") or [],
        alias_rules=case.get("alias_rules"),
        continuity=case.get("continuity"),
        as_of=case.get("as_of"),
    )
    payload = assessment.as_dict()
    if payload["finding_confirmed"]:
        raise RuntimeError("finding_confirmed must stay false")
    return {
        "id": case["id"],
        "tags": case.get("tags") or [],
        "expect_compatibility": case["expect_compatibility"],
        "expect_pairing_decision": case["expect_pairing_decision"],
        "compatibility": payload["compatibility"],
        "pairing_decision": payload["pairing_decision"],
        "identity_assessment": payload["identity_assessment"],
        "owner_evidence_ref": payload["owner_evidence_ref"],
        "actor_evidence_ref": payload["actor_evidence_ref"],
        "compatibility_match": payload["compatibility"] == case["expect_compatibility"],
        "naive_pairing_decision": naive_pairing_decision(case),
        "finding_confirmed": False,
    }


def score_split(cases: list[dict[str, Any]]) -> dict[str, Any]:
    rows = [score_case(case) for case in cases]
    after = classification_counts(rows)
    naive_rows = [
        {
            **row,
            "pairing_decision": row["naive_pairing_decision"],
            "compatibility": "compatible" if row["naive_pairing_decision"] else "incompatible",
        }
        for row in rows
    ]
    before = classification_counts(naive_rows)
    mismatches = [row["id"] for row in rows if not row["compatibility_match"]]
    return {"before_naive_id_match": before, "after_compatibility_v4": after, "rows": rows, "mismatches": mismatches}


def reevaluate_irb() -> dict[str, Any]:
    """Apply the opt-in evaluator to frozen IRB FINAL captures. Labels are not written."""
    from labs.independent_research_eval.metrics import pairing_counts as score_pairs

    labels = irb_reeval.load_labels()
    rows: list[dict[str, Any]] = []
    leaks = 0
    for scenario in labels:
        evidences = irb_reeval.evidence_from_scenario(scenario)
        predicted = irb_reeval.admitted_kinds(evidences)
        lab = scenario["labels"]
        counts = score_pairs(predicted, lab.get("ideal_pair_types") or [], lab.get("forbidden_pair_types") or [])
        blob = json.dumps({"id": scenario["id"], "predicted": predicted})
        leaks += sum(blob.count(token) for token in CANARIES)
        rows.append(
            {
                "id": scenario["id"],
                "family": scenario.get("family"),
                "predicted": predicted,
                "ideal_pair_types": lab.get("ideal_pair_types") or [],
                "forbidden_pair_types": lab.get("forbidden_pair_types") or [],
                "pairing": counts,
            }
        )
    tp = sum(row["pairing"]["tp"] for row in rows)
    fp = sum(row["pairing"]["fp"] for row in rows)
    fn = sum(row["pairing"]["fn"] for row in rows)
    precision = ratio(tp, tp + fp)
    recall = ratio(tp, tp + fn)
    return {
        "benchmark": "independent-research-benchmark FINAL",
        "scenarios": len(rows),
        "labels_modified": False,
        "reference": {
            "pairing_precision": REFERENCE_PRECISION,
            "pairing_recall": REFERENCE_RECALL,
            "source": "labs/independent_research_eval/results/final_metrics.json",
        },
        "after": {
            "tp": tp,
            "fp": fp,
            "fn": fn,
            "precision": precision,
            "recall": recall,
            "f1": f1(precision, recall),
            "forbidden_hits": sum(row["pairing"]["forbidden_hits"] for row in rows),
        },
        "reference_f1": f1(REFERENCE_PRECISION, REFERENCE_RECALL),
        "rows": rows,
        "secret_leaks": leaks,
        "finding_confirmed": False,
    }


def scan_leaks(payload: str) -> int:
    return sum(payload.count(token) for token in CANARIES)


def run(split: str, *, include_irb: bool) -> dict[str, Any]:
    if __version__ != "0.2.2":
        raise RuntimeError(f"version must stay 0.2.2, found {__version__}")
    digest = verify_manifest(split)
    attempts = {"count": 0}
    saved = (socket.socket.connect, socket.socket.connect_ex, socket.create_connection, socket.getaddrinfo)

    def guard(*_args: Any, **_kwargs: Any) -> Any:
        attempts["count"] += 1
        raise OSError("network disabled during pairing-precision lab")

    socket.socket.connect = guard  # type: ignore[method-assign]
    socket.socket.connect_ex = guard  # type: ignore[method-assign]
    socket.create_connection = guard
    socket.getaddrinfo = guard
    tracemalloc.start()
    started = time.perf_counter()
    try:
        lab = score_split(load_cases(split))
        irb = reevaluate_irb() if include_irb else None
    finally:
        _current, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        elapsed = time.perf_counter() - started
        socket.socket.connect, socket.socket.connect_ex, socket.create_connection, socket.getaddrinfo = saved  # type: ignore[method-assign]
    document: dict[str, Any] = {
        "schema": SCHEMA,
        "split": split,
        "manifest_sha256": digest,
        "version": __version__,
        "finding_confirmed": False,
        "network_attempts": attempts["count"],
        "external_requests": attempts["count"],
        "wall_time_seconds": round(elapsed, 4),
        "peak_memory_kib": round(peak / 1024, 1),
        "lab": {key: value for key, value in lab.items() if key != "rows"},
        "lab_rows": lab["rows"],
        "irb_reeval": None if irb is None else {key: value for key, value in irb.items() if key != "rows"},
        "irb_rows": None if irb is None else irb["rows"],
    }
    encoded = json.dumps(document)
    document["secret_leaks"] = scan_leaks(encoded)
    if irb is not None:
        document["secret_leaks"] += int(irb["secret_leaks"])
    return document


def render_report(document: dict[str, Any]) -> str:
    lab_before = document["lab"]["before_naive_id_match"]
    lab_after = document["lab"]["after_compatibility_v4"]
    lines = [
        "# IDOR pairing precision v4",
        "",
        f"Split `{document['split']}` manifest `{document['manifest_sha256']}`.",
        f"Version `{document['version']}`. finding_confirmed `{document['finding_confirmed']}`.",
        "",
        "## Lab before (naive equal path id) / after (compatibility v4)",
        "",
        "| metric | before | after |",
        "|---|---:|---:|",
        f"| precision | {lab_before['precision']} | {lab_after['precision']} |",
        f"| recall | {lab_before['recall']} | {lab_after['recall']} |",
        f"| f1 | {lab_before['f1']} | {lab_after['f1']} |",
        f"| false_pairs | {lab_before['false_pairs']} | {lab_after['false_pairs']} |",
        f"| missed_valid_pairs | {lab_before['missed_valid_pairs']} | {lab_after['missed_valid_pairs']} |",
        f"| abstentions | {lab_before['abstentions']} | {lab_after['abstentions']} |",
        f"| cross_kind_collisions | {lab_before['cross_kind_collisions']} | {lab_after['cross_kind_collisions']} |",
        f"| cross_program_contamination | {lab_before['cross_program_contamination']} | {lab_after['cross_program_contamination']} |",
        f"| cross_origin_contamination | {lab_before['cross_origin_contamination']} | {lab_after['cross_origin_contamination']} |",
        "",
        f"Mismatches vs frozen expectations: {document['lab']['mismatches'] or 'none'}.",
        f"Provenance completeness {lab_after['provenance_completeness']}.",
        f"Wall time {document['wall_time_seconds']}s. Peak memory {document['peak_memory_kib']} KiB.",
        f"secret_leaks {document['secret_leaks']}. network_attempts {document['network_attempts']}. external_requests {document['external_requests']}.",
        "",
    ]
    irb = document.get("irb_reeval")
    if irb:
        after = irb["after"]
        lines.extend(
            [
                "## IRB FINAL 45 re-eval (labels not modified)",
                "",
                "| metric | frozen reference | compatibility v4 |",
                "|---|---:|---:|",
                f"| precision | {irb['reference']['pairing_precision']} | {after['precision']} |",
                f"| recall | {irb['reference']['pairing_recall']} | {after['recall']} |",
                f"| f1 | {irb['reference_f1']} | {after['f1']} |",
                f"| false pairs (fp) | 14 | {after['fp']} |",
                f"| missed valid (fn) | 1 | {after['fn']} |",
                "",
                "The reference counts legacy handoff proposal types. The v4 column counts kinds admitted by `evaluate_compatibility` on the same frozen captures. Legacy handoff defaults were not changed.",
                "",
            ]
        )
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="IDOR pairing precision v4 lab")
    parser.add_argument("--split", choices=("dev", "final"), default="dev")
    parser.add_argument("--irb", action="store_true", help="also re-evaluate frozen IRB FINAL 45")
    parser.add_argument("--json", type=Path, help="write metrics JSON")
    parser.add_argument("--report", type=Path, help="write markdown report")
    args = parser.parse_args(argv)
    document = run(args.split, include_irb=args.irb)
    text = json.dumps(document, indent=2, sort_keys=True) + "\n"
    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(text, encoding="utf-8")
    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(render_report(document), encoding="utf-8")
    print(
        f"split={args.split} precision={document['lab']['after_compatibility_v4']['precision']} "
        f"recall={document['lab']['after_compatibility_v4']['recall']} mismatches={document['lab']['mismatches']} "
        f"leaks={document['secret_leaks']} network={document['network_attempts']}"
    )
    return (
        0
        if not document["lab"]["mismatches"] and document["secret_leaks"] == 0 and document["network_attempts"] == 0
        else 1
    )


if __name__ == "__main__":
    raise SystemExit(main())
