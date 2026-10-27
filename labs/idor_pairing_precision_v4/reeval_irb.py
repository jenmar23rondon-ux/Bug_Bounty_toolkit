"""Re-score IRB FINAL 45 with the opt-in compatibility gate.

Labels, MANIFEST.sha256 and historical result files under
labs/independent_research_eval/ are read and never written. Legacy
propose_object_handoff is not modified and is not the scorer here: each
capture exchange becomes an evidence side, and only same-instance pairs can
be admitted. That is a different question from IRB's type-level handoff
metric, which counts distinct instances of one kind as a true pair.
"""

from __future__ import annotations

import hashlib
import json
import socket
import sys
import time
import tracemalloc
from collections import defaultdict
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
IRB = ROOT / "labs" / "independent_research_eval"
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from bugbounty_toolkit.analysis.idor_pairing_compatibility import evaluate_compatibility  # noqa: E402
from bugbounty_toolkit.analysis.object_relationships import _read_sources  # noqa: E402
from bugbounty_toolkit.case_generator import SESSION_HEADER  # noqa: E402
from labs.idor_pairing_precision_v4.metrics import f1, ratio  # noqa: E402
from labs.independent_research_eval.metrics import pairing_counts  # noqa: E402

REFERENCE = {"pairing_precision": 0.65, "pairing_recall": 0.963}
LEAK_MARKERS = ("IRBCANARY", "Bearer ", "ib30-")


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _session_ref(headers: dict[str, str] | None) -> str | None:
    if not headers:
        return None
    parts = [f"{key.lower()}={value}" for key, value in headers.items() if SESSION_HEADER.search(key)]
    if not parts:
        return None
    digest = hashlib.sha256("|".join(sorted(parts)).encode()).hexdigest()[:16]
    return "sess:" + digest


def _evidence(source: Any, ref: str, batch_id: str) -> dict[str, Any]:
    request_headers = {str(key).lower(): str(value) for key, value in (source.request_headers or {}).items()}
    response_headers = {str(key).lower(): str(value) for key, value in (source.response_headers or {}).items()}
    body = source.response_body or ""
    present = source.status_code is not None or bool(body)
    return {
        "evidence_ref": ref,
        "method": source.method,
        "url": source.url,
        "program": "irb-final",
        "session_ref": _session_ref(request_headers),
        "batch_id": batch_id,
        "continuity_declared": False,
        "response_present": present,
        "status_code": source.status_code,
        "response_body": body,
        "response_headers": response_headers,
        "request_headers": request_headers,
    }


def _block_network() -> tuple[dict[str, int], tuple[Any, Any, Any, Any]]:
    saved = (socket.socket.connect, socket.socket.connect_ex, socket.create_connection, socket.getaddrinfo)
    attempts = {"count": 0}

    def guard(*_args: object, **_kwargs: object) -> object:
        attempts["count"] += 1
        raise OSError("network disabled during offline evaluation")

    socket.socket.connect = guard  # type: ignore[method-assign, assignment]
    socket.socket.connect_ex = guard  # type: ignore[method-assign, assignment]
    socket.create_connection = guard  # type: ignore[assignment]
    socket.getaddrinfo = guard  # type: ignore[assignment]
    return attempts, saved


def _restore(saved: tuple[Any, Any, Any, Any]) -> None:
    socket.socket.connect, socket.socket.connect_ex, socket.create_connection, socket.getaddrinfo = saved  # type: ignore[method-assign]


def _admitted_kinds(evidences: list[dict[str, Any]]) -> tuple[set[str], int, int]:
    """Return admitted kinds, cross-kind pairs seen, and cross-kind pairs admitted."""
    groups: dict[tuple[str, str, str], list[dict[str, Any]]] = defaultdict(list)
    for evidence in evidences:
        described_kind = evidence.get("_kind")
        described_id = evidence.get("_id")
        origin = evidence.get("_origin")
        if described_kind and described_id and origin:
            groups[(str(origin), str(described_kind), str(described_id))].append(evidence)
    admitted: set[str] = set()
    for rows in groups.values():
        by_session: dict[str, dict[str, Any]] = {}
        for row in rows:
            session = row.get("session_ref")
            if isinstance(session, str):
                by_session.setdefault(session, row)
        ordered = [by_session[key] for key in sorted(by_session)]
        if len(ordered) < 2:
            continue
        assessment = evaluate_compatibility(ordered[0], ordered[1], pair_id="irb")
        if assessment["finding_confirmed"]:
            raise RuntimeError("finding_confirmed must stay false")
        if assessment["pairing_decision"] and assessment["resource_kind"]:
            admitted.add(str(assessment["resource_kind"]))
    by_digits: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for evidence in evidences:
        resource_id = evidence.get("_id")
        kind = evidence.get("_kind")
        if isinstance(resource_id, str) and resource_id.isdigit() and kind:
            by_digits[resource_id].append(evidence)
    seen = admitted_cross = 0
    for rows in by_digits.values():
        kinds = {str(row.get("_kind")) for row in rows}
        if len(kinds) < 2:
            continue
        first = rows[0]
        second = next(row for row in rows if row.get("_kind") != first.get("_kind"))
        seen += 1
        assessment = evaluate_compatibility(first, second, pair_id="irb-cross-kind")
        if assessment["pairing_decision"]:
            admitted_cross += 1
    return admitted, seen, admitted_cross


def reevaluate_final() -> dict[str, Any]:
    split = IRB / "final"
    manifest = split / "MANIFEST.sha256"
    labels_path = split / "ground_truth.json"
    if not manifest.is_file() or not labels_path.is_file():
        raise FileNotFoundError("IRB FINAL corpus is missing")
    before_manifest = manifest.read_text(encoding="utf-8")
    before_labels = _sha(labels_path)
    document = json.loads(labels_path.read_text(encoding="utf-8"))
    attempts, saved = _block_network()
    tracemalloc.start()
    started = time.perf_counter()
    rows: list[dict[str, Any]] = []
    cross_seen = cross_admitted = 0
    try:
        from bugbounty_toolkit.analysis.idor_pairing_compatibility import describe_http_target

        for scenario in document["scenarios"]:
            evidences: list[dict[str, Any]] = []
            error = None
            try:
                for relative in scenario["captures"]:
                    path = split / relative
                    _data, captures, _summary = _read_sources(path, None, False, False)
                    for index, source in enumerate(captures):
                        evidence = _evidence(source, f"{scenario['id']}:{index}", path.name)
                        described = describe_http_target(source.url)
                        evidence["_kind"] = described["resource_kind"]
                        evidence["_id"] = described["resource_id"]
                        evidence["_origin"] = described["origin"]
                        evidences.append(evidence)
            except (OSError, ValueError, TypeError, KeyError) as exc:
                error = type(exc).__name__
            kinds, seen, admitted_cross = _admitted_kinds(evidences)
            cross_seen += seen
            cross_admitted += admitted_cross
            labels = scenario["labels"]
            counts = pairing_counts(kinds, labels.get("ideal_pair_types") or [], labels.get("forbidden_pair_types") or [])
            rows.append(
                {
                    "id": scenario["id"],
                    "tag": scenario.get("tag"),
                    "admitted_kinds": sorted(kinds),
                    "ideal_pair_types": labels.get("ideal_pair_types") or [],
                    "pairing": counts,
                    "read_error": error,
                    "finding_confirmed": False,
                }
            )
    finally:
        _restore(saved)
        _, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
    tp = sum(row["pairing"]["tp"] for row in rows)
    fp = sum(row["pairing"]["fp"] for row in rows)
    fn = sum(row["pairing"]["fn"] for row in rows)
    precision = ratio(tp, tp + fp)
    recall = ratio(tp, tp + fn)
    after_manifest = manifest.read_text(encoding="utf-8")
    after_labels = _sha(labels_path)
    report = {
        "lab": "irb-1.0-compatibility-reeval",
        "split": "final",
        "scenarios": len(rows),
        "labels_modified": before_labels != after_labels or before_manifest != after_manifest,
        "ground_truth_sha256": after_labels,
        "reference": REFERENCE,
        "before_legacy_handoff": {
            "pairing_precision": REFERENCE["pairing_precision"],
            "pairing_recall": REFERENCE["pairing_recall"],
            "note": "Frozen IRB FINAL 45 headline. Legacy propose_object_handoff was not re-run and was not changed.",
        },
        "after_evaluate_compatibility": {
            "tp": tp,
            "fp": fp,
            "fn": fn,
            "pairing_precision": precision,
            "pairing_recall": recall,
            "f1": f1(precision, recall),
        },
        "false_pairs": fp,
        "missed_valid_pairs": fn,
        "cross_kind_pairs_seen": cross_seen,
        "cross_kind_collisions_admitted": cross_admitted,
        "wall_time_s": round(time.perf_counter() - started, 6),
        "peak_memory_kib": round(peak / 1024, 1),
        "network_attempts": attempts["count"],
        "external_requests": attempts["count"],
        "secret_leaks": 0,
        "finding_confirmed": False,
        "recall_regression": {
            "reference_recall": REFERENCE["pairing_recall"],
            "new_recall": recall,
            "cause": (
                "IRB ideal_pair_types credit any proposed resource type, including distinct "
                "instances (owner id N and actor id N+1). evaluate_compatibility admits a pair "
                "only when the canonical resource identity matches and the other controls hold. "
                "Distinct-instance handoff proposals therefore become missed pairs under the "
                "frozen type-level metric. Labels were not edited. Legacy handoff still emits "
                "those proposals; this re-eval does not flip that default."
            ),
        },
        "rows": rows,
    }
    encoded = json.dumps(report)
    report["secret_leaks"] = sum(encoded.count(marker) for marker in LEAK_MARKERS)
    if report["labels_modified"] or report["secret_leaks"] or report["network_attempts"] or report["finding_confirmed"]:
        raise RuntimeError("IRB re-eval safety check failed")
    return report


def main() -> None:
    parser_out = Path(sys.argv[1]) if len(sys.argv) > 1 else None
    report = reevaluate_final()
    text = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if parser_out is not None:
        parser_out.write_text(text, encoding="utf-8")
    after = report["after_evaluate_compatibility"]
    print(
        f"irb45 precision {after['pairing_precision']} recall {after['pairing_recall']} "
        f"f1 {after['f1']} fp {after['fp']} fn {after['fn']} "
        f"leaks {report['secret_leaks']} network {report['network_attempts']}"
    )


if __name__ == "__main__":
    main()
