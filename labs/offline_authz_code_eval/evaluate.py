"""Metrics for the offline authorization code audit lab (synthetic corpus only)."""

from __future__ import annotations

import json
import re
import shutil
import socket
import sys
import tempfile
import time
import tracemalloc
from pathlib import Path
from typing import Any

from bugbounty_toolkit.analysis.offline_authorization_audit import AuditReport, audit

HERE = Path(__file__).resolve().parent
CORPUS = HERE / "corpus"
EXPECTED = HERE / "expected.json"


def materialize(dest: Path) -> Path:
    """Copy the corpus, restoring ``*.fixture`` files (kept out of repo linters) to their real suffix."""
    root = dest / "corpus"
    shutil.copytree(CORPUS, root)
    for f in list(root.rglob("*.fixture")):
        f.rename(f.with_suffix(""))
    return root


def naive_baseline(root: Path) -> dict[tuple[str, str], bool]:
    """Name-based grep baseline: a route is 'protected' if its span mentions an auth-ish identifier."""
    out: dict[tuple[str, str], bool] = {}
    route_re = re.compile(r"\.(get|post|put|patch|delete)\(\s*[\"']([^\"']+)[\"']")
    for f in sorted(list(root.rglob("*.py")) + list(root.rglob("*.js"))):
        text = f.read_text(encoding="utf-8")
        hits = list(route_re.finditer(text))
        for i, m in enumerate(hits):
            span = text[m.start() : hits[i + 1].start() if i + 1 < len(hits) else len(text)]
            key = (str(f.relative_to(root)), f"{m.group(1).upper()} {m.group(2)}")
            has_id = bool(re.search(r"\{\w+\}|:\w+", m.group(2)))
            protected = bool(re.search(r"authori[sz]e|permission|owner|verify|ensure", span, re.I))
            out[key] = has_id and not protected
    return out


class _NetGuard:
    def __init__(self) -> None:
        self.attempts = 0
        self._orig = socket.socket.connect

    def __enter__(self) -> _NetGuard:
        guard = self

        def blocked(sock: socket.socket, *args: Any, **kwargs: Any) -> None:
            guard.attempts += 1
            raise OSError("network disabled in offline authz lab")

        socket.socket.connect = blocked  # type: ignore[method-assign,assignment]
        return self

    def __exit__(self, *exc: object) -> None:
        socket.socket.connect = self._orig  # type: ignore[method-assign]


def _valid_ref(root: Path, ref: str) -> bool:
    path, _, line = ref.rpartition(":")
    f = root / path
    if not f.is_file() or not line.isdigit():
        return False
    n = int(line)
    return 1 <= n <= len(f.read_text(encoding="utf-8").splitlines())


def evaluate(root: Path) -> dict[str, Any]:
    expected = json.loads(EXPECTED.read_text(encoding="utf-8"))
    truth = {(r["file"], r["route_ref"]): r for r in expected["routes"]}
    modules_before = set(sys.modules)
    tracemalloc.start()
    t0 = time.perf_counter()
    with _NetGuard() as guard:
        report: AuditReport = audit(root)
    elapsed = time.perf_counter() - t0
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    new_modules = set(sys.modules) - modules_before
    target_imports = sorted(m for m in new_modules if m.split(".")[0] in {"main", "deps", "services", "fastapi_app"})

    pred = {(r.source_file, r.route_ref): r for r in report.routes}
    tp_routes = len(set(pred) & set(truth))
    expected_observed = [k for k, v in truth.items() if v["object_authz"] == "observed"]
    expected_gaps = [k for k, v in truth.items() if v["gap"] is True]
    expected_unknown = [k for k, v in truth.items() if v["object_authz"] == "unknown"]
    false_gap = [
        k for k, r in pred.items() if r.possible_authorization_gap is True and truth.get(k, {}).get("gap") is not True
    ]
    refs = [ref for r in report.routes for ref in r.evidence_refs + [f"{r.source_file}:{n}" for n in r.source_lines]]
    baseline = naive_baseline(root)
    base_false_gap = [k for k, v in baseline.items() if v and truth.get(k, {}).get("gap") is not True]
    base_gap_hits = [k for k in expected_gaps if baseline.get(k)]
    return {
        "routes_expected": len(truth),
        "routes_predicted": len(pred),
        "route_extraction_recall": round(tp_routes / len(truth), 4),
        "route_extraction_precision": round(tp_routes / len(pred), 4) if pred else 0.0,
        "authz_check_recall": round(
            sum(1 for k in expected_observed if k in pred and pred[k].object_authz_observed == "observed")
            / len(expected_observed),
            4,
        ),
        "gap_hypothesis_recall": round(
            sum(1 for k in expected_gaps if k in pred and pred[k].possible_authorization_gap is True)
            / len(expected_gaps),
            4,
        ),
        "false_gap_warnings": len(false_gap),
        "correct_abstentions": sum(
            1 for k in expected_unknown if k in pred and pred[k].object_authz_observed == "unknown"
        ),
        "expected_abstentions": len(expected_unknown),
        "valid_file_line_refs": sum(1 for ref in refs if _valid_ref(root, ref)),
        "total_file_line_refs": len(refs),
        "malformed_files_skipped": sorted(k for k in report.files_skipped if k in expected["malformed_files"]),
        "finding_confirmed_true": sum(1 for r in report.routes if r.finding_confirmed),
        "human_review_required_all": all(r.human_review_required for r in report.routes),
        "elapsed_seconds": round(elapsed, 4),
        "peak_memory_kib": peak // 1024,
        "unauthorized_files_read": report.unauthorized_reads
        + sum(1 for f in report.files_read if not (root / f).resolve().is_relative_to(root.resolve())),
        "target_code_executions": report.target_code_executions + len(target_imports),
        "network_attempts": guard.attempts,
        "baseline_naive_grep": {
            "gap_recall": round(len(base_gap_hits) / len(expected_gaps), 4),
            "false_gap_warnings": len(base_false_gap),
            "abstentions": 0,
        },
    }


def run() -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="bbtk-oaca-") as tmp:
        return evaluate(materialize(Path(tmp)))
