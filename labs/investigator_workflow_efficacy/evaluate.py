"""Run the manual checklist and unchanged bbtk modules on one disposable lab.

python -m labs.investigator_workflow_efficacy.evaluate --split all
"""

from __future__ import annotations

import argparse
import hashlib
import json
import tempfile
import time
from pathlib import Path
from typing import Any

from . import bbtk_arm, manual
from .capture import Capture, fetch
from .guard import LoopbackGuard
from .metrics import NOT_MEASURED, PRIOR_KNOWLEDGE_BIAS, arm_envelope, dumps, score_arm
from .secrets import leak_count
from .server import LabServer

LAB = Path(__file__).resolve().parent
SPLITS = ("dev", "final", "stress")


def load_split(split: str) -> list[dict[str, Any]]:
    data = json.loads((LAB / split / "cases.json").read_text(encoding="utf-8"))
    cases = data["cases"]
    if not isinstance(cases, list):
        raise ValueError("cases must be a list")
    return cases


def manifest_matches(split: str) -> bool:
    text = (LAB / split / "cases.json").read_bytes()
    expected = (LAB / split / "MANIFEST.sha256").read_text(encoding="utf-8").split()[0]
    return hashlib.sha256(text).hexdigest() == expected


def _digest(capture: Capture) -> str:
    body = "\n".join(item.body for item in capture.exchanges)
    return hashlib.sha256(body.encode("utf-8")).hexdigest()


def _dedup(captures: list[Capture], classify: Any) -> tuple[list[dict[str, Any]], list[float]]:
    seen: dict[tuple[str, str], str] = {}
    rows: list[dict[str, Any]] = []
    stamps: list[float] = []
    for capture in captures:
        key = (capture.workflow, _digest(capture))
        if key in seen:
            rows.append(
                {
                    "case_id": capture.case_id,
                    "disposition": "reject",
                    "reason": "duplicate_of:" + seen[key],
                    "finding_confirmed": False,
                    "checklist": 5,
                    "missing_evidence": 0 if capture.exchanges else 1,
                    "incomplete_repro": 0,
                }
            )
            stamps.append(time.perf_counter())
            continue
        seen[key] = capture.case_id
        disposition, reason, confirmed = classify(capture)
        rows.append(
            {
                "case_id": capture.case_id,
                "disposition": disposition,
                "reason": reason,
                "finding_confirmed": bool(confirmed),
                "checklist": 5,
                "missing_evidence": 0 if capture.exchanges else 1,
                "incomplete_repro": 0,
            }
        )
        stamps.append(time.perf_counter())
    return rows, stamps


def _first_review(started: float, rows: list[dict[str, Any]], stamps: list[float]) -> float | None:
    for row, stamp in zip(rows, stamps, strict=True):
        if row["disposition"] == "review":
            return stamp - started
    return None


def _classify_manual(capture: Capture) -> tuple[str, str, bool]:
    disposition, reason = manual.classify(capture)
    return disposition, reason, False


def _with_dossier(captures: list[Capture], rows: list[dict[str, Any]]) -> dict[str, Any]:
    by_id = {capture.case_id: capture for capture in captures}
    validation: dict[str, int] = {}
    repro_incomplete = 0
    confirmed = 0
    with tempfile.TemporaryDirectory(prefix="iwe-dossier-") as tmp:
        root = Path(tmp)
        for row in rows:
            if str(row["reason"]).startswith("duplicate_of:"):
                continue
            draft = bbtk_arm.verify_draft(root / row["case_id"], by_id[row["case_id"]], str(row["disposition"]))
            if draft["finding_confirmed"]:
                confirmed += 1
                row["finding_confirmed"] = True
            state = str(draft["validation_result"])
            validation[state] = validation.get(state, 0) + 1
            if draft["reproducibility"] != "reproducible_with_recorded_evidence":
                repro_incomplete += 1
                row["incomplete_repro"] = 1
        workflow = bbtk_arm.workflow_stops_for_human(root / "workflow")
    return {
        "dossier_validation_results": validation,
        "incomplete_repro_from_dossier": repro_incomplete,
        "dossier_finding_confirmed_true": confirmed,
        "workflow": workflow,
    }


def run_split(split: str) -> dict[str, Any]:
    if split in {"final", "stress"} and not manifest_matches(split):
        raise RuntimeError(f"{split} manifest does not match cases.json; refusing to score")
    cases = load_split(split)
    with LoopbackGuard() as guard:
        with LabServer(cases) as server:
            captures = [fetch(server.url, case) for case in cases]
        manual_started = time.perf_counter()
        manual_rows, manual_stamps = _dedup(captures, _classify_manual)
        manual_done = time.perf_counter()
        bbtk_started = time.perf_counter()
        bbtk_rows, bbtk_stamps = _dedup(captures, bbtk_arm.classify)
        dossier = _with_dossier(captures, bbtk_rows)
        bbtk_done = time.perf_counter()
    manual_scored = score_arm(cases, manual_rows)
    bbtk_scored = score_arm(cases, bbtk_rows)
    manual_arm = arm_envelope(
        "manual",
        manual_scored,
        wall_clock_seconds=manual_done - manual_started,
        seconds_to_first_review=_first_review(manual_started, manual_rows, manual_stamps),
        seconds_to_report=manual_done - manual_started,
    )
    bbtk_arm_metrics = arm_envelope(
        "bbtk",
        bbtk_scored,
        wall_clock_seconds=bbtk_done - bbtk_started,
        seconds_to_first_review=_first_review(bbtk_started, bbtk_rows, bbtk_stamps),
        seconds_to_report=bbtk_done - bbtk_started,
        extra={
            "dossier_validation_results": dossier["dossier_validation_results"],
            "workflow_finding_confirmed": dossier["workflow"]["finding_confirmed"],
            "workflow_auto_confirmations": dossier["workflow"]["auto_confirmations"],
            "workflow_network_requests_sent": dossier["workflow"]["network_requests_sent"],
            "workflow_executions": dossier["workflow"]["executions"],
            "workflow_next_reviewable_tasks": dossier["workflow"]["next_reviewable_tasks"],
            "workflow_documental_complete": dossier["workflow"]["documental_complete"],
        },
    )
    serialized = dumps({"manual": manual_rows, "bbtk": bbtk_rows, "dossier": dossier})
    return {
        "split": split,
        "external_requests": guard.external,
        "loopback_requests": guard.loopback,
        "network_attempts": guard.attempts,
        "secret_leaks": leak_count(serialized) + leak_count(dumps({"manual": manual_arm, "bbtk": bbtk_arm_metrics})),
        "finding_confirmed_policy": False,
        "manual": manual_arm,
        "bbtk": bbtk_arm_metrics,
        "dispositions": {"manual": manual_rows, "bbtk": bbtk_rows},
    }


def run_report(splits: list[str]) -> dict[str, Any]:
    payloads = {split: run_split(split) for split in splits}
    external = sum(item["external_requests"] for item in payloads.values())
    leaks = sum(item["secret_leaks"] for item in payloads.values())
    confirmed = sum(
        item["manual"]["finding_confirmed_true"] + item["bbtk"]["finding_confirmed_true"] for item in payloads.values()
    )
    return {
        "lab": "investigator-workflow-efficacy",
        "reproducibility": {
            "case_sha256": {
                split: hashlib.sha256((LAB / split / "cases.json").read_bytes()).hexdigest() for split in splits
            },
            "adapter_sha256": hashlib.sha256((LAB / "bbtk_arm.py").read_bytes()).hexdigest(),
            "measurement_kind": "synthetic_loopback_scripted",
        },
        "version_policy": "0.2.2",
        "fixture_results_only": True,
        "finding_confirmed": False,
        "prior_knowledge_bias": PRIOR_KNOWLEDGE_BIAS,
        "NOT_MEASURED": NOT_MEASURED,
        "external_requests": external,
        "secret_leaks": leaks,
        "finding_confirmed_true": confirmed,
        "splits": payloads,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--split", choices=(*SPLITS, "all"), default="all")
    parser.add_argument("--write", type=Path, help="Write the JSON report here")
    args = parser.parse_args(argv)
    splits = list(SPLITS) if args.split == "all" else [args.split]
    report = run_report(splits)
    text = dumps(report)
    if args.write:
        args.write.parent.mkdir(parents=True, exist_ok=True)
        args.write.write_text(text, encoding="utf-8")
    print(text)
    if report["external_requests"] or report["secret_leaks"] or report["finding_confirmed_true"]:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
