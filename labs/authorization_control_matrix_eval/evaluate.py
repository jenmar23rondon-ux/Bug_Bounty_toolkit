"""Run the authorization control matrix lab. Offline; loopback is never contacted.

``python -m labs.authorization_control_matrix_eval.evaluate --split dev``
``python -m labs.authorization_control_matrix_eval.evaluate --split final``
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path
from typing import Any

from labs.adversarial_idor_eval.evaluate import no_network

from bugbounty_toolkit.analysis.authorization_control_matrix import evaluate_control_matrix

from .baseline import naive_control_matrix
from .metrics import scenario_pass, summarize

HERE = Path(__file__).resolve().parent
LEAK = re.compile(r"(AKIA[0-9A-Z]{16}|-----BEGIN |CANARY_SECRET|Bearer\s+\S+|password\s*=)", re.I)


class FrozenCorpusError(RuntimeError):
    pass


def load_split(split: str) -> tuple[dict[str, Any], str]:
    directory = HERE / split
    blob = (directory / "scenarios.json").read_bytes()
    manifest = (directory / "MANIFEST.sha256").read_text(encoding="utf-8").split()
    digest = hashlib.sha256(blob).hexdigest()
    if not manifest or digest != manifest[0]:
        raise FrozenCorpusError(f"{split} scenarios.json does not match MANIFEST.sha256")
    payload: dict[str, Any] = json.loads(blob)
    return payload, digest


def _leak_count(text: str) -> int:
    return len(LEAK.findall(text))


def run_split(split: str) -> dict[str, Any]:
    payload, digest = load_split(split)
    fixture_text = (HERE / split / "scenarios.json").read_text(encoding="utf-8")
    secret_leaks = _leak_count(fixture_text)
    matrix_rows: list[dict[str, Any]] = []
    baseline_rows: list[dict[str, Any]] = []
    failures: list[str] = []
    with no_network() as attempts:
        for scenario in payload["scenarios"]:
            predicted = evaluate_control_matrix(
                scenario["observations"],
                comparison_scope=scenario["comparison_scope"],
            )
            baseline = naive_control_matrix(
                scenario["observations"],
                comparison_scope=scenario["comparison_scope"],
            )
            secret_leaks += _leak_count(json.dumps(predicted))
            secret_leaks += _leak_count(json.dumps({"id": scenario["id"]}))
            if not scenario_pass(scenario["expected"], predicted):
                failures.append(scenario["id"])
            matrix_rows.append({"id": scenario["id"], "expected": scenario["expected"], "predicted": predicted})
            baseline_rows.append({"id": scenario["id"], "expected": scenario["expected"], "predicted": baseline})
        external_requests = int(attempts["count"])
    matrix_metrics = summarize(matrix_rows)
    baseline_metrics = summarize(baseline_rows)
    matrix_metrics["secret_leaks"] = secret_leaks
    matrix_metrics["external_requests"] = external_requests
    baseline_metrics["secret_leaks"] = secret_leaks
    baseline_metrics["external_requests"] = external_requests
    return {
        "schema": "bbtk.authorization-control-matrix-metrics/1",
        "split": split,
        "manifest_sha256": digest,
        "finding_confirmed": False,
        "version": "0.2.2",
        "failures": failures,
        "matrix": matrix_metrics,
        "naive_baseline": baseline_metrics,
        "external_requests": external_requests,
        "secret_leaks": secret_leaks,
        "passed": len(payload["scenarios"]) - len(failures),
        "scenario_count": len(payload["scenarios"]),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Score the frozen authorization control matrix lab")
    parser.add_argument("--split", choices=("dev", "final", "both"), default="both")
    parser.add_argument("--write", action="store_true", help="Write results JSON under results/")
    args = parser.parse_args()
    splits = ("dev", "final") if args.split == "both" else (args.split,)
    reports = [run_split(split) for split in splits]
    if args.write:
        out = HERE / "results"
        out.mkdir(exist_ok=True)
        for report in reports:
            (out / f"{report['split']}_metrics.json").write_text(
                json.dumps(report, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
        if len(reports) == 2 or any(item["split"] == "final" for item in reports):
            final = next(item for item in reports if item["split"] == "final")
            before_after = {
                "schema": "bbtk.authorization-control-matrix-before-after/1",
                "version": "0.2.2",
                "finding_confirmed": False,
                "base_sha": "bbd0068f90b0f411360519434008ccdcfcbaaae0",
                "historical_reference": {
                    "authorization_control_matrix": "NOT_MEASURED",
                    "reason": (
                        "This lab did not exist at bbd0068f. The before column is the naive "
                        "status baseline on this frozen FINAL split, not a historical production score."
                    ),
                },
                "final_manifest_sha256": final["manifest_sha256"],
                "before": final["naive_baseline"],
                "after": final["matrix"],
                "external_requests": final["external_requests"],
                "secret_leaks": final["secret_leaks"],
            }
            (out / "before_after.json").write_text(
                json.dumps(before_after, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
    print(json.dumps([{k: v for k, v in report.items() if k != "naive_baseline"} for report in reports], indent=2))
    return (
        0
        if all(
            not report["failures"] and report["secret_leaks"] == 0 and report["external_requests"] == 0
            for report in reports
        )
        else 1
    )


if __name__ == "__main__":
    raise SystemExit(main())
