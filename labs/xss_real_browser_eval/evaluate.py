"""Run parser and Chromium validations for the disposable XSS lab.

    python -m labs.xss_real_browser_eval.evaluate --split dev --mode mock
    python -m labs.xss_real_browser_eval.evaluate --split all --mode live --repeat 3 --write-results

Live Chromium numbers are written only after a real launch. Mock mode records
``NOT_MEASURED`` for the live table. ``finding_confirmed`` stays false.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import time
from pathlib import Path
from typing import Any, Sequence

from bugbounty_toolkit.xss.context_classifier import classify_reflected_context

from . import PACKAGE_VERSION
from .chromium_gate import probe_chromium
from .metrics import browser_metrics, parser_metrics, reproducibility
from .observe import ChromiumSession, fetch_loopback, mock_case_row, public_navigation_url
from .secrets import secret_leak_count
from .server import LoopbackLab
from .spec import Scenario, payload_for, scenario_url
from .states import seal

LAB = Path(__file__).resolve().parent


def final_manifest_digest() -> str:
    text = (LAB / "final" / "MANIFEST.sha256").read_text(encoding="utf-8")
    return text.split()[0]


def final_is_frozen() -> bool:
    raw = (LAB / "final" / "scenarios.json").read_bytes()
    return hashlib.sha256(raw).hexdigest() == final_manifest_digest()


def load_cases(split: str) -> list[dict[str, Any]]:
    document = json.loads((LAB / split / "scenarios.json").read_text(encoding="utf-8"))
    cases = document["cases"]
    if not isinstance(cases, list):
        raise ValueError("scenarios.json cases must be a list")
    return cases


def cases_as_scenarios(split: str) -> tuple[Scenario, ...]:
    loaded: list[Scenario] = []
    for raw in load_cases(split):
        loaded.append(
            Scenario(
                letter=str(raw["letter"]),
                name=str(raw["name"]),
                path=str(raw["path"]),
                marker=str(raw["marker"]),
                payload_kind=str(raw["payload_kind"]),
                placement=str(raw["placement"]),
                expected_browser_state=str(raw["expected_browser_state"]),
                expected_parser_context=str(raw["expected_parser_context"]),
                expected_parser_decision=str(raw["expected_parser_decision"]),
                expect_execution=bool(raw["expect_execution"]),
                reflected_in_body=bool(raw["reflected_in_body"]),
                metric_groups=tuple(str(item) for item in raw["metric_groups"]),
                timeout_ms=int(raw["timeout_ms"]),
            )
        )
    return tuple(loaded)


def parser_rows(base_url: str, cases: Sequence[Scenario]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for case in cases:
        url = scenario_url(base_url, case)
        started = time.perf_counter()
        status, content_type, body, _csp = fetch_loopback(url)
        media = content_type.split(";", 1)[0].strip().lower()
        assessment = classify_reflected_context(body, case.marker, payload_for(case.payload_kind, case.marker), media)
        runtime_ms = round((time.perf_counter() - started) * 1000.0, 3)
        row = {
            "scenario_id": case.letter,
            "letter": case.letter,
            "name": case.name,
            "navigation_url": public_navigation_url(url),
            "origin": f"http://{base_url.split('://', 1)[1]}",
            "status": status,
            "content_type": media,
            "context": assessment.context,
            "decision": assessment.decision,
            "reflected": assessment.reflected,
            "escaped": assessment.escaped,
            "runtime_ms": runtime_ms,
            "browser_time_ms": 0.0,
            "external_requests": 0,
            "measurement": "offline_parser",
            "marker_in_body": case.marker in body,
        }
        rows.append(seal(row))
    return rows


def _safety_blob(payload: object) -> int:
    return secret_leak_count(json.dumps(payload, sort_keys=True))


def run_split(
    split: str,
    *,
    mode: str,
    repeat: int,
    gate: dict[str, Any] | None = None,
) -> dict[str, Any]:
    cases = cases_as_scenarios(split)
    chromium = gate if gate is not None else probe_chromium()
    live = mode == "live" or (mode == "auto" and bool(chromium.get("available")))
    if mode == "live" and not chromium.get("available"):
        return {
            "split": split,
            "parser": {"status": "NOT_MEASURED", "reason": "live mode refused to run without Chromium"},
            "chromium": {
                "status": "NOT_MEASURED",
                "reason": str(chromium.get("reason")),
                "finding_confirmed": False,
            },
        }
    with LoopbackLab() as lab:
        base_url = lab.base_url
        parsed = parser_rows(base_url, cases)
        browser_runs: list[list[dict[str, Any]]] = []
        peak_rss = 0
        if live:
            with ChromiumSession() as session:
                for _index in range(repeat):
                    browser_runs.append([session.run_case(base_url, case) for case in cases])
                peak_rss = session.peak_rss_bytes
        else:
            browser_runs.append([mock_case_row(case) for case in cases])
    parser_table = parser_metrics(parsed, cases)
    parser_table["secret_leaks"] = _safety_blob(parsed)
    report: dict[str, Any] = {
        "split": split,
        "origin": base_url,
        "parser": parser_table,
        "parser_rows": parsed,
    }
    if live:
        per_run = [browser_metrics(run, cases) for run in browser_runs]
        for table, run in zip(per_run, browser_runs, strict=True):
            table["secret_leaks"] = _safety_blob(run)
            table["peak_rss_bytes"] = peak_rss
        report["chromium"] = {
            "status": "measured",
            "browser_version": chromium.get("browser_version"),
            "playwright_version": chromium.get("playwright_version"),
            "runs": per_run,
            "reproducibility": reproducibility(browser_runs)
            if repeat >= 2
            else {
                "status": "NOT_MEASURED",
                "reason": "single live run; pass --repeat 3 to measure reproducibility",
                "runs": repeat,
            },
            "finding_confirmed": False,
            "external_requests": sum(int(table["external_requests"]) for table in per_run),
            "external_socket_observations": max(int(table["external_socket_observations"]) for table in per_run),
        }
        report["chromium_rows"] = browser_runs
    else:
        mock_table = browser_metrics(browser_runs[0], cases)
        mock_table["secret_leaks"] = _safety_blob(browser_runs[0])
        report["chromium"] = {
            "status": "NOT_MEASURED",
            "reason": "mock CI path; Chromium was not executed for this report"
            if mode == "mock" or not chromium.get("available")
            else "live suite was not selected",
            "gate": chromium,
            "finding_confirmed": False,
            "external_requests": "NOT_MEASURED",
        }
        report["mock_ci_pipeline"] = mock_table
    return report


def _public_report(report: dict[str, Any]) -> dict[str, Any]:
    """Drop per-scenario rows from the stdout summary; callers keep them in files."""
    hidden = {"parser_rows", "chromium_rows"}
    return {key: value for key, value in report.items() if key not in hidden}


def write_results(reports: dict[str, Any]) -> None:
    results = LAB / "results"
    results.mkdir(exist_ok=True)
    parser_doc = {
        "version": PACKAGE_VERSION,
        "measurement": "offline_parser",
        "finding_confirmed": False,
        "splits": {
            split: {"parser": reports[split]["parser"], "rows": reports[split].get("parser_rows", [])}
            for split in reports
        },
    }
    (results / "parser.json").write_text(json.dumps(parser_doc, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    chromium_doc: dict[str, Any] = {"version": PACKAGE_VERSION, "finding_confirmed": False, "splits": {}}
    any_live = False
    for split, report in reports.items():
        chromium = report["chromium"]
        entry: dict[str, Any] = {
            "status": chromium.get("status"),
            "reason": chromium.get("reason"),
            "browser_version": chromium.get("browser_version"),
            "playwright_version": chromium.get("playwright_version"),
            "external_requests": chromium.get("external_requests"),
            "external_socket_observations": chromium.get("external_socket_observations"),
            "finding_confirmed": False,
            "reproducibility": chromium.get("reproducibility"),
            "runs": chromium.get("runs"),
        }
        if chromium.get("status") == "measured":
            any_live = True
            entry["rows"] = report.get("chromium_rows", [])
        chromium_doc["splits"][split] = entry
    chromium_doc["status"] = "measured" if any_live else "NOT_MEASURED"
    (results / "chromium.json").write_text(
        json.dumps(chromium_doc, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--split", choices=("dev", "final", "all"), default="all")
    parser.add_argument("--mode", choices=("auto", "mock", "live"), default="auto")
    parser.add_argument("--repeat", type=int, default=1)
    parser.add_argument("--write-results", action="store_true")
    args = parser.parse_args(argv)
    if args.repeat < 1:
        print("repeat must be positive", flush=True)
        return 2
    if not final_is_frozen():
        print("FINAL corpus hash mismatch — refusing to evaluate a thawed FINAL.", flush=True)
        return 2
    gate = (
        probe_chromium()
        if args.mode != "mock"
        else {
            "available": False,
            "reason": "--mode mock does not launch Chromium",
            "browser_version": None,
            "playwright_version": None,
        }
    )
    splits = ["dev", "final"] if args.split == "all" else [args.split]
    reports = {split: run_split(split, mode=args.mode, repeat=args.repeat, gate=gate) for split in splits}
    summary = {
        "lab": "xss_real_browser_eval",
        "version": PACKAGE_VERSION,
        "finding_confirmed": False,
        "final_frozen": True,
        "splits": {split: _public_report(reports[split]) for split in splits},
    }
    print(json.dumps(summary, indent=2, sort_keys=True))
    if args.write_results:
        write_results(reports)
    bad = False
    for report in reports.values():
        parser_table = report.get("parser")
        if isinstance(parser_table, dict) and (
            parser_table.get("automatic_confirmations")
            or parser_table.get("secret_leaks")
            or parser_table.get("external_requests")
        ):
            bad = True
        chromium = report.get("chromium", {})
        if chromium.get("status") == "measured":
            if chromium.get("external_requests") or chromium.get("external_socket_observations"):
                bad = True
            for run in chromium.get("runs", []):
                if run.get("automatic_confirmations") or run.get("secret_leaks"):
                    bad = True
        mock = report.get("mock_ci_pipeline")
        if isinstance(mock, dict) and (mock.get("automatic_confirmations") or mock.get("secret_leaks")):
            bad = True
    return 1 if bad else 0


if __name__ == "__main__":
    raise SystemExit(main())
