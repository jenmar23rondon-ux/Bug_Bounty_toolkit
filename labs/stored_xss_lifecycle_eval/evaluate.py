"""Run the stored-XSS lifecycle lab.

The write → store → render → browser chain is ``run_stored_local``. This module
does not reimplement it. Live Chromium metrics stay ``NOT_MEASURED`` when the
browser binary is not installed.

    python -m labs.stored_xss_lifecycle_eval.evaluate --split all --runs 3
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import sys
import tempfile
import time
import tracemalloc
from pathlib import Path
from typing import Any, Mapping, cast

from bugbounty_toolkit.xss.playwright_confirm import PlaywrightExecutionChecker

from bugbounty_toolkit import __version__
from bugbounty_toolkit.core.http_client import HttpClient
from bugbounty_toolkit.core.rate_limiter import RateLimiter
from bugbounty_toolkit.core.scope_validator import ScopeValidator
from bugbounty_toolkit.xss.stored_local import StoredLocalOptions, run_stored_local

from labs.stored_xss_lifecycle_eval.checker import MockLoopbackChecker
from labs.stored_xss_lifecycle_eval.evidence import (
    build_case_evidence,
    count_confirmed,
    count_secret_leaks,
)
from labs.stored_xss_lifecycle_eval.metrics import rate, summarize_cases
from labs.stored_xss_lifecycle_eval.network import NetworkGuard, browser_processes_observed
from labs.stored_xss_lifecycle_eval.server import base_url, configure, fetch_state, reset, serve

LAB = Path(__file__).resolve().parent
REUSED_ENTRYPOINT = "bugbounty_toolkit.xss.stored_local.run_stored_local"
_NOT_MEASURED = "NOT_MEASURED"


def load_split(split: str) -> list[dict[str, Any]]:
    payload = json.loads((LAB / split / "cases.json").read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("Case file must be a JSON object.")
    if payload.get("declared_before_run") is not True or payload.get("finding_confirmed") is not False:
        raise ValueError("Cases must be declared before the run and keep finding_confirmed false.")
    cases = payload.get("cases")
    if not isinstance(cases, list) or len(cases) != 17:
        raise ValueError("The lifecycle lab declares exactly 17 cases.")
    return [case for case in cases if isinstance(case, dict)]


def final_is_frozen() -> bool:
    manifest = (LAB / "final" / "FROZEN.sha256").read_text(encoding="utf-8").split()[0]
    digest = hashlib.sha256((LAB / "final" / "cases.json").read_bytes()).hexdigest()
    return manifest == digest


def chromium_available() -> bool:
    """True only when a local Chromium binary is already installed. Never downloads one."""
    if importlib.util.find_spec("playwright") is None:
        return False
    roots: list[Path] = []
    env = os.environ.get("PLAYWRIGHT_BROWSERS_PATH")
    if env and env != "0":
        roots.append(Path(env))
    roots.append(Path.home() / ".cache" / "ms-playwright")
    for root in roots:
        if not root.is_dir():
            continue
        for name in ("chrome", "headless_shell", "chromium"):
            for match in root.glob(f"**/{name}"):
                if match.is_file() and os.access(match, os.X_OK):
                    return True
    return False


def _vm_hwm_bytes() -> int | None:
    try:
        lines = Path("/proc/self/status").read_text(encoding="utf-8").splitlines()
    except OSError:
        return None
    for line in lines:
        if line.startswith("VmHWM:"):
            parts = line.split()
            if len(parts) >= 2 and parts[1].isdigit():
                return int(parts[1]) * 1024
    return None


def _mode(browser: str) -> str:
    if browser == "mock":
        return "mock"
    available = chromium_available()
    if browser == "live":
        if not available:
            raise RuntimeError("Chromium is not installed; refusing to invent live execution results.")
        return "live"
    return "live" if available else "mock"


def _scan_evidence(directory: Path) -> tuple[int, int]:
    leaks = 0
    confirmed = 0
    if not directory.is_dir():
        return leaks, confirmed
    for path in directory.glob("*.json"):
        text = path.read_text(encoding="utf-8", errors="replace")
        leaks += count_secret_leaks(text)
        try:
            confirmed += count_confirmed(json.loads(text))
        except json.JSONDecodeError:
            leaks += 1
    return leaks, confirmed


def _events(state: Mapping[str, object], kind: str) -> list[dict[str, object]]:
    raw = state.get("events")
    if not isinstance(raw, list):
        return []
    return [item for item in raw if isinstance(item, dict) and item.get("kind") == kind]


def _observe(
    state: Mapping[str, object],
    pipeline: list[dict[str, object]],
    *,
    browser_error: bool,
    execution_observed: object,
) -> dict[str, object]:
    writes = _events(state, "write")
    views = _events(state, "view")
    write = writes[-1] if writes else {}
    view = views[-1] if views else None
    records = state.get("records")
    storage_sha = None
    if isinstance(records, list) and records and isinstance(records[-1], dict):
        storage_sha = records[-1].get("stored_sha256")
    primary = pipeline[-1] if pipeline else {}
    claim = any(item.get("browser_execution_observed") is True for item in pipeline)
    confirmed = any(item.get("confirmed") is True for item in pipeline)
    finding = any(item.get("finding_confirmed") is True for item in pipeline)
    pipeline_status = primary.get("write_status")
    observed: dict[str, object] = {
        "write_status": write.get("status"),
        "persisted": write.get("persisted") is True,
        "truncated": write.get("truncated") is True,
        "marker_in_write_body": write.get("marker_in_write_body") is True,
        "actor_writer": write.get("actor"),
        "storage_id": write.get("storage_id") if write.get("persisted") is True else None,
        "storage_sha256": storage_sha if write.get("persisted") is True else None,
        "view_status": None if view is None else view.get("status"),
        "content_type": None if view is None else view.get("content_type"),
        "render_context": None if view is None else view.get("render_context"),
        "marker_in_html": False if view is None else view.get("marker_in_html") is True,
        "executable_img": False if view is None else view.get("executable_img") is True,
        "sanitize_path": "none" if view is None else view.get("sanitize_path"),
        "csp_restrictive": False if view is None else view.get("csp_restrictive") is True,
        "csp_directives": [] if view is None else view.get("csp_directives") or [],
        "interaction_required": False if view is None else view.get("interaction_required") is True,
        "actor_viewer": None if view is None else view.get("actor"),
        "browser_error": browser_error,
        "execution_observed": execution_observed,
        "pipeline_classification": primary.get("classification"),
        "pipeline_phase": primary.get("phase"),
        "pipeline_probe": primary.get("probe"),
        "pipeline_execution_claim": claim,
        "pipeline_confirmed": confirmed,
        "pipeline_finding_confirmed": finding,
        "status_disagreement": pipeline_status != write.get("status"),
    }
    return observed


def _run_cases(
    cases: list[dict[str, Any]],
    *,
    mode: str,
    origin: str,
    scope: ScopeValidator,
    evidence_dir: Path,
) -> list[dict[str, object]]:
    client = HttpClient(scope, timeout=5.0, rate_limiter=RateLimiter(requests_per_second=200))
    live = None
    if mode == "live":
        from bugbounty_toolkit.xss.playwright_confirm import PlaywrightExecutionChecker

        live = PlaywrightExecutionChecker(scope, timeout_ms=5000, rate_limiter=client.rate_limiter)
    checker = MockLoopbackChecker()
    results: list[dict[str, Any]] = []
    try:
        for case in cases:
            results.append(
                _run_case(
                    case, origin=origin, client=client, checker=checker, live=live, evidence_dir=evidence_dir, mode=mode
                )
            )
    finally:
        checker.close()
        if live is not None:
            live.close()
    return results


def _run_case(
    case: Mapping[str, Any],
    *,
    origin: str,
    client: HttpClient,
    checker: MockLoopbackChecker,
    live: object,
    evidence_dir: Path,
    mode: str,
) -> dict[str, Any]:
    from labs.stored_xss_lifecycle_eval.metrics import case_mismatches

    case_id = str(case.get("id"))
    inputs = case.get("inputs")
    expected = case.get("expected")
    if not isinstance(inputs, dict) or not isinstance(expected, dict):
        raise ValueError(f"{case_id} is missing inputs or expected outcomes.")
    timeout_s = inputs.get("browser_timeout_s", 5.0)
    if isinstance(timeout_s, bool) or not isinstance(timeout_s, (int, float)) or timeout_s <= 0:
        raise ValueError(f"{case_id} has an invalid browser timeout.")
    truncate_at = inputs.get("truncate_at")
    delay_s = inputs.get("view_delay_s", 0)
    scenario = case.get("scenario")
    if not isinstance(scenario, str) or not isinstance(truncate_at, int) or isinstance(delay_s, bool):
        raise ValueError(f"{case_id} has invalid fixture inputs.")
    if not isinstance(delay_s, (int, float)):
        raise ValueError(f"{case_id} has an invalid view delay.")
    configure(origin, scenario, truncate_at, float(delay_s))
    active = inputs.get("active_marker") is True
    max_tests = inputs.get("max_tests")
    if type(max_tests) is not int or max_tests <= 0:
        raise ValueError(f"{case_id} has an invalid max_tests.")
    parameter = inputs.get("parameter")
    if not isinstance(parameter, str) or not parameter:
        parameter = "content"
    browser_error = False
    browser_error_name: str | None = None
    pipeline: list[dict[str, object]] = []
    failure: str | None = None
    try:
        if mode == "live" and live is not None:
            timeout_ms = max(1, int(float(timeout_s) * 1000))
            setattr(live, "timeout_ms", timeout_ms)
            _path, pipeline = run_stored_local(
                StoredLocalOptions(
                    write_url=f"{origin}/comments",
                    render_url=f"{origin}/comments/latest",
                    parameter=parameter,
                    max_tests=max_tests,
                    active_marker=active,
                ),
                client,
                cast(PlaywrightExecutionChecker, live),
                evidence_dir,
            )
        else:
            checker.timeout_s = float(timeout_s)
            checker.last = None
            _path, pipeline = run_stored_local(
                StoredLocalOptions(
                    write_url=f"{origin}/comments",
                    render_url=f"{origin}/comments/latest",
                    parameter=parameter,
                    max_tests=max_tests,
                    active_marker=active,
                ),
                client,
                cast(PlaywrightExecutionChecker, checker),
                evidence_dir,
            )
    except Exception as exc:
        failure = type(exc).__name__
        browser_error = True
        browser_error_name = failure
    if mode == "mock" and checker.last and isinstance(checker.last.get("browser_error"), str):
        browser_error = True
        browser_error_name = str(checker.last["browser_error"])
    if any(item.get("classification") == "error" for item in pipeline):
        browser_error = True
        if browser_error_name is None:
            browser_error_name = "pipeline_error"
    if mode == "live":
        execution_observed: object = any(item.get("browser_execution_observed") is True for item in pipeline)
    else:
        execution_observed = _NOT_MEASURED
    state = fetch_state(origin)
    observed = _observe(state, pipeline, browser_error=browser_error, execution_observed=execution_observed)
    reset(origin)
    after = fetch_state(origin)
    cleanup_ok = after.get("record_count") == 0 and after.get("event_count") == 0
    mismatches = case_mismatches(expected, observed)
    if failure is not None:
        mismatches.append({"field": "harness", "expected": "completed", "got": failure})
    evidence = build_case_evidence(
        case_id=case_id,
        observed=observed,
        cleanup_ok=cleanup_ok,
        execution_observed=execution_observed,
        browser_error=browser_error_name,
    )
    return {
        "id": case_id,
        "number": case.get("number"),
        "scenario": scenario,
        "cleanup_ok": cleanup_ok,
        "mismatches": mismatches,
        "evidence": evidence,
        "write_status": observed["write_status"],
        "view_status": observed["view_status"],
        "persisted": observed["persisted"],
        "truncated": observed["truncated"],
        "marker_in_html": observed["marker_in_html"],
        "marker_in_write_body": observed["marker_in_write_body"],
        "executable_img": observed["executable_img"],
        "execution_expected": expected.get("execution_expected"),
        "execution_observed": execution_observed,
        "pipeline_classification": observed["pipeline_classification"],
        "pipeline_execution_claim": observed["pipeline_execution_claim"],
        "pipeline_confirmed": observed["pipeline_confirmed"],
        "pipeline_finding_confirmed": observed["pipeline_finding_confirmed"],
        "browser_error": browser_error,
        "status_disagreement": observed["status_disagreement"],
        "finding_confirmed": False,
    }


def _with_execution_metrics(summary: dict[str, Any], cases: list[dict[str, Any]], mode: str) -> dict[str, Any]:
    if mode != "live":
        return summary
    tp = fp = fn = 0
    for case in cases:
        claim = case.get("pipeline_execution_claim") is True
        expected = case.get("execution_expected") is True
        if claim and expected:
            tp += 1
        elif claim and not expected:
            fp += 1
        elif expected and not claim:
            fn += 1
    summary["exec_precision"] = rate(tp, tp + fp) if (tp + fp) else 1.0
    summary["exec_false_positive_rate"] = rate(fp, len(cases))
    summary["exec_false_negative_rate"] = rate(fn, len(cases))
    summary["exec_counts"] = {"tp": tp, "fp": fp, "fn": fn}
    return summary


def _one_run(cases: list[dict[str, Any]], *, mode: str) -> dict[str, Any]:
    tracemalloc.start()
    started = time.perf_counter()
    with tempfile.TemporaryDirectory(prefix="stored-xss-lifecycle-") as directory:
        root = Path(directory)
        scope_file = root / "scope.txt"
        scope_file.write_text("127.0.0.1\n", encoding="utf-8")
        evidence_dir = root / "evidence"
        evidence_dir.mkdir()
        with serve() as server:
            origin = base_url(server)
            case_results = _run_cases(
                cases,
                mode=mode,
                origin=origin,
                scope=ScopeValidator(scope_file),
                evidence_dir=evidence_dir,
            )
        leaks, confirmed = _scan_evidence(evidence_dir)
    elapsed = time.perf_counter() - started
    peak = tracemalloc.get_traced_memory()[1]
    tracemalloc.stop()
    summary = summarize_cases(case_results)
    summary["declared_outcome_accuracy"] = rate(
        sum(1 for item in case_results if not item.get("mismatches")),
        len(case_results),
    )
    _with_execution_metrics(summary, case_results, mode)
    return {
        "elapsed_seconds": round(elapsed, 6),
        "python_tracemalloc_peak_bytes": peak,
        "process_hwm_bytes": _vm_hwm_bytes(),
        "secret_leaks": leaks,
        "automatic_confirmations": confirmed,
        "browser_processes_observed": browser_processes_observed(),
        "metrics": summary,
        "cases": case_results,
        "finding_confirmed": False,
    }


def _not_measured(mode: str, chromium: bool) -> list[dict[str, str]]:
    items = [
        {
            "item": "historical_lifecycle_baseline",
            "reason": "No stored-XSS lifecycle lab existed on the base commit, so there is no prior score to compare.",
        }
    ]
    if mode != "live":
        items.extend(
            [
                {
                    "item": "live_chromium_execution",
                    "reason": "Chromium is not installed"
                    if not chromium
                    else "This run selected the mock checker, so JavaScript was not executed.",
                },
                {
                    "item": "exec_precision",
                    "reason": "Execution precision needs a live Chromium observation. The mock checker never reports execution.",
                },
                {
                    "item": "exec_false_positive_rate",
                    "reason": "Not measured without live Chromium.",
                },
                {
                    "item": "exec_false_negative_rate",
                    "reason": "Not measured without live Chromium. Case 7 declares execution_expected true for a real browser only.",
                },
                {
                    "item": "live_browser_timeout",
                    "reason": "Case 16 times out the mock loopback GET through the same ToolkitError path. A Chromium navigation timeout was not launched.",
                },
                {
                    "item": "chromium_process_rss",
                    "reason": "No Chromium process was started.",
                },
            ]
        )
    return items


def evaluate(split: str, *, runs: int = 3, browser: str = "mock") -> dict[str, Any]:
    if split not in {"dev", "final"}:
        raise ValueError("split must be dev or final.")
    if type(runs) is not int or runs <= 0:
        raise ValueError("runs must be a positive integer.")
    if split == "final" and not final_is_frozen():
        raise RuntimeError("FINAL corpus hash mismatch — refusing to evaluate a thawed FINAL.")
    mode = _mode(browser)
    chromium = chromium_available()
    cases = load_split(split)
    per_run: list[dict[str, Any]] = []
    with NetworkGuard() as guard:
        for _index in range(runs):
            per_run.append(_one_run(cases, mode=mode))
        external = guard.external_requests
        loopback = guard.loopback_attempts
    leaks = sum(int(item["secret_leaks"]) for item in per_run)
    confirmed = sum(int(item["automatic_confirmations"]) for item in per_run)
    report_body: dict[str, Any] = {
        "lab": "stored-xss-lifecycle",
        "split": split,
        "version": __version__,
        "reused_entrypoint": REUSED_ENTRYPOINT,
        "browser_mode": mode,
        "chromium_available": chromium,
        "runs": runs,
        "finding_confirmed": False,
        "human_review_required": True,
        "external_requests": external,
        "loopback_attempts": loopback,
        "secret_leaks": leaks,
        "automatic_confirmations": confirmed,
        "browser_processes_observed": max(int(item["browser_processes_observed"]) for item in per_run),
        "elapsed_seconds_mean": round(sum(float(item["elapsed_seconds"]) for item in per_run) / runs, 6),
        "python_tracemalloc_peak_bytes": max(int(item["python_tracemalloc_peak_bytes"]) for item in per_run),
        "process_hwm_bytes": max(
            (int(item["process_hwm_bytes"]) for item in per_run if isinstance(item["process_hwm_bytes"], int)),
            default=None,
        ),
        "metrics": per_run[-1]["metrics"],
        "per_run": [
            {
                "elapsed_seconds": item["elapsed_seconds"],
                "python_tracemalloc_peak_bytes": item["python_tracemalloc_peak_bytes"],
                "process_hwm_bytes": item["process_hwm_bytes"],
                "metrics": item["metrics"],
                "finding_confirmed": False,
            }
            for item in per_run
        ],
        "cases": per_run[-1]["cases"],
        "not_measured": _not_measured(mode, chromium),
        "limitations": [
            "run_stored_local treats a marker in the write body as source_observed and does not record the rendered HTML body.",
            "Playwright local_only source detection looks at the URL query and fragment, not the stored comment body.",
            "run_stored_local does not pass CSP, sanitization, interaction, or browser-failure flags into classify_dom_state.",
            "The same headers are used for the writer and the browser view, so a distinct viewer identity is modeled by the lab as the cookieless GET.",
            "Mock navigation proves the loopback view was fetched. It does not execute JavaScript.",
            "P05 DOM hooks in dom_local.py and playwright_confirm.py are not modified.",
        ],
    }
    text = json.dumps(report_body, sort_keys=True)
    leaks += count_secret_leaks(text)
    confirmed += count_confirmed(json.loads(text))
    report_body["secret_leaks"] = leaks
    report_body["automatic_confirmations"] = confirmed
    report_body["gates_passed"] = _gates_passed(report_body)
    return report_body


def _gates_passed(report: Mapping[str, object]) -> bool:
    metrics = report.get("metrics")
    if not isinstance(metrics, dict):
        return False
    if report.get("finding_confirmed") is not False or report.get("version") != "0.2.2":
        return False
    if report.get("external_requests") != 0 or report.get("secret_leaks") != 0:
        return False
    if report.get("automatic_confirmations") != 0 or report.get("browser_processes_observed") != 0:
        return False
    attempts = report.get("loopback_attempts")
    if isinstance(attempts, bool) or not isinstance(attempts, int) or attempts <= 0:
        return False
    required = {
        "persistence_correctness": 1.0,
        "render_recall": 1.0,
        "control_accuracy": 1.0,
        "cleanup_success_rate": 1.0,
        "declared_outcome_accuracy": 1.0,
        "write_success_confirmed": 0,
        "marker_only_execution_claims": 0,
        "status_disagreements": 0,
    }
    for key, expected in required.items():
        if metrics.get(key) != expected:
            return False
    return True


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--split", choices=("dev", "final", "all"), default="all")
    parser.add_argument("--runs", type=int, default=3)
    parser.add_argument("--browser", choices=("auto", "mock", "live"), default="auto")
    parser.add_argument("--out", type=Path, default=None)
    args = parser.parse_args(argv)
    if not final_is_frozen():
        print("FINAL corpus hash mismatch — refusing to evaluate a thawed FINAL.", file=sys.stderr)
        return 2
    splits = ["dev", "final"] if args.split == "all" else [args.split]
    exit_code = 0
    for split in splits:
        try:
            report = evaluate(split, runs=args.runs, browser=args.browser)
        except RuntimeError as exc:
            print(str(exc), file=sys.stderr)
            return 2
        rendered = json.dumps(report, indent=2, sort_keys=True)
        print(rendered)
        if args.out is not None:
            args.out.mkdir(parents=True, exist_ok=True)
            (args.out / f"{split}.json").write_text(rendered + "\n", encoding="utf-8")
        if report.get("gates_passed") is not True:
            exit_code = 1
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
