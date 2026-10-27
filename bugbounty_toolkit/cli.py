from __future__ import annotations

import argparse
from contextlib import redirect_stderr, redirect_stdout
import importlib
import hashlib
import io
import json
import math
from dataclasses import asdict
from pathlib import Path
import re
import shutil
import subprocess
import sys

from . import __version__
from .core.checks import render_checklist
from .core.execution_budget import ExecutionBudget
from .core.records import ProgramPaths, RecordStore
from .core.reporting import render_markdown, render_pdf
from .core.runner import run_tool
from .core.scope import ensure_in_scope, validate_rule
from .core.scope_validator import ScopeValidator
from .core.settings import load_settings, ExecutorSettings
from .core.http_client import HttpClient
from .core.rate_limiter import RateLimiter
from .core.redaction import redact_url
from .core.target import load_routes, normalize_url
from .fuzzing.ffuf_runner import FfufOptions, FfufRunner
from .fuzzing.context_planner import (
    DISCOVERY_CATEGORIES,
    build_fuzz_plan,
    save_plan,
)
from .fuzzing.wordlist_manager import (
    WORDLIST_CATEGORIES,
    default_prepared_root,
    default_registry_path,
    detect_local_collections,
    inspect_wordlist,
    list_wordlists,
    load_collections,
    prepare_wordlist,
    recommend_wordlists,
    register_collection,
    scan_collections,
)
from .requests_engine.replay import RequestReplayer
from .requests_engine.headers import parse_header_items, parse_cookie_items
from .requests_engine.parameters import load_parameter_names, parse_parameter_items, with_parameter
from .xss.parameter_tester import XssOptions, XssParameterTester
from .sqli.parameter_tester import SqliOptions, SqliParameterTester, request_group_size
from .cors_check import CorsChecker, CorsOptions
from .open_redirect import OpenRedirectOptions, OpenRedirectTester
from .ssrf_check import SsrfChecker, SsrfOptions
from .csrf_audit import CsrfAuditor, CsrfOptions
from .apk_scan import ApkScanner
from .takeover_check import analyze_cnames, normalize_dns_name, resolve_cname_records
from .analysis.html_context import analyze_html
from .analysis.jwt_inspector import inspect_jwt, ALGORITHMS
from .analysis.information_disclosure import (
    assess_batch as assess_disclosure_batch,
    load_records as load_disclosure_records,
)
from .analysis.disclosure_access_correlation import (
    correlate_batch as correlate_disclosure_access_batch,
    load_cases as load_disclosure_access_cases,
)
from .jwt_forge import MAX_PUBLIC_KEY_BYTES, forge_jwt
from .analysis.sql_query import analyze_sql
from .analysis.evidence_review import review_evidence
from .analysis.evidence_engine import correlations_from_bundle, import_evidence
from .analysis.api_workflow import build_api_workflow
from .analysis.object_relationships import (
    discover_to_file,
    load_object_key,
    object_candidates,
    read_object_graph,
    save_object_json,
    verify_object_sources,
)
from .analysis.object_handoff import default_lab_root, handoff_to_file, run_object_discovery_lab
from .core.private_files import local_path
from .analysis.evidence_graph import EvidenceGraphStore, preview_graph_ingest
from .analysis.hypotheses import SECOND_OPINION as HYPOTHESES_SECOND_OPINION, analyze_hypotheses
from .analysis.access_assessment import assess_access_control
from .analysis.skill_router import route_hypotheses, route_hypotheses_file
from .analysis.benchmark import run_idor_benchmark, write_benchmark_reports
from .analysis.prioritization import prioritize_hypotheses_file, write_prioritization_report
from .analysis.investigation import investigate_evidence
from .analysis.investigation_memory import InvestigationMemory
from .analysis import evidence_ledger as ledger_mod
from .analysis.evidence_ledger_lab import run_evidence_ledger_lab
from .analysis.evidence_gap_planner import PLAN_SCHEMA, build_plan, dumps_plan, validate_plan
from .access_control.comparison import AccessControlTester
from .access_control.range_checker import AccessRangeOptions, AccessRangeTester, MAX_RANGE_REQUESTS
from .access_control.write_lab import AccessWriteLabTester
from .access_control.write_range import AccessWriteRangeTester
from .access_control.function_matrix import AccessFunctionMatrixTester
from .access_control.guards import is_loopback_url
from .analysis.ollama_review import DEFAULT_OLLAMA_MODEL, review_with_ollama, validate_ollama_config
from .analysis.ai_backend import AISelection, review_packet, selection_from_args
from .analysis.artifact_review import (
    SECOND_OPINION,
    generate_ai_report,
    review_artifact,
    review_evidence_with_ollama,
)
from .analysis.live_review import (
    add_ai_review_arguments,
    format_ai_review,
    config_selection,
    resolve_ai_review_config,
    review_evidence_file,
)
from .integrations.catalog import catalog
from .integrations.external_plan import build_external_plan, TOOLS
from .reporting.evidence import write_evidence_json
from .reporting.html_report import render_html_report
from .reporting.json_report import render_json_report
from .reporting.review_markdown import render_evidence_review
from .utils.exceptions import ExternalToolError
from .reporting.finding_report import (
    build_evidence_finding_report,
    render_evidence_report_html,
    render_evidence_report_json,
    render_evidence_report_pdf,
)
from .burp_import import (
    MAX_ITEM_BYTES,
    MAX_REQUEST_BYTES,
    MAX_SITEMAP_BYTES,
    extract_item_artifacts,
    normalize_raw_request,
    parse_sitemap,
    read_bounded as read_burp_file,
    safe_artifact_name,
)
from .case_generator import CaseGenerationOptions, generate_case
from .idor_discovery import approve_idor, discover_idor, discovery_summary, save_proposal
from .diagnostics import diagnose
from .hunt import (
    HuntTask,
    MODULE_ORDER,
    allocate_request_budgets,
    collect_findings,
    parse_module_selection,
    plan_fingerprint,
    redistribute_unused_budget,
    render_hunt_html,
    summarize_module,
)
from .utils.exceptions import ToolkitError
from .utils.logger import setup_logger

try:
    yaml = importlib.import_module("yaml")
except ModuleNotFoundError:  # Keep bbtk doctor usable when a required dependency is missing.
    yaml = None

_YAML_ERROR = yaml.YAMLError if yaml is not None else type("_YAML_ERROR", (Exception,), {})


RECORDS_ROOT = Path("registros")


def store_for(program: str) -> RecordStore:
    return RecordStore(ProgramPaths(RECORDS_ROOT, program))


def executor_context(args: argparse.Namespace, automated: bool = False):
    store = store_for(args.program)
    store.require_authorization()
    if automated and store.metadata().get("automation_allowed") != "true":
        raise ValueError("Program automation is not enabled. Check its policy and use init --automation-allowed.")
    settings_path = store.paths.program_dir / "settings.yaml"
    settings = load_settings(settings_path if settings_path.exists() else None)
    rate = getattr(args, "rate", None)
    if rate is not None and rate > settings.requests_per_second:
        raise ValueError("Requested rate exceeds the configured program limit.")
    threads = getattr(args, "threads", None)
    if threads is not None and threads > settings.max_concurrency:
        raise ValueError("Requested threads exceed the configured program limit.")
    concurrency = getattr(args, "concurrency", None)
    if concurrency is not None and concurrency > settings.max_concurrency:
        raise ValueError("Requested concurrency exceeds the configured program limit.")
    run_concurrency = getattr(args, "run_max_concurrency", None)
    if run_concurrency is not None and run_concurrency > settings.max_concurrency:
        raise ValueError("Run concurrency exceeds the configured program limit.")
    if not hasattr(args, "_execution_budget"):
        args._execution_budget = ExecutionBudget(
            max_requests=getattr(args, "run_max_requests", None),
            max_seconds=getattr(args, "run_max_seconds", None),
            max_concurrency=run_concurrency or settings.max_concurrency,
        )
    return store, settings, ScopeValidator(store.paths.scope_file)


def client_for(args: argparse.Namespace, settings: ExecutorSettings, scope: ScopeValidator) -> HttpClient:
    return HttpClient(
        scope,
        timeout=args.timeout or settings.timeout,
        rate_limiter=getattr(args, "_rate_limiter", None) or RateLimiter(args.rate or settings.requests_per_second),
        max_response_bytes=settings.max_response_bytes,
        execution_budget=getattr(args, "_execution_budget", None),
    )


def print_live_ai_review(
    path: Path, config: tuple[str, float] | tuple[str, float, AISelection] | None, toolkit_verdict: str
) -> None:
    if config is None:
        return
    ai_review = review_evidence_file(path, config[0], config[1], config_selection(config))
    print(format_ai_review(ai_review, toolkit_verdict))


def cmd_init(args: argparse.Namespace) -> None:
    store = store_for(args.program)
    if not args.authorization.strip():
        raise ValueError("Authorization reference cannot be empty.")
    if yaml is None:
        raise RuntimeError("PyYAML is required for program initialization. Install the base package dependencies.")
    settings_path = store.paths.program_dir / "settings.yaml"
    settings = load_settings(args.config or (settings_path if settings_path.exists() else None))
    settings_path.write_text(yaml.safe_dump(asdict(settings)), encoding="utf-8")
    store.set_program_meta(
        platform=args.platform,
        authorization=args.authorization,
        automation_allowed="true" if args.automation_allowed else "false",
    )
    print(f"[+] Program initialized: {store.paths.program_dir}")


def cmd_lab_idor(args: argparse.Namespace) -> None:
    """Run or preview the deterministic local IDOR end-to-end workflow."""
    project_root = Path(__file__).resolve().parents[1]
    test_file = project_root / "tests" / "test_end_to_end_idor.py"
    if args.dry_run:
        print("[i] Local-only IDOR lab plan. --dry-run sends no requests and writes no files.")
        print("[1] Server command for a manual run: bash labs/idor_lab/run.sh (PowerShell: ./labs/idor_lab/run.ps1).")
        print(
            '[2] bbtk --records-root <LAB_ROOT>/records init idor-lab --authorization "isolated local IDOR lab fixture" --automation-allowed'
        )
        print("[3] bbtk --records-root <LAB_ROOT>/records scope add idor-lab 127.0.0.1")
        print(
            "[4] bbtk --records-root <LAB_ROOT>/records import case idor-lab "
            "--owner labs/idor_lab/captures/owner.txt --actor labs/idor_lab/captures/actor.txt "
            "--base-url http://127.0.0.1:8099 --resource-pointer /data/id "
            "--success-pointer /success --success-value true --private-pointer /data/marker "
            "--private-marker owner-order-marker-1001 --actor-marker actor-order-marker-1002 "
            "--attest-authorized-accounts --attest-private-resource"
        )
        print(
            "[5] After policy approval for this disposable lab only, add "
            '"identifier_enumeration_authorized": true to <LAB_ROOT>/records/idor-lab/private/case.json.'
        )
        print(
            "[6] bbtk --records-root <LAB_ROOT>/records access-check idor-lab "
            "--case-file <LAB_ROOT>/records/idor-lab/private/case.json --range 1001-1002 "
            "--max-range 2 --max-tests 4 --min-interval 0.01"
        )
        print("[7] The test builds <LAB_ROOT>/records/idor-lab/private/public-case.json for /api/public/status.")
        print(
            "[8] bbtk --records-root <LAB_ROOT>/records access-check idor-lab "
            "--case-file <LAB_ROOT>/records/idor-lab/private/public-case.json --anonymous-check --max-tests 4 "
            "(expected: public_endpoint, not candidate)."
        )
        print("[9] bbtk --records-root <LAB_ROOT>/records report idor-lab --format json (repeat with --format html).")
        print("[one command] bbtk lab idor")
        print("[equivalent test command] python -m unittest discover -s tests -p test_end_to_end_idor.py -v")
        return
    if not test_file.is_file():
        raise RuntimeError("The runnable IDOR lab needs the repository tests/test_end_to_end_idor.py file.")
    print("[i] Running the deterministic IDOR lab. Traffic is restricted to 127.0.0.1; no external requests are sent.")
    completed = subprocess.run(
        [sys.executable, "-m", "unittest", "discover", "-s", "tests", "-p", "test_end_to_end_idor.py", "-v"],
        cwd=project_root,
        check=False,
    )
    if completed.returncode:
        raise RuntimeError(f"The end-to-end IDOR lab failed with exit code {completed.returncode}.")


def cmd_lab_web_vuln(args: argparse.Namespace) -> None:
    """Run or preview the local XSS/SQLi evidence-to-report workflow."""
    project_root = Path(__file__).resolve().parents[1]
    test_file = project_root / "tests" / "test_end_to_end_web_vuln.py"
    if args.dry_run:
        print("[i] Local-only XSS/SQLi lab plan. --dry-run starts no server and sends no requests.")
        print(
            "[1] Optional manual fixture server: bash labs/web_vuln_lab/run.sh (PowerShell: ./labs/web_vuln_lab/run.ps1)."
        )
        print("[2] The end-to-end test starts a temporary fixture on 127.0.0.1 and runs bounded XSS and SQLi checks.")
        print(
            "[3] It imports redacted evidence, builds API workflow, reviews mocked hypotheses, routes skills, and drafts reports."
        )
        print(
            "[4] Fixtures simulate HTML reflection and SQL error text; no browser execution or real SQL engine is used."
        )
        print("[one command] bbtk lab web-vuln")
        print("[equivalent test command] python -m unittest discover -s tests -p test_end_to_end_web_vuln.py -v")
        return
    if not test_file.is_file():
        raise RuntimeError("The runnable web vulnerability lab needs tests/test_end_to_end_web_vuln.py.")
    print("[i] Running deterministic XSS/SQLi fixtures. Requests are limited to an ephemeral loopback server.")
    completed = subprocess.run(
        [sys.executable, "-m", "unittest", "discover", "-s", "tests", "-p", "test_end_to_end_web_vuln.py", "-v"],
        cwd=project_root,
        check=False,
    )
    if completed.returncode:
        raise RuntimeError(f"The end-to-end web vulnerability lab failed with exit code {completed.returncode}.")


def cmd_lab_object_discover(args: argparse.Namespace) -> None:
    """Run the offline object-discovery efficacy lab (synthetic labeled corpus)."""
    root = args.corpus_root or default_lab_root()
    result = run_object_discovery_lab(root, split=args.split, limit=args.limit, dry_run=args.dry_run)
    primary = result["primary"]
    metrics = primary["metrics"]
    summary = {
        "split": result["split"],
        "dry_run": args.dry_run,
        "handoff_proposals": primary["handoff_proposals"],
        "precision_at_1": metrics["precision_at_1"],
        "precision_at_3": metrics["precision_at_3"],
        "precision_at_5": metrics["precision_at_5"],
        "recall": metrics["recall"],
        "fp_count": metrics["fp_count"],
        "fn_count": metrics["fn_count"],
        "vulnerable_in_top3": metrics["vulnerable_in_top3"],
        "baseline_precision_at_3": metrics["baseline_precision_at_3"],
        "asymmetric_selected": primary["asymmetric_selected"],
        "request_only_recall": primary["request_only_comparison"]["recall"],
        "request_only_fn_count": primary["request_only_comparison"]["fn_count"],
        "processing_ms": metrics["processing_ms"],
        "network_requests_sent": 0,
        "vulnerabilities_confirmed": 0,
        "confirmed": False,
    }
    print(json.dumps(summary, indent=2, sort_keys=True))
    print("[i] Synthetic ranking metrics only; not real bug-bounty confirmation performance.")
    print("[i] " + result["human_gate"])
    if args.metrics_json:
        destination = local_path(args.metrics_json)
        if destination.exists() and not args.force:
            raise ValueError(f"Metrics output already exists: {destination}. Pass --force to replace it.")
        rendered = json.dumps(result, indent=2, sort_keys=True, ensure_ascii=True) + "\n"
        destination.parent.mkdir(parents=True, exist_ok=True)
        if args.force:
            destination.write_text(rendered, encoding="utf-8")
        else:
            with destination.open("x", encoding="utf-8", newline="") as handle:
                handle.write(rendered)
        print(f"[+] Metrics saved: {destination}")
    if args.dry_run:
        print("[dry-run] Lab computed in memory only; metrics file written solely if --metrics-json was set.")


def cmd_scope_add(args: argparse.Namespace) -> None:
    store = store_for(args.program)
    value = args.domain.lstrip("!-")
    validate_rule(value)
    rule = "!" + value if args.exclude or args.domain.startswith(("!", "-")) else value
    current = store.paths.scope_file.read_text(encoding="utf-8").splitlines() if store.paths.scope_file.exists() else []
    if rule not in current:
        with store.paths.scope_file.open("a", encoding="utf-8") as handle:
            handle.write(f"{rule}\n")
    store.mark_reviewed("scope", rule, "Scope rule added")
    print(f"[+] Scope added: {rule}")


def cmd_scope_import(args: argparse.Namespace) -> None:
    if yaml is None:
        raise RuntimeError("PyYAML is required to import scope YAML. Install the base package dependencies.")
    data = yaml.safe_load(args.file.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or set(data) - {"allowed", "excluded"}:
        raise ValueError("Scope YAML must contain allowed and excluded lists.")
    rules = []
    for key in ("allowed", "excluded"):
        values = data.get(key, [])
        if not isinstance(values, list) or not all(isinstance(value, str) for value in values):
            raise ValueError("Scope entries must be lists of strings.")
        for value in values:
            validate_rule(value)
            rules.append(("!" if key == "excluded" else "") + value)
    store = store_for(args.program)
    current = store.paths.scope_file.read_text(encoding="utf-8").splitlines() if store.paths.scope_file.exists() else []
    store.paths.scope_file.write_text("\n".join(dict.fromkeys(current + rules)) + "\n", encoding="utf-8")
    print(f"[+] Imported {len(rules)} scope rules.")


def cmd_request(args: argparse.Namespace) -> None:
    store, settings, scope = executor_context(args)
    replayer = RequestReplayer(scope, client_for(args, settings, scope))
    if args.raw_request:
        spec = replayer.from_raw_file(args.raw_request, args.base_url)
        spec.headers.update(parse_header_items(args.header))
        cookies = parse_cookie_items(args.cookie)
        if cookies:
            spec.headers["Cookie"] = cookies
        spec.params.update(parse_parameter_items(args.param))
        if args.method:
            spec.method = args.method
        if args.data is not None:
            spec.body = args.data
    else:
        spec = replayer.from_cli(args.url, args.method or "GET", args.header, args.cookie, args.param, args.data)
    if args.dry_run:
        scope.require(spec.prepared_url())
        print(f"[+] Request validated: {spec.method.upper()} {redact_url(spec.prepared_url())}. No request sent.")
        return
    record, path = replayer.send_and_save(spec, store.paths.evidence_dir / "requests")
    target = redact_url(spec.prepared_url())
    store.add_run("request", target, [spec.method, target], 0, path)
    store.mark_reviewed("request-url", target, str(path))
    print(f"[+] HTTP {record.status_code} | {record.duration_ms} ms | {record.body_size} bytes")
    print(f"[+] Evidence: {path}")


def cmd_recon(args: argparse.Namespace) -> None:
    store, settings, scope = executor_context(args, automated=True)
    rate = external_rate(settings)
    ensure_in_scope(args.target, store.paths.scope_file)
    budget = getattr(args, "_execution_budget", None)
    tool_kwargs = {
        "timeout_seconds": max(60.0, float(settings.timeout) * 20.0),
        "max_output_bytes": max(settings.max_response_bytes * 20, 1_000_000),
        "execution_budget": budget,
        "contact_external": True,
        "authorization_attested": True,
        "scope_attested": True,
    }
    subfinder = run_tool(store, "subfinder", args.target, ["subfinder", "-silent", "-d", args.target], **tool_kwargs)
    amass = run_tool(store, "amass", args.target, ["amass", "enum", "-passive", "-d", args.target], **tool_kwargs)
    merged = store.paths.raw_dir / "subdomains.txt"
    values = set()
    for path in [subfinder, amass]:
        values.update(
            line.strip() for line in path.read_text(encoding="utf-8", errors="ignore").splitlines() if line.strip()
        )
    authorized = []
    for host in sorted(values):
        try:
            scope.require(host)
        except ValueError:
            continue
        authorized.append(host)
    if not authorized:
        raise ValueError("No discovered hosts are in scope. Add explicit subdomains or a permitted wildcard.")
    merged.write_text("\n".join(authorized) + "\n", encoding="utf-8")
    httpx = run_tool(
        store,
        "httpx",
        args.target,
        ["httpx", "-silent", "-l", str(merged), "-rl", str(rate)],
        **tool_kwargs,
    )
    print(f"[+] Recon complete. Live host output: {httpx}")


def cmd_scan_nuclei(args: argparse.Namespace) -> None:
    store, settings, scope = executor_context(args, automated=True)
    rate = external_rate(settings)
    hosts = store.paths.raw_dir / "subdomains.txt"
    if not hosts.exists():
        raise SystemExit("Run recon first; missing registros/<program>/raw/subdomains.txt")
    scope.require_all([line.strip() for line in hosts.read_text(encoding="utf-8").splitlines() if line.strip()])
    budget = getattr(args, "_execution_budget", None)
    output = run_tool(
        store,
        "nuclei",
        None,
        [
            "nuclei",
            "-l",
            str(hosts),
            "-severity",
            args.severity,
            "-dr",
            "-rl",
            str(rate),
            "-c",
            str(settings.max_concurrency),
        ],
        timeout_seconds=max(60.0, float(settings.timeout) * 20.0),
        max_output_bytes=max(settings.max_response_bytes * 20, 1_000_000),
        execution_budget=budget,
        contact_external=True,
        authorization_attested=True,
        scope_attested=True,
    )
    print(f"[+] Nuclei scan complete: {output}")


def cmd_fuzz(args: argparse.Namespace) -> None:
    if args.max_seconds is not None and args.run_max_seconds is None:
        args.run_max_seconds = args.max_seconds
    store, settings, scope = executor_context(args, automated=True)
    rate = args.rate or settings.requests_per_second
    if rate < 1 or rate != int(rate):
        raise ValueError("ffuf requires a whole-number rate of at least 1 request/second.")
    max_tests = args.max_tests or settings.max_tests
    if max_tests > settings.max_tests:
        raise ValueError("Max tests exceeds the configured program limit.")
    run_budget = args._execution_budget
    threads = args.threads or settings.max_concurrency
    if args.run_max_concurrency is not None:
        if args.threads is not None and args.threads > args.run_max_concurrency:
            raise ValueError("Requested ffuf threads exceed --run-max-concurrency.")
        threads = min(threads, args.run_max_concurrency)
    total_cap = max_tests
    if run_budget.max_requests is None:
        run_budget.max_requests = total_cap
    else:
        already_started = run_budget.summary().requests_started
        external_reserved = run_budget.summary().external_requests_reserved
        remaining = run_budget.max_requests - already_started - external_reserved
        total_cap = min(total_cap, remaining)
    if total_cap < 2:
        raise ValueError("Fuzzing needs a budget for one baseline request and at least one wordlist entry.")
    max_seconds = args.max_seconds or 120.0
    if args.run_max_seconds is not None:
        max_seconds = min(max_seconds, args.run_max_seconds)
    if settings.timeout < 1:
        raise ValueError("ffuf needs a configured program timeout of at least one whole second.")
    request_timeout = args.timeout or int(settings.timeout)
    if request_timeout > settings.timeout:
        raise ValueError("ffuf request timeout exceeds the configured program timeout.")
    options = FfufOptions(
        url=args.url,
        wordlist=args.wordlist,
        threads=threads,
        timeout=request_timeout,
        rate=int(rate),
        match_codes=args.match_codes,
        filter_size=args.filter_size,
        max_entries=total_cap - 1,
        max_seconds=max_seconds,
    )
    runner = FfufRunner(store, scope, client_for(args, settings, scope))
    runner.validate(options)
    selected = runner.preview_entries(options)
    selected_sha256 = hashlib.sha256(("\n".join(selected) + "\n").encode("utf-8")).hexdigest()
    planned_upper_bound = len(selected) + 1
    print(
        f"[i] Fuzz plan: target {redact_url(args.url)}; wordlist {args.wordlist}; "
        f"selected inputs {len(selected)} (cap {options.max_entries}); selected SHA-256 {selected_sha256}."
    )
    print(
        f"[i] Planned upper bound: {planned_upper_bound} requests including one baseline; "
        f"rate {options.rate}/s; concurrency {options.threads}; request timeout {options.timeout}s; "
        f"wall-clock cap {options.max_seconds:g}s; redirects/recursion disabled."
    )
    if args.dry_run:
        print("[+] Fuzz plan validated. No requests sent and no wordlist file prepared.")
        return
    if not args.confirm:
        raise ValueError("Active fuzzing requires explicit --confirm after reviewing the bounded plan.")
    if shutil.which("ffuf") is None:
        raise ExternalToolError("Required tool not found in PATH: ffuf")
    run_budget.reserve_external_requests(len(selected), options.url, options.threads)
    path, results = runner.run(options)
    store.mark_reviewed("fuzz-url", redact_url(args.url), str(path))
    evidence = json.loads(path.read_text(encoding="utf-8"))
    raw_output = evidence.get("raw_output") if isinstance(evidence, dict) else None
    integrated: dict[str, object] = {}
    if isinstance(raw_output, str):
        integrated = _integrate_fuzz_evidence(store, args.program, path, Path(raw_output), settings.max_tests)
    stopped = evidence.get("status") == "stopped_rate_limited_baseline" if isinstance(evidence, dict) else False
    if stopped:
        run_budget.release_external_reservation(len(selected))
        print("[!] Baseline returned HTTP 429; ffuf was not started and no follow-up traffic was sent.")
    else:
        candidates = evidence.get("followup_candidates", []) if isinstance(evidence, dict) else []
        candidate_count = len(candidates) if isinstance(candidates, list) else 0
        print(
            f"[+] Fuzzing complete: {len(results)} unique responses, {candidate_count} routes for manual authorization review."
        )
    if integrated:
        print(
            f"[+] Evidence integration: bundle {integrated.get('bundle')}; API workflow {integrated.get('workflow')}; "
            f"graph nodes {integrated.get('graph_nodes')}; investigation {integrated.get('investigation_id')}."
        )
        if integrated.get("route_plan"):
            print(f"[i] Offline skill follow-up plan: {integrated['route_plan']} (not executed).")
    print(f"[+] Evidence: {path}")


def _integrate_fuzz_evidence(
    store: RecordStore, program: str, fuzz_path: Path, raw_path: Path, max_tests: int
) -> dict[str, object]:
    """Import ffuf output into the existing evidence, workflow, graph and memory systems."""
    bundle = import_evidence([raw_path], format_name="ffuf-json")
    bundle_path = write_evidence_json(store.paths.evidence_dir / "imports", bundle, "fuzz-unified")
    workflow = build_api_workflow(bundle_path)
    workflow_path = write_evidence_json(store.paths.evidence_dir / "workflows", workflow, "fuzz-api-workflow")
    graph_result = EvidenceGraphStore(store).ingest(bundle_path)

    fuzz_evidence = json.loads(fuzz_path.read_text(encoding="utf-8"))
    followups = fuzz_evidence.get("followup_candidates", []) if isinstance(fuzz_evidence, dict) else []
    records = bundle.get("records", [])
    hypotheses: list[tuple[str, dict[str, object]]] = []
    if isinstance(followups, list) and isinstance(records, list):
        for index, item in enumerate(followups, start=1):
            if not isinstance(item, dict) or not isinstance(item.get("route_template"), str):
                continue
            matching = next(
                (row for row in records if isinstance(row, dict) and row.get("endpoint") == item["route_template"]),
                None,
            )
            evidence_id = matching.get("evidence_id") if isinstance(matching, dict) else None
            if not isinstance(evidence_id, str) or not re.fullmatch(r"[a-f0-9]{24}", evidence_id):
                continue
            hypothesis: dict[str, object] = {
                "category": "access_control",
                "summary": f"Observed resource-shaped endpoint {item['route_template']} for manual authorization review.",
                "evidence_for": [
                    {
                        "record_id": evidence_id,
                        "why": "ffuf observed a response distinct from the missing-route baseline.",
                    }
                ],
                "evidence_against": [],
                "missing_controls": [
                    "owner account can read its own known resource",
                    "second authorized account can read its own known resource",
                    "cross-account comparison for a resource known to belong to the other account",
                ],
                "confidence": "low",
                "next_check": {
                    "kind": "offline",
                    "suggestion": "Prepare a private reviewed case.json from two authorized accounts, then inspect access-check --dry-run.",
                    "why": "Endpoint discovery does not establish ownership, privacy or authorization behavior.",
                },
                "status": "hypothesis",
            }
            hypotheses.append((f"ffuf-followup-{index}", hypothesis))

    route_path: Path | None = None
    if hypotheses:
        route = route_hypotheses(
            {"type": "ffuf-discovery-hypotheses"},
            hypotheses,
            program,
            max_tests,
            use_ollama=False,
        )
        route_path = write_evidence_json(store.paths.evidence_dir / "fuzzing", route, "fuzz-followup-plan")

    bundle_id = bundle.get("bundle_id")
    if not isinstance(bundle_id, str) or not re.fullmatch(r"[a-f0-9]{24}", bundle_id):
        raise ValueError("Evidence engine returned an invalid bundle ID for investigation memory.")
    investigation_id = f"fuzz-{bundle_id}"
    snapshot_ref = bundle_path.relative_to(store.paths.program_dir).as_posix()
    memory = InvestigationMemory(store).save_snapshot(
        investigation_id,
        bundle_id,
        snapshot_ref,
        {
            "discovery": {"status": "completed; responses classified against one baseline"},
            "api_workflow": {"status": "completed; relationships remain descriptive"},
            "evidence_graph": {"status": "ingested locally"},
            "authorization": {"status": "pending owner/actor controls and human review"},
        },
    )
    graph_nodes = graph_result.get("nodes_written", 0)
    return {
        "bundle": str(bundle_path),
        "workflow": str(workflow_path),
        "graph_nodes": graph_nodes,
        "route_plan": str(route_path) if route_path else None,
        "investigation_id": memory.get("investigation_id"),
        "network_requests_sent": 0,
        "ollama_calls": 0,
        "plan_executed": False,
    }


def cmd_fuzz_plan(args: argparse.Namespace) -> None:
    """Build an offline, context-aware discovery plan from a local HAR capture.

    Never downloads wordlists, never opens network sockets, and never starts ffuf.
    Approved execution reuses ``bbtk fuzz`` (authorization + ``--confirm``).
    """
    store = RecordStore(ProgramPaths(RECORDS_ROOT, args.program))
    settings_path = store.paths.program_dir / "settings.yaml"
    settings = load_settings(settings_path if settings_path.exists() else None)
    scope = ScopeValidator(store.paths.scope_file)
    registry = args.registry or default_registry_path()
    collections = load_collections(registry)
    max_tests = args.max_tests or min(settings.max_tests, 40)
    if max_tests > settings.max_tests:
        raise ValueError("Max tests exceeds the configured program limit.")
    object_rows = None
    object_key = None
    if args.object_candidates:
        payload = json.loads(Path(args.object_candidates).read_text(encoding="utf-8"))
        if isinstance(payload, dict) and isinstance(payload.get("candidates"), list):
            object_rows = payload["candidates"]
        elif isinstance(payload, list):
            object_rows = payload
        else:
            raise ValueError("Object candidates file must be a list or an object with a candidates array.")
    if args.object_key:
        from .analysis.object_relationships import load_object_key

        object_key = load_object_key(Path(args.object_key))
    capture_path = args.capture if args.capture is not None else args.har
    capture_format = args.capture_format if args.capture is not None else "har"
    if args.capture is None and (args.response is not None or args.origin is not None):
        raise ValueError("--response and --origin require --capture.")
    plan = build_fuzz_plan(
        args.program,
        Path(capture_path),
        collections=collections,
        scope=scope,
        category=args.category,
        max_tests=max_tests,
        max_targets=args.max_targets,
        object_candidates=object_rows,
        object_key=object_key,
        strict=args.strict,
        allow_truncate=args.allow_truncate,
        ranking=getattr(args, "ranking", "filename"),
        capture_format=capture_format,
        response_path=Path(args.response) if args.response is not None else None,
        origin=args.origin,
    )
    print(
        json.dumps(
            {
                "dry_run": bool(args.dry_run),
                "program": plan.program,
                "plan_version": plan.plan_version,
                "capture_import": plan.context.capture_import if plan.context else {},
                "hosts": list(plan.context.hosts) if plan.context else [],
                "technologies": list(plan.context.technologies) if plan.context else [],
                "categories_needed": list(plan.context.categories_needed) if plan.context else [],
                "recommendations": len(plan.recommendations),
                "targets": len(plan.targets),
                "discarded": len(plan.discarded),
                "estimated_requests_total": plan.budget.get("estimated_requests_total"),
                "object_associations": len(plan.object_associations),
                "network_requests_sent": 0,
                "auto_execute": False,
                "vulnerabilities_confirmed": 0,
            },
            sort_keys=True,
            indent=2,
        )
    )
    if plan.recommendations:
        print("[i] Wordlist recommendations (local collections only):")
        for item in plan.recommendations:
            print(f"  - {item.category}: {item.path} ({item.reason})")
    if plan.targets:
        print("[i] Planned targets (not executed):")
        for item in plan.targets:
            print(
                f"  - {item.url_template}  wordlist={item.wordlist}  "
                f"cap={item.max_entries}  est_requests={item.estimated_requests}"
            )
    for note in plan.notes:
        print(f"[i] {note}")
    if args.dry_run and not args.output:
        print("[dry-run] Plan preview only. No evidence file, investigation memory entry or fuzz run was written.")
        print("[i] Re-run without --dry-run (and optionally --output plan.json) to save the plan for review.")
        return
    # --dry-run --output writes the plan JSON only; evidence/memory require a non-dry-run save.
    if args.dry_run and args.output:
        output = Path(args.output)
        if output.exists():
            raise FileExistsError(f"Plan output already exists: {output}")
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(plan.to_dict(), indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(f"[dry-run] Plan JSON written to {output}. No evidence or investigation memory entry created.")
        return
    saved = save_plan(store, plan, output=Path(args.output) if args.output else None, record_memory=True)
    print(f"[+] Plan saved: {saved['output']}")
    if saved.get("investigation_id"):
        print(f"[+] Investigation memory: {saved['investigation_id']} (planning stage only).")
    print(
        "[i] To execute one target after human review, reuse: "
        "bbtk fuzz <program> --url <url_template> --wordlist <path> --max-tests N --dry-run, then --confirm."
    )


def cmd_wordlists(args: argparse.Namespace) -> None:
    """Manage local wordlist collections without network access."""
    registry = getattr(args, "registry", None) or default_registry_path()
    action = args.wordlists_action
    if action == "scan":
        if args.dry_run:
            detected = detect_local_collections()
            registered = {item.path.resolve(strict=False) for item in load_collections(registry)}
            candidates = [(name, path) for name, path in detected if path.resolve(strict=False) not in registered]
            if not candidates:
                print("[i] No new local wordlist collections detected. No files written.")
                return
            print("[i] Detected collections (dry-run; no registry changes):")
            for name, path in candidates:
                print(f"  {name}\t{path}")
            return
        added = scan_collections(registry)
        if not added:
            print(f"[i] No new collections detected. Registry: {registry}")
            return
        print(f"[+] Registered {len(added)} local collection(s):")
        for collection in added:
            print(f"  {collection.name}\t{collection.path}")
        print(f"[i] Registry: {registry}")
        return

    if action == "register":
        collection = register_collection(registry, args.name, args.path, args.category)
        print(f"[+] Registered {collection.name}: {collection.path} (category: {collection.category or 'auto'})")
        print(f"[i] Registry: {registry}")
        return

    collections = load_collections(registry)
    if action == "list":
        if not collections:
            print(f"[i] No collections registered. Run `bbtk wordlists scan` or `register`. Registry: {registry}")
            return
        files = list_wordlists(collections)
        print(f"Collections: {len(collections)} | Wordlist files: {len(files)} | Registry: {registry}")
        for collection in collections:
            collection_files = [item for item in files if item.collection == collection.name]
            print(f"\n{collection.name}\t{collection.path}\t{len(collection_files)} file(s)")
            for item in collection_files:
                print(f"  [{item.category}] {item.size_bytes:,} bytes\t{item.path}")
        return

    if action == "inspect":
        result = inspect_wordlist(args.path, rate=args.rate, large_file_warning_bytes=args.warning_mib * 1024 * 1024)
        print(f"File: {result.path}")
        print(f"Size: {result.size_bytes:,} bytes" + (" [!] large-file warning" if result.large_file_warning else ""))
        print(f"SHA-256: {result.sha256}")
        print(
            f"Entries: {result.entry_count:,} | unique: {result.unique_entries:,} | "
            f"duplicates: {result.duplicate_entries:,} | invalid: {result.invalid_lines:,}"
        )
        print(f"Blank: {result.blank_lines:,} | comments: {result.comment_lines:,}")
        print(
            f"Estimated requests: {result.requests_estimate:,} | minimum at {args.rate:g}/s: {result.minimum_seconds:.1f}s"
        )
        print("Preview:")
        for entry in result.preview:
            print(f"  {entry}")
        return

    if action == "recommend":
        recommendations = recommend_wordlists(collections, args.category)
        if not recommendations:
            print(f"[i] No local wordlists found for category {args.category!r}.")
            return
        print(f"Recommended local lists for {args.category} (smaller files first):")
        for item in recommendations:
            print(f"  [{item.category}] {item.size_bytes:,} bytes\t{item.path}")
        return

    if action == "prepare":
        output = args.output or (default_prepared_root() / f"{args.category}.txt")
        result = prepare_wordlist(
            collections,
            args.category,
            output,
            max_entries=args.max_entries,
            rate=args.rate,
            force=args.force,
            dry_run=args.dry_run,
        )
        mode = "Would prepare" if args.dry_run else "Prepared"
        print(f"[+] {mode} {result.unique_entries:,} unique entries for {result.category}.")
        print(
            f"[i] Source files: {len(result.source_files)} | duplicates removed: {result.duplicate_entries:,} | "
            f"invalid lines skipped: {result.invalid_lines:,}"
        )
        print(
            f"[i] Estimated requests: {result.requests_estimate:,} | "
            f"minimum at {args.rate:g}/s: {result.minimum_seconds:.1f}s | cap reached: {result.limit_reached}"
        )
        print("[i] Source SHA-256:")
        for source, digest in result.source_hashes:
            print(f"  {digest}  {source}")
        if result.output_sha256:
            print(f"[i] Prepared SHA-256: {result.output_sha256}")
        print(f"[i] Output: {result.output}" + (" (not written)" if args.dry_run else ""))


def cmd_xss(args: argparse.Namespace) -> None:
    ai_review_config = resolve_ai_review_config(
        args.ai_review,
        args.ai_model,
        args.ai_timeout,
        getattr(args, "ai_provider", None),
        getattr(args, "ai_endpoint", None),
    )
    store, settings, scope = executor_context(args, automated=True)
    headers = parse_header_items(args.header)
    cookies = parse_cookie_items(args.cookie)
    if cookies:
        headers["Cookie"] = cookies
    tester = XssParameterTester(scope, client_for(args, settings, scope))
    options = XssOptions(
        args.routes or Path("/dev/null"),
        args.parameters or Path("/dev/null"),
        args.base_url,
        args.max_tests or settings.max_tests,
        headers,
        args.html_parser,
        args.confirm_exec,
        args.dom_local,
        enrich_context=not getattr(args, "no_enrich_context", False),
        stored_local=bool(getattr(args, "stored_local", False)),
        stored_write_url=getattr(args, "stored_write_url", None),
        stored_render_url=getattr(args, "stored_render_url", None),
        stored_parameter=getattr(args, "stored_parameter", "content") or "content",
        capture_review_file=getattr(args, "capture_review", None),
    )
    if options.max_tests > settings.max_tests:
        raise ValueError("Max tests exceeds the configured program limit.")
    if not options.stored_local and options.capture_review_file is None:
        if args.routes is None or args.parameters is None:
            raise ValueError(
                "--routes and --parameters are required unless --stored-local or --capture-review is used."
            )
    elif options.stored_local and (not options.stored_write_url or not options.stored_render_url):
        raise ValueError("--stored-local requires --stored-write-url and --stored-render-url.")
    routes, parameters = tester.validate(options)
    if options.capture_review_file is not None:
        total = 0
    elif options.stored_local:
        total = options.max_tests
    else:
        variants = 4 if options.dom_local else 11 if options.confirm_exec else 4
        total = len(routes) * len(parameters) * variants
    if args.dry_run:
        if options.capture_review_file is not None:
            print("[+] Offline capture review. No HTTP requests will be issued.")
            return
        if options.stored_local:
            print(
                "[+] Stored-XSS local lab (write→store→render→browser) on loopback only. "
                "No third-party writes. No Blind XSS callbacks. No requests sent (dry-run)."
            )
            return
        print(
            f"[+] {len(routes)} routes, {len(parameters)} parameters, up to {min(total, options.max_tests)} "
            + (
                "local browser probes (HTTP subrequests governed by --run-max-*)."
                if options.dom_local
                else f"HTTP requests. Browser confirmation {'enabled' if options.confirm_exec else 'disabled'}."
            )
            + " No requests sent."
        )
        return
    path, results = tester.run(options, store.paths.evidence_dir / "xss")
    failures = sum(item.get("classification") == "error" for item in results)
    possible = sum(item.get("classification") == "possible" for item in results)
    confirmed = sum(item.get("classification") == "confirmed" for item in results)
    not_executed = sum(item.get("classification") == "reflected_not_executed" for item in results)
    store.add_run("xss", str(args.routes), ["xss", str(args.routes), str(args.parameters)], 1 if failures else 0, path)
    summary = f"{len(results)} tests, {possible} possible reflections, {failures} errors"
    if options.capture_review_file is not None:
        summary += f", {len(results)} offline capture recommendations (no requests issued)"
    elif options.stored_local:
        observed = sum(bool(item.get("browser_execution_observed")) for item in results)
        summary += f", {observed} stored-lab executions observed (not vulnerability verdicts)"
    elif options.dom_local:
        observed = sum(item["classification"] == "execution_observed" for item in results)
        summary += f", {observed} DOM executions observed in a local fixture (not vulnerability verdicts)"
    elif options.confirm_exec:
        summary += f", {confirmed} confirmed executions, {not_executed} reflected but not executed"
    else:
        summary += ". No XSS automatically confirmed"
    print(f"[+] {summary}.")
    print(f"[+] Evidence: {path}")
    print_live_ai_review(path, ai_review_config, f"{possible} possible, {confirmed} confirmed by browser")
    if len(results) < total:
        stop = json.loads(path.read_text(encoding="utf-8")).get("stop_reason")
        print(
            f"[!] Batch stopped: {stop}; remaining inputs were not tested."
            if stop
            else "[!] Test budget reached; remaining inputs were not tested."
        )


def cmd_params(args: argparse.Namespace) -> None:
    store, settings, _ = executor_context(args, automated=True)
    ensure_in_scope(args.url, store.paths.scope_file)
    budget = getattr(args, "_execution_budget", None)
    tool_kwargs = {
        "timeout_seconds": max(60.0, float(settings.timeout) * 20.0),
        "max_output_bytes": max(settings.max_response_bytes * 20, 1_000_000),
        "execution_budget": budget,
        "contact_external": True,
        "authorization_attested": True,
        "scope_attested": True,
    }
    paramspider = run_tool(store, "paramspider", args.url, ["paramspider", "-d", args.url], **tool_kwargs)
    arjun = run_tool(store, "arjun", args.url, ["arjun", "-u", args.url], **tool_kwargs)
    store.mark_reviewed("parameter-target", args.url, "paramspider and arjun executed")
    print(f"[+] Parameter analysis complete: {paramspider}, {arjun}")


def cmd_sqli(args: argparse.Namespace) -> None:
    ai_review_config = resolve_ai_review_config(
        args.ai_review,
        args.ai_model,
        args.ai_timeout,
        getattr(args, "ai_provider", None),
        getattr(args, "ai_endpoint", None),
    )
    store, settings, scope = executor_context(args, automated=True)
    headers = parse_header_items(args.header)
    if args.cookie:
        headers["Cookie"] = parse_cookie_items(args.cookie)
    options = SqliOptions(
        args.routes,
        args.parameters,
        args.base_url,
        args.max_tests or settings.max_tests,
        headers,
        args.deep,
        args.union,
        args.union_max_columns,
    )
    if options.max_tests > settings.max_tests:
        raise ValueError("Max tests exceeds the configured program limit.")
    tester = SqliParameterTester(scope, client_for(args, settings, scope))
    routes, parameters = tester.validate(options)
    if args.dry_run:
        group_size = request_group_size(options)
        budget = min(len(routes) * len(parameters) * group_size, options.max_tests // group_size * group_size)
        modes = ["error probes"]
        if options.deep:
            modes.extend(("timing", "boolean"))
        if options.union:
            modes.append("ORDER BY/UNION NULL probes")
        mode = ", ".join(modes)
        print(f"[+] {mode} validated, up to {budget} requests. No requests sent.")
        return
    path, results = tester.run(options, store.paths.evidence_dir / "sqli")
    failures = sum(item["classification"] == "error" for item in results)
    possible = sum(item["classification"] == "possible" for item in results)
    store.add_run(
        "sqli", str(args.routes), ["sqli", str(args.routes), str(args.parameters)], 1 if failures else 0, path
    )
    mode = "deep" if options.deep else "error-based"
    if options.union:
        mode += "+union"
    print(
        f"[+] {len(results)} {mode} SQLi responses, {possible} possible indicators, {failures} errors. No SQLi automatically confirmed."
    )
    print(f"[+] Evidence: {path}")
    print_live_ai_review(path, ai_review_config, f"{possible} possible SQLi indicators")


def cmd_cors_check(args: argparse.Namespace) -> None:
    ai_review_config = resolve_ai_review_config(
        args.ai_review,
        args.ai_model,
        args.ai_timeout,
        getattr(args, "ai_provider", None),
        getattr(args, "ai_endpoint", None),
    )
    store, settings, scope = executor_context(args, automated=True)
    headers = parse_header_items(args.header)
    cookies = parse_cookie_items(args.cookie)
    if cookies:
        headers["Cookie"] = cookies
    checker = CorsChecker(scope, client_for(args, settings, scope))
    options = CorsOptions(args.url, headers)
    origins = checker.validate(options)
    if args.dry_run:
        print(f"[+] CORS target in scope; {len(origins)} Origin values validated. No requests sent.")
        return
    path, results = checker.run(options, store.paths.evidence_dir / "cors")
    counts = {
        label: sum(row.get("classification") == label for row in results) for label in ("VULNERABLE", "DÉBIL", "SEGURO")
    }
    state_counts = {
        label: sum(row.get("finding_state") == label for row in results)
        for label in ("confirmed", "candidate", "not_observed", "inconclusive", "rejected")
    }
    confirmed_n = state_counts["confirmed"]
    for row in results:
        print(
            f"{row.get('origin', '-'):<40} ACAO={row.get('access_control_allow_origin', '-')} "
            f"ACAC={row.get('access_control_allow_credentials', '-')} verdict={row['classification']} "
            f"state={row.get('finding_state', '-')} confirmed={row.get('confirmed', False)} "
            f"status={row.get('status_code', '-')}"
        )
    store.add_run(
        "cors-check",
        redact_url(args.url),
        ["cors-check", redact_url(args.url)],
        1 if confirmed_n or counts["VULNERABLE"] else 0,
        path,
    )
    print(
        f"[+] CORS summary: {counts['VULNERABLE']} header-vulnerable, {counts['DÉBIL']} weak, "
        f"{counts['SEGURO']} safe; finding_state confirmed={state_counts['confirmed']} "
        f"candidate={state_counts['candidate']} not_observed={state_counts['not_observed']}. "
        f"Header reflection alone is never confirmation. Evidence: {path}"
    )
    print_live_ai_review(
        path,
        ai_review_config,
        f"{confirmed_n} confirmed, {state_counts['candidate']} candidate, "
        f"{counts['VULNERABLE']} header-vulnerable, {counts['DÉBIL']} weak, {counts['SEGURO']} safe",
    )


def cmd_ssrf_check(args: argparse.Namespace) -> None:
    ai_review_config = resolve_ai_review_config(
        args.ai_review,
        args.ai_model,
        args.ai_timeout,
        getattr(args, "ai_provider", None),
        getattr(args, "ai_endpoint", None),
    )
    store, settings, scope = executor_context(args, automated=True)
    headers = parse_header_items(args.header)
    cookies = parse_cookie_items(args.cookie)
    if cookies:
        headers["Cookie"] = cookies
    checker = SsrfChecker(scope, client_for(args, settings, scope))
    options = SsrfOptions(args.url, args.param, headers)
    request_urls = checker.validate(options)
    if args.dry_run:
        print(
            f"[+] SSRF target in scope; one baseline and {len(request_urls)} fixed probes validated. No requests sent."
        )
        return
    path, result = checker.run(options, store.paths.evidence_dir / "ssrf")
    baseline = result["baseline"]
    baseline_status = baseline.get("status_code", "-") if isinstance(baseline, dict) else "-"
    baseline_time = baseline.get("duration_ms", "-") if isinstance(baseline, dict) else "-"
    for row in result["results"]:
        if not isinstance(row, dict):
            continue
        delta = row.get("timing_delta_ms")
        delta_text = f"{delta:+}ms" if isinstance(delta, int) else "-"
        print(
            f"{row.get('payload', '-'):<52} status={row.get('status_code', '-')} "
            f"time={row.get('duration_ms', '-')}ms delta={delta_text} verdict={row.get('classification', 'error')}"
        )
    possible = sum(row.get("classification") in {"possible", "reflected"} for row in result["results"])
    store.add_run(
        "ssrf-check",
        redact_url(args.url),
        ["ssrf-check", redact_url(args.url)],
        1 if possible else 0,
        path,
    )
    print(
        f"[+] SSRF heuristic: {possible} possible/reflected of {len(result['results'])} probes; "
        f"baseline status {baseline_status}, time {baseline_time}ms; no SSRF automatically confirmed. Evidence: {path}"
    )
    print_live_ai_review(path, ai_review_config, f"{possible} possible/reflected SSRF indicators")


def cmd_csrf_audit(args: argparse.Namespace) -> None:
    ai_review_config = resolve_ai_review_config(
        args.ai_review,
        args.ai_model,
        args.ai_timeout,
        getattr(args, "ai_provider", None),
        getattr(args, "ai_endpoint", None),
    )
    store, settings, scope = executor_context(args, automated=True)
    headers = parse_header_items(args.header)
    cookies = parse_cookie_items(args.cookie)
    if cookies:
        headers["Cookie"] = cookies
    auditor = CsrfAuditor(scope, client_for(args, settings, scope))
    options = CsrfOptions(args.url, headers)
    auditor.validate(options)
    if args.dry_run:
        print("[+] CSRF audit target in scope; one HTML GET validated. No requests sent.")
        return

    path, result = auditor.run(options, store.paths.evidence_dir / "csrf-audit")
    print(
        f"[+] CSRF heuristic: {result.get('classification', 'inconclusive')}; "
        f"forms={result.get('form_count', '-')} methods={result.get('form_methods', [])} "
        f"POST tokens={result.get('post_forms_with_hidden_token', '-')} "
        f"cookie SameSite={result.get('cookie_samesite', [])}"
    )

    if result.get("samesite_none_without_secure", 0):
        print("[!] One or more SameSite=None cookies lack Secure.")
    if result.get("stop_reason"):
        print(f"[!] Audit stopped: {result['stop_reason']}")
    print("[!] Heuristic only; no CSRF request was forged or confirmed.")
    classification = result.get("classification")
    store.add_run(
        "csrf-audit",
        redact_url(args.url),
        ["csrf-audit", redact_url(args.url)],
        1 if classification == "possible_csrf" else 0,
        path,
    )
    print(f"[+] Evidence: {path}")
    print_live_ai_review(path, ai_review_config, str(classification or "inconclusive"))


def cmd_apk_scan(args: argparse.Namespace) -> None:
    ai_review_config = resolve_ai_review_config(
        args.ai_review,
        args.ai_model,
        args.ai_timeout,
        getattr(args, "ai_provider", None),
        getattr(args, "ai_endpoint", None),
    )
    paths = ProgramPaths(RECORDS_ROOT, args.program)
    scope = ScopeValidator(paths.scope_file)
    if not scope.summary()["allowed"]:
        raise ValueError("Add at least one allowed domain to this program's scope before scanning an APK.")
    scanner = ApkScanner(scope)
    apk = scanner.validate_input(args.apk)
    if args.dry_run:
        print(
            f"[+] APK archive validated: {apk.name}. Local scan only; no archive files extracted and no requests sent."
        )
        return

    evidence = scanner.scan(apk, decompile=args.decompile)
    store = store_for(args.program)
    path = write_evidence_json(store.paths.evidence_dir / "apk-scan", evidence, prefix="apk-scan")
    secret_count = evidence["counts"].get("secret", 0)
    counts = evidence["counts"]
    print(
        "[+] APK static scan: "
        f"{evidence['files_scanned']} files, "
        f"{counts.get('endpoint', 0)} endpoints, {secret_count} secret candidates, "
        f"{counts.get('firebase', 0)} Firebase references, {counts.get('deep_link', 0)} deep links, "
        f"{counts.get('email', 0)} emails."
    )
    print(
        f"[i] Referenced web destinations: {evidence['scope_counts']['in_scope']} in scope, "
        f"{evidence['scope_counts']['out_of_scope']} out of scope. Nothing was contacted."
    )
    for warning in evidence["warnings"]:
        print(f"[!] {warning}")
    store.add_run(
        "apk-scan",
        apk.name,
        ["apk-scan", "--apk", apk.name],
        1 if secret_count else 0,
        path,
    )
    store.connection.close()
    print(f"[+] Evidence (secrets masked): {path}")
    print_live_ai_review(path, ai_review_config, f"{secret_count} secret-pattern candidates")


def cmd_takeover_check(args: argparse.Namespace) -> None:
    store = store_for(args.program)
    try:
        scope = ScopeValidator(store.paths.scope_file)
        host = normalize_dns_name(args.host)
        scope.require(host)
        if not args.cname and not args.resolve_dns:
            raise ValueError("Provide --cname for offline analysis or opt in to --resolve-dns.")
        supplied_cnames = args.cname or []
        analyze_cnames(host, supplied_cnames, "supplied_offline")
        if args.resolve_dns:
            store.require_authorization()

        if args.dry_run:
            operation = "DNS lookup validated" if args.resolve_dns else "offline CNAME analysis validated"
            print(f"[+] {host} is in scope; {operation}. No DNS or HTTP requests sent.")
            return

        dns_status = "supplied_offline"
        dns_queries = 0
        cnames = list(supplied_cnames)
        if args.resolve_dns:
            resolved, dns_status, dns_queries = resolve_cname_records(host)
            cnames = resolved + cnames
        result = analyze_cnames(host, cnames, dns_status, dns_queries)
        result["cname_source"] = (
            "dns_and_supplied"
            if args.resolve_dns and supplied_cnames
            else ("dns" if args.resolve_dns else "supplied_offline")
        )
        path = write_evidence_json(store.paths.evidence_dir / "takeover", result, prefix="takeover-check")
        store.add_run(
            "takeover-check",
            host,
            ["takeover-check", host],
            1 if result["classification"] == "possible_takeover" else 0,
            path,
        )
    finally:
        store.close()
    for row in result["provider_matches"]:
        print(f"[?] CNAME {row['cname']} matches: {', '.join(row['services'])}")
    print(
        f"[+] Takeover heuristic: {result['classification']}; DNS={result['dns_status']}; "
        f"unclaimed status={result['unclaimed_status']}. No HTTP requests or claim attempts. Evidence: {path}"
    )


def cmd_open_redirect(args: argparse.Namespace) -> None:
    ai_review_config = resolve_ai_review_config(
        args.ai_review,
        args.ai_model,
        args.ai_timeout,
        getattr(args, "ai_provider", None),
        getattr(args, "ai_endpoint", None),
    )
    store, settings, scope = executor_context(args, automated=True)
    headers = parse_header_items(args.header)
    cookies = parse_cookie_items(args.cookie)
    if cookies:
        headers["Cookie"] = cookies
    tester = OpenRedirectTester(scope, client_for(args, settings, scope))
    options = OpenRedirectOptions(args.url, args.param, headers)
    request_urls = tester.validate(options)
    if args.dry_run:
        print(
            f"[+] Open-redirect target in scope; parameter exists and {len(request_urls)} payloads validated. No requests sent."
        )
        return
    path, results = tester.run(options, store.paths.evidence_dir / "open-redirect")
    for row in results:
        print(
            f"{row.get('payload', '-'):<28} status={row.get('status_code', '-')} "
            f"Location={row.get('location') or '-'} verdict={row['classification']}"
        )
    vulnerable = sum(row.get("classification") == "VULNERABLE" for row in results)
    store.add_run(
        "open-redirect", redact_url(args.url), ["open-redirect", redact_url(args.url)], 1 if vulnerable else 0, path
    )
    print(f"[+] Open redirect summary: {vulnerable} vulnerable of {len(results)} probes. Evidence: {path}")
    print_live_ai_review(path, ai_review_config, f"{vulnerable} vulnerable of {len(results)} probes")


def _hunt_tasks(
    args: argparse.Namespace, scope: ScopeValidator
) -> tuple[list[HuntTask], dict[str, dict[str, str]], str]:
    selected = set(parse_module_selection(args.only, args.skip))
    base_url = normalize_url(args.base_url)
    scope.require(base_url)
    static: dict[str, dict[str, str]] = {}
    tasks: list[HuntTask] = []

    for module in MODULE_ORDER:
        if module not in selected:
            reason = "not selected by --only" if args.only else "excluded by --skip"
            static[module] = {"status": "skipped", "reason": reason}

    params: list[str] = []
    params_error: str | None = None
    if args.params is not None:
        try:
            params = load_parameter_names(args.params)
            if not params:
                params_error = "parameter file contains no usable parameter names"
        except (OSError, UnicodeError, ValueError) as exc:
            params_error = type(exc).__name__

    routes: list[str] = []
    routes_error: str | None = None
    if args.routes is not None:
        try:
            routes = load_routes(args.routes, base_url=base_url)
            if not routes:
                routes_error = "route file contains no usable routes"
        except (OSError, UnicodeError, ValueError) as exc:
            routes_error = type(exc).__name__

    if "cors-check" in selected:
        tasks.append(HuntTask("cors-check", "cors-check", ("cors-check", args.program, "--url", base_url), 4, 4, 4))

    if "ssrf-check" in selected:
        if bool(args.ssrf_url) != bool(args.ssrf_param):
            static["ssrf-check"] = {
                "status": "error",
                "reason": "--ssrf-url and --ssrf-param must be supplied together",
            }
        elif not args.ssrf_url:
            static["ssrf-check"] = {
                "status": "skipped",
                "reason": "SSRF probes require explicit --ssrf-url and --ssrf-param inputs",
            }
        else:
            ssrf_url = normalize_url(args.ssrf_url)
            scope.require(ssrf_url)
            tasks.append(
                HuntTask(
                    "ssrf-check",
                    "ssrf-check",
                    ("ssrf-check", args.program, "--url", ssrf_url, "--param", args.ssrf_param),
                    6,
                    6,
                    6,
                )
            )

    # csrf-audit cannot reach confirmed; keep as standalone `bbtk csrf-audit` only.

    if "open-redirect" in selected:
        if params_error:
            static["open-redirect"] = {"status": "error", "reason": params_error}
        elif args.params is None:
            static["open-redirect"] = {"status": "skipped", "reason": "--params was not supplied"}
        elif not params:
            static["open-redirect"] = {"status": "skipped", "reason": "no usable parameters were supplied"}
        else:
            tasks.append(
                HuntTask(
                    "open-redirect",
                    "open-redirect",
                    ("open-redirect", args.program),
                    5 * len(params),
                    5,
                    5,
                    tuple(params),
                )
            )

    for module in ("xss", "sqli"):
        if module not in selected:
            continue
        if args.routes is None or args.params is None:
            missing = [flag for flag, value in (("--routes", args.routes), ("--params", args.params)) if value is None]
            static[module] = {"status": "skipped", "reason": f"required input missing: {', '.join(missing)}"}
        elif routes_error or params_error:
            static[module] = {"status": "error", "reason": routes_error or params_error or "invalid input"}
        elif not routes or not params:
            static[module] = {"status": "skipped", "reason": "routes and parameters must both contain usable entries"}
        else:
            command_parts = [
                module,
                args.program,
                "--routes",
                str(args.routes),
                "--parameters",
                str(args.params),
                "--base-url",
                base_url,
            ]
            if module == "xss":
                variants = 11 if args.confirm_exec else 4
                estimate = len(routes) * len(params) * variants * (2 if args.confirm_exec else 1)
                minimum = 1
                quantum = 1
                if args.confirm_exec:
                    command_parts.append("--confirm-exec")
            else:
                group_size = (8 if args.deep else 3) + (args.union_max_columns + 1 if args.union else 0)
                estimate = len(routes) * len(params) * group_size
                minimum = group_size
                quantum = group_size
                if args.deep:
                    command_parts.append("--deep")
                if args.union:
                    command_parts.extend(("--union", "--union-max-columns", str(args.union_max_columns)))
            command = tuple(command_parts)
            tasks.append(HuntTask(module, module, command, estimate, minimum, quantum))

    if "access-check" in selected:
        if args.case_file is None:
            static["access-check"] = {"status": "skipped", "reason": "--case-file was not supplied"}
        else:
            tasks.append(
                HuntTask(
                    "access-check",
                    "access-check",
                    ("access-check", args.program, "--case-file", str(args.case_file)),
                    3,
                    3,
                    3,
                )
            )

    return tasks, static, base_url


def _hunt_child_argv(
    task: HuntTask,
    allocation: int,
    settings: ExecutorSettings,
    ai_config: tuple[str, float] | None,
    dry_run: bool,
    parameter: str | None = None,
    base_url: str | None = None,
) -> list[str]:
    argv = list(task.argv)
    if task.module == "open-redirect":
        if parameter is None or base_url is None:
            raise ValueError("Open-redirect hunt task requires a parameter and base URL.")
        argv.extend(("--url", with_parameter(base_url, parameter, ""), "--param", parameter))
    elif task.module in {"xss", "sqli", "access-check"}:
        limit = allocation if allocation > 0 else settings.max_tests
        argv.extend(("--max-tests", str(limit)))
    if ai_config is not None:
        argv.extend(("--ai-review", "--ai-model", ai_config[0], "--ai-timeout", str(ai_config[1])))
    if dry_run:
        argv.append("--dry-run")
    return argv


def _run_hunt_child(
    parser: argparse.ArgumentParser,
    task: HuntTask,
    allocation: int,
    settings: ExecutorSettings,
    ai_config: tuple[str, float] | None,
    budget: ExecutionBudget,
    limiter: RateLimiter,
    dry_run: bool,
    parameter: str | None = None,
    base_url: str | None = None,
) -> None:
    child = parser.parse_args(_hunt_child_argv(task, allocation, settings, ai_config, dry_run, parameter, base_url))
    child._execution_budget = budget
    child._rate_limiter = limiter
    child.func(child)


def _hunt_evidence_dir(store: RecordStore, module: str) -> Path:
    return (
        store.paths.evidence_dir
        / {
            "cors-check": "cors",
            "ssrf-check": "ssrf",
            "csrf-audit": "csrf-audit",
            "open-redirect": "open-redirect",
            "xss": "xss",
            "sqli": "sqli",
            "access-check": "access-control",
        }[module]
    )


def _has_rate_limit(evidence_path: Path) -> bool:
    try:
        evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return False
    if not isinstance(evidence, dict):
        return False
    if evidence.get("stop_reason") == "rate_limited":
        return True
    stack: list[object] = [evidence]
    while stack:
        current = stack.pop()
        if isinstance(current, dict):
            if current.get("status_code") == 429:
                return True
            stack.extend(current.values())
        elif isinstance(current, list):
            stack.extend(current)
    return False


def _atomic_json(path: Path, value: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.replace(path)


def _hunt_report(
    program: str,
    base_url: str,
    max_tests: int,
    requests_started: int,
    module_results: list[dict[str, object]],
    static: dict[str, dict[str, str]],
    dry_run: bool,
    cancelled: bool = False,
) -> dict[str, object]:
    modules: list[dict[str, object]] = []
    for module in MODULE_ORDER:
        rows = [item for item in module_results if item.get("module") == module]
        if rows:
            modules.append(summarize_module(module, rows))
        elif module in static:
            entry = static[module]
            modules.append(
                {
                    "module": module,
                    "status": entry["status"],
                    "toolkit_verdict": entry["status"],
                    "reason": entry["reason"],
                    "classification_counts": {},
                    "requests_attempted": 0,
                    "inputs_not_tested": 0,
                    "stop_reasons": [],
                    "evidence_paths": [],
                    "ai_reviews": [],
                }
            )
        else:
            modules.append(
                {
                    "module": module,
                    "status": "skipped",
                    "toolkit_verdict": "skipped",
                    "reason": "not selected or no eligible inputs",
                    "classification_counts": {},
                    "requests_attempted": 0,
                    "inputs_not_tested": 0,
                    "stop_reasons": [],
                    "evidence_paths": [],
                    "ai_reviews": [],
                }
            )
    findings = collect_findings(modules)
    errors = any(module.get("status") == "error" for module in modules)
    limited = any(module.get("status") == "rate_limited" for module in modules)
    status = (
        "cancelled"
        if cancelled
        else "validation_errors"
        if dry_run and errors
        else "validated"
        if dry_run
        else "error"
        if errors
        else "completed_with_rate_limits"
        if limited
        else "completed"
    )
    return {
        "type": "hunt",
        "program": program,
        "base_url": redact_url(base_url),
        "status": status,
        "dry_run": dry_run,
        "budget": {
            "max_tests": max_tests,
            "requests_started": requests_started,
            "remaining": max(0, max_tests - requests_started),
        },
        "modules": modules,
        "findings": findings,
        "ai_review_note": "Ollama is a local second opinion over minimized evidence; it never confirms a vulnerability.",
    }


def _write_hunt_report(store: RecordStore, report: dict[str, object]) -> tuple[Path, Path]:
    json_path = write_evidence_json(store.paths.reports_dir, report, prefix="hunt")
    html_path = render_hunt_html(report, json_path.with_suffix(".html"))
    report["html_report"] = str(html_path)
    json_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return_code = 1 if report.get("status") in {"error", "validation_errors"} else 0
    store.add_run(
        "hunt",
        report.get("base_url") if isinstance(report.get("base_url"), str) else None,
        ["hunt"],
        return_code,
        json_path,
    )
    return json_path, html_path


def _fingerprint_hunt_plan(
    args: argparse.Namespace,
    base_url: str,
    tasks: list[HuntTask],
    selected: tuple[str, ...],
    ai_config: tuple[str, float] | None,
    scope_path: Path,
    max_tests: int,
) -> str:
    def digest(path: Path | None) -> str | None:
        if path is None:
            return None
        try:
            return hashlib.sha256(path.read_bytes()).hexdigest()
        except OSError:
            return "unreadable"

    payload = {
        "program": args.program,
        "base_url": base_url,
        "modules": selected,
        "max_tests": max_tests,
        "run_max_requests": args.run_max_requests,
        "run_max_seconds": args.run_max_seconds,
        "run_max_concurrency": args.run_max_concurrency,
        "ai_review": ai_config,
        "scope_sha256": digest(scope_path),
        "routes_sha256": digest(args.routes),
        "params_sha256": digest(args.params),
        "case_sha256": digest(args.case_file),
        "tasks": [
            {
                "id": task.task_id,
                "module": task.module,
                "argv": task.argv,
                "parameters": task.parameters,
                "estimate": task.estimated_requests,
                "minimum": task.minimum_requests,
                "quantum": task.request_quantum,
            }
            for task in tasks
        ],
    }
    return plan_fingerprint(payload)


def _execute_hunt_task(
    parser: argparse.ArgumentParser,
    task: HuntTask,
    allocation: int,
    settings: ExecutorSettings,
    ai_config: tuple[str, float] | None,
    budget: ExecutionBudget,
    limiter: RateLimiter,
    store: RecordStore,
    base_url: str,
) -> dict[str, object]:
    before_requests = budget.summary().requests_started
    evidence_paths: list[Path] = []
    status = "completed"
    error_type: str | None = None
    rate_limited = False
    inputs_not_tested = 0
    attempted_parameters = 0
    parameters = task.parameters
    if task.module == "open-redirect":
        count = min(len(parameters), allocation // 5)
        selected_parameters = parameters[:count]
    else:
        selected_parameters = (None,)

    for parameter in selected_parameters:
        attempted_parameters += 1
        evidence_dir = _hunt_evidence_dir(store, task.module)
        before_files = set(evidence_dir.glob("*.json")) if evidence_dir.exists() else set()
        try:
            with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                _run_hunt_child(
                    parser,
                    task,
                    allocation,
                    settings,
                    ai_config,
                    budget,
                    limiter,
                    False,
                    parameter=parameter if isinstance(parameter, str) else None,
                    base_url=base_url,
                )
        except KeyboardInterrupt:
            raise
        except (Exception, SystemExit) as exc:
            status = "error"
            error_type = type(exc).__name__
            break
        after_files = set(evidence_dir.glob("*.json")) if evidence_dir.exists() else set()
        created = sorted(after_files - before_files, key=lambda path: path.stat().st_mtime_ns)
        if not created:
            status = "error"
            error_type = "missing_evidence"
            break
        evidence_paths.extend(created)
        if any(_has_rate_limit(path) for path in created):
            status = "rate_limited"
            rate_limited = True
            break

    if task.module == "open-redirect":
        inputs_not_tested = max(0, len(parameters) - attempted_parameters)
    requests_used = max(0, budget.summary().requests_started - before_requests)
    outcome: dict[str, object] = {
        "task_id": task.task_id,
        "module": task.module,
        "status": status,
        "requests_started": requests_used,
        "evidence_paths": [str(path) for path in evidence_paths],
        "inputs_not_tested": inputs_not_tested,
    }
    if error_type:
        outcome["error_type"] = error_type
    if rate_limited:
        outcome["reason"] = "module stopped after HTTP 429; later modules remain eligible"
    elif inputs_not_tested:
        outcome["reason"] = f"global budget left {inputs_not_tested} parameter(s) untested"
    return outcome


def cmd_hunt(args: argparse.Namespace) -> None:
    ai_config = resolve_ai_review_config(
        args.ai_review,
        args.ai_model,
        args.ai_timeout,
        getattr(args, "ai_provider", None),
        getattr(args, "ai_endpoint", None),
    )
    if args.resume and args.dry_run:
        raise ValueError("--resume cannot be combined with --dry-run.")
    selected = parse_module_selection(args.only, args.skip)
    store, settings, scope = executor_context(args, automated=True)
    try:
        max_tests = args.max_tests or settings.max_tests
        if max_tests > settings.max_tests:
            raise ValueError("--max-tests exceeds the configured program limit.")
        tasks, static, base_url = _hunt_tasks(args, scope)
        parser = build_parser()
        fingerprint = _fingerprint_hunt_plan(
            args, base_url, tasks, selected, ai_config, store.paths.scope_file, max_tests
        )
        progress_path = store.paths.reports_dir / "hunt-progress.json"

        if args.resume:
            try:
                state = json.loads(progress_path.read_text(encoding="utf-8"))
            except (OSError, ValueError) as exc:
                raise ValueError("No valid saved hunt progress exists; run without --resume first.") from exc
            if not isinstance(state, dict) or state.get("fingerprint") != fingerprint:
                raise ValueError("Saved hunt progress does not match this program, inputs, scope or budget.")
            prior_requests = state.get("requests_started", 0)
            task_results = state.get("task_results", [])
            completed = state.get("completed_tasks", [])
            if (
                type(prior_requests) is not int
                or prior_requests < 0
                or not isinstance(task_results, list)
                or not isinstance(completed, list)
            ):
                raise ValueError("Saved hunt progress is malformed.")
            if prior_requests > max_tests:
                raise ValueError("Saved hunt progress already consumed the complete global request budget.")
            state = {
                "fingerprint": fingerprint,
                "requests_started": prior_requests,
                "completed_tasks": [item for item in completed if isinstance(item, str)],
                "task_results": [item for item in task_results if isinstance(item, dict)],
                "complete": False,
            }
        else:
            prior_requests = 0
            state = {
                "fingerprint": fingerprint,
                "requests_started": 0,
                "completed_tasks": [],
                "task_results": [],
                "complete": False,
            }

        remaining = max_tests - prior_requests
        limiter = RateLimiter(settings.requests_per_second)
        preflight_budget = ExecutionBudget(max_requests=1, max_concurrency=1)
        preflight_budget.cancel("dry_run_validation_only")
        args._execution_budget = preflight_budget
        args._rate_limiter = limiter

        completed_ids = set(state["completed_tasks"])
        result_by_id = {str(item.get("task_id")): item for item in state["task_results"]}
        preflight_errors: dict[str, str] = {}
        for task in tasks:
            if task.task_id in completed_ids:
                continue
            try:
                parameters = task.parameters or (None,)
                for parameter in parameters:
                    with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                        _run_hunt_child(
                            parser,
                            task,
                            settings.max_tests,
                            settings,
                            ai_config,
                            preflight_budget,
                            limiter,
                            True,
                            parameter=parameter if isinstance(parameter, str) else None,
                            base_url=base_url,
                        )
            except (Exception, SystemExit) as exc:
                preflight_errors[task.task_id] = type(exc).__name__

        if args.dry_run:
            dry_run_cap = min(max_tests, args.run_max_requests or max_tests)
            allocations = allocate_request_budgets(tasks, dry_run_cap)
            dry_results: list[dict[str, object]] = []
            for task in tasks:
                if task.task_id in preflight_errors:
                    dry_results.append(
                        {
                            "task_id": task.task_id,
                            "module": task.module,
                            "status": "error",
                            "error_type": preflight_errors[task.task_id],
                            "evidence_paths": [],
                            "requests_started": 0,
                        }
                    )
                elif allocations[task.task_id]:
                    dry_results.append(
                        {
                            "task_id": task.task_id,
                            "module": task.module,
                            "status": "validated",
                            "evidence_paths": [],
                            "requests_started": 0,
                        }
                    )
                else:
                    dry_results.append(
                        {
                            "task_id": task.task_id,
                            "module": task.module,
                            "status": "skipped",
                            "reason": "global budget cannot fit the module minimum",
                            "evidence_paths": [],
                            "requests_started": 0,
                        }
                    )
            report = _hunt_report(args.program, base_url, max_tests, 0, dry_results, static, True)
            json_path, html_path = _write_hunt_report(store, report)
            print("[+] Hunt plan validated. No HTTP requests sent.")
            print(f"[+] Consolidated JSON: {json_path}")
            print(f"[+] Consolidated HTML: {html_path}")
            return

        request_cap = min(remaining, args.run_max_requests or remaining)
        budget = ExecutionBudget(
            max_requests=max(1, request_cap),
            max_seconds=args.run_max_seconds,
            max_concurrency=1,
        )
        args._execution_budget = budget

        for task_id, error_type in preflight_errors.items():
            if task_id not in completed_ids:
                error_task = next(task for task in tasks if task.task_id == task_id)
                result_by_id[task_id] = {
                    "task_id": task_id,
                    "module": error_task.module,
                    "status": "error",
                    "error_type": error_type,
                    "requests_started": 0,
                    "evidence_paths": [],
                }
                completed_ids.add(task_id)
        state["completed_tasks"] = sorted(completed_ids)
        state["task_results"] = list(result_by_id.values())
        _atomic_json(progress_path, state)

        pending = [task for task in tasks if task.task_id not in completed_ids]
        allocations = (
            allocate_request_budgets(pending, request_cap)
            if pending and request_cap
            else {task.task_id: 0 for task in pending}
        )
        stop_module: str | None = None
        for index, task in enumerate(pending):
            budget_stop = budget.summary().stop_reason
            if budget_stop:
                outcome = {
                    "task_id": task.task_id,
                    "module": task.module,
                    "status": "skipped",
                    "reason": f"shared run budget stopped: {budget_stop}",
                    "requests_started": 0,
                    "evidence_paths": [],
                }
            elif task.module == stop_module:
                outcome: dict[str, object] = {
                    "task_id": task.task_id,
                    "module": task.module,
                    "status": "skipped",
                    "reason": "module stopped after HTTP 429",
                    "requests_started": 0,
                    "evidence_paths": [],
                }
                quota = allocations.get(task.task_id, 0)
                _ = redistribute_unused_budget(pending, allocations, index + 1, quota)
            else:
                quota = allocations.get(task.task_id, 0)
                if quota <= 0:
                    outcome = {
                        "task_id": task.task_id,
                        "module": task.module,
                        "status": "skipped",
                        "reason": "global request budget exhausted or below the module minimum",
                        "requests_started": 0,
                        "evidence_paths": [],
                    }
                else:
                    before = budget.summary().requests_started
                    try:
                        outcome = _execute_hunt_task(
                            parser, task, quota, settings, ai_config, budget, limiter, store, base_url
                        )
                    except KeyboardInterrupt:
                        used = max(0, budget.summary().requests_started - before)
                        state["requests_started"] = int(state["requests_started"]) + used
                        result_by_id[task.task_id] = {
                            "task_id": task.task_id,
                            "module": task.module,
                            "status": "cancelled",
                            "reason": "cancelled by user; resume restarts this module within the remaining budget",
                            "requests_started": used,
                            "evidence_paths": [],
                        }
                        state["task_results"] = list(result_by_id.values())
                        state["completed_tasks"] = sorted(completed_ids)
                        _atomic_json(progress_path, state)
                        budget.cancel("cancelled_by_user")
                        report = _hunt_report(
                            args.program,
                            base_url,
                            max_tests,
                            int(state["requests_started"]),
                            list(result_by_id.values()),
                            static,
                            False,
                            cancelled=True,
                        )
                        json_path, html_path = _write_hunt_report(store, report)
                        print("[!] Hunt cancelled. Progress is saved; use --resume with the same inputs to continue.")
                        print(f"[+] Consolidated JSON: {json_path}")
                        print(f"[+] Consolidated HTML: {html_path}")
                        return
                    except (Exception, SystemExit) as exc:
                        outcome = {
                            "task_id": task.task_id,
                            "module": task.module,
                            "status": "error",
                            "error_type": type(exc).__name__,
                            "reason": f"module failed: {type(exc).__name__}",
                            "requests_started": max(0, budget.summary().requests_started - before),
                            "evidence_paths": [],
                        }
                    used = int(outcome.get("requests_started", 0))
                    unused = max(0, quota - used)
                    _ = redistribute_unused_budget(pending, allocations, index + 1, unused)
                    if outcome.get("status") == "rate_limited":
                        stop_module = task.module
            state["requests_started"] = int(state["requests_started"]) + int(outcome.get("requests_started", 0))
            result_by_id[task.task_id] = outcome
            completed_ids.add(task.task_id)
            state["completed_tasks"] = sorted(completed_ids)
            state["task_results"] = list(result_by_id.values())
            _atomic_json(progress_path, state)

        all_results = list(result_by_id.values())
        report = _hunt_report(
            args.program, base_url, max_tests, int(state["requests_started"]), all_results, static, False
        )
        state["complete"] = True
        _atomic_json(progress_path, state)
        json_path, html_path = _write_hunt_report(store, report)
        for module in report["modules"]:
            print(
                f"[+] {module['module']}: status={module['status']}; toolkit={module['toolkit_verdict']}; "
                f"requests={module['requests_attempted']}"
            )
            for review in module.get("ai_reviews", []):
                print(format_ai_review(review, str(module["toolkit_verdict"])))
        for finding in report["findings"]:
            print(
                f"[!] {finding['severity']} {finding['type']}: {finding['classification']} "
                f"parameter={finding.get('parameter') or '-'} status={finding.get('status_code') or '-'}"
            )
        print(f"[+] Global budget: {report['budget']['requests_started']}/{max_tests} requests.")
        print(f"[+] Consolidated JSON: {json_path}")
        print(f"[+] Consolidated HTML: {html_path}")
    finally:
        store.close()


def cmd_access_check(args: argparse.Namespace) -> None:
    ai_review_config = resolve_ai_review_config(
        args.ai_review,
        args.ai_model,
        args.ai_timeout,
        getattr(args, "ai_provider", None),
        getattr(args, "ai_endpoint", None),
    )
    if args.function_matrix:
        incompatible = (
            args.id_range
            or args.lab_write
            or args.lab_write_range
            or args.anonymous_check
            or args.inverse_cross
            or args.multi_account
            or args.verify_persistence
            or args.inverse_write
            or args.cleanup
            or args.allow_public_range
            or args.allow_public_writes
            or args.max_range is not None
            or args.concurrency is not None
            or args.min_interval is not None
        )
        if incompatible:
            raise ValueError(
                "--function-matrix is a separate read-only mode; do not combine it with other access modes."
            )
        store, settings, scope = executor_context(args, automated=True)
        budget = args.max_tests or settings.max_tests
        if budget > settings.max_tests:
            raise ValueError("Max tests exceeds the configured program limit.")
        tester = AccessFunctionMatrixTester(scope, client_for(args, settings, scope))
        case = tester.validate(args.case_file, budget)
        if args.dry_run:
            print(
                f"[+] Read-only BFLA function matrix validated: {len(case.functions)} functions, "
                f"{len({account.name for function in case.functions for account in function.accounts})} accounts, "
                f"{case.request_count} GET requests planned; no requests sent."
            )
            return
        path, result = tester.run(args.case_file, store.paths.evidence_dir / "access-control", budget)
        print_live_ai_review(path, ai_review_config, str(result["classification"]))
        store.add_run(
            "access-check-function-matrix",
            None,
            ["access-check", "--function-matrix"],
            0 if result["classification"] != "insufficient_evidence" else 1,
            path,
        )
        print(
            f"[+] BFLA function matrix: {result['classification']}; "
            f"{result['requests_attempted']} GET requests attempted. No authorization flaw automatically confirmed."
        )
        print(f"[+] Evidence: {path}")
        return
    range_requested = bool(args.id_range or args.lab_write_range)
    read_options = args.anonymous_check or args.inverse_cross or args.multi_account
    write_options = args.verify_persistence or args.inverse_write or args.cleanup
    if args.allow_public_writes and not args.lab_write:
        raise ValueError("--allow-public-writes requires --lab-write.")
    if args.lab_write_range and not args.lab_write:
        raise ValueError("--lab-write-range requires --lab-write.")
    if args.id_range and args.lab_write_range:
        raise ValueError("--range and --lab-write-range are mutually exclusive.")
    if args.lab_write and args.id_range:
        raise ValueError("--lab-write cannot be combined with --range.")
    if read_options and (args.lab_write or range_requested):
        raise ValueError(
            "--anonymous-check, --inverse-cross and --multi-account apply only to single read-mode checks."
        )
    if write_options and not args.lab_write:
        raise ValueError("--verify-persistence, --inverse-write and --cleanup require --lab-write.")
    range_options = (args.max_range, args.concurrency, args.min_interval)
    if not range_requested and any(value is not None for value in range_options):
        raise ValueError("--max-range, --concurrency and --min-interval require --range or --lab-write-range.")
    if args.allow_public_range and not range_requested:
        raise ValueError("--allow-public-range requires --range or --lab-write-range.")

    store, settings, scope = executor_context(args, automated=True)
    range_cap = args.max_range or 25
    if range_requested:
        default_budget = min(settings.max_tests, range_cap + 2)
    elif args.lab_write:
        default_budget = AccessWriteLabTester.write_request_count(
            args.verify_persistence, args.inverse_write, args.cleanup
        )
    elif args.multi_account:
        default_budget = settings.max_tests
    else:
        default_budget = 3 + int(args.anonymous_check) + int(args.inverse_cross)
    budget = args.max_tests or default_budget
    if budget > settings.max_tests:
        raise ValueError("Max tests exceeds the configured program limit.")
    if args.id_range:
        if budget > MAX_RANGE_REQUESTS:
            raise ValueError(
                f"Range checks are capped at {MAX_RANGE_REQUESTS} requests including controls in loopback labs."
            )
        client = client_for(args, settings, scope)
        tester = AccessRangeTester(scope, client)
        interval = args.min_interval if args.min_interval is not None else (1.0 if args.allow_public_range else 10.0)
        options = AccessRangeOptions(
            args.id_range, budget, range_cap, args.concurrency or 1, interval, args.allow_public_range
        )
        case, requests = tester.validate(args.case_file, options)
        local_lab = all(is_loopback_url(request.prepared_url()) for request in (case.owner, case.actor, *requests))
        if local_lab and args.allow_public_range and args.min_interval is None:
            options = AccessRangeOptions(args.id_range, budget, range_cap, args.concurrency or 1, 10.0, True)
            case, requests = tester.validate(args.case_file, options)
        elif not local_lab and args.allow_public_range:
            print("[!] Public range relaxed: more requests than default")
        if args.dry_run:
            print(
                f"[+] Bounded range validated: two controls and {len(requests)} GETs; cap {range_cap}, concurrency {options.concurrency}, minimum interval {options.min_interval:g}s. No requests sent."
            )
            return
        path, result = tester.run(args.case_file, options, store.paths.evidence_dir / "access-control")
        print_live_ai_review(path, ai_review_config, str(result["classification"]))
        store.add_run(
            "access-check",
            None,
            ["access-check", "--range"],
            1 if result["classification"] == "inconclusive" else 0,
            path,
        )
        print(
            f"[+] Bounded access comparison: {result['classification']}; {result['requests_attempted']} requests attempted; candidate offset: {result['candidate_offset']}."
        )
        print(f"[+] Stop reason: {result['stop_reason']}. No IDOR automatically confirmed. Evidence: {path}")
        return
    if args.lab_write_range:
        if args.allow_public_writes:
            print("[!] Public writes enabled: requests may modify remote state")
        client = client_for(args, settings, scope)
        tester = AccessWriteRangeTester(scope, client, allow_public_writes=args.allow_public_writes)
        interval = args.min_interval if args.min_interval is not None else (1.0 if args.allow_public_range else 10.0)
        options = AccessRangeOptions(
            args.lab_write_range, budget, range_cap, args.concurrency or 1, interval, args.allow_public_range
        )
        case, requests = tester.validate(args.case_file, options)
        local_lab = all(is_loopback_url(request.prepared_url()) for request in (case.owner, case.actor, *requests))
        if local_lab and args.allow_public_range and args.min_interval is None:
            options = AccessRangeOptions(args.lab_write_range, budget, range_cap, args.concurrency or 1, 10.0, True)
            case, requests = tester.validate(args.case_file, options)
        elif not local_lab and args.allow_public_range:
            print("[!] Public range relaxed: more requests than default")
        if args.dry_run:
            print(
                f"[+] JSON write range validated: two controls and {len(requests)} POST/PUT/PATCH probes; cap {range_cap}, concurrency {options.concurrency}, minimum interval {options.min_interval:g}s. No requests sent."
            )
            return
        path, result = tester.run(args.case_file, options, store.paths.evidence_dir / "access-control")
        print_live_ai_review(path, ai_review_config, str(result["classification"]))
        store.add_run(
            "access-check-lab-write-range",
            None,
            ["access-check", "--lab-write-range"],
            1 if result["classification"] == "inconclusive" else 0,
            path,
        )
        print(
            f"[+] Bounded write comparison: {result['classification']}; {result['requests_attempted']} requests attempted; candidate offset: {result['candidate_offset']}."
        )
        print(f"[+] Stop reason: {result['stop_reason']}. No IDOR automatically confirmed. Evidence: {path}")
        return
    if args.lab_write:
        if args.allow_public_writes:
            print("[!] Public writes enabled: requests may modify remote state")
        tester = AccessWriteLabTester(
            scope, client_for(args, settings, scope), allow_public_writes=args.allow_public_writes
        )
        request_count = tester.write_request_count(args.verify_persistence, args.inverse_write, args.cleanup)
        tester.validate(args.case_file, budget, args.verify_persistence, args.inverse_write, args.cleanup)
        if args.dry_run:
            print(f"[+] JSON write case validated: {request_count} requests budgeted; no requests sent.")
            return
        path, result = tester.run(
            args.case_file,
            store.paths.evidence_dir / "access-control",
            budget,
            args.verify_persistence,
            args.inverse_write,
            args.cleanup,
        )
        print_live_ai_review(path, ai_review_config, str(result["classification"]))
        store.add_run(
            "access-check-lab-write",
            None,
            ["access-check", "--lab-write"],
            1 if result["classification"] == "inconclusive" else 0,
            path,
        )
        print(
            f"[+] JSON write comparison: {result['classification']}; {result['requests_attempted']} requests attempted. No IDOR automatically confirmed. Evidence: {path}"
        )
        if args.cleanup:
            print(f"[+] Cleanup status: {result['cleanup_status']}; verified: {result['cleanup_verified']}.")
        return
    tester = AccessControlTester(scope, client_for(args, settings, scope))
    case = tester.validate(args.case_file, budget, args.anonymous_check, args.inverse_cross, args.multi_account)
    request_count = tester.request_count(case, args.anonymous_check, args.inverse_cross, args.multi_account)
    if args.dry_run:
        print(f"[+] Known-resource access case validated: {request_count} requests planned; no requests sent.")
        return
    path, result = tester.run(
        args.case_file,
        store.paths.evidence_dir / "access-control",
        budget,
        args.anonymous_check,
        args.inverse_cross,
        args.multi_account,
    )
    print_live_ai_review(path, ai_review_config, str(result["classification"]))
    store.add_run("access-check", None, ["access-check"], 0 if result["classification"] != "inconclusive" else 1, path)
    print(
        f"[+] Access comparison: {result['classification']}; {result['requests_attempted']} requests attempted; controls valid: {result['controls_valid']}."
    )
    if result.get("matrix") is not None:
        print(
            f"[+] Account matrix: {result['matrix_crosses']} crossed pairs plus {len(result['matrix']) - result['matrix_crosses']} account controls."
        )
    if result.get("anonymous_classification") == "anonymous_access":
        print("[!] Anonymous request returned the configured private-resource proof.")
    elif result.get("anonymous_classification") == "public_endpoint":
        print("[i] Anonymous check was informational: the case does not declare this resource private.")
    if result.get("anonymous_expectation_mismatch"):
        print("[!] Anonymous access differed from expected_anonymous in the case.")
    if result.get("bidirectional_access"):
        print("[!] Both directed account crossings returned their configured private-resource proof.")
    print(f"[+] Stop reason: {result['stop_reason']}. No IDOR automatically confirmed. Evidence: {path}")


def bounded_text(path: Path, limit: int) -> str:
    with path.open("rb") as handle:
        raw = handle.read(limit + 1)
    if len(raw) > limit:
        raise ValueError("Input file exceeds the analysis size limit.")
    return raw.decode("utf-8")


def print_or_save(data: dict, output: Path | None) -> None:
    text = json.dumps(data, indent=2, sort_keys=True)
    if output:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(text, encoding="utf-8")
        print(f"[+] Offline analysis saved: {output}")
    else:
        print(text)


def cmd_resources(args: argparse.Namespace) -> None:
    print_or_save(catalog(), args.output)


def cmd_analyze(args: argparse.Namespace) -> None:
    text = bounded_text(args.input, 65536 if args.analysis == "jwt" else 1_000_000)
    if args.analysis == "html":
        data = analyze_html(text, args.marker, args.parser)
    elif args.analysis == "sql":
        data = analyze_sql(text)
    elif args.analysis == "disclosure":
        # Offline only: minimized indicators, never secret values; finding_confirmed stays false.
        data = assess_disclosure_batch(load_disclosure_records(text))
    elif args.analysis == "disclosure-access":
        # Offline correlation of disclosure indicators with IDOR/access evidence; never confirms.
        data = correlate_disclosure_access_batch(load_disclosure_access_cases(text))
    elif args.analysis == "evidence":
        data = review_evidence(json.loads(text))
        if args.ai == "ollama":
            model = args.model or DEFAULT_OLLAMA_MODEL
            data["ollama_review"] = review_with_ollama(data, model, args.ai_timeout)
            data["network_requests_sent_by_review"] = 1
        elif args.ai == "lmstudio":
            selection = AISelection("lmstudio", args.model or DEFAULT_OLLAMA_MODEL, None, float(args.ai_timeout))
            data["ai_review"] = review_packet(data, selection.model, selection.timeout, selection.validate())
            data["network_requests_sent_by_review"] = 1
        elif args.model:
            raise ValueError("--model requires --ai ollama or --ai lmstudio.")
    else:
        key = bounded_text(args.key_file, 65536).encode("utf-8") if args.key_file else None
        data = inspect_jwt(text.strip(), key, args.algorithm, args.issuer, args.audience)
    print_or_save(data, args.output)


def cmd_jwt_forge(args: argparse.Namespace) -> None:
    token = bounded_text(args.input, 65536).strip()
    public_key = None
    if args.public_key:
        if args.public_key.stat().st_size > MAX_PUBLIC_KEY_BYTES:
            raise ValueError("Public key file must be at most 1 MiB.")
        public_key = args.public_key.read_bytes()
    data = forge_jwt(token, args.secret, public_key)
    print_or_save(data, args.output)


def cmd_tool_plan(args: argparse.Namespace) -> None:
    store, settings, scope = executor_context(args)
    plan = build_external_plan(args.tool, args.url, args.parameter, scope, settings, args.script)
    plan["automation_allowed_in_program"] = store.metadata().get("automation_allowed") == "true"
    if not plan["automation_allowed_in_program"]:
        plan["warnings"].append(
            "This program does not record automation permission. Planning is offline; executing an automated scan is not authorized by this plan."
        )
    if args.dry_run:
        print("[+] External plan validated. No scanner executed and no requests sent.")
        return
    # Command plans may contain private URL values; only their redacted summary enters reports.
    path = write_evidence_json(store.paths.raw_dir / "external-plans", plan, prefix=args.tool)
    summary = write_evidence_json(
        store.paths.evidence_dir / "external-plans",
        {
            "type": "external-tool-plan",
            "tool": args.tool,
            "target": redact_url(args.url),
            "executed": False,
            "confirmed": False,
            "requires_manual_review": True,
            "automatic_request_budget_enforced": False,
        },
        prefix=args.tool,
    )
    store.add_run("tool-plan", redact_url(args.url), ["tool-plan", args.tool], 0, summary)
    print(f"[+] Private {args.tool} command plan: {path}")
    print("[!] Review required. No scanner executed. External tools do not inherit the bounded executor controls.")


def cmd_checklist(args: argparse.Namespace) -> None:
    store = store_for(args.program)
    checklist = store.paths.reviewed_dir / "vulnerability-checklist.md"
    checklist.write_text(render_checklist(), encoding="utf-8")
    print(f"[+] Checklist created: {checklist}")


def cmd_mark_reviewed(args: argparse.Namespace) -> None:
    store = store_for(args.program)
    store.mark_reviewed(args.kind, args.value, args.note)
    print(f"[+] Reviewed item recorded: {args.kind} -> {args.value}")


def cmd_add_finding(args: argparse.Namespace) -> None:
    store = store_for(args.program)
    ensure_in_scope(args.target, store.paths.scope_file)
    store.add_finding(
        args.finding_id, args.title, args.category, args.severity, args.target, args.summary, args.evidence
    )
    print(f"[+] Finding saved: {args.finding_id}")


def cmd_import_burp(args: argparse.Namespace) -> None:
    paths = ProgramPaths(RECORDS_ROOT, args.program)
    input_root = paths.program_dir / "inputs"
    output_files: dict[Path, str] = {}
    summary: list[str] = []

    if args.base_url and not (args.sitemap or args.request):
        raise ValueError("--base-url is supported only with --sitemap or --request.")
    if args.sitemap:
        parsed = parse_sitemap(read_burp_file(args.sitemap, MAX_SITEMAP_BYTES, "Burp sitemap"), args.base_url)
        output_files[Path("routes.txt")] = "".join(f"{route}\n" for route in parsed.routes)
        output_files[Path("parameters.txt")] = "".join(f"{name}\n" for name in parsed.parameters)
        summary.append(
            f"{len(parsed.routes)} unique routes, {len(parsed.parameters)} unique parameters, "
            f"{parsed.ignored_static} static items ignored, {parsed.ignored_items} malformed items skipped"
        )
    elif args.request:
        raw = read_burp_file(args.request, MAX_REQUEST_BYTES, "Burp request")
        normalized = normalize_raw_request(raw, args.base_url)
        output_files[Path("requests") / f"{safe_artifact_name(args.request)}.txt"] = normalized
        summary.append("one normalized raw HTTP request; sensitive headers and body values redacted")
    else:
        item = extract_item_artifacts(read_burp_file(args.item, MAX_ITEM_BYTES, "Burp item"))
        stem = safe_artifact_name(args.item)
        if item.html is not None:
            output_files[Path("burp") / f"{stem}-response.html"] = item.html
        for index, token in enumerate(item.jwts, start=1):
            output_files[Path("burp") / "private" / f"{stem}-jwt-{index:02d}.txt"] = token + "\n"
        summary.append(f"HTML response: {'yes' if item.html is not None else 'no'}; JWTs extracted: {len(item.jwts)}")

    destinations = {input_root / relative: content for relative, content in output_files.items()}
    conflicts = [path for path in destinations if path.exists()]
    if args.dry_run:
        print(f"[i] Burp import dry-run for {args.program}; no files changed and no network requests sent.")
        for path in destinations:
            state = (
                "would replace"
                if path in conflicts and args.force
                else "already exists (use --force)"
                if path in conflicts
                else "would create"
            )
            print(f"[dry-run] {state}: {path}")
        if summary:
            print(f"[+] Import plan: {'; '.join(summary)}")
        if any(path in conflicts for path in destinations) and not args.force:
            print("[!] Existing files will be left untouched; pass --force to replace them.")
        return
    if conflicts and not args.force:
        joined = ", ".join(str(path) for path in conflicts)
        raise ValueError(f"Import would overwrite existing file(s): {joined}. Pass --force to replace them.")
    for path, content in destinations.items():
        path.parent.mkdir(parents=True, exist_ok=True)
        if args.force:
            path.write_text(content, encoding="utf-8", newline="")
        else:
            with path.open("x", encoding="utf-8", newline="") as handle:
                handle.write(content)
        print(f"[+] Imported: {path}")
    print(f"[+] Burp import complete: {'; '.join(summary)}. No network requests sent.")
    if args.item and any("/private/" in str(path).replace("\\", "/") for path in destinations):
        print("[!] Extracted JWT files contain sensitive credentials; keep them local and never commit them.")


def cmd_import_discover_idor(args: argparse.Namespace) -> None:
    paths = ProgramPaths(RECORDS_ROOT, args.program)
    discovery = discover_idor(
        args.program,
        args.owner,
        args.actor,
        base_url=args.base_url,
        owner_response=args.owner_response,
        actor_response=args.actor_response,
        accounts_authorized=args.attest_authorized_accounts,
    )
    print(json.dumps(discovery_summary(discovery), indent=2, sort_keys=True))
    if args.dry_run:
        print("[dry-run] Offline discovery only; no files changed, no requests sent and no cases approved.")
        return
    destination = args.output_dir or paths.program_dir / "private" / "idor-discovery"
    save_proposal(discovery, destination)
    print("[+] Private proposal.json and capture snapshots saved in the selected proposal directory.")
    print("[!] Keep the entire bundle private. Review the pending fields, then use import approve-idor --approve.")


def cmd_import_approve_idor(args: argparse.Namespace) -> None:
    paths = ProgramPaths(RECORDS_ROOT, args.program)
    result = approve_idor(
        args.proposal,
        args.candidate,
        args.program,
        ScopeValidator(paths.scope_file),
        approve=args.approve,
        dry_run=args.dry_run,
    )
    print(json.dumps(result, indent=2, sort_keys=True))
    if result["case_written"]:
        print(f"[+] Native case-{args.candidate}.json saved beside the private proposal; no requests sent.")
    else:
        print("[dry-run] Reviewed inputs validated offline; no case written and no requests sent.")


def cmd_import_case(args: argparse.Namespace) -> None:
    paths = ProgramPaths(RECORDS_ROOT, args.program)
    output = args.output or paths.program_dir / "private" / "case.json"
    try:
        success_value = json.loads(args.success_value)
    except json.JSONDecodeError as exc:
        raise ValueError('--success-value must be a JSON string, integer or boolean, such as true or "ok".') from exc
    if type(success_value) not in {bool, str, int}:
        raise ValueError("--success-value must be a JSON string, integer or boolean.")
    result = generate_case(
        CaseGenerationOptions(
            owner=args.owner,
            actor=args.actor,
            output=output,
            base_url=args.base_url,
            resource_pointer=args.resource_pointer,
            private_pointer=args.private_pointer,
            success_pointer=args.success_pointer,
            success_value=success_value,
            private_marker=args.private_marker,
            actor_marker=args.actor_marker,
            accounts_authorized=args.attest_authorized_accounts,
            resource_private=args.attest_private_resource,
            force=args.force,
            dry_run=args.dry_run,
        )
    )
    print(f"[i] Offline case generation for {args.program}; no HTTP requests sent.")
    print(
        f"[+] Captures: same origin, method {result.method}; resource inferred from {result.resource_kind} {result.resource_name}."
    )
    print(f"[+] Sesión detectada: {', '.join(result.session_summary)}.")
    print(
        "[+] Declarations: authorized accounts and private owner resource were attested; "
        "cross-account access is expected to be denied."
    )
    print(
        "[i] JSON pointers were syntax-checked only; without response captures the generator cannot verify "
        "that they identify the resource, success field or private marker."
    )
    if result.dry_run:
        state = "would replace" if result.existing_output and args.force else "would create"
        if result.existing_output and not args.force:
            state = "already exists (use --force to replace)"
        print(f"[dry-run] {state}: {result.output}")
    else:
        print(f"[+] Case file saved: {result.output}")
    print("[!] The generated case contains resource IDs and private markers; keep it local and outside public commits.")


def _write_offline_json(path: Path, data: dict[str, object], force: bool) -> None:
    if path.exists() and not force:
        raise ValueError(f"Output already exists: {path}. Pass --force to replace it.")
    path.parent.mkdir(parents=True, exist_ok=True)
    rendered = json.dumps(data, indent=2, sort_keys=True, ensure_ascii=True) + "\n"
    if force:
        path.write_text(rendered, encoding="utf-8")
    else:
        with path.open("x", encoding="utf-8", newline="") as handle:
            handle.write(rendered)


def cmd_evidence_import(args: argparse.Namespace) -> None:
    paths = ProgramPaths(RECORDS_ROOT, args.program)
    bundle = import_evidence(args.input, args.format, getattr(args, "har_mode", "compat"))
    default_path = paths.evidence_dir / "imports" / "unified-evidence.json"
    destination = args.output or default_path
    summary = bundle["summary"]
    if not isinstance(summary, dict):
        raise RuntimeError("Evidence importer returned an invalid summary.")
    if args.dry_run:
        print(
            f"[i] Offline evidence import plan for {args.program}: {summary['records_parsed']} observations parsed, "
            f"{summary['records_unique']} unique, {summary['correlation_groups']} correlation groups."
        )
        print(f"[dry-run] would write: {destination}")
        print("[i] No target requests or Ollama calls sent; correlations are not vulnerability findings.")
        return
    _write_offline_json(destination, bundle, args.force)
    print(
        f"[+] Evidence bundle saved: {destination} ({summary['records_unique']} unique observations, "
        f"{summary['correlation_groups']} correlation groups). No network requests sent."
    )


def cmd_evidence_correlate(args: argparse.Namespace) -> None:
    paths = ProgramPaths(RECORDS_ROOT, args.program)
    result = correlations_from_bundle(args.input)
    bundle_id = result.get("bundle_id")
    safe_id = bundle_id if isinstance(bundle_id, str) and re.fullmatch(r"[a-f0-9]{24}", bundle_id) else "bundle"
    destination = args.output or paths.reports_dir / f"evidence-correlations-{safe_id}.json"
    summary = result["summary"]
    if not isinstance(summary, dict):
        raise RuntimeError("Evidence correlator returned an invalid summary.")
    if args.dry_run:
        print(
            f"[i] Offline correlation plan: {summary['records']} records, "
            f"{summary['correlation_groups']} descriptive groups. No findings are inferred."
        )
        print(f"[dry-run] would write: {destination}")
        return
    _write_offline_json(destination, result, args.force)
    print(f"[+] Correlations saved: {destination} ({summary['correlation_groups']} groups; no findings inferred).")


def cmd_api_workflow(args: argparse.Namespace) -> None:
    paths = ProgramPaths(RECORDS_ROOT, args.program)
    result = build_api_workflow(args.input, args.openapi)
    bundle_id = result.get("bundle_id")
    safe_id = bundle_id if isinstance(bundle_id, str) and re.fullmatch(r"[A-Za-z0-9_-]{1,64}", bundle_id) else "unknown"
    destination = args.output or paths.evidence_dir / "workflows" / f"api-workflow-{safe_id}.json"
    summary = result.get("summary")
    if not isinstance(summary, dict):
        raise RuntimeError("API workflow builder returned an invalid summary.")
    if args.dry_run:
        print(
            f"[i] Offline API workflow plan: {summary['records_usable']} observations, "
            f"{summary['nodes']} nodes, {summary['relations']} relations, "
            f"{summary['hypotheses']} hypotheses. No server behavior or findings inferred."
        )
        print(f"[dry-run] would write: {destination}")
        print("[i] No HTTP requests, Ollama calls or file writes performed.")
        return
    _write_offline_json(destination, result, args.force)
    print(
        f"[+] API workflow model saved: {destination} ({summary['nodes']} nodes, "
        f"{summary['relations']} relations). Hypotheses are explicitly labeled; no findings confirmed."
    )


def _object_key_path(args: argparse.Namespace) -> Path:
    paths = ProgramPaths(RECORDS_ROOT, args.program)
    return args.key_file or paths.program_dir / "private" / "object-relationships" / "key.bin"


def cmd_object_discover(args: argparse.Namespace) -> None:
    paths = ProgramPaths(RECORDS_ROOT, args.program)
    destination = args.output or paths.program_dir / "private" / "object-relationships" / "graph.json"
    graph, candidates = discover_to_file(
        args.program,
        args.input,
        _object_key_path(args),
        destination,
        authorized=args.attest_authorized_captures,
        dry_run=args.dry_run,
        force=args.force,
        base_url=args.base_url,
        strict=args.strict,
        allow_truncate=args.allow_truncate,
    )
    summary = graph["summary"]
    capture_import = {k: v for k, v in graph["capture_import"].items() if k != "sources"}
    print(
        json.dumps(
            {
                "dry_run": args.dry_run,
                **summary,
                "candidates": candidates["total_candidates"],
                "capture_import": capture_import,
                "network_requests_sent": 0,
                "vulnerabilities_confirmed": 0,
            },
            sort_keys=True,
        )
    )
    print("[i] Offline object references only; ownership and permissions require researcher review.")
    if capture_import["rejected"] or capture_import["truncated"]:
        print(
            f"[!] Partial HAR recovery: {capture_import['accepted']} entries accepted, "
            f"{capture_import['rejected']} isolated (reason codes only; see capture_import). Use --strict to reject."
        )
    if args.dry_run:
        print("[dry-run] No key, graph, database or other file was written.")
    else:
        print("[+] Minimized graph saved privately with a local HMAC key. No HTTP requests sent.")


def cmd_object_candidates(args: argparse.Namespace) -> None:
    key_path = _object_key_path(args)
    if args.output and local_path(args.output) in {
        local_path(args.graph),
        local_path(key_path),
        *[local_path(p) for p in args.verify_input],
    }:
        raise ValueError("Candidate output must not replace the graph, key or source captures.")
    key = load_object_key(key_path)
    graph = read_object_graph(args.graph, args.program, key)
    if args.verify_input:
        verify_object_sources(graph, args.verify_input, key)
    result = object_candidates(graph, args.program, key, limit=args.limit, min_score=args.min_score)
    if args.dry_run:
        print(
            json.dumps(
                {
                    "dry_run": True,
                    "total_candidates": result["total_candidates"],
                    "listed": len(result["candidates"]),
                    "network_requests_sent": 0,
                    "vulnerabilities_confirmed": 0,
                },
                sort_keys=True,
            )
        )
    else:
        if args.output:
            save_object_json(args.output, result, force=args.force)
        print(json.dumps(result, indent=2, sort_keys=True))


def cmd_object_handoff(args: argparse.Namespace) -> None:
    """Propose offline owner/actor capture pairs from object-relationship candidates."""
    document = handoff_to_file(
        args.program,
        args.graph,
        _object_key_path(args),
        candidate=args.candidate,
        verify_inputs=args.verify_input or None,
        output=None if args.dry_run else args.output,
        materialize_dir=None if args.dry_run else args.materialize_dir,
        dry_run=args.dry_run,
        force=args.force,
        base_url=args.base_url,
        limit=args.limit,
        include_response_identifiers=not args.request_only,
    )
    if args.dry_run:
        print(
            json.dumps(
                {
                    "dry_run": True,
                    "status": document["status"],
                    "total_proposals": document["total_proposals"],
                    "asymmetric_selected": document["response_identifiers"]["asymmetric_selected"],
                    "materialized_pairs": document["materialized_pairs"],
                    "network_requests_sent": 0,
                    "vulnerabilities_confirmed": 0,
                    "confirmed": False,
                },
                sort_keys=True,
            )
        )
        print("[dry-run] No proposal JSON, captures or cases were written.")
    else:
        if args.output:
            print(f"[+] Handoff proposals saved: {args.output}")
        print(json.dumps(document, indent=2, sort_keys=True))
    print("[i] " + document["human_gate"])
    print("[i] Offline handoff only; no HTTP requests sent and no cases approved.")


def cmd_graph_ingest(args: argparse.Namespace) -> None:
    paths = ProgramPaths(RECORDS_ROOT, args.program)
    preview = preview_graph_ingest(
        args.input,
        args.openapi,
        args.hypotheses,
        args.route,
        args.case_file,
        args.access_evidence,
    )
    if args.dry_run:
        print("[dry-run] Local evidence graph ingest validated; no SQLite file was created or changed.")
        print(json.dumps(preview, indent=2, sort_keys=True))
        return
    store = RecordStore(paths)
    try:
        result = EvidenceGraphStore(store).ingest(
            args.input,
            args.openapi,
            args.hypotheses,
            args.route,
            args.case_file,
            args.access_evidence,
        )
    finally:
        store.close()
    print("[+] Evidence graph saved in the program's existing local SQLite database.")
    print("[i] Imported model opinions remain hypotheses; account/resource declarations remain attestations.")
    print(json.dumps(result, indent=2, sort_keys=True))


def cmd_graph_search(args: argparse.Namespace) -> None:
    paths = ProgramPaths(RECORDS_ROOT, args.program)
    if not paths.db_path.exists():
        raise ValueError(f"No local program database exists for {args.program}; run `bbtk graph ingest` first.")
    store = RecordStore(paths)
    try:
        result = EvidenceGraphStore(store).search(
            endpoint=args.endpoint,
            account=args.account,
            resource=args.resource,
            category=args.category,
            finding_id=args.finding_id,
            limit=args.limit,
        )
    finally:
        store.close()
    print(json.dumps(result, indent=2, sort_keys=True))


def _multi_provider_requested(args: argparse.Namespace) -> bool:
    if args.artifact and not (args.structured or args.second_ai_provider or args.second_ai_model):
        return False
    return bool(
        args.ai_provider != "ollama"
        or args.second_ai_provider
        or args.second_ai_model
        or args.structured
        or args.ai_endpoint
    )


def cmd_ai_review_structured(args: argparse.Namespace) -> None:
    from .analysis.ai_providers import GenerationLimits, build_provider
    from .analysis.multi_review import build_evidence_bundle, review_evidence_multi

    if not args.evidence_file:
        raise ValueError("Structured/second-provider review requires --evidence-file; artifacts accept --ai-provider.")
    if bool(args.second_ai_provider) != bool(args.second_ai_model):
        raise ValueError("--second-ai-provider and --second-ai-model must be used together.")
    limits = GenerationLimits(timeout=args.ai_timeout, max_output_tokens=args.ai_max_tokens)
    limits.validate()
    reviewers = [(build_provider(args.ai_provider, args.ai_endpoint, args.ai_concurrency), args.model)]
    if args.second_ai_provider:
        validate_ollama_config(args.second_ai_model, args.ai_timeout)
        reviewers.append((build_provider(args.second_ai_provider, None, args.ai_concurrency), args.second_ai_model))
    for _, model in reviewers:
        validate_ollama_config(model, args.ai_timeout)
    try:
        data = json.loads(bounded_text(args.evidence_file, 2_000_000))
    except json.JSONDecodeError as exc:
        raise ValueError("Evidence file must contain valid JSON.") from exc
    if not isinstance(data, dict):
        raise ValueError("Evidence file must contain a JSON object.")
    if args.dry_run:
        bundle = build_evidence_bundle(data)
        result: dict[str, object] = {
            "type": "ai-evidence-review",
            "status": "dry_run",
            "decision": "inconclusive",
            "evidence_bundle_id": bundle["evidence_bundle_id"],
            "evidence_bundle": {key: value for key, value in bundle.items() if key != "minimized_packet"},
            "reviewers": [{"provider": p.provider_id, "model": m, "endpoint": p.spec.endpoint()} for p, m in reviewers],
            "execution_performed": False,
            "finding_confirmed": False,
            "raw_evidence_sent": False,
            "reason": "Evidence minimized locally; no AI provider was contacted.",
            "notice": SECOND_OPINION,
        }
    else:
        result = review_evidence_multi(data, reviewers, limits)
    print(f"[i] {SECOND_OPINION}")
    print(json.dumps(result, indent=2, sort_keys=True))


def _add_ai_provider_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--ai-provider",
        choices=("ollama", "lmstudio"),
        help="Allowlisted local provider via the AIProvider adapters (default: legacy Ollama client)",
    )
    parser.add_argument(
        "--ai-endpoint", help="Optional restatement of the provider's authorized loopback host:port; others rejected"
    )


def cmd_ai_dual_review(args: argparse.Namespace) -> None:
    from .analysis.dual_review import dual_review
    from .analysis.multi_review import build_evidence_bundle

    ProgramPaths(RECORDS_ROOT, args.program)
    analyst = AISelection(args.analyst_provider, args.analyst_model, None, float(args.ai_timeout)).validate()
    critic = AISelection(args.critic_provider, args.critic_model, None, float(args.ai_timeout)).validate()
    try:
        data = json.loads(bounded_text(args.evidence_file, 2_000_000))
    except json.JSONDecodeError as exc:
        raise ValueError("Evidence file must contain valid JSON.") from exc
    if not isinstance(data, dict):
        raise ValueError("Evidence file must contain a JSON object.")
    if args.dry_run:
        bundle = build_evidence_bundle(data)
        result: dict[str, object] = {
            "type": "ai-dual-review",
            "status": "dry_run",
            "evidence_bundle_id": bundle["evidence_bundle_id"],
            "analyst": analyst.describe(),
            "critic": critic.describe(),
            "finding_confirmed": False,
            "execution_performed": False,
            "reason": "Evidence minimized locally; no AI provider was contacted.",
        }
    else:
        result = dual_review(data, analyst, critic)
    print(f"[i] {SECOND_OPINION} Consensus between models is not confirmation.")
    print(json.dumps(result, indent=2, sort_keys=True))


def cmd_ai_evidence_assist(args: argparse.Namespace) -> None:
    """Local AI evidence assistant: explain/summarize/questions/contradictions/drafts/missing data."""
    from .analysis.ai_backend import AISelection
    from .analysis.local_ai_evidence_assistant import assist_evidence

    ProgramPaths(RECORDS_ROOT, args.program)
    try:
        data = json.loads(bounded_text(args.evidence_file, 2_000_000))
    except json.JSONDecodeError as exc:
        raise ValueError("Evidence file must contain valid JSON.") from exc
    if not isinstance(data, dict):
        raise ValueError("Evidence file must contain a JSON object.")
    selection = None
    compare = None
    if not args.dry_run:
        selection = AISelection(args.ai_provider, args.ai_model, args.ai_endpoint, float(args.ai_timeout)).validate()
        if args.compare_provider or args.compare_model:
            if not (args.compare_provider and args.compare_model):
                raise ValueError("--compare-provider and --compare-model must be used together.")
            compare = AISelection(args.compare_provider, args.compare_model, None, float(args.ai_timeout)).validate()
    elif args.ai_provider:
        selection = AISelection(args.ai_provider, args.ai_model, args.ai_endpoint, float(args.ai_timeout)).validate()
    result = assist_evidence(data, selection=selection, compare=compare, dry_run=bool(args.dry_run))
    print(f"[i] {SECOND_OPINION} Deterministic baseline stays primary; AI never confirms findings.")
    print(json.dumps(result, indent=2, sort_keys=True))


def cmd_ai_providers(args: argparse.Namespace) -> None:
    from .analysis.ai_providers import build_provider, list_providers

    rows = list_providers()
    if args.check:
        for row in rows:
            if row["enabled"]:
                provider = build_provider(str(row["provider"]))
                row["availability"] = provider.check_availability(args.ai_model, args.ai_timeout).as_dict()
    print(json.dumps({"type": "ai-providers", "providers": rows, "remote_providers_enabled": False}, indent=2))


def cmd_ai_review(args: argparse.Namespace) -> None:
    ProgramPaths(RECORDS_ROOT, args.program)
    validate_ollama_config(args.model, args.ai_timeout)
    if _multi_provider_requested(args):
        cmd_ai_review_structured(args)
        return
    if args.evidence_file:
        if args.kind is not None:
            raise ValueError("--kind is only valid with --artifact.")
        try:
            data = json.loads(bounded_text(args.evidence_file, 2_000_000))
        except json.JSONDecodeError as exc:
            raise ValueError("Evidence file must contain valid JSON.") from exc
        if not isinstance(data, dict):
            raise ValueError("Evidence file must contain a JSON object.")
        packet = review_evidence(data)
        if args.dry_run:
            result = {
                "type": "ai-evidence-review",
                "status": "dry_run",
                "decision": "inconclusive",
                "reason": "Evidence minimized locally; Ollama was not contacted.",
                "notice": SECOND_OPINION,
                "model": args.model,
                "raw_evidence_sent": False,
                "minimized_packet": packet,
            }
        else:
            result = review_evidence_with_ollama(data, args.model, args.ai_timeout)
    else:
        if args.kind is None:
            raise ValueError("--kind is required with --artifact (html, request or response).")
        artifact_selection = (
            AISelection(args.ai_provider, args.model, args.ai_endpoint, float(args.ai_timeout)).validate()
            if args.ai_provider != "ollama" or args.ai_endpoint
            else None
        )
        result = review_artifact(
            args.artifact,
            args.kind,
            args.model,
            args.ai_timeout,
            args.chunk_chars,
            args.max_chunks,
            args.dry_run,
            selection=artifact_selection,
        )
    print(f"[i] {SECOND_OPINION}")
    print(json.dumps(result, indent=2, sort_keys=True))


def cmd_ai_hypotheses(args: argparse.Namespace) -> None:
    if args.access_evidence and not args.case_file:
        raise ValueError("--access-evidence requires --case-file.")
    paths = ProgramPaths(RECORDS_ROOT, args.program)
    selection = selection_from_args(args.ai_provider, args.ai_model, args.ai_timeout, args.ai_endpoint)
    result = analyze_hypotheses(args.input, args.ai_model, args.ai_timeout, args.dry_run, selection=selection)
    if args.case_file:
        result["access_control_assessment"] = assess_access_control(args.case_file, args.access_evidence)
    print(f"[i] {HYPOTHESES_SECOND_OPINION}")
    if args.dry_run:
        print("[dry-run] No Ollama request or file write performed.")
    else:
        history_path = write_evidence_json(paths.evidence_dir / "ai-hypotheses", result, prefix="ai-hypotheses")
        print(f"[+] Non-overwriting review history: {history_path}")
    print(json.dumps(result, indent=2, sort_keys=True))


def cmd_ai_route(args: argparse.Namespace) -> None:
    ProgramPaths(RECORDS_ROOT, args.program)
    selection = selection_from_args(args.ai_provider, args.ai_model, args.ai_timeout, args.ai_endpoint)
    result = route_hypotheses_file(
        args.input, args.program, args.max_tests, args.ai_model, args.ai_timeout, selection=selection
    )
    print("[i] Route plan only. No skill command or target request was executed; review missing inputs before use.")
    print(json.dumps(result, indent=2, sort_keys=True))


def cmd_ai_prioritize(args: argparse.Namespace) -> None:
    ProgramPaths(RECORDS_ROOT, args.program)
    if args.force and args.output is None:
        raise ValueError("--force requires --output.")
    result = prioritize_hypotheses_file(args.input, args.program, args.max_tests)
    result["dry_run"] = args.dry_run
    if args.dry_run:
        print("[dry-run] No target request, Ollama call or file write performed.")
    elif args.output is not None:
        try:
            report_path = write_prioritization_report(result, args.output, args.force)
        except FileExistsError as exc:
            raise ValueError(
                f"Prioritization report already exists: {exc.filename}; use --force to replace it."
            ) from exc
        result["output"] = str(report_path)
        print(f"[+] Prioritization report saved: {report_path}")
    print("[i] Deterministic triage only. It does not confirm findings or execute the plan.")
    print(json.dumps(result, indent=2, sort_keys=True))


def cmd_ai_investigate(args: argparse.Namespace) -> None:
    paths = ProgramPaths(RECORDS_ROOT, args.program)
    if args.force and args.output is None:
        raise ValueError("--force requires --output.")
    if args.resume_session and not args.session_id:
        raise ValueError("--resume-session requires --session-id.")
    if args.session_id and args.output is not None:
        raise ValueError("--session-id uses the program's non-overwriting investigation history; omit --output.")
    selection = selection_from_args(args.ai_provider, args.ai_model, args.ai_timeout, args.ai_endpoint)
    if selection is not None and not args.with_ollama and not args.dry_run:
        raise ValueError("--ai-provider requires --with-ai (alias --with-ollama) to opt in to a local model.")
    result = investigate_evidence(
        args.program,
        args.input,
        max_tests=args.max_tests,
        model=args.ai_model,
        timeout=args.ai_timeout,
        offline=not args.with_ollama,
        dry_run=args.dry_run,
        case_file=args.case_file,
        access_evidence=args.access_evidence,
        selection=selection,
    )
    rendered: dict[str, object] = dict(result)
    history_path: Path | None = None
    if args.dry_run:
        print("[dry-run] No Ollama call, target request, command execution or file write performed.")
        if args.output is not None:
            print(f"[dry-run] would write: {args.output}")
        if args.session_id:
            print(f"[dry-run] would save investigation memory: {args.session_id}")
    elif args.output is not None:
        _write_offline_json(args.output, rendered, args.force)
        rendered["output"] = str(args.output)
        print(f"[+] Investigation saved: {args.output}")
    else:
        history_path = write_evidence_json(paths.evidence_dir / "ai-investigations", rendered, prefix="investigation")
        rendered["output"] = str(history_path)
        print(f"[+] Non-overwriting investigation history: {history_path}")
    if args.session_id and history_path is not None:
        bundle_id = result["correlation_summary"].get("bundle_id")
        if not isinstance(bundle_id, str):
            raise ValueError("Investigation result has no stable evidence bundle ID for memory storage.")
        store = store_for(args.program)
        try:
            memory = InvestigationMemory(store).save_snapshot(
                args.session_id,
                bundle_id,
                history_path.relative_to(paths.program_dir).as_posix(),
                result["stages"],
                resume=args.resume_session,
            )
        finally:
            store.close()
        rendered["memory"] = memory
        print(f"[+] Investigation memory {memory['status']}: {args.session_id}")
    print(f"[i] {HYPOTHESES_SECOND_OPINION} The plan is advisory and was not executed.")
    print(json.dumps(rendered, indent=2, sort_keys=True))


def _ledger_location(args: argparse.Namespace) -> tuple[Path, Path]:
    paths = ProgramPaths(RECORDS_ROOT, args.program)
    ledger_path = args.ledger or (paths.program_dir / "ledger" / "evidence-ledger.json")
    return paths.program_dir, ledger_path


def _ledger_load(args: argparse.Namespace) -> tuple[Path, Path, dict[str, object]]:
    program_dir, ledger_path = _ledger_location(args)
    return program_dir, ledger_path, ledger_mod.load_ledger(ledger_path)


def cmd_ledger_schema(args: argparse.Namespace) -> None:
    print(json.dumps(ledger_mod.LEDGER_SCHEMA, indent=2, sort_keys=True))


def cmd_ledger_init(args: argparse.Namespace) -> None:
    program_dir, ledger_path = _ledger_location(args)
    if ledger_path.exists():
        raise ValueError(f"Ledger already exists: {ledger_path}")
    ledger_mod.save_ledger(ledger_path, ledger_mod.new_ledger(args.program))
    print(f"[+] Evidence ledger created: {ledger_path}")


def cmd_ledger_surface(args: argparse.Namespace) -> None:
    program_dir, ledger_path, ledger = _ledger_load(args)
    row = {
        "surface_id": args.id,
        "kind": args.kind,
        "ref": args.ref,
        "status": args.status,
        "blocker": args.blocker,
        "reason": args.reason,
        "fingerprint": args.fingerprint,
        "investigation_id": args.investigation_id,
        "notes": args.notes,
    }
    ledger_mod.upsert_surface(ledger, row)
    ledger_mod.save_ledger(ledger_path, ledger, program_dir=program_dir)
    print(f"[+] Surface {args.id} recorded as {args.status}.")


def cmd_ledger_evidence(args: argparse.Namespace) -> None:
    program_dir, ledger_path, ledger = _ledger_load(args)
    row = ledger_mod.add_evidence(
        ledger,
        program_dir,
        args.id,
        args.path,
        tool=args.tool,
        surface_fingerprint=args.surface_fingerprint,
        bundle_id=args.bundle_id,
        investigation_id=args.investigation_id,
        graph_node_ids=args.graph_node or None,
    )
    ledger_mod.save_ledger(ledger_path, ledger, program_dir=program_dir)
    print(f"[+] Evidence {args.id} recorded (sha256 {row['sha256'][:16]}...).")


def cmd_ledger_candidate(args: argparse.Namespace) -> None:
    program_dir, ledger_path, ledger = _ledger_load(args)
    ledger_mod.add_candidate(
        ledger,
        args.id,
        args.surface,
        args.category,
        args.raised_by,
        args.evidence or [],
        title=args.title,
        dedup_key=args.dedup_key,
        finding_id=args.finding_id,
    )
    ledger_mod.save_ledger(ledger_path, ledger, program_dir=program_dir)
    print(f"[+] Candidate {args.id} recorded in state 'candidate' (never auto-confirmed).")


def cmd_ledger_import(args: argparse.Namespace) -> None:
    program_dir, ledger_path, ledger = _ledger_load(args)
    result = ledger_mod.import_native_evidence(
        ledger, program_dir, args.evidence_path, args.surface, raised_by=args.raised_by
    )
    ledger_mod.save_ledger(ledger_path, ledger, program_dir=program_dir)
    print(json.dumps(result, indent=2, sort_keys=True))
    print("[i] Tool labels are kept as notes only; imported candidates require human review.")


def cmd_ledger_review(args: argparse.Namespace) -> None:
    program_dir, ledger_path, ledger = _ledger_load(args)
    cand = ledger_mod.review_candidate(
        ledger,
        args.id,
        args.state,
        args.reviewer,
        method=args.method,
        basis=args.basis,
        rejection_reason=args.reason,
        rejection_detail=args.detail,
        blockers=args.blocker or None,
        duplicate_of=args.duplicate_of,
        human_attestation=args.i_reviewed_the_evidence,
    )
    ledger_mod.save_ledger(ledger_path, ledger, program_dir=program_dir)
    print(f"[+] Candidate {args.id} -> {cand['state']} by {args.reviewer}.")


def cmd_ledger_validate(args: argparse.Namespace) -> None:
    program_dir = ProgramPaths(RECORDS_ROOT, args.program).program_dir
    ledger_path = args.ledger or (program_dir / "ledger" / "evidence-ledger.json")
    result = ledger_mod.validate_ledger(ledger_mod.load_ledger(ledger_path), program_dir=program_dir)
    print(json.dumps(result, indent=2, sort_keys=True))
    if not result["valid"]:
        raise SystemExit(1)


def cmd_ledger_report(args: argparse.Namespace) -> None:
    program_dir, ledger_path, ledger = _ledger_load(args)
    validation = ledger_mod.validate_ledger(ledger, program_dir=program_dir)
    text = ledger_mod.render_markdown(ledger, validation)
    if args.output:
        destination = local_path(args.output)
        if destination.exists() and not args.force:
            raise ValueError(f"Report already exists: {destination}. Pass --force to replace it.")
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(text, encoding="utf-8")
        print(f"[+] Ledger report saved: {destination}")
    else:
        print(text)


def cmd_lab_evidence_ledger(args: argparse.Namespace) -> None:
    result = run_evidence_ledger_lab()
    print(json.dumps(result["metrics"], indent=2, sort_keys=True))
    print("[i] Synthetic offline lab; measures ledger integrity checks, not vulnerability detection.")
    if args.metrics_json:
        destination = local_path(args.metrics_json)
        if destination.exists() and not args.force:
            raise ValueError(f"Metrics output already exists: {destination}. Pass --force to replace it.")
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(f"[+] Metrics saved: {destination}")
    if (
        result["metrics"]["false_confirmations"]
        or result["metrics"]["scenarios_passed"] != result["metrics"]["scenarios"]
    ):
        raise SystemExit(1)


def cmd_investigation_close(args: argparse.Namespace) -> None:
    store = store_for(args.program)
    try:
        result = InvestigationMemory(store).close(args.investigation_id)
    finally:
        store.close()
    print("[+] Investigation closed; local evidence history is retained.")
    print(json.dumps(result, indent=2, sort_keys=True))


def cmd_investigation_status(args: argparse.Namespace) -> None:
    paths = ProgramPaths(RECORDS_ROOT, args.program)
    if not paths.db_path.exists():
        raise ValueError(f"No local investigation memory exists for {args.program}.")
    store = store_for(args.program)
    try:
        result = InvestigationMemory(store).get(args.investigation_id)
    finally:
        store.close()
    if result is None:
        raise ValueError("Investigation does not exist in this program's local memory.")
    print(json.dumps(result, indent=2, sort_keys=True))


def cmd_investigation_next_steps(args: argparse.Namespace) -> None:
    """Opt-in, read-only evidence-gap next-step plan. Never writes the ledger."""
    paths = ProgramPaths(RECORDS_ROOT, args.program)
    plan = build_plan(paths, ledger_file=args.ledger)
    problems = validate_plan(plan)
    if problems:
        raise ValueError("Plan failed contract validation: " + ", ".join(problems))
    if args.schema:
        print(json.dumps(PLAN_SCHEMA, indent=2, sort_keys=True))
        return
    body = dumps_plan(plan) if args.minimize else json.dumps(plan, indent=2, sort_keys=True)
    if args.output:
        destination = local_path(args.output)
        if destination.exists() and not args.force:
            raise ValueError(f"Output already exists: {destination}. Pass --force to replace it.")
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(body + ("\n" if not body.endswith("\n") else ""), encoding="utf-8")
        print(f"[+] Evidence-gap plan saved: {destination}")
    else:
        print(body)
    if args.dry_run:
        print(
            "[i] Dry-run: plan is advisory only; execution_allowed=false and finding_confirmed=false on every step.",
            file=sys.stderr,
        )


def cmd_lab_evidence_gap(args: argparse.Namespace) -> None:
    from labs.evidence_gap_planner_eval.run_lab import main as lab_main

    argv = ["--split", args.split]
    if args.metrics_json:
        argv.extend(["--output", str(local_path(args.metrics_json))])
    code = lab_main(argv)
    if code:
        raise SystemExit(code)


def cmd_dashboard(args: argparse.Namespace) -> None:
    try:
        from .dashboard import create_app, require_loopback_host

        import uvicorn
    except ImportError as exc:
        raise ToolkitError(
            "Dashboard dependencies are optional; install with `pip install -e '.[dashboard]'`."
        ) from exc
    host = require_loopback_host(args.host)
    if not 1 <= args.port <= 65535:
        raise ValueError("Dashboard port must be between 1 and 65535.")
    app = create_app(RECORDS_ROOT, args.program)
    print(f"[i] Local dashboard for {args.program}: http://{host}:{args.port}/")
    print("[i] Loopback only. No active checks or target requests are available from the dashboard.")
    uvicorn.run(app, host=host, port=args.port, access_log=False)


def cmd_ai_benchmark(args: argparse.Namespace) -> None:
    if not args.dry_run and args.output is None:
        raise ValueError("--output is required unless --dry-run is used.")
    if args.force and args.output is None:
        raise ValueError("--force requires --output.")
    selection = selection_from_args(args.ai_provider, args.ai_model, args.ai_timeout, args.ai_endpoint)
    if selection is not None and not args.with_ollama:
        raise ValueError("--ai-provider requires --with-ai (alias --with-ollama) to opt in to a local model.")
    result = run_idor_benchmark(
        args.dataset,
        split=args.split,
        with_ollama=args.with_ollama,
        model=args.ai_model,
        timeout=args.ai_timeout,
        dry_run=args.dry_run,
        selection=selection if not args.dry_run else None,
    )
    if args.dry_run:
        print("[dry-run] No Ollama call, target request or file write performed.")
    else:
        result["outputs"] = {"json": str(args.output), "markdown": str(args.output.with_suffix(".md"))}
        try:
            json_path, markdown_path = write_benchmark_reports(result, args.output, args.force)
        except FileExistsError as exc:
            raise ValueError(str(exc)) from exc
        result["outputs"] = {"json": str(json_path), "markdown": str(markdown_path)}
        print(f"[+] Benchmark reports saved: {json_path} and {markdown_path}")
    print(f"[i] {SECOND_OPINION}")
    print(json.dumps(result, indent=2, sort_keys=True))


def cmd_report(args: argparse.Namespace) -> None:
    store = store_for(args.program)
    if args.draft_with_ai and not args.evidence_file:
        raise ValueError("--draft-with-ai requires --evidence-file.")
    if not args.draft_with_ai and (
        args.ai_model is not None
        or args.ai_timeout is not None
        or args.ai_provider is not None
        or args.ai_endpoint is not None
    ):
        raise ValueError("--ai-model, --ai-timeout, --ai-provider and --ai-endpoint require --draft-with-ai.")
    if args.force and not args.evidence_file and not args.finding_id:
        raise ValueError("--force applies to evidence and individual finding reports only.")
    if args.evidence_file:
        if args.finding_id:
            raise ValueError("--evidence-file cannot be combined with --finding-id.")
        report_format = args.format or "markdown"
        if args.draft_with_ai and report_format != "markdown":
            raise ValueError("--draft-with-ai currently produces Markdown only.")
        try:
            data = json.loads(bounded_text(args.evidence_file, 2_000_000))
        except json.JSONDecodeError as exc:
            raise ValueError("Evidence file must contain valid JSON.") from exc
        if not isinstance(data, dict):
            raise ValueError("Evidence file must contain a JSON object.")
        extension = "md" if report_format == "markdown" else report_format
        destination = args.output or store.paths.reports_dir / f"evidence-review-{args.evidence_file.stem}.{extension}"
        if destination.exists() and not args.force:
            raise ValueError(f"Report already exists: {destination}. Use --force to replace it.")
        report = build_evidence_finding_report(data, program=args.program, source_name=args.evidence_file.name)
        if report_format == "json":
            output = render_evidence_report_json(report, destination)
        elif report_format == "html":
            output = render_evidence_report_html(report, destination)
        elif report_format == "pdf":
            output = render_evidence_report_pdf(report, destination)
        elif report_format == "markdown":
            output = render_evidence_review(
                data, destination, program=args.program, source_name=args.evidence_file.name
            )
        else:
            raise ValueError("Evidence reports support markdown, json, html or pdf.")
        if args.draft_with_ai:
            model = args.ai_model or DEFAULT_OLLAMA_MODEL
            timeout = args.ai_timeout or 120.0
            try:
                draft = generate_ai_report(
                    data,
                    model,
                    timeout,
                    selection=selection_from_args(args.ai_provider, model, timeout, args.ai_endpoint),
                )
            except (OSError, RuntimeError, ValueError):
                fallback = "> Ollama unavailable or returned an unusable draft. Deterministic template only; no AI confirmation.\n\n"
                output.write_text(fallback + output.read_text(encoding="utf-8"), encoding="utf-8")
                print(f"[!] Ollama draft unavailable; deterministic draft used: {output}. Nothing was submitted.")
                return
            output.write_text(draft, encoding="utf-8")
            print(f"[+] AI-assisted Markdown draft created: {output}. {SECOND_OPINION} Nothing was submitted.")
            return
        print(f"[+] Review draft created: {output}. Nothing was submitted.")
        return
    if args.output:
        raise ValueError("--output requires --evidence-file.")
    if not args.finding_id:
        report_format = args.format or "html"
        if report_format not in {"html", "json"}:
            raise ValueError("Program reports support html/json. Use --finding-id for markdown/pdf.")
        destination = store.paths.reports_dir / f"program-report.{report_format}"
        output = (
            render_html_report(store, destination)
            if report_format == "html"
            else render_json_report(store, destination)
        )
        print(f"[+] Report created: {output}")
        return
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,79}", args.finding_id):
        raise ValueError("Finding ID must use letters, digits, underscores or hyphens.")
    if args.format not in {None, "markdown", "pdf"}:
        raise ValueError("Individual finding reports support markdown/pdf.")
    finding = store.finding(args.finding_id)
    if not finding:
        raise SystemExit(f"Finding not found: {args.finding_id}")
    finding_format = args.format or "pdf"
    markdown_path = store.paths.reports_dir / f"{args.finding_id}.md"
    pdf_path = store.paths.reports_dir / f"{args.finding_id}.pdf"
    outputs = [markdown_path] if finding_format == "markdown" else [markdown_path, pdf_path]
    existing = [path for path in outputs if path.exists()]
    if existing and not args.force:
        raise ValueError(f"Report already exists: {existing[0]}. Use --force to replace it.")
    markdown = render_markdown(finding, markdown_path)
    output = markdown if finding_format == "markdown" else render_pdf(markdown, pdf_path)
    store.mark_reviewed("report", args.finding_id, str(output))
    print(f"[+] Report created: {output}")


def cmd_status(args: argparse.Namespace) -> None:
    store = store_for(args.program)
    counts = store.counts()
    print(f"Program: {args.program}")
    print(f"Runs: {counts['runs']}")
    print(f"Reviewed items: {counts['reviewed']}")
    print(f"Findings: {counts['findings']}")
    print(f"Records path: {store.paths.program_dir}")


def cmd_doctor(args: argparse.Namespace) -> None:
    result = diagnose(
        args.records_root,
        args.program,
        installed_skills=args.skills_dir,
    )
    if args.json_output:
        print(json.dumps(result, indent=2, sort_keys=True))
        return
    print(f"Bug Bounty Toolkit {result['toolkit_version']} | offline diagnostics | no HTTP requests")
    for check in result["checks"]:
        marker = {"ok": "+", "warning": "!", "error": "x"}.get(check["status"], "?")
        print(f"[{marker}] {check['name']}: {check['detail']}")
    print("[+] Diagnostics passed." if result["ok"] else "[!] Required checks need attention.")


def add_run_budget_arguments(command: argparse.ArgumentParser) -> None:
    command.add_argument(
        "--run-max-requests",
        type=positive_int,
        help="Shared cap across this command's HTTP/browser requests; program scope gates every destination",
    )
    command.add_argument(
        "--run-max-seconds",
        type=positive_float,
        help="Shared wall-clock budget across HTTP/browser requests in this command",
    )
    command.add_argument(
        "--run-max-concurrency",
        type=positive_int,
        help="Shared HTTP/browser concurrency cap, never above the program configuration",
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="bbtk", description="Authorized bug bounty automation toolkit")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument("--records-root", type=Path, default=RECORDS_ROOT)
    parser.add_argument("--log-file", type=Path, help="Optional local execution log; request secrets are not logged")
    sub = parser.add_subparsers(required=True)

    init = sub.add_parser("init")
    init.add_argument("program")
    init.add_argument("--platform", default="hackerone")
    init.add_argument("--authorization", required=True)
    init.add_argument(
        "--automation-allowed", action="store_true", help="Record that the program permits automated testing"
    )
    init.add_argument("--config", type=Path, help="YAML limits copied into the program records")
    init.set_defaults(func=cmd_init)

    scope = sub.add_parser("scope")
    scope_sub = scope.add_subparsers(required=True)
    scope_add = scope_sub.add_parser("add")
    scope_add.add_argument("program")
    scope_add.add_argument("domain")
    scope_add.add_argument("--exclude", action="store_true")
    scope_add.set_defaults(func=cmd_scope_add)
    scope_import = scope_sub.add_parser("import")
    scope_import.add_argument("program")
    scope_import.add_argument("file", type=Path)
    scope_import.set_defaults(func=cmd_scope_import)

    request = sub.add_parser("request")
    request.add_argument("program")
    source = request.add_mutually_exclusive_group(required=True)
    source.add_argument("--url")
    source.add_argument("--raw-request", type=Path)
    request.add_argument("--base-url")
    request.add_argument("--method")
    request.add_argument("--header", action="append")
    request.add_argument("--cookie", action="append")
    request.add_argument("--param", action="append")
    request.add_argument("--data")
    request.add_argument("--timeout", type=positive_float)
    request.add_argument("--rate", type=positive_float)
    request.add_argument("--dry-run", action="store_true")
    add_run_budget_arguments(request)
    request.set_defaults(func=cmd_request)

    recon = sub.add_parser("recon")
    recon.add_argument("program")
    recon.add_argument("--target", required=True)
    recon.set_defaults(func=cmd_recon)

    scan = sub.add_parser("scan")
    scan_sub = scan.add_subparsers(required=True)
    nuclei = scan_sub.add_parser("nuclei")
    nuclei.add_argument("program")
    nuclei.add_argument("--severity", default="low,medium,high,critical")
    nuclei.set_defaults(func=cmd_scan_nuclei)

    fuzz = sub.add_parser("fuzz")
    fuzz.add_argument("program")
    fuzz.add_argument("--url", required=True)
    fuzz.add_argument("--wordlist", required=True, type=Path)
    fuzz.add_argument("--threads", type=positive_int)
    fuzz.add_argument("--timeout", type=positive_int)
    fuzz.add_argument("--rate", type=positive_float)
    fuzz.add_argument("--max-tests", type=positive_int, help="Maximum total requests, including the baseline probe")
    fuzz.add_argument("--max-seconds", type=positive_float, help="Maximum wall-clock time for baseline plus ffuf")
    fuzz.add_argument("--match-codes", default="200,204,301,302,307,401,403,405,500")
    fuzz.add_argument("--filter-size")
    fuzz.add_argument("--dry-run", action="store_true")
    fuzz.add_argument(
        "--confirm", action="store_true", help="Authorize the bounded active run after reviewing its plan"
    )
    add_run_budget_arguments(fuzz)
    fuzz.set_defaults(func=cmd_fuzz)

    fuzz_plan = sub.add_parser(
        "fuzz-plan",
        help="Offline context-aware discovery plan from a local HAR (no downloads, no fuzz execution)",
    )
    fuzz_plan.add_argument("program")
    capture_source = fuzz_plan.add_mutually_exclusive_group(required=True)
    capture_source.add_argument("--har", type=Path, help="Local HAR capture to analyze offline")
    capture_source.add_argument(
        "--capture",
        type=Path,
        help="Local HAR, Burp XML, or raw HTTP request capture (format auto-detected or set with --format)",
    )
    fuzz_plan.add_argument(
        "--format",
        dest="capture_format",
        choices=["auto", "har", "burp-xml", "raw-http"],
        default="auto",
        help="Capture format for --capture (default: auto-detect; mismatches are rejected)",
    )
    fuzz_plan.add_argument(
        "--response",
        type=Path,
        help="Raw HTTP response explicitly paired with a single --capture raw request (never inferred)",
    )
    fuzz_plan.add_argument(
        "--origin",
        help="Explicit http(s)://host[:port] origin for a raw HTTP request; must agree with its Host header",
    )
    fuzz_plan.add_argument(
        "--category",
        choices=list(DISCOVERY_CATEGORIES),
        help="Limit recommendations to one discovery category",
    )
    fuzz_plan.add_argument("--max-tests", type=positive_int, help="Per-target request budget including one baseline")
    fuzz_plan.add_argument(
        "--max-targets",
        type=positive_int,
        default=40,
        help="Maximum planned FUZZ targets (default 40)",
    )
    fuzz_plan.add_argument("--registry", type=Path, help="Override the per-user wordlist collection registry")
    fuzz_plan.add_argument(
        "--ranking",
        choices=["filename", "content"],
        default="filename",
        help="Wordlist ranking: filename (default, historical) or opt-in bounded content sampling",
    )
    fuzz_plan.add_argument(
        "--object-candidates",
        type=Path,
        help="Optional object-candidates JSON for structural endpoint association (never confirms ownership)",
    )
    fuzz_plan.add_argument("--object-key", type=Path, help="Optional local HMAC key used when associating object refs")
    fuzz_plan.add_argument("--output", type=Path, help="Write the redacted plan JSON to this path")
    fuzz_plan.add_argument("--strict", action="store_true", help="Reject the HAR if any entry fails validation")
    fuzz_plan.add_argument(
        "--allow-truncate",
        action="store_true",
        help="Opt in to analyzing only the first 32 entries of an over-cap HAR",
    )
    fuzz_plan.add_argument(
        "--dry-run",
        action="store_true",
        help="Preview the plan without writing evidence or investigation memory",
    )
    fuzz_plan.set_defaults(func=cmd_fuzz_plan)

    wordlists = sub.add_parser("wordlists", help="Manage local wordlist collections offline")
    wordlists_sub = wordlists.add_subparsers(dest="wordlists_action", required=True)
    wordlists_scan = wordlists_sub.add_parser("scan", help="Detect common local wordlist collection directories")
    wordlists_scan.add_argument("--registry", type=Path, help="Override the per-user collection registry")
    wordlists_scan.add_argument("--dry-run", action="store_true", help="Show detected collections without saving")
    wordlists_scan.set_defaults(func=cmd_wordlists)
    wordlists_register = wordlists_sub.add_parser("register", help="Register a local collection directory")
    wordlists_register.add_argument("name")
    wordlists_register.add_argument("path", type=Path)
    wordlists_register.add_argument("--category", choices=WORDLIST_CATEGORIES)
    wordlists_register.add_argument("--registry", type=Path, help="Override the per-user collection registry")
    wordlists_register.set_defaults(func=cmd_wordlists)
    wordlists_list = wordlists_sub.add_parser("list", help="List registered collections and supported files")
    wordlists_list.add_argument("--registry", type=Path, help="Override the per-user collection registry")
    wordlists_list.set_defaults(func=cmd_wordlists)
    wordlists_inspect = wordlists_sub.add_parser("inspect", help="Stream-count and preview one wordlist")
    wordlists_inspect.add_argument("path", type=Path)
    wordlists_inspect.add_argument("--rate", type=positive_float, default=1.0)
    wordlists_inspect.add_argument("--warning-mib", type=positive_int, default=1024)
    wordlists_inspect.set_defaults(func=cmd_wordlists)
    wordlists_recommend = wordlists_sub.add_parser("recommend", help="Recommend registered lists by category")
    wordlists_recommend.add_argument(
        "--category", "--context", dest="category", required=True, choices=WORDLIST_CATEGORIES[:-1]
    )
    wordlists_recommend.add_argument("--registry", type=Path, help="Override the per-user collection registry")
    wordlists_recommend.set_defaults(func=cmd_wordlists)
    wordlists_prepare = wordlists_sub.add_parser("prepare", help="Combine, deduplicate and cap local lists")
    wordlists_prepare.add_argument("--category", required=True, choices=WORDLIST_CATEGORIES[:-1])
    wordlists_prepare.add_argument("--max-entries", type=positive_int, required=True)
    wordlists_prepare.add_argument("--rate", type=positive_float, default=1.0)
    wordlists_prepare.add_argument("--output", type=Path, help="Output path; defaults to the per-user cache")
    wordlists_prepare.add_argument("--force", action="store_true", help="Replace an existing prepared file")
    wordlists_prepare.add_argument("--dry-run", action="store_true", help="Estimate the prepared file without writing")
    wordlists_prepare.add_argument("--registry", type=Path, help="Override the per-user collection registry")
    wordlists_prepare.set_defaults(func=cmd_wordlists)

    xss = sub.add_parser("xss")
    xss.add_argument("program")
    xss.add_argument("--routes", type=Path)
    xss.add_argument("--parameters", type=Path)
    xss.add_argument("--base-url")
    xss.add_argument("--header", action="append")
    xss.add_argument("--cookie", action="append")
    xss.add_argument("--timeout", type=positive_float)
    xss.add_argument("--rate", type=positive_float)
    xss.add_argument("--max-tests", type=positive_int)
    xss.add_argument("--html-parser", choices=("html.parser", "lxml", "html5lib"), default="html.parser")
    xss.add_argument(
        "--confirm-exec",
        action="store_true",
        help="Opt in to headless Playwright confirmation for possible reflected payloads",
    )
    xss.add_argument(
        "--dom-local",
        action="store_true",
        help="Opt-in query/hash DOM checks on literal loopback IP fixtures only",
    )
    xss.add_argument(
        "--stored-local",
        action="store_true",
        help="Opt-in stored XSS write→store→render lab on literal loopback only",
    )
    xss.add_argument("--stored-write-url", help="Loopback URL that accepts the stored write")
    xss.add_argument("--stored-render-url", help="Loopback URL that renders the stored value")
    xss.add_argument("--stored-parameter", default="content", help="Form/query parameter for stored write")
    xss.add_argument(
        "--capture-review",
        type=Path,
        help="Offline JSON of captured exchanges to recommend XSS review (no new requests)",
    )
    xss.add_argument(
        "--no-enrich-context",
        action="store_true",
        help="Disable additive reflected context enrichment on XSS results",
    )
    xss.add_argument("--dry-run", action="store_true")
    add_run_budget_arguments(xss)
    add_ai_review_arguments(xss)
    xss.set_defaults(func=cmd_xss)

    sqli = sub.add_parser("sqli", help="Bounded baseline/quote probes; --deep opts into timing and boolean probes")
    sqli.add_argument("program")
    sqli.add_argument("--routes", required=True, type=Path)
    sqli.add_argument("--parameters", required=True, type=Path)
    sqli.add_argument("--base-url")
    sqli.add_argument("--header", action="append")
    sqli.add_argument("--cookie", action="append")
    sqli.add_argument("--timeout", type=positive_float)
    sqli.add_argument("--rate", type=positive_float)
    sqli.add_argument("--max-tests", type=positive_int)
    sqli.add_argument(
        "--deep", action="store_true", help="Add three delay and two boolean probes per complete parameter group"
    )
    sqli.add_argument(
        "--union",
        action="store_true",
        help="Opt in to bounded ORDER BY column-count and one UNION SELECT NULL comparison",
    )
    sqli.add_argument(
        "--union-max-columns",
        type=positive_int,
        default=5,
        help="Maximum ORDER BY positions to test with --union (1-8; default: 5)",
    )
    sqli.add_argument("--dry-run", action="store_true")
    add_run_budget_arguments(sqli)
    add_ai_review_arguments(sqli)
    sqli.set_defaults(func=cmd_sqli)

    cors = sub.add_parser("cors-check", help="Check CORS response headers for a supplied in-scope URL")
    cors.add_argument("program")
    cors.add_argument("--url", required=True)
    cors.add_argument("--header", action="append")
    cors.add_argument("--cookie", action="append")
    cors.add_argument("--timeout", type=positive_float)
    cors.add_argument("--rate", type=positive_float)
    cors.add_argument("--dry-run", action="store_true")
    add_run_budget_arguments(cors)
    add_ai_review_arguments(cors)
    cors.set_defaults(func=cmd_cors_check)

    ssrf = sub.add_parser("ssrf-check", help="Compare a supplied URL parameter against bounded SSRF indicators")
    ssrf.add_argument("program")
    ssrf.add_argument("--url", required=True)
    ssrf.add_argument("--param", required=True)
    ssrf.add_argument("--header", action="append")
    ssrf.add_argument("--cookie", action="append")
    ssrf.add_argument("--timeout", type=positive_float)
    ssrf.add_argument("--rate", type=positive_float)
    ssrf.add_argument("--dry-run", action="store_true")
    add_run_budget_arguments(ssrf)
    add_ai_review_arguments(ssrf)
    ssrf.set_defaults(func=cmd_ssrf_check)

    redirect = sub.add_parser("open-redirect", help="Check a supplied in-scope URL parameter for external redirects")
    redirect.add_argument("program")
    redirect.add_argument("--url", required=True)
    redirect.add_argument("--param", required=True)
    redirect.add_argument("--header", action="append")
    redirect.add_argument("--cookie", action="append")
    redirect.add_argument("--timeout", type=positive_float)
    redirect.add_argument("--rate", type=positive_float)
    redirect.add_argument("--dry-run", action="store_true")
    add_run_budget_arguments(redirect)
    add_ai_review_arguments(redirect)
    redirect.set_defaults(func=cmd_open_redirect)

    hunt = sub.add_parser(
        "hunt",
        help="Run a scoped, sequential multi-check workflow under one shared request budget",
    )
    hunt.add_argument("program")
    hunt.add_argument("--base-url", required=True)
    hunt.add_argument("--routes", type=Path, help="User-supplied route list used by XSS and SQLi")
    hunt.add_argument("--params", type=Path, help="User-supplied parameter names for redirects, XSS and SQLi")
    hunt.add_argument("--case-file", type=Path, help="Known-resource access comparison case")
    hunt.add_argument("--csrf-url", help="Form URL to audit; defaults to --base-url")
    hunt.add_argument("--ssrf-url", help="Explicit URL with a user-controlled parameter for SSRF comparison")
    hunt.add_argument("--ssrf-param", help="Parameter name paired with --ssrf-url; SSRF is otherwise skipped")
    hunt.add_argument(
        "--confirm-exec",
        action="store_true",
        help="Use Playwright for possible XSS reflections and include context-specific probes",
    )
    hunt.add_argument("--deep", action="store_true", help="Enable SQLi timing and boolean probes")
    hunt.add_argument("--union", action="store_true", help="Enable bounded SQLi ORDER BY/UNION NULL probes")
    hunt.add_argument("--union-max-columns", type=positive_int, default=5)
    hunt.add_argument("--max-tests", type=positive_int, help="Global target-request cap (default: program setting)")
    hunt.add_argument("--only", help="Comma-separated modules to run")
    hunt.add_argument("--skip", help="Comma-separated modules to omit")
    hunt.add_argument("--dry-run", action="store_true", help="Validate the complete plan without HTTP requests")
    hunt.add_argument("--resume", action="store_true", help="Resume a saved run with identical inputs and scope")
    add_run_budget_arguments(hunt)
    add_ai_review_arguments(hunt)
    hunt.set_defaults(func=cmd_hunt)

    csrf = sub.add_parser("csrf-audit", help="Heuristically inspect one in-scope HTML response for CSRF defenses")
    csrf.add_argument("program")
    csrf.add_argument("--url", required=True)
    csrf.add_argument("--header", action="append")
    csrf.add_argument("--cookie", action="append")
    csrf.add_argument("--timeout", type=positive_float)
    csrf.add_argument("--rate", type=positive_float)
    csrf.add_argument("--dry-run", action="store_true")
    add_run_budget_arguments(csrf)
    add_ai_review_arguments(csrf)
    csrf.set_defaults(func=cmd_csrf_audit)

    apk_scan = sub.add_parser(
        "apk-scan", help="Scan a local APK archive for endpoints, secret patterns and Android deep links"
    )
    apk_scan.add_argument("program")
    apk_scan.add_argument("--apk", required=True, type=Path)
    apk_scan.add_argument(
        "--decompile",
        action="store_true",
        help="Opt in to local jadx/apktool parsing in a temporary directory (120-second limit)",
    )
    apk_scan.add_argument(
        "--dry-run", action="store_true", help="Validate the APK archive without scanning its contents"
    )
    add_ai_review_arguments(apk_scan)
    apk_scan.set_defaults(func=cmd_apk_scan)

    takeover = sub.add_parser(
        "takeover-check",
        help="Match an in-scope host's CNAME to local provider signatures; no HTTP or claim attempts",
    )
    takeover.add_argument("program")
    takeover.add_argument("--host", required=True, help="In-scope subdomain hostname")
    takeover.add_argument(
        "--cname", action="append", help="Captured CNAME target for offline signature matching (repeatable)"
    )
    takeover.add_argument(
        "--resolve-dns", action="store_true", help="Opt in to one scoped CNAME lookup using optional dnspython"
    )
    takeover.add_argument("--dry-run", action="store_true", help="Validate scope and inputs without DNS queries")
    takeover.set_defaults(func=cmd_takeover_check)

    lab = sub.add_parser("lab", help="Run deterministic local security labs; traffic never leaves loopback")
    lab_sub = lab.add_subparsers(dest="lab_name", required=True)
    lab_idor = lab_sub.add_parser("idor", help="Run the local IDOR/BOLA end-to-end demonstration")
    lab_idor.add_argument("--dry-run", action="store_true", help="Print the exact local workflow without running it")
    lab_idor.set_defaults(func=cmd_lab_idor)
    lab_web = lab_sub.add_parser("web-vuln", help="Run the local XSS/SQLi evidence-to-report demonstration")
    lab_web.add_argument(
        "--dry-run", action="store_true", help="Print the workflow without starting the fixture server"
    )
    lab_web.set_defaults(func=cmd_lab_web_vuln)
    lab_object = lab_sub.add_parser(
        "object-discover",
        help="Run the synthetic offline object-discovery efficacy lab (ranking metrics only)",
    )
    lab_object.add_argument(
        "--split",
        choices=("dev", "eval", "all"),
        default="eval",
        help="Corpus split; eval is the holdout and must not be used to tune rules",
    )
    lab_object.add_argument("--limit", type=positive_int, default=10, help="Max handoff proposals ranked, 1-64")
    lab_object.add_argument(
        "--corpus-root",
        type=Path,
        help="Override labs/object_discovery_lab path (tests only)",
    )
    lab_object.add_argument("--metrics-json", type=Path, help="Optional metrics JSON output path")
    lab_object.add_argument("--force", action="store_true", help="Replace metrics JSON if it exists")
    lab_object.add_argument(
        "--dry-run",
        action="store_true",
        help="Compute metrics in memory; write metrics only if --metrics-json is set",
    )
    lab_object.set_defaults(func=cmd_lab_object_discover)

    lab_ledger = lab_sub.add_parser(
        "evidence-ledger", help="Run the synthetic offline evidence-ledger integrity lab (no network)"
    )
    lab_ledger.add_argument("--metrics-json", type=Path, help="Optional metrics JSON output path")
    lab_ledger.add_argument("--force", action="store_true", help="Replace metrics JSON if it exists")
    lab_ledger.set_defaults(func=cmd_lab_evidence_ledger)

    lab_egp = lab_sub.add_parser(
        "evidence-gap", help="Run the synthetic offline evidence-gap planner evaluation lab (no network)"
    )
    lab_egp.add_argument("--split", choices=("dev", "final", "both"), default="both")
    lab_egp.add_argument("--metrics-json", type=Path, help="Optional metrics JSON output path")
    lab_egp.set_defaults(func=cmd_lab_evidence_gap)

    access = sub.add_parser(
        "access-check", help="Known-resource authorization comparison; bounded read and disposable JSON write modes"
    )
    access.add_argument("program")
    access.add_argument(
        "--case-file", required=True, type=Path, help="Private JSON case and separate raw owner/actor requests"
    )
    access.add_argument(
        "--range", dest="id_range", help="One numeric interval; non-loopback targets remain sequential and capped"
    )
    access.add_argument(
        "--max-range", type=positive_int, help="Maximum IDs in --range (default 25; loopback hard cap 100)"
    )
    access.add_argument("--concurrency", type=positive_int, help="Range workers (default 1; loopback hard cap 4)")
    access.add_argument(
        "--min-interval",
        type=positive_float,
        help="Minimum seconds between starts (public relaxed default 1; otherwise 10; loopback minimum 0.01)",
    )
    access.add_argument(
        "--allow-public-range",
        action="store_true",
        help="Opt in to up to 100 public range probes, four workers and a one-second minimum interval",
    )
    access.add_argument(
        "--lab-write",
        action="store_true",
        help="Run one JSON-body POST/PUT/PATCH A/B comparison; public targets require --allow-public-writes",
    )
    access.add_argument(
        "--allow-public-writes",
        action="store_true",
        help="Opt in to state-changing write comparisons on in-scope non-loopback hosts",
    )
    access.add_argument("--lab-write-range", help="With --lab-write, sweep one numeric JSON-body ID interval")
    access.add_argument(
        "--anonymous-check", action="store_true", help="After the normal crossed GET, repeat it without session headers"
    )
    access.add_argument(
        "--inverse-cross", action="store_true", help="Also check the owner session against the actor's private resource"
    )
    access.add_argument(
        "--multi-account",
        action="store_true",
        help="Build the complete read-access matrix for owner, actor and additional_accounts",
    )
    access.add_argument(
        "--function-matrix",
        action="store_true",
        help="Run a read-only role/function matrix from exact supplied GET captures (BFLA triage)",
    )
    access.add_argument(
        "--verify-persistence", action="store_true", help="After the crossed write, read back a declared changed field"
    )
    access.add_argument(
        "--inverse-write", action="store_true", help="Also write the actor resource using the owner's session"
    )
    access.add_argument(
        "--cleanup", action="store_true", help="Restore original write bodies and verify each with a final GET"
    )
    access.add_argument("--timeout", type=positive_float)
    access.add_argument("--rate", type=positive_float)
    access.add_argument("--max-tests", type=positive_int)
    access.add_argument("--dry-run", action="store_true")
    add_run_budget_arguments(access)
    add_ai_review_arguments(access)
    access.set_defaults(func=cmd_access_check)

    resources = sub.add_parser("resources", help="Offline tool/library availability and official resource catalog")
    resources.add_argument("--output", type=Path)
    resources.set_defaults(func=cmd_resources)

    analyze = sub.add_parser("analyze", help="Analyze local HTML, SQL, JWT or native evidence")
    analyze_sub = analyze.add_subparsers(dest="analysis", required=True)
    html = analyze_sub.add_parser("html")
    html.add_argument("--input", required=True, type=Path)
    html.add_argument("--marker", required=True)
    html.add_argument("--parser", choices=("html.parser", "lxml", "html5lib"), default="html.parser")
    html.add_argument("--output", type=Path)
    html.set_defaults(func=cmd_analyze)
    sql = analyze_sub.add_parser("sql")
    sql.add_argument("--input", required=True, type=Path)
    sql.add_argument("--output", type=Path)
    sql.set_defaults(func=cmd_analyze)
    jwt = analyze_sub.add_parser("jwt")
    jwt.add_argument(
        "--input", required=True, type=Path, help="Local compact JWS token; never pass a token on the command line"
    )
    jwt.add_argument("--key-file", type=Path)
    jwt.add_argument("--algorithm", choices=ALGORITHMS)
    jwt.add_argument("--issuer")
    jwt.add_argument("--audience")
    jwt.add_argument("--output", type=Path)
    jwt.set_defaults(func=cmd_analyze)

    jwt_forge = sub.add_parser(
        "jwt-forge",
        help="Generate offline JWT test candidates; never sends requests or confirms server acceptance",
    )
    jwt_forge.add_argument(
        "--input", required=True, type=Path, help="Local compact JWT file; never pass tokens in chat"
    )
    jwt_forge.add_argument(
        "--secret",
        help="Optional local test secret; also generates candidates for secret, 123456 and password (not echoed)",
    )
    jwt_forge.add_argument(
        "--public-key", type=Path, help="Optional local PEM public key/certificate for RS256-to-HS256 candidates"
    )
    jwt_forge.add_argument("--output", type=Path, help="Save generated candidate tokens to a local JSON file")
    jwt_forge.set_defaults(func=cmd_jwt_forge)
    disclosure = analyze_sub.add_parser(
        "disclosure",
        help="Offline information-disclosure indicators in stored responses; never confirms, never sends requests",
    )
    disclosure.add_argument(
        "--input",
        required=True,
        type=Path,
        help="Local JSON with stored response records (see docs/information-disclosure.md)",
    )
    disclosure.add_argument(
        "--output", type=Path, help="Write the minimized summary (no secret values) to a local file"
    )
    disclosure.set_defaults(func=cmd_analyze)
    disclosure_access = analyze_sub.add_parser(
        "disclosure-access",
        help="Offline correlate disclosure indicators with IDOR/access evidence; never confirms, never sends requests",
    )
    disclosure_access.add_argument(
        "--input",
        required=True,
        type=Path,
        help="Local JSON with owner/actor/cross correlation cases (see docs/disclosure-access-correlation.md)",
    )
    disclosure_access.add_argument(
        "--output", type=Path, help="Write the minimized correlation summary (no secret values) to a local file"
    )
    disclosure_access.set_defaults(func=cmd_analyze)
    evidence = analyze_sub.add_parser("evidence", help="Allowlisted observations with optional local Ollama review")
    evidence.add_argument("--input", required=True, type=Path)
    evidence.add_argument("--output", type=Path)
    evidence.add_argument("--ai", choices=("ollama", "lmstudio"), help="Optional allowlisted local provider")
    evidence.add_argument(
        "--model",
        help=f"Installed local Ollama model name (default: {DEFAULT_OLLAMA_MODEL})",
    )
    evidence.add_argument("--ai-timeout", type=positive_float, default=120)
    evidence.set_defaults(func=cmd_analyze)

    tool_plan = sub.add_parser("tool-plan", help="Prepare a private scanner command; NEVER executes it")
    tool_plan.add_argument("program")
    tool_plan.add_argument("--tool", choices=TOOLS, required=True)
    tool_plan.add_argument("--url", required=True)
    tool_plan.add_argument("--parameter", required=True)
    tool_plan.add_argument(
        "--script", type=Path, help="Reviewed sqlmap.py or xsstrike.py; Dalfox plans target version 3"
    )
    tool_plan.add_argument("--dry-run", action="store_true")
    tool_plan.set_defaults(func=cmd_tool_plan)

    params = sub.add_parser("params")
    params.add_argument("program")
    params.add_argument("--url", required=True)
    params.set_defaults(func=cmd_params)

    checklist = sub.add_parser("checklist")
    checklist.add_argument("program")
    checklist.set_defaults(func=cmd_checklist)

    reviewed = sub.add_parser("mark-reviewed")
    reviewed.add_argument("program")
    reviewed.add_argument("--kind", required=True)
    reviewed.add_argument("--value", required=True)
    reviewed.add_argument("--note")
    reviewed.set_defaults(func=cmd_mark_reviewed)

    finding = sub.add_parser("add-finding")
    finding.add_argument("program")
    finding.add_argument("--finding-id", required=True)
    finding.add_argument("--title", required=True)
    finding.add_argument("--category", required=True)
    finding.add_argument("--severity", required=True)
    finding.add_argument("--target", required=True)
    finding.add_argument("--summary", required=True)
    finding.add_argument("--evidence")
    finding.set_defaults(func=cmd_add_finding)

    report = sub.add_parser("report")
    report.add_argument("program")
    report.add_argument("--finding-id")
    report.add_argument("--format", choices=["html", "json", "markdown", "pdf"])
    report.add_argument("--evidence-file", type=Path, help="Create a redacted review report from native JSON evidence")
    report.add_argument("--output", type=Path, help="Optional destination for an evidence review draft")
    report.add_argument("--force", action="store_true", help="Replace an existing evidence or finding report")
    report.add_argument(
        "--draft-with-ai", action="store_true", help="Ask local Ollama for an optional evidence-based Markdown draft"
    )
    report.add_argument("--ai-model", help=f"Local Ollama model for --draft-with-ai (default: {DEFAULT_OLLAMA_MODEL})")
    report.add_argument("--ai-timeout", type=positive_float, help="Local Ollama timeout in seconds (default: 120)")
    _add_ai_provider_arguments(report)
    report.set_defaults(func=cmd_report)

    import_parser = sub.add_parser("import", help="Import supported local artifacts into one program's inputs")
    import_sub = import_parser.add_subparsers(required=True)
    burp_import = import_sub.add_parser(
        "burp", help="Import Burp sitemap XML, raw requests or saved HTTP items; never sends requests"
    )
    burp_import.add_argument("program")
    burp_source = burp_import.add_mutually_exclusive_group(required=True)
    burp_source.add_argument("--sitemap", type=Path, help="Burp XML sitemap export")
    burp_source.add_argument("--request", type=Path, help="Raw HTTP request exported from Burp")
    burp_source.add_argument("--item", type=Path, help="Saved Burp item XML or raw HTTP response")
    burp_import.add_argument("--base-url", help="Relativize same-origin sitemap URLs or resolve request targets")
    burp_import.add_argument("--dry-run", action="store_true", help="List planned local files without writing")
    burp_import.add_argument("--force", action="store_true", help="Replace existing imported files")
    burp_import.set_defaults(func=cmd_import_burp)

    discovery_import = import_sub.add_parser(
        "discover-idor", help="Propose known-resource IDOR/BOLA cases from two local captures; no HTTP traffic"
    )
    discovery_import.add_argument("program")
    discovery_import.add_argument("--owner", type=Path, required=True, help="Account A raw request or Burp XML items")
    discovery_import.add_argument("--actor", type=Path, required=True, help="Account B raw request or Burp XML items")
    discovery_import.add_argument("--owner-response", type=Path, help="Paired HTTP response for one raw owner request")
    discovery_import.add_argument("--actor-response", type=Path, help="Paired HTTP response for one raw actor request")
    discovery_import.add_argument(
        "--base-url", help="Actual captured origin for raw relative requests; not a host override"
    )
    discovery_import.add_argument(
        "--attest-authorized-accounts",
        action="store_true",
        help="Record account authorization; approval still requires explicit ownership/private-resource review",
    )
    discovery_import.add_argument(
        "--output-dir",
        type=Path,
        help="New private bundle directory; defaults to registros/<program>/private/idor-discovery",
    )
    discovery_import.add_argument(
        "--dry-run", action="store_true", help="Print count-only candidate summary; create no files"
    )
    discovery_import.set_defaults(func=cmd_import_discover_idor)

    approval_import = import_sub.add_parser(
        "approve-idor", help="Convert an explicitly reviewed private proposal to a native access-check case offline"
    )
    approval_import.add_argument("program")
    approval_import.add_argument("--proposal", type=Path, required=True)
    approval_import.add_argument("--candidate", required=True, help="Reviewed candidate ID, such as candidate-001")
    approval_import.add_argument(
        "--approve",
        action="store_true",
        required=True,
        help="Explicitly approve the completed researcher review; never sends HTTP requests",
    )
    approval_import.add_argument(
        "--dry-run", action="store_true", help="Validate reviewed inputs without creating a case"
    )
    approval_import.set_defaults(func=cmd_import_approve_idor)

    case_import = import_sub.add_parser(
        "case", help="Generate a private access-check read case from two local Burp captures; never sends requests"
    )
    case_import.add_argument("program")
    case_import.add_argument(
        "--owner", type=Path, required=True, help="Raw GET capture for account A and its own resource"
    )
    case_import.add_argument(
        "--actor", type=Path, required=True, help="Raw GET capture for account B and its own resource"
    )
    case_import.add_argument("--base-url", help="Origin for relative request targets; defaults to HTTPS when omitted")
    case_import.add_argument(
        "--resource-pointer",
        required=True,
        help="JSON pointer to the resource ID in a response (syntax checked offline)",
    )
    case_import.add_argument("--success-pointer", required=True, help="JSON pointer to the successful-response field")
    case_import.add_argument(
        "--success-value", required=True, help='Expected success scalar as JSON, e.g. true or "ok"'
    )
    case_import.add_argument(
        "--private-pointer", required=True, help="JSON pointer to the private marker in a response"
    )
    case_import.add_argument(
        "--private-marker", required=True, help="Unique marker attested to exist in account A's resource"
    )
    case_import.add_argument(
        "--actor-marker", required=True, help="Unique marker attested to exist in account B's resource"
    )
    case_import.add_argument(
        "--attest-authorized-accounts",
        action="store_true",
        required=True,
        help="Attest that both accounts are yours or explicitly authorized test accounts",
    )
    case_import.add_argument(
        "--attest-private-resource",
        action="store_true",
        required=True,
        help="Attest that the owner's resource is private and the markers are already present",
    )
    case_import.add_argument("--output", type=Path, help="Output path (default: registros/<program>/private/case.json)")
    case_import.add_argument("--dry-run", action="store_true", help="Validate and show the plan without writing")
    case_import.add_argument("--force", action="store_true", help="Replace an existing case.json")
    case_import.set_defaults(func=cmd_import_case)

    evidence_cli = sub.add_parser(
        "evidence", help="Normalize and correlate local evidence from Burp and supported scanner formats"
    )
    evidence_sub = evidence_cli.add_subparsers(dest="evidence_command", required=True)
    evidence_import = evidence_sub.add_parser(
        "import", help="Build a redacted, provenance-preserving evidence bundle; never sends requests"
    )
    evidence_import.add_argument("program")
    evidence_import.add_argument(
        "--input", type=Path, nargs="+", required=True, help="One or more local artifact files"
    )
    evidence_import.add_argument(
        "--har-mode",
        choices=("compat", "partial", "strict"),
        default="compat",
        help="HAR handling: compat keeps historical records and only reports entries the resilient "
        "importer would reject; partial emits only valid entries; strict rejects the file on any invalid entry",
    )
    evidence_import.add_argument(
        "--format",
        choices=(
            "auto",
            "burp-xml",
            "har",
            "ffuf-json",
            "nuclei-json",
            "nuclei-jsonl",
            "toolkit-json",
            "http",
            "html",
            "markdown",
            "text",
            "csv",
        ),
        default="auto",
        help="Input format; auto-detected by default",
    )
    evidence_import.add_argument("--output", type=Path, help="Optional local bundle path")
    evidence_import.add_argument("--dry-run", action="store_true", help="Parse and summarize without writing files")
    evidence_import.add_argument("--force", action="store_true", help="Replace an existing output file")
    evidence_import.set_defaults(func=cmd_evidence_import)

    evidence_correlate = evidence_sub.add_parser(
        "correlate", help="Recompute descriptive endpoint/session/resource groups from a local bundle"
    )
    evidence_correlate.add_argument("program")
    evidence_correlate.add_argument("--input", type=Path, required=True, help="Unified evidence bundle JSON")
    evidence_correlate.add_argument("--output", type=Path, help="Optional local correlation report path")
    evidence_correlate.add_argument("--dry-run", action="store_true", help="Validate and summarize without writing")
    evidence_correlate.add_argument("--force", action="store_true", help="Replace an existing output file")
    evidence_correlate.set_defaults(func=cmd_evidence_correlate)

    api_workflow = sub.add_parser("api-workflow", help="Build an offline API workflow graph from normalized evidence")
    api_workflow.add_argument("program")
    api_workflow.add_argument("--input", type=Path, required=True, help="Unified evidence bundle JSON")
    api_workflow.add_argument("--openapi", type=Path, help="Optional local OpenAPI JSON/YAML document")
    api_workflow.add_argument("--output", type=Path, help="Optional local JSON model path")
    api_workflow.add_argument("--dry-run", action="store_true", help="Validate and summarize without writing")
    api_workflow.add_argument("--force", action="store_true", help="Replace an existing output file")
    api_workflow.set_defaults(func=cmd_api_workflow)

    object_discover = sub.add_parser(
        "object-discover", help="Discover object relationships from authorized local captures, fully offline"
    )
    object_discover.add_argument("program")
    object_discover.add_argument(
        "--input",
        type=Path,
        action="append",
        required=True,
        help="Burp XML, raw HTTP or HAR; repeat for multiple files",
    )
    object_discover.add_argument("--base-url", help="Captured origin for raw HTTP without an absolute URL")
    object_discover.add_argument("--key-file", type=Path, help="Private mode-0600 local HMAC key (created if absent)")
    object_discover.add_argument("--output", type=Path, help="Private graph JSON destination")
    object_discover.add_argument(
        "--attest-authorized-captures",
        action="store_true",
        help="Declare authorization to analyze these captures, not to perform active tests",
    )
    object_discover.add_argument(
        "--dry-run", action="store_true", help="Summarize without creating a key, graph, DB or directories"
    )
    object_discover.add_argument("--force", action="store_true", help="Atomically replace the graph output only")
    object_discover.add_argument(
        "--strict",
        action="store_true",
        help="Reject a whole HAR file if any entry is invalid (default: isolate invalid entries)",
    )
    object_discover.add_argument(
        "--allow-truncate",
        action="store_true",
        help="Analyze only the first 32 HAR entries of an over-cap file and flag truncated (default: reject file)",
    )
    object_discover.set_defaults(func=cmd_object_discover)

    object_candidates_cli = sub.add_parser(
        "object-candidates", help="Rank offline object references for researcher review, without executing cases"
    )
    object_candidates_cli.add_argument("program")
    object_candidates_cli.add_argument(
        "--graph", type=Path, required=True, help="Versioned signed graph from object-discover"
    )
    object_candidates_cli.add_argument("--key-file", type=Path, help="Same local HMAC key used for discovery")
    object_candidates_cli.add_argument(
        "--verify-input",
        type=Path,
        action="append",
        default=[],
        help="Verify exact source commitments; repeat for all source captures",
    )
    object_candidates_cli.add_argument("--limit", type=positive_int, default=20, help="Candidate count, 1-100")
    object_candidates_cli.add_argument("--min-score", type=int, default=0, help="Minimum investigation priority, 0-100")
    object_candidates_cli.add_argument("--output", type=Path, help="Optional private minimized candidate JSON")
    object_candidates_cli.add_argument(
        "--dry-run", action="store_true", help="Validate and count without writing files"
    )
    object_candidates_cli.add_argument("--force", action="store_true", help="Atomically replace candidate output")
    object_candidates_cli.set_defaults(func=cmd_object_candidates)

    object_handoff_cli = sub.add_parser(
        "object-handoff",
        help="Propose offline owner/actor capture pairs from object candidates; never approves or sends HTTP",
    )
    object_handoff_cli.add_argument("program")
    object_handoff_cli.add_argument(
        "--graph", type=Path, required=True, help="Versioned signed graph from object-discover"
    )
    object_handoff_cli.add_argument("--key-file", type=Path, help="Same local HMAC key used for discovery")
    object_handoff_cli.add_argument(
        "--candidate",
        help="Optional object_ref to filter proposals; without it, rank all pairable candidates",
    )
    object_handoff_cli.add_argument(
        "--verify-input",
        type=Path,
        action="append",
        default=[],
        help="Verify exact source commitments; required to materialize capture pairs",
    )
    object_handoff_cli.add_argument("--base-url", help="Captured origin for raw relative requests")
    object_handoff_cli.add_argument("--limit", type=positive_int, default=20, help="Proposal count, 1-64")
    object_handoff_cli.add_argument("--output", type=Path, help="Optional private handoff proposal JSON destination")
    object_handoff_cli.add_argument(
        "--materialize-dir",
        type=Path,
        help="Private directory for raw HTTP owner/actor snapshots used by discover-idor",
    )
    object_handoff_cli.add_argument(
        "--dry-run",
        action="store_true",
        help="Validate and summarize without writing proposal JSON or capture snapshots",
    )
    object_handoff_cli.add_argument(
        "--request-only",
        action="store_true",
        help="Disable inferred pairing from typed response-only identifiers (request-side pairs only)",
    )
    object_handoff_cli.add_argument("--force", action="store_true", help="Replace existing outputs")
    object_handoff_cli.set_defaults(func=cmd_object_handoff)

    graph_cli = sub.add_parser("graph", help="Persist and search minimized local investigation evidence")
    graph_sub = graph_cli.add_subparsers(dest="graph_command", required=True)
    graph_ingest = graph_sub.add_parser(
        "ingest", help="Add unified evidence and optional hypotheses/attestations to the local SQLite graph"
    )
    graph_ingest.add_argument("program")
    graph_ingest.add_argument("--input", type=Path, required=True, help="Unified evidence bundle JSON")
    graph_ingest.add_argument("--openapi", type=Path, help="Optional local OpenAPI JSON/YAML; documentation only")
    graph_ingest.add_argument("--hypotheses", type=Path, help="Optional ai-hypotheses JSON; opinions remain hypotheses")
    graph_ingest.add_argument("--route", type=Path, help="Optional validated ai route JSON; the plan is never executed")
    graph_ingest.add_argument(
        "--case-file", type=Path, help="Optional private access case; declarations are attestations"
    )
    graph_ingest.add_argument("--access-evidence", type=Path, help="Native access-check evidence; requires --case-file")
    graph_ingest.add_argument("--dry-run", action="store_true", help="Validate and count without creating SQLite files")
    graph_ingest.set_defaults(func=cmd_graph_ingest)

    graph_search = graph_sub.add_parser("search", help="Search graph nodes and their one-hop evidence relations")
    graph_search.add_argument("program")
    graph_search.add_argument("--endpoint", help="Exact API path (numeric/UUID IDs are normalized)")
    graph_search.add_argument("--account", help="Researcher account label; stored as a local pseudonym")
    graph_search.add_argument("--resource", help="Resource ID or imported opaque fingerprint")
    graph_search.add_argument("--category", help="Finding/hypothesis category")
    graph_search.add_argument("--finding-id", help="Exact toolkit finding ID")
    graph_search.add_argument("--limit", type=positive_int, default=50, help="Maximum matching nodes (1-100)")
    graph_search.set_defaults(func=cmd_graph_search)

    ledger_cli = sub.add_parser(
        "ledger", help="Offline evidence verification and coverage ledger for human review (no network)"
    )
    ledger_sub = ledger_cli.add_subparsers(dest="ledger_command", required=True)

    def _ledger_parser(name: str, help_text: str) -> argparse.ArgumentParser:
        parser_ = ledger_sub.add_parser(name, help=help_text)
        if name != "schema":
            parser_.add_argument("program")
            parser_.add_argument(
                "--ledger", type=Path, help="Ledger path (default: <program>/ledger/evidence-ledger.json)"
            )
        return parser_

    ledger_schema = _ledger_parser("schema", "Print the versioned ledger JSON schema")
    ledger_schema.set_defaults(func=cmd_ledger_schema)
    ledger_init = _ledger_parser("init", "Create an empty ledger for a program")
    ledger_init.set_defaults(func=cmd_ledger_init)
    ledger_surface = _ledger_parser("surface", "Record or update a surface's coverage status")
    ledger_surface.add_argument("--id", required=True)
    ledger_surface.add_argument(
        "--kind", required=True, choices=("endpoint", "workflow", "source_file", "component", "asset")
    )
    ledger_surface.add_argument("--ref", required=True, help="Path, workflow or file reference")
    ledger_surface.add_argument("--status", required=True, choices=ledger_mod.SURFACE_STATUSES)
    ledger_surface.add_argument("--blocker", help="Required for pending/blocked")
    ledger_surface.add_argument("--reason", help="Required for out_of_scope")
    ledger_surface.add_argument("--fingerprint", help="Code/surface revision; changes invalidate older evidence")
    ledger_surface.add_argument("--investigation-id")
    ledger_surface.add_argument("--notes")
    ledger_surface.set_defaults(func=cmd_ledger_surface)
    ledger_evidence = _ledger_parser("evidence", "Register a local evidence file with digest and provenance")
    ledger_evidence.add_argument("--id", required=True)
    ledger_evidence.add_argument("--path", required=True, help="Program-relative evidence path")
    ledger_evidence.add_argument("--tool", required=True, help="Producing tool or manual source")
    ledger_evidence.add_argument("--surface-fingerprint")
    ledger_evidence.add_argument("--bundle-id")
    ledger_evidence.add_argument("--investigation-id")
    ledger_evidence.add_argument("--graph-node", action="append", help="Evidence Graph node ID (repeatable)")
    ledger_evidence.set_defaults(func=cmd_ledger_evidence)
    ledger_candidate = _ledger_parser("candidate", "Raise a candidate (always starts as 'candidate')")
    ledger_candidate.add_argument("--id", required=True)
    ledger_candidate.add_argument("--surface", required=True)
    ledger_candidate.add_argument("--category", required=True)
    ledger_candidate.add_argument("--raised-by", required=True)
    ledger_candidate.add_argument("--evidence", action="append", help="Evidence ID (repeatable)")
    ledger_candidate.add_argument("--title")
    ledger_candidate.add_argument("--dedup-key")
    ledger_candidate.add_argument("--finding-id", help="Existing toolkit finding ID")
    ledger_candidate.set_defaults(func=cmd_ledger_candidate)
    ledger_import = _ledger_parser("import", "Register native tool evidence; positive labels become candidates only")
    ledger_import.add_argument("--evidence-path", required=True, help="Program-relative native evidence JSON")
    ledger_import.add_argument("--surface", required=True)
    ledger_import.add_argument("--raised-by", default="bbtk-import")
    ledger_import.set_defaults(func=cmd_ledger_import)
    ledger_review = _ledger_parser("review", "Apply one human review decision to a candidate")
    ledger_review.add_argument("--id", required=True)
    ledger_review.add_argument("--state", required=True, choices=ledger_mod.CANDIDATE_STATES)
    ledger_review.add_argument(
        "--reviewer", required=True, help="Human reviewer; must differ from raised_by to confirm"
    )
    ledger_review.add_argument("--method", choices=ledger_mod.REVIEW_METHODS)
    ledger_review.add_argument("--basis", help="Observed, reproducible basis for the decision")
    ledger_review.add_argument("--reason", choices=ledger_mod.REJECTION_REASONS, help="Rejection reason")
    ledger_review.add_argument("--detail", help="Rejection detail")
    ledger_review.add_argument("--blocker", action="append", help="Unresolved fact (requires_validation)")
    ledger_review.add_argument("--duplicate-of")
    ledger_review.add_argument(
        "--i-reviewed-the-evidence", action="store_true", help="Explicit human attestation; required to confirm"
    )
    ledger_review.set_defaults(func=cmd_ledger_review)
    ledger_validate = _ledger_parser("validate", "Validate schema, references, states and evidence digests")
    ledger_validate.set_defaults(func=cmd_ledger_validate)
    ledger_report = _ledger_parser("report", "Render a Markdown coverage and review report")
    ledger_report.add_argument("--output", type=Path)
    ledger_report.add_argument("--force", action="store_true")
    ledger_report.set_defaults(func=cmd_ledger_report)

    investigation_cli = sub.add_parser(
        "investigation", help="Close, inspect, or plan next offline investigation steps without deleting history"
    )
    investigation_sub = investigation_cli.add_subparsers(dest="investigation_command", required=True)
    investigation_close = investigation_sub.add_parser("close", help="Close an active saved investigation")
    investigation_close.add_argument("program")
    investigation_close.add_argument("--id", dest="investigation_id", required=True)
    investigation_close.set_defaults(func=cmd_investigation_close)
    investigation_status = investigation_sub.add_parser("status", help="Show saved investigation state and events")
    investigation_status.add_argument("program")
    investigation_status.add_argument("--id", dest="investigation_id", required=True)
    investigation_status.set_defaults(func=cmd_investigation_status)

    investigation_next = investigation_sub.add_parser(
        "next-steps",
        help="Opt-in evidence-gap next-step plan (read-only, offline, no AI, no execution)",
    )
    investigation_next.add_argument("program")
    investigation_next.add_argument(
        "--ledger", type=Path, help="Ledger path (default: <program>/ledger/evidence-ledger.json)"
    )
    investigation_next.add_argument("--dry-run", action="store_true", help="Emphasize that steps are not executable")
    investigation_next.add_argument("--minimize", action="store_true", help="Emit minimized JSON")
    investigation_next.add_argument("--schema", action="store_true", help="Print the plan JSON schema and exit")
    investigation_next.add_argument("--output", type=Path, help="Write the plan JSON to this path")
    investigation_next.add_argument("--force", action="store_true", help="Replace --output if it exists")
    investigation_next.set_defaults(func=cmd_investigation_next_steps)

    dashboard = sub.add_parser(
        "dashboard", help="Open a loopback-only local dashboard for one program; no active checks are exposed"
    )
    dashboard.add_argument("program")
    dashboard.add_argument("--host", default="127.0.0.1", help="Loopback bind address only (default: 127.0.0.1)")
    dashboard.add_argument("--port", type=positive_int, default=8765)
    dashboard.set_defaults(func=cmd_dashboard)

    ai_review = sub.add_parser(
        "ai-review", help="Ask local Ollama for a second opinion on minimized evidence or a redacted artifact"
    )
    ai_review.add_argument("program")
    ai_source = ai_review.add_mutually_exclusive_group(required=True)
    ai_source.add_argument("--evidence-file", type=Path, help="Native JSON evidence, minimized before Ollama sees it")
    ai_source.add_argument("--artifact", type=Path, help="Local HTML or raw HTTP request/response text")
    ai_review.add_argument("--kind", choices=("html", "request", "response"), help="Required with --artifact")
    ai_review.add_argument(
        "--ai-model", "--model", dest="model", default=DEFAULT_OLLAMA_MODEL, help="Local Ollama model"
    )
    ai_review.add_argument("--ai-timeout", type=positive_float, default=120.0, help="Ollama timeout in seconds")
    ai_review.add_argument("--chunk-chars", type=positive_int, default=6000, help="Artifact chunk size (default: 6000)")
    ai_review.add_argument("--max-chunks", type=positive_int, default=20, help="Maximum artifact chunks (default: 20)")
    ai_review.add_argument(
        "--dry-run", action="store_true", help="Validate and minimize locally without contacting Ollama"
    )
    ai_review.add_argument(
        "--ai-provider",
        choices=("ollama", "lmstudio"),
        default="ollama",
        help="Allowlisted local provider (default: ollama). Non-default values use the structured v1 result.",
    )
    ai_review.add_argument(
        "--ai-endpoint",
        help="Optional restatement of the provider's authorized loopback host:port; others are rejected",
    )
    ai_review.add_argument(
        "--structured", action="store_true", help="Return the versioned bbtk.ai-evidence-review.v1 result"
    )
    ai_review.add_argument("--second-ai-provider", choices=("ollama", "lmstudio"), help="Second independent review")
    ai_review.add_argument("--second-ai-model", help="Model for the second review")
    ai_review.add_argument("--ai-max-tokens", type=positive_int, default=512, help="Output token budget (max 4096)")
    ai_review.add_argument("--ai-concurrency", type=positive_int, default=1, help="Per-provider concurrency (max 4)")
    ai_review.set_defaults(func=cmd_ai_review)

    ai_cli = sub.add_parser("ai", help="Analyze hypotheses or prepare a non-executing skill route")
    ai_sub = ai_cli.add_subparsers(dest="ai_command", required=True)
    ai_hypotheses = ai_sub.add_parser(
        "hypotheses", help="Ask local Ollama for hypotheses from minimized correlated evidence"
    )
    ai_hypotheses.add_argument("program")
    ai_hypotheses.add_argument("--input", type=Path, required=True, help="Unified evidence bundle JSON")
    ai_hypotheses.add_argument(
        "--case-file", type=Path, help="Local private A/B case for deterministic IDOR assessment"
    )
    ai_hypotheses.add_argument(
        "--access-evidence", type=Path, help="Native read-mode access-check JSON; requires --case-file"
    )
    ai_hypotheses.add_argument("--ai-model", default=DEFAULT_OLLAMA_MODEL, help="Local Ollama model")
    ai_hypotheses.add_argument("--ai-timeout", type=positive_float, default=120.0, help="Ollama timeout in seconds")
    _add_ai_provider_arguments(ai_hypotheses)
    ai_hypotheses.add_argument(
        "--dry-run", action="store_true", help="Validate and minimize locally without Ollama or file writes"
    )
    ai_hypotheses.set_defaults(func=cmd_ai_hypotheses)

    ai_route = ai_sub.add_parser("route", help="Choose existing topic skills and print a validated non-executing plan")
    ai_route.add_argument("program")
    ai_route.add_argument("--input", type=Path, required=True, help="JSON output from `bbtk ai hypotheses`")
    ai_route.add_argument("--max-tests", type=positive_int, default=100, help="Maximum planned HTTP test count")
    ai_route.add_argument(
        "--ai-model", default=DEFAULT_OLLAMA_MODEL, help="Local Ollama model for ambiguous categories"
    )
    ai_route.add_argument("--ai-timeout", type=positive_float, default=120.0, help="Ollama timeout in seconds")
    _add_ai_provider_arguments(ai_route)
    ai_route.add_argument(
        "--dry-run", action="store_true", required=True, help="Required; the router never executes plans"
    )
    ai_route.set_defaults(func=cmd_ai_route)

    ai_prioritize = ai_sub.add_parser(
        "prioritize", help="Rank reviewed hypotheses by evidence, potential impact, cost and operational risk"
    )
    ai_prioritize.add_argument("program")
    ai_prioritize.add_argument("--input", type=Path, required=True, help="JSON output from `bbtk ai hypotheses`")
    ai_prioritize.add_argument("--max-tests", type=positive_int, default=100, help="Estimated request budget")
    ai_prioritize.add_argument("--output", type=Path, help="Optional JSON report path; refuses overwrite by default")
    ai_prioritize.add_argument("--force", action="store_true", help="Replace an existing output report")
    ai_prioritize.add_argument(
        "--dry-run", action="store_true", help="Validate and print the plan without writing a report"
    )
    ai_prioritize.set_defaults(func=cmd_ai_prioritize)

    ai_dual = ai_sub.add_parser(
        "dual-review", help="Analyst (A) + critic (B) local-model review with a deterministic comparator"
    )
    ai_dual.add_argument("program")
    ai_dual.add_argument("--evidence-file", type=Path, required=True, help="Native JSON evidence (minimized first)")
    ai_dual.add_argument("--analyst-provider", choices=("ollama", "lmstudio"), default="ollama")
    ai_dual.add_argument("--analyst-model", default=DEFAULT_OLLAMA_MODEL, help="Model A (analysis)")
    ai_dual.add_argument("--critic-provider", choices=("ollama", "lmstudio"), default="ollama")
    ai_dual.add_argument("--critic-model", required=True, help="Model B (contradictions and missing controls)")
    ai_dual.add_argument("--ai-timeout", type=positive_float, default=120.0, help="Per-call timeout in seconds")
    ai_dual.add_argument("--dry-run", action="store_true", help="Minimize locally without contacting any model")
    ai_dual.set_defaults(func=cmd_ai_dual_review)

    ai_assist = ai_sub.add_parser(
        "evidence-assist",
        help="Local AI evidence assistant (explain/summarize/questions/contradictions/drafts/missing data)",
    )
    ai_assist.add_argument("program")
    ai_assist.add_argument("--evidence-file", type=Path, required=True, help="Native JSON evidence (minimized first)")
    ai_assist.add_argument("--ai-provider", choices=("ollama", "lmstudio"), default="ollama")
    ai_assist.add_argument("--ai-model", default=DEFAULT_OLLAMA_MODEL, help="Local model for advisory assist")
    ai_assist.add_argument("--ai-endpoint", help="Optional authorized loopback host:port restatement")
    ai_assist.add_argument("--ai-timeout", type=positive_float, default=120.0)
    ai_assist.add_argument("--compare-provider", choices=("ollama", "lmstudio"), help="Optional second model provider")
    ai_assist.add_argument("--compare-model", help="Optional second local model for comparison")
    ai_assist.add_argument(
        "--dry-run",
        action="store_true",
        help="Deterministic assist only; do not contact any local model",
    )
    ai_assist.set_defaults(func=cmd_ai_evidence_assist)

    ai_providers = ai_sub.add_parser("providers", help="List allowlisted local AI providers and capabilities")
    ai_providers.add_argument("--check", action="store_true", help="Probe availability on authorized loopback only")
    ai_providers.add_argument("--ai-model", default=DEFAULT_OLLAMA_MODEL, help="Model to look for with --check")
    ai_providers.add_argument("--ai-timeout", type=positive_float, default=5.0, help="Probe timeout in seconds")
    ai_providers.set_defaults(func=cmd_ai_providers)

    ai_investigate = ai_sub.add_parser(
        "investigate", help="Join evidence review, access assessment, skill routing and prioritization"
    )
    ai_investigate.add_argument("program")
    ai_investigate.add_argument("--input", type=Path, required=True, help="Unified evidence bundle JSON")
    ai_investigate.add_argument("--case-file", type=Path, help="Optional private A/B case file")
    ai_investigate.add_argument(
        "--access-evidence", type=Path, help="Native read-mode access-check evidence; requires --case-file"
    )
    ai_investigate.add_argument("--max-tests", type=positive_int, default=100, help="Maximum planned check budget")
    ai_investigate.add_argument(
        "--with-ollama",
        "--with-ai",
        dest="with_ollama",
        action="store_true",
        help="Opt in to local-model hypotheses and ambiguous routing (Ollama, or --ai-provider)",
    )
    ai_investigate.add_argument("--ai-model", default=DEFAULT_OLLAMA_MODEL, help="Local Ollama model")
    ai_investigate.add_argument("--ai-timeout", type=positive_float, default=120.0, help="Ollama timeout in seconds")
    _add_ai_provider_arguments(ai_investigate)
    ai_investigate.add_argument("--output", type=Path, help="Optional JSON output path; refuses overwrite by default")
    ai_investigate.add_argument("--force", action="store_true", help="Replace an existing --output file")
    ai_investigate.add_argument(
        "--session-id", help="Save the result in local investigation memory and append-only history"
    )
    ai_investigate.add_argument(
        "--resume-session", action="store_true", help="Resume a closed session with the same evidence bundle"
    )
    ai_investigate.add_argument(
        "--dry-run", action="store_true", help="Validate and preview offline without Ollama, HTTP or file writes"
    )
    ai_investigate.set_defaults(func=cmd_ai_investigate)

    ai_benchmark = ai_sub.add_parser(
        "benchmark", help="Measure deterministic IDOR/BOLA assessment and optional local Ollama second opinion"
    )
    ai_benchmark.add_argument("--dataset", type=Path, required=True, help="Versioned synthetic benchmark JSON")
    ai_benchmark.add_argument(
        "--split", choices=("holdout", "development", "all"), default="holdout", help="Evaluation split"
    )
    ai_benchmark.add_argument(
        "--with-ollama",
        "--with-ai",
        dest="with_ollama",
        action="store_true",
        help="Opt in to a local-model call for each selected case (Ollama, or --ai-provider)",
    )
    ai_benchmark.add_argument("--ai-model", default=DEFAULT_OLLAMA_MODEL, help="Local Ollama model")
    ai_benchmark.add_argument("--ai-timeout", type=positive_float, default=120.0, help="Ollama timeout in seconds")
    _add_ai_provider_arguments(ai_benchmark)
    ai_benchmark.add_argument("--output", type=Path, help="Output JSON path; a sibling Markdown report is created")
    ai_benchmark.add_argument("--force", action="store_true", help="Replace existing JSON and Markdown reports")
    ai_benchmark.add_argument(
        "--dry-run", action="store_true", help="Validate dataset only; do not call Ollama or write reports"
    )
    ai_benchmark.set_defaults(func=cmd_ai_benchmark)

    doctor = sub.add_parser("doctor", help="Offline checks for dependencies, skills and local configuration")
    doctor.add_argument("--program", help="Optionally validate one initialized program")
    doctor.add_argument("--skills-dir", type=Path, help="Installed skill root (defaults to CODEX_HOME/skills)")
    doctor.add_argument("--json", dest="json_output", action="store_true", help="Print machine-readable diagnostics")
    doctor.set_defaults(func=cmd_doctor)

    status = sub.add_parser("status")
    status.add_argument("program")
    status.set_defaults(func=cmd_status)
    return parser


def positive_float(value: str) -> float:
    number = float(value)
    if not math.isfinite(number) or number <= 0:
        raise argparse.ArgumentTypeError("Must be a finite positive number.")
    return number


def external_rate(settings: ExecutorSettings) -> int:
    rate = settings.requests_per_second
    if rate < 1 or rate != int(rate):
        raise ValueError(
            "This external tool requires a whole-number rate of at least 1. Use request/xss for fractional rates."
        )
    return int(rate)


def positive_int(value: str) -> int:
    number = int(value)
    if number <= 0:
        raise argparse.ArgumentTypeError("Must be a positive integer.")
    return number


def print_execution_summary(args: argparse.Namespace) -> None:
    budget = getattr(args, "_execution_budget", None)
    if budget is None:
        return
    result = budget.summary()
    if (
        not any(
            getattr(args, name, None) is not None
            for name in ("run_max_requests", "run_max_seconds", "run_max_concurrency")
        )
        and not result.external_requests_reserved
    ):
        return
    request_cap = str(result.max_requests) if result.max_requests is not None else "unlimited"
    time_cap = f"{result.max_seconds:g}s" if result.max_seconds is not None else "unlimited"
    destinations = ", ".join(result.destinations) or "none"
    reason = result.stop_reason or "completed"
    if result.external_requests_reserved:
        request_detail = (
            f"{result.requests_started} native requests observed plus up to "
            f"{result.external_requests_reserved} external requests reserved (not directly counted) / {request_cap}"
        )
    else:
        request_detail = f"{result.requests_started}/{request_cap} requests sent"
    print(
        f"[i] Run summary: {request_detail}, {result.responses_received} responses, "
        f"{result.transport_errors} transport errors; {result.elapsed_seconds:.2f}/{time_cap}; "
        f"peak concurrency {result.peak_concurrency}/{result.max_concurrency}; "
        f"destinations: {destinations}; stop: {reason}."
    )


def main() -> None:
    global RECORDS_ROOT
    parser = build_parser()
    args = parser.parse_args()
    RECORDS_ROOT = args.records_root
    offline_dry_run = (
        args.func
        in {cmd_object_discover, cmd_object_candidates, cmd_object_handoff, cmd_lab_object_discover, cmd_fuzz_plan}
        and args.dry_run
    )
    logger = setup_logger(args.log_file) if args.log_file and not offline_dry_run else None
    try:
        if logger:
            logger.info("Starting %s", args.func.__name__)
        args.func(args)
        if logger:
            logger.info("Completed %s", args.func.__name__)
        print_execution_summary(args)
    except (ToolkitError, ValueError, OSError, RuntimeError, _YAML_ERROR) as exc:
        if logger:
            logger.error("Failed %s (%s)", args.func.__name__, type(exc).__name__)
        print_execution_summary(args)
        parser.exit(1, f"Error: {exc}\n")
    except KeyboardInterrupt:
        budget = getattr(args, "_execution_budget", None)
        if budget is not None:
            budget.cancel("cancelled_by_user")
        print_execution_summary(args)
        parser.exit(130, "Interrupted.\n")


if __name__ == "__main__":
    main()
