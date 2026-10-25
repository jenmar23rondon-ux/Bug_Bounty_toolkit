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
from .jwt_forge import MAX_PUBLIC_KEY_BYTES, forge_jwt
from .analysis.sql_query import analyze_sql
from .analysis.evidence_review import review_evidence
from .analysis.evidence_engine import correlations_from_bundle, import_evidence
from .analysis.hypotheses import SECOND_OPINION as HYPOTHESES_SECOND_OPINION, analyze_hypotheses
from .analysis.access_assessment import assess_access_control
from .analysis.skill_router import route_hypotheses_file
from .access_control.comparison import AccessControlTester
from .access_control.range_checker import AccessRangeOptions, AccessRangeTester, MAX_RANGE_REQUESTS
from .access_control.write_lab import AccessWriteLabTester
from .access_control.write_range import AccessWriteRangeTester
from .access_control.guards import is_loopback_url
from .analysis.ollama_review import DEFAULT_OLLAMA_MODEL, review_with_ollama, validate_ollama_config
from .analysis.artifact_review import (
    SECOND_OPINION,
    generate_ai_report,
    review_artifact,
    review_evidence_with_ollama,
)
from .analysis.live_review import (
    add_ai_review_arguments,
    format_ai_review,
    resolve_ai_review_config,
    review_evidence_file,
)
from .integrations.catalog import catalog
from .integrations.external_plan import build_external_plan, TOOLS
from .reporting.evidence import write_evidence_json
from .reporting.html_report import render_html_report
from .reporting.json_report import render_json_report
from .reporting.review_markdown import render_evidence_review
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


def print_live_ai_review(path: Path, config: tuple[str, float] | None, toolkit_verdict: str) -> None:
    if config is None:
        return
    ai_review = review_evidence_file(path, config[0], config[1])
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
    subfinder = run_tool(store, "subfinder", args.target, ["subfinder", "-silent", "-d", args.target])
    amass = run_tool(store, "amass", args.target, ["amass", "enum", "-passive", "-d", args.target])
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
    httpx = run_tool(store, "httpx", args.target, ["httpx", "-silent", "-l", str(merged), "-rl", str(rate)])
    print(f"[+] Recon complete. Live host output: {httpx}")


def cmd_scan_nuclei(args: argparse.Namespace) -> None:
    store, settings, scope = executor_context(args, automated=True)
    rate = external_rate(settings)
    hosts = store.paths.raw_dir / "subdomains.txt"
    if not hosts.exists():
        raise SystemExit("Run recon first; missing registros/<program>/raw/subdomains.txt")
    scope.require_all([line.strip() for line in hosts.read_text(encoding="utf-8").splitlines() if line.strip()])
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
    )
    print(f"[+] Nuclei scan complete: {output}")


def cmd_fuzz(args: argparse.Namespace) -> None:
    store, settings, scope = executor_context(args, automated=True)
    rate = args.rate or settings.requests_per_second
    if rate < 1 or rate != int(rate):
        raise ValueError("ffuf requires a whole-number rate of at least 1 request/second.")
    options = FfufOptions(
        url=args.url,
        wordlist=args.wordlist,
        threads=args.threads or settings.max_concurrency,
        timeout=args.timeout or math.ceil(settings.timeout),
        rate=int(rate),
        match_codes=args.match_codes,
        filter_size=args.filter_size,
    )
    runner = FfufRunner(store, scope)
    if args.dry_run:
        runner.validate(options)
        print("[+] Fuzz inputs validated. No requests sent.")
        return
    path, results = runner.run(options)
    store.mark_reviewed("fuzz-url", redact_url(args.url), str(path))
    print(f"[+] Fuzzing complete: {len(results)} unique matches. Evidence: {path}")


def cmd_xss(args: argparse.Namespace) -> None:
    ai_review_config = resolve_ai_review_config(args.ai_review, args.ai_model, args.ai_timeout)
    store, settings, scope = executor_context(args, automated=True)
    headers = parse_header_items(args.header)
    cookies = parse_cookie_items(args.cookie)
    if cookies:
        headers["Cookie"] = cookies
    tester = XssParameterTester(scope, client_for(args, settings, scope))
    options = XssOptions(
        args.routes,
        args.parameters,
        args.base_url,
        args.max_tests or settings.max_tests,
        headers,
        args.html_parser,
        args.confirm_exec,
    )
    if options.max_tests > settings.max_tests:
        raise ValueError("Max tests exceeds the configured program limit.")
    routes, parameters = tester.validate(options)
    variants = 11 if options.confirm_exec else 4
    total = len(routes) * len(parameters) * variants
    if args.dry_run:
        print(
            f"[+] {len(routes)} routes, {len(parameters)} parameters, up to {min(total, options.max_tests)} HTTP requests. Browser confirmation {'enabled' if options.confirm_exec else 'disabled'}. No requests sent."
        )
        return
    path, results = tester.run(options, store.paths.evidence_dir / "xss")
    failures = sum(item["classification"] == "error" for item in results)
    possible = sum(item["classification"] == "possible" for item in results)
    confirmed = sum(item["classification"] == "confirmed" for item in results)
    not_executed = sum(item["classification"] == "reflected_not_executed" for item in results)
    store.add_run("xss", str(args.routes), ["xss", str(args.routes), str(args.parameters)], 1 if failures else 0, path)
    summary = f"{len(results)} tests, {possible} possible reflections, {failures} errors"
    if options.confirm_exec:
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
    store, _, _ = executor_context(args, automated=True)
    ensure_in_scope(args.url, store.paths.scope_file)
    paramspider = run_tool(store, "paramspider", args.url, ["paramspider", "-d", args.url])
    arjun = run_tool(store, "arjun", args.url, ["arjun", "-u", args.url])
    store.mark_reviewed("parameter-target", args.url, "paramspider and arjun executed")
    print(f"[+] Parameter analysis complete: {paramspider}, {arjun}")


def cmd_sqli(args: argparse.Namespace) -> None:
    ai_review_config = resolve_ai_review_config(args.ai_review, args.ai_model, args.ai_timeout)
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
    ai_review_config = resolve_ai_review_config(args.ai_review, args.ai_model, args.ai_timeout)
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
    for row in results:
        print(
            f"{row.get('origin', '-'):<40} ACAO={row.get('access_control_allow_origin', '-')} "
            f"ACAC={row.get('access_control_allow_credentials', '-')} verdict={row['classification']} "
            f"status={row.get('status_code', '-')}"
        )
    store.add_run(
        "cors-check", redact_url(args.url), ["cors-check", redact_url(args.url)], 1 if counts["VULNERABLE"] else 0, path
    )
    print(
        f"[+] CORS summary: {counts['VULNERABLE']} vulnerable, {counts['DÉBIL']} weak, {counts['SEGURO']} safe. Evidence: {path}"
    )
    print_live_ai_review(
        path,
        ai_review_config,
        f"{counts['VULNERABLE']} vulnerable, {counts['DÉBIL']} weak, {counts['SEGURO']} safe",
    )


def cmd_ssrf_check(args: argparse.Namespace) -> None:
    ai_review_config = resolve_ai_review_config(args.ai_review, args.ai_model, args.ai_timeout)
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
    ai_review_config = resolve_ai_review_config(args.ai_review, args.ai_model, args.ai_timeout)
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
    ai_review_config = resolve_ai_review_config(args.ai_review, args.ai_model, args.ai_timeout)
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
    ai_review_config = resolve_ai_review_config(args.ai_review, args.ai_model, args.ai_timeout)
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

    if "csrf-audit" in selected:
        csrf_url = normalize_url(args.csrf_url or base_url)
        scope.require(csrf_url)
        tasks.append(HuntTask("csrf-audit", "csrf-audit", ("csrf-audit", args.program, "--url", csrf_url), 1, 1, 1))

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
    ai_config = resolve_ai_review_config(args.ai_review, args.ai_model, args.ai_timeout)
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
    ai_review_config = resolve_ai_review_config(args.ai_review, args.ai_model, args.ai_timeout)
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
    elif args.analysis == "evidence":
        data = review_evidence(json.loads(text))
        if args.ai == "ollama":
            model = args.model or DEFAULT_OLLAMA_MODEL
            data["ollama_review"] = review_with_ollama(data, model, args.ai_timeout)
            data["network_requests_sent_by_review"] = 1
        elif args.model:
            raise ValueError("--model requires --ai ollama.")
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
    bundle = import_evidence(args.input, args.format)
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


def cmd_ai_review(args: argparse.Namespace) -> None:
    ProgramPaths(RECORDS_ROOT, args.program)
    validate_ollama_config(args.model, args.ai_timeout)
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
        result = review_artifact(
            args.artifact,
            args.kind,
            args.model,
            args.ai_timeout,
            args.chunk_chars,
            args.max_chunks,
            args.dry_run,
        )
    print(f"[i] {SECOND_OPINION}")
    print(json.dumps(result, indent=2, sort_keys=True))


def cmd_ai_hypotheses(args: argparse.Namespace) -> None:
    if args.access_evidence and not args.case_file:
        raise ValueError("--access-evidence requires --case-file.")
    paths = ProgramPaths(RECORDS_ROOT, args.program)
    result = analyze_hypotheses(args.input, args.ai_model, args.ai_timeout, args.dry_run)
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
    result = route_hypotheses_file(args.input, args.program, args.max_tests, args.ai_model, args.ai_timeout)
    print("[i] Route plan only. No skill command or target request was executed; review missing inputs before use.")
    print(json.dumps(result, indent=2, sort_keys=True))


def cmd_report(args: argparse.Namespace) -> None:
    store = store_for(args.program)
    if args.draft_with_ai and not args.evidence_file:
        raise ValueError("--draft-with-ai requires --evidence-file.")
    if not args.draft_with_ai and (args.ai_model is not None or args.ai_timeout is not None):
        raise ValueError("--ai-model and --ai-timeout require --draft-with-ai.")
    if args.evidence_file:
        if args.finding_id:
            raise ValueError("--evidence-file cannot be combined with --finding-id.")
        if args.format not in {None, "markdown"}:
            raise ValueError("Evidence review drafts use --format markdown.")
        try:
            data = json.loads(bounded_text(args.evidence_file, 2_000_000))
        except json.JSONDecodeError as exc:
            raise ValueError("Evidence file must contain valid JSON.") from exc
        if not isinstance(data, dict):
            raise ValueError("Evidence file must contain a JSON object.")
        destination = args.output or store.paths.reports_dir / f"evidence-review-{args.evidence_file.stem}.md"
        output = render_evidence_review(data, destination)
        if args.draft_with_ai:
            model = args.ai_model or DEFAULT_OLLAMA_MODEL
            timeout = args.ai_timeout or 120.0
            try:
                draft = generate_ai_report(data, model, timeout)
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
    markdown = render_markdown(finding, store.paths.reports_dir / f"{args.finding_id}.md")
    output = (
        markdown
        if args.format == "markdown"
        else render_pdf(markdown, store.paths.reports_dir / f"{args.finding_id}.pdf")
    )
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
    fuzz.add_argument("--match-codes", default="200,204,301,302,307,401,403,405,500")
    fuzz.add_argument("--filter-size")
    fuzz.add_argument("--dry-run", action="store_true")
    fuzz.set_defaults(func=cmd_fuzz)

    xss = sub.add_parser("xss")
    xss.add_argument("program")
    xss.add_argument("--routes", required=True, type=Path)
    xss.add_argument("--parameters", required=True, type=Path)
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
    evidence = analyze_sub.add_parser("evidence", help="Allowlisted observations with optional local Ollama review")
    evidence.add_argument("--input", required=True, type=Path)
    evidence.add_argument("--output", type=Path)
    evidence.add_argument("--ai", choices=("ollama",))
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
    report.add_argument(
        "--evidence-file", type=Path, help="Create a redacted Markdown review draft from native JSON evidence"
    )
    report.add_argument("--output", type=Path, help="Optional destination for an evidence review draft")
    report.add_argument(
        "--draft-with-ai", action="store_true", help="Ask local Ollama for an optional evidence-based Markdown draft"
    )
    report.add_argument("--ai-model", help=f"Local Ollama model for --draft-with-ai (default: {DEFAULT_OLLAMA_MODEL})")
    report.add_argument("--ai-timeout", type=positive_float, help="Local Ollama timeout in seconds (default: 120)")
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
    ai_route.add_argument(
        "--dry-run", action="store_true", required=True, help="Required; the router never executes plans"
    )
    ai_route.set_defaults(func=cmd_ai_route)

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
    if not any(
        getattr(args, name, None) is not None for name in ("run_max_requests", "run_max_seconds", "run_max_concurrency")
    ):
        return
    budget = getattr(args, "_execution_budget", None)
    if budget is None:
        return
    result = budget.summary()
    request_cap = str(result.max_requests) if result.max_requests is not None else "unlimited"
    time_cap = f"{result.max_seconds:g}s" if result.max_seconds is not None else "unlimited"
    destinations = ", ".join(result.destinations) or "none"
    reason = result.stop_reason or "completed"
    print(
        f"[i] Run summary: {result.requests_started}/{request_cap} requests sent, "
        f"{result.responses_received} responses, {result.transport_errors} transport errors; "
        f"{result.elapsed_seconds:.2f}/{time_cap}; peak concurrency "
        f"{result.peak_concurrency}/{result.max_concurrency}; destinations: {destinations}; stop: {reason}."
    )


def main() -> None:
    global RECORDS_ROOT
    parser = build_parser()
    args = parser.parse_args()
    RECORDS_ROOT = args.records_root
    logger = setup_logger(args.log_file) if args.log_file else None
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
