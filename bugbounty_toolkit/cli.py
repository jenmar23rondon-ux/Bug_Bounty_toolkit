from __future__ import annotations

import argparse
import json
import math
from dataclasses import asdict
from pathlib import Path
import re

import yaml

from .core.checks import render_checklist
from .core.records import ProgramPaths, RecordStore
from .core.reporting import render_markdown, render_pdf
from .core.runner import run_tool
from .core.scope import ensure_in_scope, validate_rule
from .core.scope_validator import ScopeValidator
from .core.settings import load_settings, ExecutorSettings
from .core.http_client import HttpClient
from .core.rate_limiter import RateLimiter
from .core.redaction import redact_url
from .fuzzing.ffuf_runner import FfufOptions, FfufRunner
from .requests_engine.replay import RequestReplayer
from .requests_engine.headers import parse_header_items, parse_cookie_items
from .requests_engine.parameters import parse_parameter_items
from .xss.parameter_tester import XssOptions, XssParameterTester
from .sqli.parameter_tester import SqliOptions, SqliParameterTester
from .analysis.html_context import analyze_html
from .analysis.jwt_inspector import inspect_jwt, ALGORITHMS
from .analysis.sql_query import analyze_sql
from .analysis.evidence_review import review_evidence
from .access_control.comparison import AccessControlTester
from .access_control.range_checker import AccessRangeOptions, AccessRangeTester, MAX_RANGE_REQUESTS
from .access_control.write_lab import AccessWriteLabTester
from .access_control.write_range import AccessWriteRangeTester
from .access_control.guards import is_loopback_url
from .analysis.ollama_review import review_with_ollama
from .integrations.catalog import catalog
from .integrations.external_plan import build_external_plan, TOOLS
from .reporting.evidence import write_evidence_json
from .reporting.html_report import render_html_report
from .reporting.json_report import render_json_report
from .utils.exceptions import ToolkitError
from .utils.logger import setup_logger


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
    return store, settings, ScopeValidator(store.paths.scope_file)


def client_for(args: argparse.Namespace, settings: ExecutorSettings, scope: ScopeValidator) -> HttpClient:
    return HttpClient(scope, timeout=args.timeout or settings.timeout,
                      rate_limiter=RateLimiter(args.rate or settings.requests_per_second),
                      max_response_bytes=settings.max_response_bytes)


def cmd_init(args: argparse.Namespace) -> None:
    store = store_for(args.program)
    if not args.authorization.strip():
        raise ValueError("Authorization reference cannot be empty.")
    settings_path = store.paths.program_dir / "settings.yaml"
    settings = load_settings(args.config or (settings_path if settings_path.exists() else None))
    settings_path.write_text(yaml.safe_dump(asdict(settings)), encoding="utf-8")
    store.set_program_meta(platform=args.platform, authorization=args.authorization,
                           automation_allowed="true" if args.automation_allowed else "false")
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
        values.update(line.strip() for line in path.read_text(encoding="utf-8", errors="ignore").splitlines() if line.strip())
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
    output = run_tool(store, "nuclei", None, ["nuclei", "-l", str(hosts), "-severity", args.severity, "-dr", "-rl", str(rate), "-c", str(settings.max_concurrency)])
    print(f"[+] Nuclei scan complete: {output}")


def cmd_fuzz(args: argparse.Namespace) -> None:
    store, settings, scope = executor_context(args, automated=True)
    rate = args.rate or settings.requests_per_second
    if rate < 1 or rate != int(rate):
        raise ValueError("ffuf requires a whole-number rate of at least 1 request/second.")
    options = FfufOptions(url=args.url, wordlist=args.wordlist,
                          threads=args.threads or settings.max_concurrency, timeout=args.timeout or math.ceil(settings.timeout),
                          rate=int(rate), match_codes=args.match_codes, filter_size=args.filter_size)
    runner = FfufRunner(store, scope)
    if args.dry_run:
        runner.validate(options)
        print("[+] Fuzz inputs validated. No requests sent.")
        return
    path, results = runner.run(options)
    store.mark_reviewed("fuzz-url", redact_url(args.url), str(path))
    print(f"[+] Fuzzing complete: {len(results)} unique matches. Evidence: {path}")


def cmd_xss(args: argparse.Namespace) -> None:
    store, settings, scope = executor_context(args, automated=True)
    headers = parse_header_items(args.header)
    cookies = parse_cookie_items(args.cookie)
    if cookies:
        headers["Cookie"] = cookies
    tester = XssParameterTester(scope, client_for(args, settings, scope))
    options = XssOptions(args.routes, args.parameters, args.base_url, args.max_tests or settings.max_tests, headers, args.html_parser)
    if options.max_tests > settings.max_tests:
        raise ValueError("Max tests exceeds the configured program limit.")
    routes, parameters = tester.validate(options)
    total = len(routes) * len(parameters) * 4
    if args.dry_run:
        print(f"[+] {len(routes)} routes, {len(parameters)} parameters, up to {min(total, options.max_tests)} requests. No requests sent.")
        return
    path, results = tester.run(options, store.paths.evidence_dir / "xss")
    failures = sum(item["classification"] == "error" for item in results)
    possible = sum(item["classification"] == "possible" for item in results)
    store.add_run("xss", str(args.routes), ["xss", str(args.routes), str(args.parameters)], 1 if failures else 0, path)
    print(f"[+] {len(results)} tests, {possible} possible reflections, {failures} errors. No XSS automatically confirmed.")
    print(f"[+] Evidence: {path}")
    if len(results) < total:
        stop = json.loads(path.read_text(encoding="utf-8")).get("stop_reason")
        print(f"[!] Batch stopped: {stop}; remaining inputs were not tested." if stop else "[!] Test budget reached; remaining inputs were not tested.")


def cmd_params(args: argparse.Namespace) -> None:
    store, _, _ = executor_context(args, automated=True)
    ensure_in_scope(args.url, store.paths.scope_file)
    paramspider = run_tool(store, "paramspider", args.url, ["paramspider", "-d", args.url])
    arjun = run_tool(store, "arjun", args.url, ["arjun", "-u", args.url])
    store.mark_reviewed("parameter-target", args.url, "paramspider and arjun executed")
    print(f"[+] Parameter analysis complete: {paramspider}, {arjun}")


def cmd_sqli(args: argparse.Namespace) -> None:
    store, settings, scope = executor_context(args, automated=True)
    headers = parse_header_items(args.header)
    if args.cookie:
        headers["Cookie"] = parse_cookie_items(args.cookie)
    options = SqliOptions(args.routes, args.parameters, args.base_url, args.max_tests or settings.max_tests, headers)
    if options.max_tests > settings.max_tests:
        raise ValueError("Max tests exceeds the configured program limit.")
    tester = SqliParameterTester(scope, client_for(args, settings, scope))
    routes, parameters = tester.validate(options)
    if args.dry_run:
        budget = min(len(routes) * len(parameters) * 3, options.max_tests // 3 * 3)
        print(f"[+] SQLi error probes validated, up to {budget} requests. No requests sent.")
        return
    path, results = tester.run(options, store.paths.evidence_dir / "sqli")
    failures = sum(item["classification"] == "error" for item in results)
    possible = sum(item["classification"] == "possible" for item in results)
    store.add_run("sqli", str(args.routes), ["sqli", str(args.routes), str(args.parameters)], 1 if failures else 0, path)
    print(f"[+] {len(results)} SQLi responses, {possible} possible indicators, {failures} errors. No SQLi automatically confirmed.")
    print(f"[+] Evidence: {path}")


def cmd_access_check(args: argparse.Namespace) -> None:
    range_requested = bool(args.id_range or args.lab_write_range)
    if args.allow_public_writes and not args.lab_write:
        raise ValueError("--allow-public-writes requires --lab-write.")
    if args.lab_write_range and not args.lab_write:
        raise ValueError("--lab-write-range requires --lab-write.")
    if args.id_range and args.lab_write_range:
        raise ValueError("--range and --lab-write-range are mutually exclusive.")
    if args.lab_write and args.id_range:
        raise ValueError("--lab-write cannot be combined with --range.")
    range_options = (args.max_range, args.concurrency, args.min_interval)
    if not range_requested and any(value is not None for value in range_options):
        raise ValueError("--max-range, --concurrency and --min-interval require --range or --lab-write-range.")
    if args.allow_public_range and not range_requested:
        raise ValueError("--allow-public-range requires --range or --lab-write-range.")

    store, settings, scope = executor_context(args, automated=True)
    range_cap = args.max_range or 25
    budget = args.max_tests or (min(settings.max_tests, range_cap + 2) if range_requested else 3)
    if budget > settings.max_tests:
        raise ValueError("Max tests exceeds the configured program limit.")
    if args.id_range:
        if budget > MAX_RANGE_REQUESTS:
            raise ValueError(f"Range checks are capped at {MAX_RANGE_REQUESTS} requests including controls in loopback labs.")
        client = client_for(args, settings, scope)
        tester = AccessRangeTester(scope, client)
        interval = args.min_interval if args.min_interval is not None else (1.0 if args.allow_public_range else 10.0)
        options = AccessRangeOptions(args.id_range, budget, range_cap, args.concurrency or 1,
                                     interval, args.allow_public_range)
        case, requests = tester.validate(args.case_file, options)
        local_lab = all(is_loopback_url(request.prepared_url()) for request in (case.owner, case.actor, *requests))
        if local_lab and args.allow_public_range and args.min_interval is None:
            options = AccessRangeOptions(args.id_range, budget, range_cap, args.concurrency or 1, 10.0, True)
            case, requests = tester.validate(args.case_file, options)
        elif not local_lab and args.allow_public_range:
            print("[!] Public range relaxed: more requests than default")
        if args.dry_run:
            print(f"[+] Bounded range validated: two controls and {len(requests)} GETs; cap {range_cap}, concurrency {options.concurrency}, minimum interval {options.min_interval:g}s. No requests sent.")
            return
        path, result = tester.run(args.case_file, options, store.paths.evidence_dir / "access-control")
        store.add_run("access-check", None, ["access-check", "--range"], 1 if result["classification"] == "inconclusive" else 0, path)
        print(f"[+] Bounded access comparison: {result['classification']}; {result['requests_attempted']} requests attempted; candidate offset: {result['candidate_offset']}.")
        print(f"[+] Stop reason: {result['stop_reason']}. No IDOR automatically confirmed. Evidence: {path}")
        return
    if args.lab_write_range:
        if args.allow_public_writes:
            print("[!] Public writes enabled: requests may modify remote state")
        client = client_for(args, settings, scope)
        tester = AccessWriteRangeTester(scope, client, allow_public_writes=args.allow_public_writes)
        interval = args.min_interval if args.min_interval is not None else (1.0 if args.allow_public_range else 10.0)
        options = AccessRangeOptions(args.lab_write_range, budget, range_cap, args.concurrency or 1,
                                     interval, args.allow_public_range)
        case, requests = tester.validate(args.case_file, options)
        local_lab = all(is_loopback_url(request.prepared_url()) for request in (case.owner, case.actor, *requests))
        if local_lab and args.allow_public_range and args.min_interval is None:
            options = AccessRangeOptions(args.lab_write_range, budget, range_cap, args.concurrency or 1, 10.0, True)
            case, requests = tester.validate(args.case_file, options)
        elif not local_lab and args.allow_public_range:
            print("[!] Public range relaxed: more requests than default")
        if args.dry_run:
            print(f"[+] JSON write range validated: two controls and {len(requests)} POST/PUT/PATCH probes; cap {range_cap}, concurrency {options.concurrency}, minimum interval {options.min_interval:g}s. No requests sent.")
            return
        path, result = tester.run(args.case_file, options, store.paths.evidence_dir / "access-control")
        store.add_run("access-check-lab-write-range", None, ["access-check", "--lab-write-range"],
                      1 if result["classification"] == "inconclusive" else 0, path)
        print(f"[+] Bounded write comparison: {result['classification']}; {result['requests_attempted']} requests attempted; candidate offset: {result['candidate_offset']}.")
        print(f"[+] Stop reason: {result['stop_reason']}. No IDOR automatically confirmed. Evidence: {path}")
        return
    if args.lab_write:
        if args.allow_public_writes:
            print("[!] Public writes enabled: requests may modify remote state")
        tester = AccessWriteLabTester(scope, client_for(args, settings, scope),
                                      allow_public_writes=args.allow_public_writes)
        tester.validate(args.case_file, budget)
        if args.dry_run:
            print("[+] JSON write case validated: two controls and one crossed POST/PUT/PATCH; no requests sent.")
            return
        path, result = tester.run(args.case_file, store.paths.evidence_dir / "access-control", budget)
        store.add_run("access-check-lab-write", None, ["access-check", "--lab-write"], 1 if result["classification"] == "inconclusive" else 0, path)
        print(f"[+] JSON write comparison: {result['classification']}; {result['requests_attempted']} requests attempted. No IDOR automatically confirmed. Evidence: {path}")
        return
    tester = AccessControlTester(scope, client_for(args, settings, scope))
    tester.validate(args.case_file, budget)
    if args.dry_run:
        print("[+] Known-resource access case validated: two controls and one crossed GET, at most 3 requests. No requests sent.")
        return
    path, result = tester.run(args.case_file, store.paths.evidence_dir / "access-control", budget)
    store.add_run("access-check", None, ["access-check"], 0 if result["classification"] != "inconclusive" else 1, path)
    print(f"[+] Access comparison: {result['classification']}; {result['requests_attempted']} requests attempted; controls valid: {result['controls_valid']}.")
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
            if not args.model:
                raise ValueError("Select a local Ollama model with --model.")
            data["ollama_review"] = review_with_ollama(data, args.model, args.ai_timeout)
            data["network_requests_sent_by_review"] = 1
        elif args.model:
            raise ValueError("--model requires --ai ollama.")
    else:
        key = bounded_text(args.key_file, 65536).encode("utf-8") if args.key_file else None
        data = inspect_jwt(text.strip(), key, args.algorithm, args.issuer, args.audience)
    print_or_save(data, args.output)


def cmd_tool_plan(args: argparse.Namespace) -> None:
    store, settings, scope = executor_context(args)
    plan = build_external_plan(args.tool, args.url, args.parameter, scope, settings, args.script)
    plan["automation_allowed_in_program"] = store.metadata().get("automation_allowed") == "true"
    if not plan["automation_allowed_in_program"]:
        plan["warnings"].append("This program does not record automation permission. Planning is offline; executing an automated scan is not authorized by this plan.")
    if args.dry_run:
        print("[+] External plan validated. No scanner executed and no requests sent.")
        return
    # Command plans may contain private URL values; only their redacted summary enters reports.
    path = write_evidence_json(store.paths.raw_dir / "external-plans", plan, prefix=args.tool)
    summary = write_evidence_json(store.paths.evidence_dir / "external-plans",
                                  {"type": "external-tool-plan", "tool": args.tool, "target": redact_url(args.url),
                                   "executed": False, "confirmed": False, "requires_manual_review": True,
                                   "automatic_request_budget_enforced": False}, prefix=args.tool)
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
    store.add_finding(args.finding_id, args.title, args.category, args.severity, args.target, args.summary, args.evidence)
    print(f"[+] Finding saved: {args.finding_id}")


def cmd_report(args: argparse.Namespace) -> None:
    store = store_for(args.program)
    if not args.finding_id:
        report_format = args.format or "html"
        if report_format not in {"html", "json"}:
            raise ValueError("Program reports support html/json. Use --finding-id for markdown/pdf.")
        destination = store.paths.reports_dir / f"program-report.{report_format}"
        output = render_html_report(store, destination) if report_format == "html" else render_json_report(store, destination)
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
    output = markdown if args.format == "markdown" else render_pdf(markdown, store.paths.reports_dir / f"{args.finding_id}.pdf")
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


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="bbtk", description="Authorized bug bounty automation toolkit")
    parser.add_argument("--records-root", type=Path, default=RECORDS_ROOT)
    parser.add_argument("--log-file", type=Path, help="Optional local execution log; request secrets are not logged")
    sub = parser.add_subparsers(required=True)

    init = sub.add_parser("init")
    init.add_argument("program")
    init.add_argument("--platform", default="hackerone")
    init.add_argument("--authorization", required=True)
    init.add_argument("--automation-allowed", action="store_true", help="Record that the program permits automated testing")
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
    xss.add_argument("--dry-run", action="store_true")
    xss.set_defaults(func=cmd_xss)

    sqli = sub.add_parser("sqli", help="Bounded baseline/quote error probes; no extraction or time delays")
    sqli.add_argument("program")
    sqli.add_argument("--routes", required=True, type=Path)
    sqli.add_argument("--parameters", required=True, type=Path)
    sqli.add_argument("--base-url")
    sqli.add_argument("--header", action="append")
    sqli.add_argument("--cookie", action="append")
    sqli.add_argument("--timeout", type=positive_float)
    sqli.add_argument("--rate", type=positive_float)
    sqli.add_argument("--max-tests", type=positive_int)
    sqli.add_argument("--dry-run", action="store_true")
    sqli.set_defaults(func=cmd_sqli)

    access = sub.add_parser("access-check", help="Known-resource A/B check; bounded GET range or loopback-only JSON write lab")
    access.add_argument("program")
    access.add_argument("--case-file", required=True, type=Path, help="Private JSON case and separate raw owner/actor requests")
    access.add_argument("--range", dest="id_range", help="One numeric interval; non-loopback targets remain sequential and capped")
    access.add_argument("--max-range", type=positive_int, help="Maximum IDs in --range (default 25; loopback hard cap 100)")
    access.add_argument("--concurrency", type=positive_int, help="Range workers (default 1; loopback hard cap 4)")
    access.add_argument("--min-interval", type=positive_float, help="Minimum seconds between starts (public relaxed default 1; otherwise 10; loopback minimum 0.01)")
    access.add_argument("--allow-public-range", action="store_true", help="Opt in to up to 100 public range probes, four workers and a one-second minimum interval")
    access.add_argument("--lab-write", action="store_true", help="Run one JSON-body POST/PUT/PATCH A/B comparison; public targets require --allow-public-writes")
    access.add_argument("--allow-public-writes", action="store_true", help="Opt in to state-changing write comparisons on in-scope non-loopback hosts")
    access.add_argument("--lab-write-range", help="With --lab-write, sweep one numeric JSON-body ID interval")
    access.add_argument("--timeout", type=positive_float)
    access.add_argument("--rate", type=positive_float)
    access.add_argument("--max-tests", type=positive_int)
    access.add_argument("--dry-run", action="store_true")
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
    jwt.add_argument("--input", required=True, type=Path, help="Local compact JWS token; never pass a token on the command line")
    jwt.add_argument("--key-file", type=Path)
    jwt.add_argument("--algorithm", choices=ALGORITHMS)
    jwt.add_argument("--issuer")
    jwt.add_argument("--audience")
    jwt.add_argument("--output", type=Path)
    jwt.set_defaults(func=cmd_analyze)
    evidence = analyze_sub.add_parser("evidence", help="Allowlisted observations with optional local Ollama review")
    evidence.add_argument("--input", required=True, type=Path)
    evidence.add_argument("--output", type=Path)
    evidence.add_argument("--ai", choices=("ollama",))
    evidence.add_argument("--model", help="Installed local Ollama model name")
    evidence.add_argument("--ai-timeout", type=positive_float, default=120)
    evidence.set_defaults(func=cmd_analyze)

    tool_plan = sub.add_parser("tool-plan", help="Prepare a private scanner command; NEVER executes it")
    tool_plan.add_argument("program")
    tool_plan.add_argument("--tool", choices=TOOLS, required=True)
    tool_plan.add_argument("--url", required=True)
    tool_plan.add_argument("--parameter", required=True)
    tool_plan.add_argument("--script", type=Path, help="Reviewed sqlmap.py or xsstrike.py; Dalfox plans target version 3")
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
    report.set_defaults(func=cmd_report)

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
        raise ValueError("This external tool requires a whole-number rate of at least 1. Use request/xss for fractional rates.")
    return int(rate)


def positive_int(value: str) -> int:
    number = int(value)
    if number <= 0:
        raise argparse.ArgumentTypeError("Must be a positive integer.")
    return number


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
    except (ToolkitError, ValueError, OSError, RuntimeError, yaml.YAMLError) as exc:
        if logger:
            logger.error("Failed %s (%s)", args.func.__name__, type(exc).__name__)
        parser.exit(1, f"Error: {exc}\n")
    except KeyboardInterrupt:
        parser.exit(130, "Interrupted.\n")


if __name__ == "__main__":
    main()
