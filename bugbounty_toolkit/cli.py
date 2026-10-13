from __future__ import annotations

import argparse
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
    options = XssOptions(args.routes, args.parameters, args.base_url, args.max_tests or settings.max_tests, headers)
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
        print("[!] Test budget reached; remaining inputs were not tested.")


def cmd_params(args: argparse.Namespace) -> None:
    store, _, _ = executor_context(args, automated=True)
    ensure_in_scope(args.url, store.paths.scope_file)
    paramspider = run_tool(store, "paramspider", args.url, ["paramspider", "-d", args.url])
    arjun = run_tool(store, "arjun", args.url, ["arjun", "-u", args.url])
    store.mark_reviewed("parameter-target", args.url, "paramspider and arjun executed")
    print(f"[+] Parameter analysis complete: {paramspider}, {arjun}")


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
    xss.add_argument("--dry-run", action="store_true")
    xss.set_defaults(func=cmd_xss)

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
