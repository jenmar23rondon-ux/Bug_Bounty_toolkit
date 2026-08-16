from __future__ import annotations

import argparse
from pathlib import Path

from .core.checks import render_checklist
from .core.records import ProgramPaths, RecordStore
from .core.reporting import render_markdown, render_pdf
from .core.runner import run_tool
from .core.scope import ensure_in_scope


RECORDS_ROOT = Path("registros")


def store_for(program: str) -> RecordStore:
    return RecordStore(ProgramPaths(RECORDS_ROOT, program))


def cmd_init(args: argparse.Namespace) -> None:
    store = store_for(args.program)
    store.set_program_meta(platform=args.platform, authorization=args.authorization)
    print(f"[+] Program initialized: {store.paths.program_dir}")


def cmd_scope_add(args: argparse.Namespace) -> None:
    store = store_for(args.program)
    current = store.paths.scope_file.read_text(encoding="utf-8").splitlines() if store.paths.scope_file.exists() else []
    if args.domain not in current:
        with store.paths.scope_file.open("a", encoding="utf-8") as handle:
            handle.write(f"{args.domain}\n")
    store.mark_reviewed("scope", args.domain, "Authorized scope rule added")
    print(f"[+] Scope added: {args.domain}")


def cmd_recon(args: argparse.Namespace) -> None:
    store = store_for(args.program)
    ensure_in_scope(args.target, store.paths.scope_file)
    subfinder = run_tool(store, "subfinder", args.target, ["subfinder", "-silent", "-d", args.target])
    amass = run_tool(store, "amass", args.target, ["amass", "enum", "-passive", "-d", args.target])
    merged = store.paths.raw_dir / "subdomains.txt"
    values = set()
    for path in [subfinder, amass]:
        values.update(line.strip() for line in path.read_text(encoding="utf-8", errors="ignore").splitlines() if line.strip())
    merged.write_text("\n".join(sorted(values)) + "\n", encoding="utf-8")
    httpx = run_tool(store, "httpx", args.target, ["httpx", "-silent", "-l", str(merged)])
    print(f"[+] Recon complete. Live host output: {httpx}")


def cmd_scan_nuclei(args: argparse.Namespace) -> None:
    store = store_for(args.program)
    hosts = store.paths.raw_dir / "subdomains.txt"
    if not hosts.exists():
        raise SystemExit("Run recon first; missing registros/<program>/raw/subdomains.txt")
    output = run_tool(store, "nuclei", None, ["nuclei", "-l", str(hosts), "-severity", args.severity])
    print(f"[+] Nuclei scan complete: {output}")


def cmd_fuzz(args: argparse.Namespace) -> None:
    store = store_for(args.program)
    ensure_in_scope(args.url, store.paths.scope_file)
    output = run_tool(store, "ffuf", args.url, ["ffuf", "-u", args.url, "-w", args.wordlist, "-of", "json"])
    store.mark_reviewed("fuzz-url", args.url, f"Wordlist: {args.wordlist}")
    print(f"[+] Fuzzing complete: {output}")


def cmd_params(args: argparse.Namespace) -> None:
    store = store_for(args.program)
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
    finding = store.finding(args.finding_id)
    if not finding:
        raise SystemExit(f"Finding not found: {args.finding_id}")
    markdown = render_markdown(finding, store.paths.reports_dir / f"{args.finding_id}.md")
    pdf = render_pdf(markdown, store.paths.reports_dir / f"{args.finding_id}.pdf")
    store.mark_reviewed("report", args.finding_id, str(pdf))
    print(f"[+] Report created: {pdf}")


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
    sub = parser.add_subparsers(required=True)

    init = sub.add_parser("init")
    init.add_argument("program")
    init.add_argument("--platform", default="hackerone")
    init.add_argument("--authorization", required=True)
    init.set_defaults(func=cmd_init)

    scope = sub.add_parser("scope")
    scope_sub = scope.add_subparsers(required=True)
    scope_add = scope_sub.add_parser("add")
    scope_add.add_argument("program")
    scope_add.add_argument("domain")
    scope_add.set_defaults(func=cmd_scope_add)

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
    fuzz.add_argument("--wordlist", required=True)
    fuzz.set_defaults(func=cmd_fuzz)

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
    report.add_argument("--finding-id", required=True)
    report.set_defaults(func=cmd_report)

    status = sub.add_parser("status")
    status.add_argument("program")
    status.set_defaults(func=cmd_status)
    return parser


def main() -> None:
    args = build_parser().parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
