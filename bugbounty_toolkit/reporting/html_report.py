from __future__ import annotations

from html import escape
import json
from pathlib import Path

from ..core.records import RecordStore
from .json_report import build_program_report


def render_html_report(store: RecordStore, destination: Path) -> Path:
    report = build_program_report(store)
    counts = report["counts"]
    rows = "\n".join(
        f"<tr><td>{escape(str(run['started_at']))}</td><td>{escape(str(run['command_name']))}</td>"
        f"<td>{escape(str(run['target'] or ''))}</td><td>{escape(str(run['return_code']))}</td>"
        f"<td>{escape(str(run['output_path'] or ''))}</td></tr>"
        for run in report["runs"]
    )
    findings = "\n".join(
        f"<tr><td>{escape(str(item['id']))}</td><td>{escape(str(item['severity']))}</td>"
        f"<td>{escape(str(item['title']))}</td><td>{escape(str(item['status']))}</td></tr>"
        for item in report["findings"]
    )
    evidence = "\n".join(
        f"<details><summary>{escape(str(item['path']))}</summary>"
        f"<pre>{escape(json.dumps(item.get('data', item.get('error')), indent=2))}</pre></details>"
        for item in report["evidence"]
    )
    html = f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Bug Bounty Toolkit Report - {escape(str(report["program"]))}</title>
  <style>
    body {{ font-family: Arial, sans-serif; margin: 24px; color: #17202a; max-width: 1200px; }}
    h1, h2 {{ color: #102a43; }}
    .stats {{ display: flex; flex-wrap: wrap; gap: 12px; margin: 20px 0; }}
    .stat {{ border: 1px solid #d9e2ec; border-radius: 6px; padding: 12px 16px; }}
    table {{ border-collapse: collapse; width: 100%; margin: 16px 0 28px; }}
    th, td {{ border: 1px solid #d9e2ec; padding: 8px; text-align: left; font-size: 14px; }}
    th {{ background: #f0f4f8; }}
    td, p, summary {{ overflow-wrap: anywhere; }}
    pre {{ white-space: pre-wrap; overflow-wrap: anywhere; font-size: 12px; padding: 12px; background: #f5f5f5; }}
    details {{ margin: 12px 0; }}
  </style>
</head>
<body>
  <h1>Bug Bounty Toolkit Report</h1>
  <p><strong>Program:</strong> {escape(str(report["program"]))}</p>
  <p><strong>Records path:</strong> {escape(str(report["records_path"]))}</p>
  <p><strong>Allowed scope:</strong> {escape(", ".join(report["scope"]["allowed"]))}</p>
  <p><strong>Exclusions:</strong> {escape(", ".join(report["scope"]["excluded"]))}</p>
  <div class="stats">
    <div class="stat"><strong>{counts["runs"]}</strong><br>Runs</div>
    <div class="stat"><strong>{counts["reviewed"]}</strong><br>Reviewed</div>
    <div class="stat"><strong>{counts["findings"]}</strong><br>Findings</div>
  </div>
  <h2>Recent Runs</h2>
  <table>
    <thead><tr><th>Started</th><th>Command</th><th>Target</th><th>Code</th><th>Output</th></tr></thead>
    <tbody>{rows or "<tr><td colspan='5'>No runs recorded.</td></tr>"}</tbody>
  </table>
  <h2>Findings</h2>
  <table>
    <thead><tr><th>ID</th><th>Severity</th><th>Title</th><th>Status</th></tr></thead>
    <tbody>{findings or "<tr><td colspan='4'>No findings recorded.</td></tr>"}</tbody>
  </table>
  <h2>Request, Fuzzing and XSS Evidence</h2>
  {evidence or "<p>No JSON evidence recorded.</p>"}
</body>
</html>
"""
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(html, encoding="utf-8")
    return destination
