"""Asset inventory reports. These are not vulnerability submissions."""

from __future__ import annotations

from collections.abc import Collection
from html import escape
import json
from pathlib import Path

from .models import ReconReport

_NOTICE = (
    "Asset inventory only. Scores are unconfirmed exposure signals for triage. "
    "Nothing here was submitted to a bug bounty platform, and no vulnerability is confirmed."
)
INVENTORY_NOTICE = _NOTICE


def render_recon_markdown(report: ReconReport) -> str:
    lines = [
        f"# Recon inventory for {report.target}",
        "",
        f"> {_NOTICE}",
        "",
        f"- Dry run: {str(report.dry_run).lower()}",
        f"- Active probing: {str(report.active).lower()}",
        f"- Nuclei: {str(report.nuclei).lower()}",
        f"- Provider requests sent: {report.requests_sent}",
        f"- Names dropped as out of scope: {report.dropped}",
        "",
        "## Provider plan",
        "",
    ]
    if not report.plans:
        lines.append("No passive provider was applicable for this target.")
    for plan in report.plans:
        state = plan.skipped or "ready"
        lines.append(f"- `{plan.source}` ({state}): {plan.url}")
    lines.extend(["", "## Errors", ""])
    if report.errors:
        lines.extend(f"- {error}" for error in report.errors)
    else:
        lines.append("None.")
    lines.extend(["", "## Assets", ""])
    if not report.assets:
        lines.append("No in-scope assets were collected.")
    for asset in report.assets:
        lines.append(f"### {asset.host}")
        lines.append("")
        lines.append(f"- Severity signal: {asset.severity} (score {asset.score}, confirmed: false)")
        lines.append(f"- Sources: {', '.join(sorted(asset.sources)) or 'none'}")
        if asset.urls:
            lines.append("- URLs:")
            lines.extend(f"  - {url}" for url in asset.urls)
        if asset.ports:
            lines.append(f"- InternetDB ports (not probed): {', '.join(str(port) for port in sorted(asset.ports))}")
        if asset.cves:
            lines.append(f"- InternetDB CVE identifiers (not confirmed): {', '.join(asset.cves)}")
        if asset.nuclei:
            lines.append(f"- Nuclei template ids (not confirmed): {', '.join(asset.nuclei)}")
        if asset.reasons:
            lines.append("- Why this score:")
            lines.extend(f"  - {reason}" for reason in asset.reasons)
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def render_recon_html(report: ReconReport) -> str:
    rows = []
    for asset in report.assets:
        rows.append(
            "<tr>"
            f"<td>{escape(asset.host)}</td>"
            f"<td>{escape(asset.severity)}</td>"
            f"<td>{asset.score}</td>"
            f"<td>{escape(', '.join(sorted(asset.sources)))}</td>"
            f"<td>{escape('; '.join(asset.reasons))}</td>"
            "</tr>"
        )
    body = "\n".join(rows) or "<tr><td colspan='5'>No in-scope assets were collected.</td></tr>"
    errors = "\n".join(f"<li>{escape(error)}</li>" for error in report.errors) or "<li>None.</li>"
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Recon inventory for {escape(report.target)}</title>
  <style>
    body {{ font-family: Georgia, serif; margin: 32px auto; max-width: 960px; color: #1b2430; line-height: 1.45; }}
    table {{ border-collapse: collapse; width: 100%; }}
    th, td {{ border: 1px solid #d5dde6; padding: 8px; text-align: left; vertical-align: top; }}
    th {{ background: #f4f7fb; }}
    .notice {{ background: #f4f7fb; border-left: 4px solid #2458a6; padding: 12px 16px; }}
  </style>
</head>
<body>
  <h1>Recon inventory for {escape(report.target)}</h1>
  <p class="notice">{escape(_NOTICE)}</p>
  <p>Provider requests sent: {report.requests_sent}. Out-of-scope names dropped: {report.dropped}.</p>
  <h2>Errors</h2>
  <ul>{errors}</ul>
  <h2>Assets</h2>
  <table>
    <thead><tr><th>Host</th><th>Signal</th><th>Score</th><th>Sources</th><th>Reasons</th></tr></thead>
    <tbody>{body}</tbody>
  </table>
</body>
</html>
"""


def write_recon_reports(
    report: ReconReport, directory: Path, *, formats: Collection[str] | None = None
) -> dict[str, Path]:
    directory.mkdir(parents=True, exist_ok=True)
    selected = {"markdown", "html", "json"} if formats is None else set(formats)
    written: dict[str, Path] = {}
    if "markdown" in selected:
        markdown = directory / "recon.md"
        markdown.write_text(render_recon_markdown(report), encoding="utf-8")
        written["markdown"] = markdown
    if "html" in selected:
        html = directory / "recon.html"
        html.write_text(render_recon_html(report), encoding="utf-8")
        written["html"] = html
    if "json" in selected:
        payload = directory / "recon.json"
        payload.write_text(json.dumps(report.to_dict(), indent=2, sort_keys=True) + "\n", encoding="utf-8")
        written["json"] = payload
    return written
