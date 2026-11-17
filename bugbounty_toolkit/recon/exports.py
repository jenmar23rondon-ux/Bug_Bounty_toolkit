"""SARIF review notes and an offline HTML dashboard. These are not confirmed findings."""

from __future__ import annotations

from html import escape
import json
from pathlib import Path

from bugbounty_toolkit import __version__

from .leads import AssetGroup, Lead
from .models import ReconReport
from .reporting import INVENTORY_NOTICE

_RULES = {
    "admin-panel": "A hostname or historical URL resembles an admin or management path. Lead only.",
    "staging-or-dev": "A hostname label looks like staging or development. Lead only.",
    "exposed-service": "InternetDB lists a sensitive port. The port was not probed. Lead only.",
    "outdated-tech": "A source recorded a CVE identifier or a technology version to review. Lead only.",
}


def render_sarif(report: ReconReport, leads: list[Lead]) -> str:
    rules = [
        {
            "id": rule_id,
            "shortDescription": {"text": text},
            "help": {"text": text + " Not a confirmed vulnerability."},
            "properties": {"confirmed": False},
        }
        for rule_id, text in _RULES.items()
    ]
    results = []
    for lead in leads:
        results.append(
            {
                "ruleId": lead.category,
                "level": "note",
                "kind": "review",
                "message": {"text": (f"{lead.title}. {lead.detail} Lead only. Not a confirmed vulnerability.")},
                "locations": [{"logicalLocations": [{"name": lead.host, "kind": "host"}]}],
                "properties": {"confirmed": False, "category": lead.category, "leadId": lead.lead_id},
            }
        )
    document = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "bbtk",
                        "version": __version__,
                        "rules": rules,
                    }
                },
                "properties": {
                    "confirmed": False,
                    "target": report.target,
                    "notice": INVENTORY_NOTICE,
                },
                "results": results,
            }
        ],
    }
    return json.dumps(document, indent=2, sort_keys=True) + "\n"


def render_dashboard_html(
    report: ReconReport,
    leads: list[Lead],
    groups: list[AssetGroup],
    stages: dict[str, str],
    diff: dict[str, object],
) -> str:
    counts = {category: sum(1 for lead in leads if lead.category == category) for category in _RULES}
    cards = [
        ("Assets", str(len(report.assets))),
        ("Leads", str(len(leads))),
        ("Confirmed", "0"),
        ("Provider requests", str(report.requests_sent)),
        ("Dropped out of scope", str(report.dropped)),
        ("Errors", str(len(report.errors))),
    ]
    card_html = "\n".join(
        f'<div class="card"><span>{escape(label)}</span><strong>{escape(value)}</strong></div>'
        for label, value in cards
    )
    stage_html = "\n".join(f"<li><code>{escape(name)}</code> {escape(state)}</li>" for name, state in stages.items())
    lead_rows = (
        "\n".join(
            "<tr>"
            f"<td>{escape(lead.category)}</td>"
            f"<td>{escape(lead.host)}</td>"
            f"<td>{escape(lead.title)}</td>"
            f"<td>{escape(lead.detail)}</td>"
            "<td>false</td>"
            "</tr>"
            for lead in leads
        )
        or "<tr><td colspan='5'>No leads.</td></tr>"
    )
    group_rows = (
        "\n".join(
            "<tr>"
            f"<td>{escape(group.kind)}</td>"
            f"<td>{escape(group.key)}</td>"
            f"<td>{escape(', '.join(group.members))}</td>"
            "</tr>"
            for group in groups
            if group.kind != "host"
        )
        or "<tr><td colspan='3'>No IP or technology groups.</td></tr>"
    )
    asset_rows = (
        "\n".join(
            "<tr>"
            f"<td>{escape(asset.host)}</td>"
            f"<td>{escape(asset.severity)}</td>"
            f"<td>{asset.score}</td>"
            f"<td>{escape(', '.join(sorted(asset.sources)))}</td>"
            f"<td>{escape('; '.join(asset.reasons))}</td>"
            "</tr>"
            for asset in report.assets
        )
        or "<tr><td colspan='5'>No in-scope assets were collected.</td></tr>"
    )
    error_html = "\n".join(f"<li>{escape(error)}</li>" for error in report.errors) or "<li>None.</li>"
    diff_html = _diff_html(diff)
    chip_html = "\n".join(
        f'<span class="chip">{escape(category)}: {count}</span>' for category, count in counts.items()
    )
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Recon dashboard for {escape(report.target)}</title>
  <style>
    :root {{ color-scheme: light; }}
    body {{ margin: 0; font-family: "Segoe UI", Helvetica, Arial, sans-serif; background: #f3f6f8; color: #1c2833; }}
    main {{ max-width: 1100px; margin: 0 auto; padding: 32px 20px 64px; }}
    h1 {{ font-size: 1.8rem; margin-bottom: 8px; }}
    h2 {{ margin-top: 32px; font-size: 1.15rem; }}
    .notice {{ background: #fff; border-left: 4px solid #1f6feb; padding: 14px 16px; }}
    .cards {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 12px; margin: 20px 0; }}
    .card {{ background: #fff; padding: 14px; border: 1px solid #d8e0e8; }}
    .card span {{ display: block; color: #52606d; font-size: 0.85rem; }}
    .card strong {{ font-size: 1.5rem; }}
    .chips {{ display: flex; flex-wrap: wrap; gap: 8px; }}
    .chip {{ background: #e8eef5; border-radius: 999px; padding: 4px 10px; font-size: 0.85rem; }}
    table {{ width: 100%; border-collapse: collapse; background: #fff; }}
    th, td {{ border: 1px solid #d8e0e8; padding: 8px; text-align: left; vertical-align: top; }}
    th {{ background: #eef3f8; }}
    code {{ font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }}
  </style>
</head>
<body>
  <main>
    <h1>Recon dashboard for {escape(report.target)}</h1>
    <p class="notice">{escape(INVENTORY_NOTICE)} Confirmed vulnerabilities: 0. Leads are triage hints.</p>
    <section class="cards">{card_html}</section>
    <p class="chips">{chip_html}</p>
    <h2>Pipeline</h2>
    <ul>{stage_html}</ul>
    <h2>Changes since the previous run</h2>
    {diff_html}
    <h2>Leads</h2>
    <table>
      <thead><tr><th>Category</th><th>Host</th><th>Title</th><th>Detail</th><th>Confirmed</th></tr></thead>
      <tbody>{lead_rows}</tbody>
    </table>
    <h2>Groups by IP and technology</h2>
    <table>
      <thead><tr><th>Kind</th><th>Key</th><th>Hosts</th></tr></thead>
      <tbody>{group_rows}</tbody>
    </table>
    <h2>Assets by host</h2>
    <table>
      <thead><tr><th>Host</th><th>Signal</th><th>Score</th><th>Sources</th><th>Reasons</th></tr></thead>
      <tbody>{asset_rows}</tbody>
    </table>
    <h2>Errors</h2>
    <ul>{error_html}</ul>
  </main>
</body>
</html>
"""


def _diff_html(diff: dict[str, object]) -> str:
    if diff.get("baseline_present") is not True:
        return "<p>No previous run. This report is the baseline.</p>"
    parts = [
        f"<p>New hosts: {len(_strings(diff.get('new_hosts')))}. "
        f"Removed hosts: {len(_strings(diff.get('removed_hosts')))}. "
        f"New URLs: {len(_strings(diff.get('new_urls')))}. "
        f"New leads: {len(_strings(diff.get('new_lead_ids')))}. "
        f"Leads no longer present: {len(_strings(diff.get('resolved_lead_ids')))}.</p>"
    ]
    new_hosts = _strings(diff.get("new_hosts"))
    if new_hosts:
        items = "\n".join(f"<li>{escape(host)}</li>" for host in new_hosts[:30])
        parts.append(f"<ul>{items}</ul>")
    return "\n".join(parts)


def _strings(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, str)]


def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(text, encoding="utf-8")
    temporary.replace(path)
