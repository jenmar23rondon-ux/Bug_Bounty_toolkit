"""HackerOne-style draft reports. The toolkit never submits them."""

from __future__ import annotations

from html import escape
import re
from pathlib import Path
from typing import Mapping

from ..core.redaction import RedactionDestination, redact_data

_CVSS_VECTOR = re.compile(
    r"^CVSS:3\.[01]/AV:[NALP]/AC:[LH]/PR:[NLH]/UI:[NR]/S:[UC]/C:[NLH]/I:[NLH]/A:[NLH](?:/[A-Za-z0-9:._-]+)*$"
)
_NOTICE = (
    "Draft for researcher review. This file is not submitted to HackerOne or any other platform. "
    "Confirm the asset is in scope and the steps reproduce before you send it."
)
_REMEDIATION = {
    "access-control": "Enforce server-side authorization on every object and action.",
    "broken-access-control": "Enforce server-side authorization on every object and action.",
    "cors": "Allow only trusted origins, and do not reflect arbitrary origins on credentialed responses.",
    "csrf": "Use the framework CSRF defense and an appropriate SameSite cookie policy.",
    "csrf-audit": "Use the framework CSRF defense and an appropriate SameSite cookie policy.",
    "information-disclosure": "Return only the fields the caller is authorized to receive.",
    "jwt": "Allowlist signature algorithms and validate issuer, audience, expiry, and key use.",
    "open-redirect": "Allow only relative destinations or an exact destination allowlist.",
    "sqli": "Use parameterized queries. Do not build SQL from untrusted input.",
    "ssrf": "Allowlist outbound destinations and block link-local, loopback, and metadata addresses.",
    "xss": "Encode output for the HTML context that receives it, and prefer safe DOM APIs.",
}


def validate_cvss(value: str | None) -> str | None:
    if value is None or not str(value).strip():
        return None
    text = str(value).strip()
    if _CVSS_VECTOR.fullmatch(text):
        return text
    try:
        score = float(text)
    except ValueError as exc:
        raise ValueError("CVSS must be a 3.0/3.1 base vector or a number from 0.0 to 10.0.") from exc
    if score < 0 or score > 10:
        raise ValueError("CVSS score must be between 0.0 and 10.0.")
    return f"{score:.1f}"


def _clean(value: object, fallback: str) -> str:
    if isinstance(value, str) and value.strip():
        return value.strip()
    return fallback


def _fields(finding: Mapping[str, object]) -> dict[str, str]:
    shared = redact_data(dict(finding), destination=RedactionDestination.SHAREABLE_REPORT)
    data = shared if isinstance(shared, dict) else {}
    category = _clean(data.get("category"), "unspecified").lower()
    return {
        "id": _clean(data.get("id"), "DRAFT"),
        "title": _clean(data.get("title"), "Untitled finding"),
        "severity": _clean(data.get("severity"), "unspecified"),
        "cvss": _clean(data.get("cvss"), "not scored"),
        "category": category,
        "target": _clean(data.get("target"), "Not recorded"),
        "summary": _clean(data.get("summary"), "Not recorded."),
        "steps": _clean(
            data.get("steps"),
            "Not recorded. Add the requests you are authorized to reproduce before submitting.",
        ),
        "impact": _clean(
            data.get("impact"),
            "Not recorded. Describe the effect on confidentiality, integrity, or availability.",
        ),
        "evidence": _clean(data.get("evidence_path"), "Evidence path not attached yet."),
        "remediation": _clean(
            data.get("remediation"),
            _REMEDIATION.get(category, "Apply the control the program expects for this issue class."),
        ),
    }


def render_submission_markdown(finding: Mapping[str, object]) -> str:
    item = _fields(finding)
    lines = [
        f"# {item['id']} - {item['title']}",
        "",
        f"> {_NOTICE}",
        "",
        "## Severity",
        f"{item['severity']} (CVSS: {item['cvss']})",
        "",
        "## Affected asset",
        item["target"],
        "",
        "## Summary",
        item["summary"],
        "",
        "## Steps to reproduce",
        item["steps"],
        "",
        "## Impact",
        item["impact"],
        "",
        "## Evidence",
        item["evidence"],
        "",
        "## Remediation",
        item["remediation"],
        "",
        f"Category: {item['category']}",
        "",
    ]
    return "\n".join(lines)


def render_submission_html(finding: Mapping[str, object]) -> str:
    item = _fields(finding)
    sections = [
        ("Severity", f"{item['severity']} (CVSS: {item['cvss']})"),
        ("Affected asset", item["target"]),
        ("Summary", item["summary"]),
        ("Steps to reproduce", item["steps"]),
        ("Impact", item["impact"]),
        ("Evidence", item["evidence"]),
        ("Remediation", item["remediation"]),
    ]
    body = "\n".join(f"<h2>{escape(title)}</h2>\n<p>{escape(text)}</p>" for title, text in sections)
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>{escape(item["id"])} - {escape(item["title"])}</title>
  <style>
    body {{ font-family: Georgia, serif; margin: 32px auto; max-width: 800px; color: #1b2430; line-height: 1.5; }}
    .notice {{ background: #f4f7fb; border-left: 4px solid #2458a6; padding: 12px 16px; }}
    h1, h2 {{ font-family: Arial, sans-serif; }}
  </style>
</head>
<body>
  <h1>{escape(item["id"])} - {escape(item["title"])}</h1>
  <p class="notice">{escape(_NOTICE)}</p>
  {body}
  <p>Category: {escape(item["category"])}</p>
</body>
</html>
"""


def write_submission_html(finding: Mapping[str, object], destination: Path) -> Path:
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(render_submission_html(finding), encoding="utf-8")
    return destination
