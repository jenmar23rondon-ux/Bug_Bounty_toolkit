from __future__ import annotations

from hashlib import sha256
from html import escape
import json
from pathlib import Path
import tempfile
from typing import Any

from ..core.redaction import redact_data
from ..core.reporting import render_pdf

PENDING = "Información pendiente"
REPORT_NOTICE = (
    "Draft only. Resume la evidencia proporcionada; no reproduce tráfico, no verifica el alcance y no envía reportes. "
    "Nothing is sent to a platform."
)
_CWE_BY_CATEGORY = {
    "access-control": "CWE-639",
    "broken-access-control": "CWE-284",
    "cors": "CWE-942",
    "csrf": "CWE-352",
    "csrf-audit": "CWE-352",
    "information-disclosure": "CWE-200",
    "jwt": "CWE-347",
    "open-redirect": "CWE-601",
    "sqli": "CWE-89",
    "ssrf": "CWE-918",
    "xss": "CWE-79",
}
_REMEDIATION_BY_CATEGORY = {
    "access-control": "Enforce server-side authorization and resource ownership checks on every object operation.",
    "broken-access-control": "Enforce least privilege and server-side authorization for every protected action.",
    "cors": "Allow only explicitly trusted origins; do not combine credentialed requests with a broad origin policy.",
    "csrf": "Use framework CSRF defenses and appropriate SameSite cookie settings for state-changing requests.",
    "csrf-audit": "Use framework CSRF defenses and appropriate SameSite cookie settings for state-changing requests.",
    "information-disclosure": "Restrict sensitive data to authorized callers and return only fields required by the client.",
    "jwt": "Use an explicit allowlist of signature algorithms and validate issuer, audience, expiry and key purpose.",
    "open-redirect": "Accept only relative destinations or destinations matched against a strict allowlist.",
    "sqli": "Use parameterized queries and avoid constructing SQL statements from untrusted input.",
    "ssrf": "Restrict outbound destinations with an allowlist and block loopback, link-local and metadata ranges.",
    "xss": "Apply context-aware output encoding and safe DOM APIs; use CSP only as defense in depth.",
}
_CANDIDATE = {
    "candidate",
    "possible",
    "possible_unauthorized_access",
    "possible_takeover",
    "reflected_not_executed",
    "vulnerable",
    "weak",
}
_NOT_OBSERVED = {
    "denied",
    "not_observed",
    "not_reproducible",
    "not_vulnerable",
    "public_endpoint",
    "rejected_in_this_test",
    "safe",
}
_INCONCLUSIVE = {"error", "inconclusive", "insufficient_evidence", "unavailable", "unparsed"}


def _text(value: object, fallback: str = PENDING, limit: int = 4_000) -> str:
    safe = redact_data(value)
    if isinstance(safe, str):
        normalized = safe.strip()
    elif isinstance(safe, (int, float, bool)):
        normalized = str(safe)
    else:
        normalized = ""
    return normalized[:limit] or fallback


def _string_list(value: object, fallback: str | None = None) -> list[str]:
    if not isinstance(value, list):
        return [fallback] if fallback else []
    output = [_text(item) for item in value if item is not None]
    return output or ([fallback] if fallback else [])


def _evidence_items(value: object) -> list[dict[str, str]]:
    if not isinstance(value, list):
        return []
    rows: list[dict[str, str]] = []
    for item in value[:100]:
        if isinstance(item, dict):
            rows.append(
                {
                    "record_id": _text(item.get("record_id", item.get("evidence_id"))),
                    "why": _text(item.get("why", item.get("summary"))),
                }
            )
        elif isinstance(item, str):
            rows.append({"record_id": PENDING, "why": _text(item)})
    return rows


def _rows(data: dict[str, Any], key: str) -> list[dict[str, Any]]:
    value = data.get(key)
    return [row for row in value if isinstance(row, dict)][:100] if isinstance(value, list) else []


def _xss_execution_validated(rows: list[dict[str, Any]]) -> bool:
    for row in rows:
        execution = row.get("execution")
        if (
            row.get("classification") == "confirmed"
            and row.get("confirmed") is True
            and row.get("browser_execution_observed") is True
            and isinstance(execution, dict)
            and execution.get("classification") == "confirmed"
            and (execution.get("marker_observed") is True or execution.get("alert_observed") is True)
        ):
            return True
    return False


def _validation(data: dict[str, Any], category: str) -> tuple[str, list[str]]:
    results = _rows(data, "results")
    if category == "xss" and _xss_execution_validated(results):
        return "validated", [
            "The native XSS result records confirmed classification, browser execution, and an observed harmless marker or alert.",
            "This validates script execution in the recorded browser run; it does not independently establish scope or impact.",
        ]

    labels = [row.get("classification") for row in results]
    if not labels and isinstance(data.get("classification"), str):
        labels = [data["classification"]]
    normalized = [str(label).strip().lower().replace(" ", "_") for label in labels if isinstance(label, str)]
    if any(label in _CANDIDATE for label in normalized):
        return "candidate", [
            "The supplied evidence records a candidate signal; this report does not confirm a vulnerability."
        ]
    if normalized and all(label in _NOT_OBSERVED for label in normalized):
        return "not_observed", [
            "This test recorded no vulnerability signal; that does not prove the asset is free of the issue."
        ]
    if any(label in _INCONCLUSIVE for label in normalized) or not normalized:
        return "inconclusive", ["The supplied evidence does not satisfy a deterministic validation rule."]
    return "inconclusive", ["The supplied classification is not accepted as technical validation by itself."]


def _observation_rows(data: dict[str, Any]) -> list[dict[str, object]]:
    fields = (
        "step",
        "account",
        "method",
        "status_code",
        "duration_ms",
        "application_success",
        "owner_resource_match",
        "actor_resource_match",
        "owner_private_match",
        "actor_private_match",
        "classification",
        "reason",
    )
    output: list[dict[str, object]] = []
    for row in _rows(data, "steps") + _rows(data, "results"):
        safe = {field: redact_data(row[field]) for field in fields if field in row}
        if safe:
            output.append(safe)
    return output


def build_evidence_finding_report(
    data: dict[str, Any], program: str = PENDING, source_name: str | None = None
) -> dict[str, object]:
    """Build a redacted, schema-stable report draft without promoting model opinions."""
    safe_data = redact_data(data)
    if not isinstance(safe_data, dict):
        raise ValueError("Evidence must be a JSON object.")

    raw_category = _text(safe_data.get("category", safe_data.get("type")), "unknown").lower()
    category = raw_category.replace("_", "-")
    validation_state, validation_basis = _validation(safe_data, category)
    endpoint_value = safe_data.get("endpoint", safe_data.get("url", safe_data.get("target")))
    result_rows = _rows(safe_data, "results")
    if endpoint_value is None:
        endpoint_value = next(
            (
                row.get("endpoint", row.get("route", row.get("url", row.get("target"))))
                for row in result_rows
                if any(row.get(k) for k in ("endpoint", "route", "url", "target"))
            ),
            None,
        )
    method_value = safe_data.get("method")
    if method_value is None:
        methods = sorted({str(row["method"]) for row in result_rows if isinstance(row.get("method"), str)})
        method_value = ", ".join(methods) if methods else None

    evidence_ids: set[str] = set()
    for key in ("evidence_id", "record_id", "run_id"):
        if isinstance(safe_data.get(key), str):
            evidence_ids.add(str(safe_data[key]))
    records = safe_data.get("records")
    if isinstance(records, list):
        evidence_ids.update(
            row["evidence_id"] for row in records if isinstance(row, dict) and isinstance(row.get("evidence_id"), str)
        )
    if not evidence_ids:
        stable = json.dumps(safe_data, ensure_ascii=True, sort_keys=True, default=str).encode("utf-8")
        evidence_ids.add(f"DRAFT-{sha256(stable).hexdigest()[:12]}")

    sources: set[str] = set()
    tools = safe_data.get("source_tools", safe_data.get("source"))
    if isinstance(tools, str):
        sources.add(_text(tools))
    elif isinstance(tools, list):
        sources.update(_text(item) for item in tools if isinstance(item, str))
    if isinstance(records, list):
        for record in records:
            if isinstance(record, dict) and isinstance(record.get("source_tools"), list):
                sources.update(_text(item) for item in record["source_tools"] if isinstance(item, str))
    if source_name:
        sources.add(_text(Path(source_name).name))

    cwe = _CWE_BY_CATEGORY.get(category, PENDING)
    if category == "unknown":
        category = PENDING
    title = _text(safe_data.get("title"), f"Draft review: {category}")
    summary = _text(safe_data.get("summary", safe_data.get("hypothesis")))
    impact = _text(safe_data.get("impact_demonstrated", safe_data.get("impact")))
    impact_basis = _text(safe_data.get("impact_basis"))
    severity = _text(safe_data.get("severity_suggested", safe_data.get("severity")))
    severity_basis = _text(safe_data.get("severity_basis", safe_data.get("severity_rationale")))
    expected = _text(safe_data.get("expected_result", safe_data.get("expected")))
    observed = _text(safe_data.get("observed_result", safe_data.get("reason")))
    if observed == PENDING:
        observed = _text(safe_data.get("classification"))
    preconditions = _string_list(safe_data.get("preconditions"), PENDING)
    reproduction = _string_list(safe_data.get("steps_to_reproduce", safe_data.get("reproduction_steps")), PENDING)
    controls = _string_list(safe_data.get("negative_controls"), None)
    controls.extend(
        _text(row.get("step"))
        for row in _rows(safe_data, "steps")
        if isinstance(row.get("step"), str)
        and any(term in row["step"].lower() for term in ("negative", "public", "control_negative"))
    )
    if not controls:
        controls = [PENDING]

    limitations = _string_list(safe_data.get("limitations"), None)
    limitations.append(
        "This draft summarizes supplied evidence; it does not independently reproduce requests or verify program authorization."
    )
    remediation = _text(safe_data.get("remediation_recommendation", safe_data.get("remediation")))
    if remediation == PENDING:
        remediation = _REMEDIATION_BY_CATEGORY.get(category, PENDING)

    report: dict[str, object] = {
        "type": "evidence-finding-report",
        "schema_version": "1.0",
        "notice": REPORT_NOTICE,
        "program": _text(program),
        "finding_id": _text(safe_data.get("finding_id"), next(iter(sorted(evidence_ids)))),
        "title": title,
        "summary": summary,
        "validation_state": validation_state,
        "validation_basis": validation_basis,
        "asset": _text(safe_data.get("asset", safe_data.get("host"))),
        "endpoint": _text(endpoint_value),
        "method": _text(method_value),
        "category": category,
        "cwe": _text(safe_data.get("cwe"), cwe),
        "preconditions": preconditions,
        "hypothesis": _text(safe_data.get("hypothesis", safe_data.get("summary"))),
        "expected_result": expected,
        "observed_result": observed,
        "evidence_for": _evidence_items(safe_data.get("evidence_for", safe_data.get("supporting_evidence"))),
        "evidence_against": _evidence_items(safe_data.get("evidence_against", safe_data.get("contradictory_evidence"))),
        "negative_controls": controls,
        "observations": _observation_rows(safe_data),
        "reproduction_steps": reproduction,
        "impact_demonstrated": impact,
        "impact_basis": impact_basis,
        "severity_suggested": severity,
        "severity_basis": severity_basis,
        "severity_assessed_by_toolkit": False,
        "remediation_recommendation": remediation,
        "limitations": limitations,
        "evidence_references": sorted(evidence_ids),
        "evidence_sources": sorted(sources),
        "ai_review": safe_data.get("ai_review", PENDING),
        "submitted": False,
    }
    return report


def _display(value: object) -> str:
    if value is None:
        return PENDING
    safe = redact_data(value)
    if isinstance(safe, (dict, list)):
        return json.dumps(safe, ensure_ascii=True, sort_keys=True)
    return str(safe).replace("\r", " ").replace("\n", " ")


def _markdown_text(value: object) -> str:
    text = _display(value).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    text = text.replace("\\", "\\\\")
    markdown_specials = set("`*_{}[]()#+-.!|>")
    return "".join(f"\\{character}" if character in markdown_specials else character for character in text)


def _list_value(report: dict[str, object], key: str) -> list[object]:
    value = report.get(key)
    return value if isinstance(value, list) else []


def render_evidence_report_markdown(report: dict[str, object]) -> str:
    """Render the stable report model to Markdown with explicit unknowns and limits."""
    lines = [
        f"# {_markdown_text(report.get('title'))}",
        "",
        f"> {REPORT_NOTICE}",
        "",
        "## Summary",
        "",
        _markdown_text(report.get("summary")),
        "",
        "## Finding and validation",
        "",
        f"- Draft ID: {_markdown_text(report.get('finding_id'))}",
        f"- State: {_markdown_text(report.get('validation_state'))}",
        f"- Category: {_markdown_text(report.get('category'))}",
        f"- CWE: {_markdown_text(report.get('cwe'))}",
        f"- Technical basis: {_markdown_text(report.get('validation_basis'))}",
        "",
        "## Affected asset and endpoint",
        "",
        f"- Program: {_markdown_text(report.get('program'))}",
        f"- Asset: {_markdown_text(report.get('asset'))}",
        f"- Endpoint: {_markdown_text(report.get('endpoint'))}",
        f"- Method: {_markdown_text(report.get('method'))}",
        "",
        "## Preconditions",
        "",
        *[f"- {_markdown_text(item)}" for item in _list_value(report, "preconditions")],
        "",
        "## Hypothesis",
        "",
        _markdown_text(report.get("hypothesis")),
        "",
        "## Steps to reproduce",
        "",
        *[
            f"{index}. {_markdown_text(item)}"
            for index, item in enumerate(_list_value(report, "reproduction_steps"), start=1)
        ],
        "",
        "## Evidence and observations",
        "",
        f"- Expected result: {_markdown_text(report.get('expected_result'))}",
        f"- Observed result: {_markdown_text(report.get('observed_result'))}",
        f"- Evidence IDs: {_markdown_text(report.get('evidence_references'))}",
        f"- Sources: {_markdown_text(report.get('evidence_sources'))}",
        "",
    ]
    for heading, key in (
        ("Evidence supporting the hypothesis", "evidence_for"),
        ("Evidence against the hypothesis", "evidence_against"),
    ):
        lines.extend([f"### {heading}", ""])
        rows = report.get(key)
        if isinstance(rows, list) and rows:
            lines.extend(
                f"- `{_markdown_text(row.get('record_id'))}`: {_markdown_text(row.get('why'))}"
                for row in rows
                if isinstance(row, dict)
            )
        else:
            lines.append(f"- {PENDING}")
        lines.append("")
    lines.extend(["### Negative controls", ""])
    lines.extend(f"- {_markdown_text(item)}" for item in _list_value(report, "negative_controls"))
    lines.extend(["", "### Structured observations", ""])
    observations = report.get("observations")
    if isinstance(observations, list) and observations:
        keys = sorted({key for row in observations if isinstance(row, dict) for key in row})
        lines.extend(["| " + " | ".join(keys) + " |", "| " + " | ".join("---" for _ in keys) + " |"])
        for row in observations:
            if isinstance(row, dict):
                lines.append("| " + " | ".join(_markdown_text(row.get(key)) for key in keys) + " |")
    else:
        lines.append(PENDING)
    lines.extend(
        [
            "",
            "## Demonstrated impact",
            "",
            _markdown_text(report.get("impact_demonstrated")),
            "",
            f"Impact basis: {_markdown_text(report.get('impact_basis'))}",
            "",
            "## Suggested severity",
            "",
            _markdown_text(report.get("severity_suggested")),
            "",
            f"Severity basis: {_markdown_text(report.get('severity_basis'))}",
            "",
            "The toolkit does not independently assess severity. Review the severity against demonstrated impact and program criteria.",
            "",
            "## Limitations",
            "",
            *[f"- {_markdown_text(item)}" for item in _list_value(report, "limitations")],
            "",
            "## Remediation recommendation",
            "",
            _markdown_text(report.get("remediation_recommendation")),
            "",
            "## AI second opinion",
            "",
            _markdown_text(report.get("ai_review")),
            "",
            "Not submitted. Review and verify every statement before sharing.",
            "",
        ]
    )
    return "\n".join(lines)


def render_evidence_report_html(report: dict[str, object], destination: Path) -> Path:
    sections = (
        ("Summary", "summary"),
        ("Finding and validation", "validation_state"),
        ("Technical basis", "validation_basis"),
        ("Affected asset", "asset"),
        ("Endpoint", "endpoint"),
        ("Method", "method"),
        ("Category", "category"),
        ("CWE", "cwe"),
        ("Preconditions", "preconditions"),
        ("Hypothesis", "hypothesis"),
        ("Expected result", "expected_result"),
        ("Observed result", "observed_result"),
        ("Structured observations", "observations"),
        ("Evidence for", "evidence_for"),
        ("Evidence against", "evidence_against"),
        ("Negative controls", "negative_controls"),
        ("Reproduction steps", "reproduction_steps"),
        ("Demonstrated impact", "impact_demonstrated"),
        ("Impact basis", "impact_basis"),
        ("Suggested severity", "severity_suggested"),
        ("Severity basis", "severity_basis"),
        ("Limitations", "limitations"),
        ("Remediation recommendation", "remediation_recommendation"),
        ("Evidence references", "evidence_references"),
        ("Evidence sources", "evidence_sources"),
        ("AI second opinion", "ai_review"),
    )
    body: list[str] = []
    for heading, key in sections:
        value = report.get(key)
        body.append(f"<section><h2>{escape(heading)}</h2>")
        if isinstance(value, list):
            body.append("<ul>" + "".join(f"<li>{escape(_display(item))}</li>" for item in value) + "</ul>")
        else:
            body.append(f"<p>{escape(_display(value))}</p>")
        body.append("</section>")
    html = (
        '<!doctype html><html lang="es"><head><meta charset="utf-8"><meta name="viewport" '
        'content="width=device-width, initial-scale=1"><title>Evidence report draft</title>'
        "<style>body{font:16px/1.5 Arial,sans-serif;max-width:1000px;margin:2rem auto;padding:0 1rem;"
        "color:#182230}h1,h2{line-height:1.2}section{border-top:1px solid #d0d7de;padding:.4rem 0}"
        "p,li{overflow-wrap:anywhere}blockquote{color:#57606a}</style></head><body>"
        f"<h1>{escape(_display(report.get('title')))}</h1><blockquote>{escape(REPORT_NOTICE)}</blockquote>"
        f"<p><strong>Report ID:</strong> {escape(_display(report.get('finding_id')))} | "
        f"<strong>Program:</strong> {escape(_display(report.get('program')))}</p>"
        + "".join(body)
        + "<p><strong>Not submitted.</strong> Review all statements before sharing.</p></body></html>"
    )
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(html, encoding="utf-8")
    return destination


def render_evidence_report_json(report: dict[str, object], destination: Path) -> Path:
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(report, indent=2, sort_keys=True, ensure_ascii=True), encoding="utf-8")
    return destination


def render_evidence_report_pdf(report: dict[str, object], destination: Path) -> Path:
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=destination.parent) as temporary:
        markdown = Path(temporary) / "report.md"
        markdown.write_text(render_evidence_report_markdown(report), encoding="utf-8")
        render_pdf(markdown, destination)
    return destination


def render_evidence_report(data: dict[str, Any], destination: Path, program: str = PENDING) -> Path:
    """Compatibility wrapper for existing Markdown evidence review callers."""
    report = build_evidence_finding_report(data, program=program, source_name=destination.stem)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(render_evidence_report_markdown(report), encoding="utf-8")
    return destination
