"""Offline importers for local Nuclei, ZAP, FFUF and SQLMap result files.

This module never starts those tools and never sends network traffic. Each
imported row is a hypothesis. ``access_confirmed`` and
``vulnerabilities_confirmed`` stay false, and ``status`` is only
``candidate``, ``needs_review`` or ``abstain``.

Nuclei identity fields come from ``evidence_engine._nuclei_row``. FFUF rows
come from ``evidence_engine._ffuf``. Request and response text, when the file
actually contains it, is normalized with ``bbtk.capture-ingestion/1``.
"""

from __future__ import annotations

import csv
import hashlib
import io
import json
import os
from pathlib import Path
import re
import stat
import xml.etree.ElementTree as ET
from typing import Any, Mapping, Sequence

from ..burp_import import _local_name
from ..core.private_files import local_path, read_private_input
from ..core.redaction import redact_text, redact_url
from .capture_ingestion import SCHEMA as INGESTION_SCHEMA
from .capture_ingestion import ingest_capture
from .evidence_engine import MAX_INPUT_BYTES, MAX_RECORDS, _ffuf, _nuclei_row

SCHEMA = "bbtk.external-finding/1"
MAX_EXTERNAL_BYTES = MAX_INPUT_BYTES
MAX_FINDINGS = MAX_RECORDS
MAX_RECORD_BYTES = 1_000_000
MAX_MESSAGE_BYTES = 256_000
MAX_EXCERPT = 240
MAX_DIR_FILES = 64
MAX_DIAGNOSTICS = 10_000
_READER_SALT = b"bbtk-external-import-v1"
_TOOLS = frozenset({"nuclei", "zap", "ffuf", "sqlmap"})
_STATUSES = frozenset({"candidate", "needs_review", "abstain"})
_CONTRADICTIONS = frozenset(
    {"ambiguous_session", "contradictory_status", "contradictory_url", "nul_rejected", "url_embedded_credentials"}
)
_TAG_CLASS = {
    "xss": "cross_site_scripting",
    "sqli": "sql_injection",
    "ssrf": "server_side_request_forgery",
    "lfi": "path_traversal",
    "rce": "remote_code_execution",
    "redirect": "open_redirect",
    "takeover": "subdomain_takeover",
    "cors": "cors",
    "csrf": "csrf",
    "exposure": "information_exposure",
}
_NUCLEI_READER = "evidence_engine._nuclei_row"
_FFUF_READER = "evidence_engine._ffuf"
_DTD = re.compile(rb"<!\s*(?:DOCTYPE|ENTITY)\b", re.I)
_BANNER = re.compile(r"^sqlmap/(\d+\.\d+(?:\.\d+)?)")
_TARGET_URL = re.compile(r"(?i)\b(?:target URL|testing URL)\b[^'\"\s]{0,40}['\"]?(https?://[^\s'\"]+)")
_INJECTABLE = re.compile(
    r"(?i)^(?:\[[^\]]{1,40}\]\s*){0,3}(GET|POST|PUT|PATCH|DELETE|Cookie|Header)?\s*parameter\s+"
    r"'([^']{1,80})'\s+appears to be\s+'([^']{1,120})'\s+injectable\b"
)
_VULNERABLE = re.compile(
    r"(?i)^(?:\[[^\]]{1,40}\]\s*){0,3}(GET|POST|PUT|PATCH|DELETE|Cookie|Header)?\s*parameter\s+"
    r"'([^']{1,80})'\s+is vulnerable\b"
)
_HEURISTIC = re.compile(
    r"(?i)^(?:\[[^\]]{1,40}\]\s*){0,3}heuristic \(basic\) test shows that\s+"
    r"(GET|POST|PUT|PATCH|DELETE|Cookie|Header)?\s*parameter\s+'([^']{1,80})'\s+might be injectable\b"
)
_NEGATIVE = re.compile(
    r"(?i)^(?:\[[^\]]{1,40}\]\s*){0,3}(GET|POST|PUT|PATCH|DELETE|Cookie|Header)?\s*parameter\s+"
    r"'([^']{1,80})'\s+(?:does not appear to be injectable|does not seem to be injectable|is not injectable)\b"
)
_CWE = re.compile(r"(?i)^(?:CWE-)?(\d{1,5})$")
_VERSION_KEY = re.compile(r"^[0-9A-Za-z][0-9A-Za-z._+-]{0,39}$")


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _digest_text(text: str) -> str:
    raw = text.encode("utf-8", errors="replace")
    if len(raw) > MAX_RECORD_BYTES:
        raw = raw[:4096] + str(len(raw)).encode() + raw[-4096:]
    return _digest(raw)


def _diag(code: str, index: int | None, severity: str, source: str) -> dict[str, object]:
    return {"code": code, "index": index, "severity": severity, "source_file": source}


def _claim(value: object, limit: int = 160) -> str | None:
    if not isinstance(value, str):
        return None
    text = " ".join(value.replace("\r", " ").replace("\n", " ").split())
    if not text:
        return None
    redacted = redact_text(text[:limit])
    if not redacted:
        return None
    return redacted[:limit]


def _http_url(value: object) -> str | None:
    if not isinstance(value, str) or not value.startswith(("http://", "https://")) or len(value) > 4096:
        return None
    if any(char in value for char in "\r\n\x00"):
        return None
    try:
        return redact_url(value)
    except (ValueError, UnicodeError):
        return None


def _version_known(tool: str, version: str | None) -> bool:
    if version is None:
        return True
    if tool == "nuclei":
        return bool(re.fullmatch(r"[23]\.\d+\.\d+", version))
    if tool == "zap":
        return version.startswith("2.") or bool(re.fullmatch(r"D-\d{4}-\d{2}-\d{2}", version))
    if tool == "ffuf":
        return bool(re.fullmatch(r"[12]\.\d+(?:\.\d+)?", version))
    if tool == "sqlmap":
        return version.startswith("1.")
    return False


def _version_string(value: object) -> str | None:
    if not isinstance(value, str) or not _VERSION_KEY.fullmatch(value.strip()):
        return None
    return value.strip()


def _cwe(value: object) -> str | None:
    if isinstance(value, list) and value:
        return _cwe(value[0])
    if isinstance(value, int) and 0 < value < 100000:
        return f"CWE-{value}"
    if not isinstance(value, str):
        return None
    match = _CWE.fullmatch(value.strip())
    if not match:
        return None
    return f"CWE-{match.group(1)}"


def _class_from_tags(tags: list[str]) -> str | None:
    for tag in tags:
        label = _TAG_CLASS.get(tag)
        if label:
            return label
    return None


def _class_from_phrase(value: str | None) -> str | None:
    if not value:
        return None
    text = value.casefold()
    rules = (
        ("cross site scripting", "cross_site_scripting"),
        ("cross-site scripting", "cross_site_scripting"),
        ("server side request forgery", "server_side_request_forgery"),
        ("server-side request forgery", "server_side_request_forgery"),
        ("path traversal", "path_traversal"),
        ("directory traversal", "path_traversal"),
        ("remote code", "remote_code_execution"),
        ("open redirect", "open_redirect"),
        ("sql injection", "sql_injection"),
    )
    for needle, label in rules:
        if needle in text:
            return label
    if re.search(r"(?<![a-z])xss(?![a-z])", text):
        return "cross_site_scripting"
    if re.search(r"(?<![a-z])ssrf(?![a-z])", text):
        return "server_side_request_forgery"
    return None


def _tags(info: Mapping[str, Any]) -> list[str]:
    raw = info.get("tags")
    if isinstance(raw, str):
        return [part.strip().casefold() for part in raw.split(",") if part.strip()][:32]
    if isinstance(raw, list):
        return [item.strip().casefold() for item in raw if isinstance(item, str) and item.strip()][:32]
    return []


def _as_list(value: object) -> list[Any]:
    if isinstance(value, list):
        return value
    if isinstance(value, dict):
        return [value]
    return []


def _finalize(
    status: str, *, identity: bool, negative: bool, contradictory: bool, version_unknown: bool, evidence_ready: bool
) -> str:
    if not identity or negative or contradictory:
        return "abstain"
    if version_unknown or not evidence_ready:
        return "needs_review"
    if status in _STATUSES:
        return status
    return "abstain"


def _seal(finding: dict[str, object]) -> dict[str, object]:
    status = finding.get("status")
    sealed = dict(finding)
    sealed["schema"] = SCHEMA
    sealed["status"] = status if status in _STATUSES else "abstain"
    sealed["access_confirmed"] = False
    sealed["vulnerabilities_confirmed"] = 0
    return sealed


def _empty_evidence() -> dict[str, object]:
    return {
        "url": None,
        "host": None,
        "endpoint": None,
        "method": None,
        "status_code": None,
        "request_present": False,
        "response_present": False,
        "ingestion_schema": None,
        "ingestion_confidence": None,
        "ingestion_diagnostics": [],
        "response_length": None,
        "excerpt": None,
        "excerpt_sha256": None,
    }


def _normalize_http(request: str | None, response: str | None) -> dict[str, object]:
    evidence = _empty_evidence()
    evidence["request_present"] = bool(request)
    evidence["response_present"] = bool(response)
    if request and len(request.encode("utf-8", errors="replace")) > MAX_MESSAGE_BYTES:
        evidence["ingestion_diagnostics"] = ["evidence_too_large"]
        return evidence
    if response and len(response.encode("utf-8", errors="replace")) > MAX_MESSAGE_BYTES:
        evidence["ingestion_diagnostics"] = ["evidence_too_large"]
        return evidence
    if not request and not response:
        return evidence
    if request and not request.lstrip().startswith(
        ("GET ", "POST ", "PUT ", "PATCH ", "DELETE ", "HEAD ", "OPTIONS ", "HTTP/")
    ):
        if not (response and response.lstrip().startswith("HTTP/")):
            evidence["ingestion_diagnostics"] = ["evidence_not_http"]
            return evidence
    payload: bytes
    separate: bytes | None
    if request and response:
        payload = request.encode("utf-8", errors="replace")
        separate = response.encode("utf-8", errors="replace")
    elif request:
        payload = request.encode("utf-8", errors="replace")
        separate = None
    else:
        payload = (response or "").encode("utf-8", errors="replace")
        separate = None
    report = ingest_capture(payload, response=separate)
    codes = [item.code for item in report.diagnostics]
    exchange = report.exchanges[0] if report.exchanges else None
    if exchange is not None:
        codes.extend(exchange.diagnostics)
    evidence["ingestion_schema"] = INGESTION_SCHEMA
    evidence["ingestion_diagnostics"] = list(dict.fromkeys(codes))
    if report.fatal or exchange is None:
        return evidence
    evidence["ingestion_confidence"] = exchange.confidence_cap
    if exchange.confidence_cap == "observed":
        evidence["method"] = exchange.method
        evidence["status_code"] = exchange.status_code
        evidence["url"] = _http_url(exchange.url) if exchange.url else None
    body = exchange.response_body
    if isinstance(body, str) and body:
        evidence["excerpt_sha256"] = _digest_text(body)
        redacted = redact_text(body[:MAX_EXCERPT]) or ""
        evidence["excerpt"] = redacted[:MAX_EXCERPT]
    return evidence


def _apply_reader_location(
    evidence: dict[str, object], host: str | None, endpoint: str | None, method: str | None
) -> None:
    evidence["host"] = host
    evidence["endpoint"] = endpoint
    if evidence.get("method") is None and method:
        evidence["method"] = method
    if evidence.get("url") is None and host and endpoint:
        scheme = "https" if host.endswith(":443") else None
        if scheme and endpoint.startswith("/"):
            evidence["url"] = _http_url(f"{scheme}://{host}{endpoint}")


def _finding(
    *,
    tool: str,
    version: str | None,
    source: str,
    record_index: int,
    file_sha: str,
    evidence: dict[str, object],
    hypothesis: dict[str, object],
    status: str,
    locator: str,
    raw_sha: str,
    reader: str,
) -> dict[str, object]:
    return _seal(
        {
            "origin": {
                "tool": tool,
                "version": version,
                "source_file": source,
                "record_index": record_index,
                "input_sha256": file_sha,
            },
            "evidence": evidence,
            "hypothesis": hypothesis,
            "status": status,
            "traceability": {"raw_locator": locator, "raw_sha256": raw_sha, "reader": reader},
        }
    )


def _hypothesis(
    *,
    vulnerability_class: str | None,
    claimed: bool,
    claim: str | None,
    severity: str | None,
    parameter: str | None,
    cwe: str | None = None,
    template_id: str | None = None,
    place: str | None = None,
) -> dict[str, object]:
    return {
        "vulnerability_class": vulnerability_class,
        "vulnerability_claimed": claimed,
        "claim": claim,
        "severity_claimed": severity,
        "parameter": parameter,
        "place": place,
        "cwe": cwe,
        "template_id": template_id,
    }


def _surface(finding: dict[str, object], diagnostics: list[dict[str, object]]) -> None:
    evidence = finding.get("evidence")
    origin = finding.get("origin")
    if not isinstance(evidence, dict) or not isinstance(origin, dict):
        return
    index = origin.get("record_index")
    codes = evidence.get("ingestion_diagnostics")
    source = origin.get("source_file")
    if not isinstance(codes, list) or not isinstance(index, int) or not isinstance(source, str):
        return
    for code in codes:
        if code in _CONTRADICTIONS or code in {"evidence_too_large", "evidence_not_http", "content_length_mismatch"}:
            diagnostics.append(_diag(str(code), index, "warning", source))


def _report(
    source: str,
    tool: str | None,
    file_sha: str,
    findings: list[dict[str, object]],
    diagnostics: list[dict[str, object]],
    fatal: str | None,
) -> dict[str, object]:
    sealed = [_seal(item) for item in findings]
    for item in sealed:
        _surface(item, diagnostics)
    if len(diagnostics) > MAX_DIAGNOSTICS:
        diagnostics = diagnostics[: MAX_DIAGNOSTICS - 1]
        diagnostics.append(_diag("diagnostic_limit", None, "warning", source))
    return {
        "schema": SCHEMA,
        "source_file": source,
        "tool": tool,
        "input_sha256": file_sha,
        "findings": sealed,
        "diagnostics": diagnostics,
        "fatal": fatal,
        "access_confirmed": False,
        "vulnerabilities_confirmed": 0,
        "network_requests_sent": 0,
    }


def _fatal_report(source: str, code: str, tool: str | None, file_sha: str = "") -> dict[str, object]:
    return _report(source, tool, file_sha, [], [_diag(code, None, "fatal", source)], code)


def _load_file(path: Path) -> tuple[bytes | None, str | None, str]:
    try:
        resolved = local_path(path)
    except ValueError:
        return None, "path_rejected", ""
    try:
        info = resolved.stat()
    except OSError:
        return None, "unreadable_input", ""
    if not stat.S_ISREG(info.st_mode):
        return None, "path_rejected", ""
    if info.st_size > MAX_EXTERNAL_BYTES:
        return None, "oversized_input", ""
    if info.st_size == 0:
        return b"", "empty_input", _digest(b"")
    try:
        data = read_private_input(resolved, MAX_EXTERNAL_BYTES)
    except ValueError:
        return None, "unreadable_input", ""
    return data, None, _digest(data)


def _decode(data: bytes, source: str) -> tuple[str | None, dict[str, object] | None]:
    if data.startswith(b"SQLite format 3\x00"):
        return None, _diag("session_pickle_refused", None, "rejected", source)
    if b"\x00" in data:
        return None, _diag("nul_rejected", None, "fatal", source)
    try:
        return data.decode("utf-8-sig"), None
    except UnicodeDecodeError:
        return None, _diag("encoding_invalid", None, "fatal", source)


def _reader_ints(technical: Mapping[str, object]) -> dict[str, object]:
    output: dict[str, object] = {}
    for key in ("response_length", "response_words", "response_lines", "extracted_result_count"):
        value = technical.get(key)
        if type(value) is int and 0 <= value <= 2**53:
            output[key] = value
    return output


def _nuclei_from_row(
    path: Path,
    row: dict[str, Any],
    index: int,
    locator: str,
    source: str,
    file_sha: str,
    version: str | None,
    raw_sha: str,
) -> tuple[dict[str, object] | None, dict[str, object] | None]:
    if not any(key in row for key in ("template-id", "templateID", "matched-at", "host", "info")):
        return None, _diag("record_missing_identity", index, "rejected", source)
    try:
        record = _nuclei_row(path, row, locator, _READER_SALT)
    except (ValueError, TypeError, RecursionError, UnicodeError):
        return None, _diag("reader_failed", index, "rejected", source)
    technical = record.technical_evidence
    raw_template = technical.get("template_id")
    template_id = raw_template if isinstance(raw_template, str) else None
    raw_severity = technical.get("severity")
    severity = raw_severity if isinstance(raw_severity, str) else None
    raw_info = row.get("info")
    info: dict[str, Any] = {}
    if isinstance(raw_info, dict):
        for key, value in raw_info.items():
            if isinstance(key, str):
                info[key] = value
    vulnerability_class = _class_from_tags(_tags(info)) or _class_from_phrase(_claim(info.get("name")))
    request = row.get("request") if isinstance(row.get("request"), str) else None
    response = row.get("response") if isinstance(row.get("response"), str) else None
    evidence = _normalize_http(request, response)
    _apply_reader_location(evidence, record.host, record.endpoint, record.method)
    if evidence.get("url") is None:
        matched = row.get("matched-at") if isinstance(row.get("matched-at"), str) else row.get("host")
        evidence["url"] = _http_url(matched)
    for key, value in _reader_ints(technical).items():
        if key == "response_length":
            evidence["response_length"] = value
    codes = evidence.get("ingestion_diagnostics")
    code_list = codes if isinstance(codes, list) else []
    contradictory = any(code in _CONTRADICTIONS for code in code_list)
    evidence_ready = evidence.get("ingestion_confidence") == "observed" and evidence.get("response_present") is True
    identity = bool(template_id or evidence.get("url") or record.host)
    status = _finalize(
        "candidate",
        identity=identity,
        negative=False,
        contradictory=contradictory,
        version_unknown=not _version_known("nuclei", version),
        evidence_ready=evidence_ready,
    )
    if not identity:
        return None, _diag("record_missing_identity", index, "rejected", source)
    classification = info.get("classification")
    finding = _finding(
        tool="nuclei",
        version=version,
        source=source,
        record_index=index,
        file_sha=file_sha,
        evidence=evidence,
        hypothesis=_hypothesis(
            vulnerability_class=vulnerability_class,
            claimed=True,
            claim=template_id,
            severity=severity,
            parameter=None,
            cwe=_cwe(classification.get("cwe-id") if isinstance(classification, dict) else None),
            template_id=template_id,
        ),
        status=status,
        locator=locator,
        raw_sha=raw_sha,
        reader=_NUCLEI_READER,
    )
    return finding, None


def _import_nuclei_jsonl(path: Path, text: str, source: str, file_sha: str) -> dict[str, object]:
    findings: list[dict[str, object]] = []
    diagnostics: list[dict[str, object]] = []
    version: str | None = None
    seen = 0
    for index, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            continue
        if len(line.encode("utf-8", errors="replace")) > MAX_RECORD_BYTES:
            diagnostics.append(_diag("record_too_large", index, "rejected", source))
            continue
        try:
            row = json.loads(line)
        except (json.JSONDecodeError, RecursionError, ValueError):
            diagnostics.append(_diag("malformed_json", index, "rejected", source))
            continue
        if not isinstance(row, dict):
            diagnostics.append(_diag("record_not_object", index, "rejected", source))
            continue
        row_version = _version_string(row.get("nuclei-version") or row.get("nuclei_version"))
        if row_version:
            version = row_version
        if set(row) <= {"nuclei-version", "nuclei_version", "version", "generated"}:
            continue
        if seen >= MAX_FINDINGS:
            diagnostics.append(_diag("record_limit", index, "rejected", source))
            continue
        seen += 1
        finding, diagnostic = _nuclei_from_row(
            path, row, index, f"line:{index}", source, file_sha, version, _digest_text(line)
        )
        if diagnostic:
            diagnostics.append(diagnostic)
        elif finding:
            findings.append(finding)
    if version and not _version_known("nuclei", version):
        diagnostics.append(_diag("unknown_version", None, "warning", source))
        findings = [_downgrade(item) for item in findings]
    if not findings and not diagnostics:
        return _fatal_report(source, "empty_input", "nuclei", file_sha)
    return _report(source, "nuclei", file_sha, findings, diagnostics, None)


def _downgrade(finding: dict[str, object]) -> dict[str, object]:
    if finding.get("status") == "candidate":
        clone = dict(finding)
        clone["status"] = "needs_review"
        return _seal(clone)
    return finding


def _import_nuclei_json(path: Path, data: Any, text: str, source: str, file_sha: str) -> dict[str, object]:
    version: str | None = None
    rows: list[tuple[int, Any]]
    if isinstance(data, dict):
        version = _version_string(data.get("nuclei-version") or data.get("nuclei_version"))
        if version is None and not any(key in data for key in ("template-id", "templateID", "matched-at", "info")):
            version = _version_string(data.get("version"))
        if any(key in data for key in ("template-id", "templateID", "matched-at")) or isinstance(
            data.get("info"), dict
        ):
            rows = [(1, data)]
        else:
            nested = data.get("results") if isinstance(data.get("results"), list) else data.get("findings")
            if not isinstance(nested, list):
                return _fatal_report(source, "unknown_format", "nuclei", file_sha)
            rows = list(enumerate(nested, start=1))
    elif isinstance(data, list):
        rows = list(enumerate(data, start=1))
    else:
        return _fatal_report(source, "malformed_json", "nuclei", file_sha)
    findings: list[dict[str, object]] = []
    diagnostics: list[dict[str, object]] = []
    if not rows:
        diagnostics.append(_diag("empty_results", None, "warning", source))
    kept = 0
    for index, row in rows:
        if kept >= MAX_FINDINGS:
            diagnostics.append(_diag("record_limit", index, "rejected", source))
            continue
        if not isinstance(row, dict):
            diagnostics.append(_diag("record_not_object", index, "rejected", source))
            continue
        kept += 1
        try:
            encoded = json.dumps(row, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        except (TypeError, ValueError, RecursionError):
            diagnostics.append(_diag("malformed_json", index, "rejected", source))
            continue
        finding, diagnostic = _nuclei_from_row(
            path, row, index, f"item:{index}", source, file_sha, version, _digest_text(encoded)
        )
        if diagnostic:
            diagnostics.append(diagnostic)
        elif finding:
            findings.append(finding)
    if version and not _version_known("nuclei", version):
        diagnostics.append(_diag("unknown_version", None, "warning", source))
        findings = [_downgrade(item) for item in findings]
    fatal = None
    if not findings and not diagnostics:
        fatal = "empty_input"
        diagnostics.append(_diag("empty_input", None, "fatal", source))
    return _report(source, "nuclei", file_sha, findings, diagnostics, fatal)


def _xml_text(node: ET.Element, name: str) -> str | None:
    for child in list(node):
        if _local_name(child.tag) == name:
            return "".join(child.itertext())
    return None


def _join_http(header: str | None, body: str | None) -> str | None:
    if header is None and body is None:
        return None
    head = (header or "").strip("\r\n")
    if not head:
        return None
    return head + "\r\n\r\n" + (body or "")


def _zap_instances(alert: Mapping[str, Any]) -> list[Any]:
    instances = alert.get("instances")
    if isinstance(instances, dict):
        inner = instances.get("instance")
        if inner is None:
            inner = instances.get("instances")
        return _as_list(inner) if inner is not None else [instances]
    return _as_list(instances)


def _zap_alerts(site: Mapping[str, Any]) -> list[Any]:
    alerts = site.get("alerts")
    if alerts is None:
        alerts = site.get("alert")
    if isinstance(alerts, dict):
        inner = alerts.get("alertitem")
        if inner is None:
            inner = alerts.get("alert")
        if inner is not None:
            return _as_list(inner)
        return [alerts]
    return _as_list(alerts)


def _zap_finding_from_parts(
    *,
    source: str,
    file_sha: str,
    version: str | None,
    index: int,
    locator: str,
    name: str | None,
    risk: str | None,
    parameter: str | None,
    uri: str | None,
    method: str | None,
    cwe: str | None,
    request: str | None,
    response: str | None,
    raw_sha: str,
    evidence_text: str | None,
) -> tuple[dict[str, object] | None, dict[str, object] | None]:
    claim = _claim(name)
    url = _http_url(uri)
    if not claim and not url:
        return None, _diag("record_missing_identity", index, "rejected", source)
    evidence = _normalize_http(request, response)
    if evidence.get("url") is None:
        evidence["url"] = url
    if evidence.get("method") is None and isinstance(method, str) and method.isalpha():
        evidence["method"] = method.upper()[:16]
    if evidence.get("excerpt") is None and evidence_text:
        redacted = _claim(evidence_text, MAX_EXCERPT)
        evidence["excerpt"] = redacted
        if redacted:
            evidence["excerpt_sha256"] = _digest_text(evidence_text[:MAX_RECORD_BYTES])
    codes = evidence.get("ingestion_diagnostics")
    code_list = codes if isinstance(codes, list) else []
    contradictory = any(code in _CONTRADICTIONS for code in code_list)
    evidence_ready = evidence.get("ingestion_confidence") == "observed" and evidence.get("response_present") is True
    status = _finalize(
        "candidate",
        identity=True,
        negative=False,
        contradictory=contradictory,
        version_unknown=not _version_known("zap", version),
        evidence_ready=evidence_ready,
    )
    return (
        _finding(
            tool="zap",
            version=version,
            source=source,
            record_index=index,
            file_sha=file_sha,
            evidence=evidence,
            hypothesis=_hypothesis(
                vulnerability_class=_class_from_phrase(claim),
                claimed=True,
                claim=claim,
                severity=risk,
                parameter=_claim(parameter, 80),
                cwe=cwe,
            ),
            status=status,
            locator=locator,
            raw_sha=raw_sha,
            reader="external_importers.zap",
        ),
        None,
    )


def _risk_label(value: object) -> str | None:
    text = str(value).strip() if isinstance(value, (str, int)) and not isinstance(value, bool) else ""
    return {"0": "info", "1": "low", "2": "medium", "3": "high"}.get(text)


def _import_zap_json(data: Any, source: str, file_sha: str) -> dict[str, object]:
    if not isinstance(data, dict):
        return _fatal_report(source, "unknown_format", "zap", file_sha)
    version = _version_string(data.get("@version") or data.get("version"))
    sites = data.get("site")
    if sites is None:
        sites = data.get("sites")
    site_rows = _as_list(sites)
    if not site_rows:
        return _fatal_report(source, "unknown_format", "zap", file_sha)
    findings: list[dict[str, object]] = []
    diagnostics: list[dict[str, object]] = []
    index = 0
    for site_index, site in enumerate(site_rows):
        if not isinstance(site, dict):
            diagnostics.append(_diag("record_not_object", site_index, "rejected", source))
            continue
        alerts = _zap_alerts(site)
        if not alerts:
            diagnostics.append(_diag("record_missing_identity", site_index, "rejected", source))
            continue
        for alert_index, alert in enumerate(alerts):
            if not isinstance(alert, dict):
                diagnostics.append(_diag("record_not_object", alert_index, "rejected", source))
                continue
            name = alert.get("alert") if isinstance(alert.get("alert"), str) else alert.get("name")
            name_text = name if isinstance(name, str) else None
            risk = _risk_label(alert.get("riskcode"))
            cwe = _cwe(alert.get("cweid") or alert.get("cwe"))
            instances = _zap_instances(alert)
            if not instances:
                index += 1
                if index > MAX_FINDINGS:
                    diagnostics.append(_diag("record_limit", index, "rejected", source))
                    continue
                finding, diagnostic = _zap_finding_from_parts(
                    source=source,
                    file_sha=file_sha,
                    version=version,
                    index=index,
                    locator=f"site[{site_index}].alerts[{alert_index}]",
                    name=name_text,
                    risk=risk,
                    parameter=None,
                    uri=site.get("@name")
                    if isinstance(site.get("@name"), str)
                    else site.get("name")
                    if isinstance(site.get("name"), str)
                    else None,
                    method=None,
                    cwe=cwe,
                    request=None,
                    response=None,
                    raw_sha=_digest_text(name_text or str(alert_index)),
                    evidence_text=None,
                )
                if diagnostic:
                    diagnostics.append(diagnostic)
                elif finding:
                    findings.append(finding)
                continue
            for instance_index, instance in enumerate(instances):
                index += 1
                if index > MAX_FINDINGS:
                    diagnostics.append(_diag("record_limit", index, "rejected", source))
                    continue
                if not isinstance(instance, dict):
                    diagnostics.append(_diag("record_not_object", index, "rejected", source))
                    continue
                request = _join_http(
                    instance.get("request-header")
                    if isinstance(instance.get("request-header"), str)
                    else instance.get("requestHeader")
                    if isinstance(instance.get("requestHeader"), str)
                    else None,
                    instance.get("request-body")
                    if isinstance(instance.get("request-body"), str)
                    else instance.get("requestBody")
                    if isinstance(instance.get("requestBody"), str)
                    else None,
                )
                response = _join_http(
                    instance.get("response-header")
                    if isinstance(instance.get("response-header"), str)
                    else instance.get("responseHeader")
                    if isinstance(instance.get("responseHeader"), str)
                    else None,
                    instance.get("response-body")
                    if isinstance(instance.get("response-body"), str)
                    else instance.get("responseBody")
                    if isinstance(instance.get("responseBody"), str)
                    else None,
                )
                uri = instance.get("uri") if isinstance(instance.get("uri"), str) else instance.get("url")
                finding, diagnostic = _zap_finding_from_parts(
                    source=source,
                    file_sha=file_sha,
                    version=version,
                    index=index,
                    locator=f"site[{site_index}].alerts[{alert_index}].instances[{instance_index}]",
                    name=name_text,
                    risk=risk,
                    parameter=instance.get("param")
                    if isinstance(instance.get("param"), str)
                    else instance.get("parameter")
                    if isinstance(instance.get("parameter"), str)
                    else None,
                    uri=uri if isinstance(uri, str) else None,
                    method=instance.get("method") if isinstance(instance.get("method"), str) else None,
                    cwe=cwe,
                    request=request,
                    response=response,
                    raw_sha=_digest_text(
                        json.dumps({"name": name_text, "uri": uri, "i": instance_index}, sort_keys=True)
                    ),
                    evidence_text=instance.get("evidence") if isinstance(instance.get("evidence"), str) else None,
                )
                if diagnostic:
                    diagnostics.append(diagnostic)
                elif finding:
                    findings.append(finding)
    if version and not _version_known("zap", version):
        diagnostics.append(_diag("unknown_version", None, "warning", source))
        findings = [_downgrade(item) for item in findings]
    if not findings and not diagnostics:
        diagnostics.append(_diag("empty_results", None, "warning", source))
    return _report(source, "zap", file_sha, findings, diagnostics, None)


def _import_zap_xml(data: bytes, source: str, file_sha: str) -> dict[str, object]:
    if _DTD.search(data):
        return _fatal_report(source, "xml_dtd_forbidden", "zap", file_sha)
    if b"\x00" in data:
        return _fatal_report(source, "nul_rejected", "zap", file_sha)
    try:
        root = ET.fromstring(data)
    except (ET.ParseError, ValueError, RecursionError):
        return _fatal_report(source, "malformed_xml", "zap", file_sha)
    root_name = _local_name(root.tag)
    if root_name not in {"owaspzapreport", "report"}:
        return _fatal_report(source, "unknown_format", "zap", file_sha)
    version = _version_string(root.attrib.get("version") or root.attrib.get("@version"))
    sites = [node for node in list(root) if _local_name(node.tag) == "site"]
    synthetic_sites: list[dict[str, Any]] = []
    for site in sites:
        alerts_parent = [node for node in list(site) if _local_name(node.tag) == "alerts"]
        alert_nodes: list[ET.Element] = []
        for parent in alerts_parent or [site]:
            alert_nodes.extend(node for node in list(parent) if _local_name(node.tag) in {"alertitem", "alert"})
        alerts: list[dict[str, Any]] = []
        for alert in alert_nodes:
            instances = []
            holders = [node for node in list(alert) if _local_name(node.tag) == "instances"]
            instance_nodes: list[ET.Element] = []
            for holder in holders or [alert]:
                instance_nodes.extend(node for node in list(holder) if _local_name(node.tag) == "instance")
            for instance in instance_nodes:
                instances.append(
                    {
                        "uri": _xml_text(instance, "uri"),
                        "method": _xml_text(instance, "method"),
                        "param": _xml_text(instance, "param"),
                        "evidence": _xml_text(instance, "evidence"),
                        "request-header": _xml_text(instance, "requestheader"),
                        "request-body": _xml_text(instance, "requestbody"),
                        "response-header": _xml_text(instance, "responseheader"),
                        "response-body": _xml_text(instance, "responsebody"),
                    }
                )
            alerts.append(
                {
                    "name": _xml_text(alert, "name") or _xml_text(alert, "alert"),
                    "alert": _xml_text(alert, "alert") or _xml_text(alert, "name"),
                    "riskcode": _xml_text(alert, "riskcode"),
                    "cweid": _xml_text(alert, "cweid"),
                    "instances": instances,
                }
            )
        synthetic_sites.append({"@name": site.attrib.get("name"), "alerts": alerts})
    if version:
        payload: dict[str, Any] = {"@version": version, "site": synthetic_sites}
    else:
        payload = {"site": synthetic_sites}
    return _import_zap_json(payload, source, file_sha)


def _ffuf_one(path: Path, row: dict[str, Any]) -> list[Any]:
    try:
        return _ffuf(path, {"results": [row]}, _READER_SALT)
    except (ValueError, TypeError, RecursionError, UnicodeError):
        return []


def _import_ffuf_rows(
    path: Path,
    rows: list[Any],
    source: str,
    file_sha: str,
    version: str | None,
    locators: list[str] | None = None,
    indexes: list[int] | None = None,
) -> dict[str, object]:
    findings: list[dict[str, object]] = []
    diagnostics: list[dict[str, object]] = []
    if not rows:
        diagnostics.append(_diag("empty_results", None, "warning", source))
    for offset, row in enumerate(rows, start=1):
        record_index = indexes[offset - 1] if indexes and offset - 1 < len(indexes) else offset
        locator = locators[offset - 1] if locators and offset - 1 < len(locators) else f"results[{record_index - 1}]"
        if offset > MAX_FINDINGS:
            diagnostics.append(_diag("record_limit", record_index, "rejected", source))
            continue
        if not isinstance(row, dict):
            diagnostics.append(_diag("record_not_object", record_index, "rejected", source))
            continue
        url = row.get("url")
        if isinstance(url, str) and len(url) > 8192:
            diagnostics.append(_diag("field_too_large", record_index, "rejected", source))
            continue
        records = _ffuf_one(path, row)
        if not records:
            diagnostics.append(_diag("record_missing_identity", record_index, "rejected", source))
            continue
        record = records[0]
        technical = record.technical_evidence
        evidence = _empty_evidence()
        evidence["url"] = _http_url(url)
        _apply_reader_location(evidence, record.host, record.endpoint, record.method)
        if type(record.status_code) is int:
            evidence["status_code"] = record.status_code
        length = technical.get("response_length")
        if type(length) is int:
            evidence["response_length"] = length
        parameter = None
        raw_input = row.get("input")
        if isinstance(raw_input, dict):
            fuzz = raw_input.get("FUZZ")
            if isinstance(fuzz, str) and fuzz.isascii() and len(fuzz) <= 80 and "\n" not in fuzz:
                parameter = _claim(fuzz, 80)
        evidence_ready = evidence.get("url") is not None and type(record.status_code) is int
        status = _finalize(
            "candidate",
            identity=bool(evidence.get("url") or record.host),
            negative=False,
            contradictory=False,
            version_unknown=not _version_known("ffuf", version),
            evidence_ready=evidence_ready,
        )
        try:
            raw = json.dumps(row, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        except (TypeError, ValueError, RecursionError):
            raw = locator
        findings.append(
            _finding(
                tool="ffuf",
                version=version,
                source=source,
                record_index=record_index,
                file_sha=file_sha,
                evidence=evidence,
                hypothesis=_hypothesis(
                    vulnerability_class="content_discovery",
                    claimed=False,
                    claim="content_discovery",
                    severity=None,
                    parameter=parameter,
                ),
                status=status,
                locator=locator,
                raw_sha=_digest_text(raw),
                reader=_FFUF_READER,
            )
        )
    if version and not _version_known("ffuf", version):
        diagnostics.append(_diag("unknown_version", None, "warning", source))
        findings = [_downgrade(item) for item in findings]
    return _report(source, "ffuf", file_sha, findings, diagnostics, None)


def _import_ffuf_json(path: Path, data: Any, source: str, file_sha: str) -> dict[str, object]:
    if isinstance(data, list):
        return _import_ffuf_rows(path, data, source, file_sha, None)
    if not isinstance(data, dict) or not isinstance(data.get("results"), list):
        return _fatal_report(source, "unknown_format", "ffuf", file_sha)
    version = _version_string(data.get("version"))
    config = data.get("config")
    if version is None and isinstance(config, dict):
        version = _version_string(config.get("version") or config.get("Version"))
    return _import_ffuf_rows(path, data["results"], source, file_sha, version)


def _csv_rows(text: str, source: str) -> tuple[list[tuple[int, dict[str, str]]], list[dict[str, object]], list[str]]:
    """Parse CSV, including quoted fields that contain newlines. Indexes are record numbers."""
    diagnostics: list[dict[str, object]] = []
    if not text.strip():
        return [], [_diag("empty_input", None, "fatal", source)], []
    for number, line in enumerate(text.splitlines(), start=1):
        if len(line.encode("utf-8", errors="replace")) > MAX_RECORD_BYTES:
            diagnostics.append(_diag("record_too_large", number, "rejected", source))
    if diagnostics:
        return [], diagnostics, []
    try:
        parsed = list(csv.reader(io.StringIO(text)))
    except csv.Error:
        return [], [_diag("malformed_csv", 1, "fatal", source)], []
    if not parsed or not any(cell.strip() for cell in parsed[0]):
        return [], [_diag("malformed_csv", 1, "fatal", source)], []
    header = [cell.strip().lower() for cell in parsed[0]]
    rows: list[tuple[int, dict[str, str]]] = []
    for number, cols in enumerate(parsed[1:], start=2):
        if not any(cell.strip() for cell in cols):
            continue
        if len(cols) != len(header):
            diagnostics.append(_diag("malformed_csv", number, "rejected", source))
            continue
        rows.append((number, {key: value for key, value in zip(header, cols) if key}))
    return rows, diagnostics, header


def _import_ffuf_csv(path: Path, text: str, source: str, file_sha: str) -> dict[str, object]:
    rows, diagnostics, header = _csv_rows(text, source)
    if any(item.get("severity") == "fatal" for item in diagnostics) or any(
        item.get("code") == "record_too_large" for item in diagnostics
    ):
        fatal_code = next((item.get("code") for item in diagnostics if item.get("severity") == "fatal"), None)
        return _report(source, "ffuf", file_sha, [], diagnostics, fatal_code if isinstance(fatal_code, str) else None)
    if "url" not in header:
        return _fatal_report(source, "unknown_format", "ffuf", file_sha)
    built: list[Any] = []
    locators: list[str] = []
    for number, values in rows:
        status_text = values.get("status_code") or values.get("status") or ""
        row: dict[str, Any] = {"url": values.get("url", "")}
        if status_text.strip().isdigit():
            row["status"] = int(status_text.strip())
        elif status_text:
            row["status"] = status_text.strip()
        for source_key, dest in (
            ("content_length", "length"),
            ("length", "length"),
            ("content_words", "words"),
            ("words", "words"),
            ("content_lines", "lines"),
            ("lines", "lines"),
        ):
            raw = values.get(source_key)
            if raw and raw.strip().isdigit() and dest not in row:
                row[dest] = int(raw.strip())
        fuzz = values.get("fuzz") or values.get("FUZZ")
        if fuzz:
            row["input"] = {"FUZZ": fuzz[:80]}
        redirect = values.get("redirectlocation")
        if redirect:
            row["redirectlocation"] = redirect[:512]
        built.append(row)
        locators.append(f"row:{number}")
    indexes = [int(locator.split(":", 1)[1]) for locator in locators]
    report = _import_ffuf_rows(path, built, source, file_sha, None, locators, indexes)
    report_diagnostics = report.get("diagnostics")
    if isinstance(report_diagnostics, list):
        report["diagnostics"] = [*diagnostics, *report_diagnostics]
    return report


def _sql_status(explicit: bool, evidence: dict[str, object], version: str | None, negative: bool) -> str:
    codes = evidence.get("ingestion_diagnostics")
    code_list = codes if isinstance(codes, list) else []
    contradictory = any(code in _CONTRADICTIONS for code in code_list)
    evidence_ready = evidence.get("ingestion_confidence") == "observed" and evidence.get("response_present") is True
    desired = "candidate" if explicit else "needs_review"
    return _finalize(
        desired,
        identity=True,
        negative=negative,
        contradictory=contradictory,
        version_unknown=not _version_known("sqlmap", version),
        evidence_ready=evidence_ready and explicit and not negative,
    )


def _sql_finding(
    *,
    source: str,
    file_sha: str,
    version: str | None,
    index: int,
    locator: str,
    parameter: str,
    place: str | None,
    claim: str,
    explicit: bool,
    negative: bool,
    target: str | None,
    request: str | None,
    response: str | None,
    raw: str,
) -> dict[str, object]:
    evidence = _normalize_http(request, response)
    if evidence.get("url") is None:
        evidence["url"] = _http_url(target)
    status = _sql_status(explicit, evidence, version, negative)
    return _finding(
        tool="sqlmap",
        version=version,
        source=source,
        record_index=index,
        file_sha=file_sha,
        evidence=evidence,
        hypothesis=_hypothesis(
            vulnerability_class=None if negative else "sql_injection",
            claimed=not negative,
            claim=claim,
            severity=None,
            parameter=_claim(parameter, 80),
            place=_claim(place, 32) if place else None,
        ),
        status=status,
        locator=locator,
        raw_sha=_digest_text(raw),
        reader="external_importers.sqlmap_log",
    )


def _import_sqlmap_log(
    text: str, source: str, file_sha: str, target: str | None = None, forced_version: str | None = None
) -> dict[str, object]:
    findings: list[dict[str, object]] = []
    diagnostics: list[dict[str, object]] = []
    version = forced_version
    current_target = target
    for index, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            continue
        if len(line) > 4000:
            diagnostics.append(_diag("log_line_too_long", index, "rejected", source))
            continue
        banner = _BANNER.match(line.strip())
        if banner:
            version = banner.group(1)
            continue
        target_match = _TARGET_URL.search(line)
        if target_match:
            current_target = _http_url(target_match.group(1)) or current_target
            continue
        injectable = _INJECTABLE.match(line.strip())
        vulnerable = _VULNERABLE.match(line.strip())
        heuristic = _HEURISTIC.match(line.strip())
        negative = _NEGATIVE.match(line.strip())
        if injectable:
            place, parameter, technique = injectable.group(1), injectable.group(2), injectable.group(3)
            findings.append(
                _sql_finding(
                    source=source,
                    file_sha=file_sha,
                    version=version,
                    index=index,
                    locator=f"line:{index}",
                    parameter=parameter,
                    place=place,
                    claim=_claim(technique) or "injectable",
                    explicit=True,
                    negative=False,
                    target=current_target,
                    request=None,
                    response=None,
                    raw=line,
                )
            )
            continue
        if vulnerable:
            findings.append(
                _sql_finding(
                    source=source,
                    file_sha=file_sha,
                    version=version,
                    index=index,
                    locator=f"line:{index}",
                    parameter=vulnerable.group(2),
                    place=vulnerable.group(1),
                    claim="tool_marked_vulnerable",
                    explicit=True,
                    negative=False,
                    target=current_target,
                    request=None,
                    response=None,
                    raw=line,
                )
            )
            continue
        if heuristic:
            findings.append(
                _sql_finding(
                    source=source,
                    file_sha=file_sha,
                    version=version,
                    index=index,
                    locator=f"line:{index}",
                    parameter=heuristic.group(2),
                    place=heuristic.group(1),
                    claim="heuristic",
                    explicit=False,
                    negative=False,
                    target=current_target,
                    request=None,
                    response=None,
                    raw=line,
                )
            )
            continue
        if negative:
            findings.append(
                _sql_finding(
                    source=source,
                    file_sha=file_sha,
                    version=version,
                    index=index,
                    locator=f"line:{index}",
                    parameter=negative.group(2),
                    place=negative.group(1),
                    claim="not_injectable",
                    explicit=False,
                    negative=True,
                    target=current_target,
                    request=None,
                    response=None,
                    raw=line,
                )
            )
            continue
        lowered = line.casefold()
        started_claim = "parameter '" in lowered and (
            "injectable" in lowered
            or "vulnerable" in lowered
            or "heuristic" in lowered
            or lowered.rstrip().endswith("appears to be")
        )
        if started_claim:
            diagnostics.append(_diag("log_claim_unparsed", index, "warning", source))
    if version and not _version_known("sqlmap", version):
        diagnostics.append(_diag("unknown_version", None, "warning", source))
        findings = [_downgrade(item) for item in findings]
    if not findings and not diagnostics:
        diagnostics.append(_diag("empty_results", None, "warning", source))
    return _report(source, "sqlmap", file_sha, findings, diagnostics, None)


def _import_sqlmap_csv(text: str, source: str, file_sha: str, target: str | None = None) -> dict[str, object]:
    rows, diagnostics, header = _csv_rows(text, source)
    if any(item.get("severity") == "fatal" for item in diagnostics) or any(
        item.get("code") == "record_too_large" for item in diagnostics
    ):
        fatal_code = next((item.get("code") for item in diagnostics if item.get("severity") == "fatal"), None)
        return _report(source, "sqlmap", file_sha, [], diagnostics, fatal_code if isinstance(fatal_code, str) else None)
    if "parameter" not in header:
        diagnostics.append(_diag("sqlmap_dump_skipped", None, "warning", source))
        return _report(source, "sqlmap", file_sha, [], diagnostics, None)
    if "payload" in header:
        diagnostics.append(_diag("payload_column_omitted", None, "warning", source))
    findings: list[dict[str, object]] = []
    for number, values in rows:
        if len(findings) >= MAX_FINDINGS:
            diagnostics.append(_diag("record_limit", number, "rejected", source))
            continue
        parameter = values.get("parameter", "").strip()
        if not parameter:
            diagnostics.append(_diag("record_missing_identity", number, "rejected", source))
            continue
        technique = values.get("technique") or values.get("title") or ""
        flag = (values.get("injectable") or "yes").strip().casefold()
        negative = flag in {"no", "false", "0", "not injectable"}
        request = (
            values.get("request")
            if values.get("request", "").lstrip().startswith(("GET ", "POST ", "PUT ", "HTTP/"))
            else None
        )
        response = values.get("response") if values.get("response", "").lstrip().startswith("HTTP/") else None
        findings.append(
            _sql_finding(
                source=source,
                file_sha=file_sha,
                version=None,
                index=number,
                locator=f"row:{number}",
                parameter=parameter,
                place=values.get("place"),
                claim="not_injectable" if negative else (_claim(technique) or "sql_injection"),
                explicit=not negative and bool(technique or flag in {"yes", "true", "1"}),
                negative=negative,
                target=values.get("target") or values.get("url") or target,
                request=request,
                response=response,
                raw=json.dumps({key: values[key] for key in values if key != "payload"}, sort_keys=True),
            )
        )
    return _report(source, "sqlmap", file_sha, findings, diagnostics, None)


def _looks_like_sql_log(text: str) -> bool:
    head = text[:4000]
    if _BANNER.match(head.lstrip()):
        return True
    lowered = head.casefold()
    return "[info]" in lowered and "parameter" in lowered


def _looks_like_csv(text: str) -> bool:
    first = text.lstrip().splitlines()[0] if text.strip() else ""
    return "," in first and not first.startswith(("{", "[", "<"))


def _csv_kind(header: list[str]) -> str | None:
    fields = set(header)
    if "url" in fields and ({"status", "status_code"} & fields):
        return "ffuf"
    if "parameter" in fields and ({"technique", "place", "injectable", "title"} & fields):
        return "sqlmap"
    if "parameter" in fields:
        return "sqlmap"
    return None


def _import_csv(path: Path, text: str, source: str, file_sha: str, tool: str | None) -> dict[str, object]:
    _rows, diagnostics, header = _csv_rows(text, source)
    if any(item.get("severity") == "fatal" for item in diagnostics):
        chosen = tool if tool in _TOOLS else None
        return _report(source, chosen, file_sha, [], diagnostics, str(diagnostics[0]["code"]))
    kind = tool if tool in {"ffuf", "sqlmap"} else _csv_kind(header)
    if kind == "ffuf":
        return _import_ffuf_csv(path, text, source, file_sha)
    if kind == "sqlmap":
        return _import_sqlmap_csv(text, source, file_sha)
    return _fatal_report(source, "unknown_format", tool, file_sha)


def _import_json(path: Path, text: str, source: str, file_sha: str, tool: str | None) -> dict[str, object]:
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, RecursionError, ValueError):
        chosen = tool if tool in _TOOLS else None
        return _fatal_report(source, "malformed_json", chosen, file_sha)
    detected = _detect_json(data)
    chosen = tool or detected
    if tool and detected and tool != detected:
        return _fatal_report(source, "ambiguous_format", tool, file_sha)
    if chosen == "nuclei":
        return _import_nuclei_json(path, data, text, source, file_sha)
    if chosen == "zap":
        return _import_zap_json(data, source, file_sha)
    if chosen == "ffuf":
        return _import_ffuf_json(path, data, source, file_sha)
    return _fatal_report(source, "unknown_format", tool, file_sha)


def _detect_json(data: Any) -> str | None:
    if isinstance(data, list):
        if any(
            isinstance(row, dict) and any(key in row for key in ("template-id", "templateID", "matched-at"))
            for row in data
        ):
            return "nuclei"
        if any(isinstance(row, dict) and "url" in row for row in data):
            return "ffuf"
        return None
    if not isinstance(data, dict):
        return None
    nuclei = any(key in data for key in ("template-id", "templateID", "matched-at")) or isinstance(
        data.get("info"), dict
    )
    zap = "site" in data or "sites" in data
    ffuf = isinstance(data.get("results"), list) and (
        "commandline" in data
        or "config" in data
        or any(isinstance(row, dict) and "url" in row for row in data["results"])
    )
    matches = [name for name, flag in (("nuclei", nuclei), ("zap", zap), ("ffuf", ffuf)) if flag]
    if len(matches) == 1:
        return matches[0]
    if len(matches) > 1:
        return None
    nested = data.get("findings")
    if isinstance(nested, list) and any(isinstance(row, dict) and "template-id" in row for row in nested):
        return "nuclei"
    return None


def _import_text(path: Path, data: bytes, text: str, source: str, file_sha: str, tool: str | None) -> dict[str, object]:
    stripped = text.lstrip()
    suffix = Path(source).suffix.lower()
    if tool == "sqlmap" and data.startswith(b"SQLite format 3\x00"):
        return _report(
            source, "sqlmap", file_sha, [], [_diag("session_pickle_refused", None, "rejected", source)], None
        )
    if suffix in {".jsonl", ".ndjson"} or tool == "nuclei" and suffix in {".jsonl", ".ndjson"}:
        return _import_nuclei_jsonl(path, text, source, file_sha)
    if suffix in {".jsonl", ".ndjson"} and tool not in {None, "nuclei"}:
        return _fatal_report(source, "unknown_format", tool, file_sha)
    if stripped.startswith("<") or suffix == ".xml" or tool == "zap" and stripped.startswith("<"):
        if tool not in {None, "zap"}:
            return _fatal_report(source, "unknown_format", tool, file_sha)
        return _import_zap_xml(data, source, file_sha)
    if stripped.startswith(("{", "[")) or suffix == ".json":
        return _import_json(path, text, source, file_sha, tool)
    if suffix in {".jsonl", ".ndjson"}:
        return _import_nuclei_jsonl(path, text, source, file_sha)
    if tool == "nuclei":
        return _import_nuclei_jsonl(path, text, source, file_sha)
    if _looks_like_csv(text) or suffix == ".csv" or tool in {"ffuf", "sqlmap"} and "," in stripped.splitlines()[0]:
        if tool == "sqlmap" and _looks_like_sql_log(text):
            return _import_sqlmap_log(text, source, file_sha)
        return _import_csv(path, text, source, file_sha, tool)
    if tool == "sqlmap" or (tool is None and _looks_like_sql_log(text)):
        return _import_sqlmap_log(text, source, file_sha)
    if tool == "ffuf":
        return _fatal_report(source, "unknown_format", "ffuf", file_sha)
    return _fatal_report(source, "unknown_format", tool, file_sha)


def _import_loaded(path: Path, data: bytes, source: str, file_sha: str, tool: str | None) -> dict[str, object]:
    if not data.strip():
        return _fatal_report(source, "empty_input", tool if tool in _TOOLS else None, file_sha or _digest(data))
    if data.startswith(b"SQLite format 3\x00"):
        if tool not in {None, "sqlmap"}:
            return _fatal_report(source, "unknown_format", tool, file_sha)
        return _report(
            source, "sqlmap", file_sha, [], [_diag("session_pickle_refused", None, "rejected", source)], None
        )
    text, diagnostic = _decode(data, source)
    if diagnostic:
        code = str(diagnostic["code"])
        severity = diagnostic.get("severity")
        return _report(
            source,
            "sqlmap" if code == "session_pickle_refused" else tool if tool in _TOOLS else None,
            file_sha,
            [],
            [diagnostic],
            code if severity == "fatal" else None,
        )
    if text is None:
        return _fatal_report(source, "encoding_invalid", tool if tool in _TOOLS else None, file_sha)
    try:
        return _import_text(path, data, text, source, file_sha, tool)
    except (ValueError, TypeError, UnicodeError, RecursionError, csv.Error, ET.ParseError):
        return _fatal_report(source, "import_failed", tool if tool in _TOOLS else None, file_sha)


def _list_dir(path: Path) -> list[os.DirEntry[str]] | None:
    try:
        return list(os.scandir(path))
    except OSError:
        return None


def _import_directory(path: Path, tool: str | None) -> dict[str, object]:
    source = path.name
    try:
        resolved = local_path(path)
    except ValueError:
        return _fatal_report(source, "path_rejected", tool)
    if not resolved.is_dir():
        return _fatal_report(source, "unreadable_input", tool)
    entries = _list_dir(resolved)
    if entries is None:
        return _fatal_report(source, "unreadable_input", tool)
    names = {entry.name for entry in entries}
    sqlmap_dir = bool({"log", "target.txt", "session.sqlite"} & names) or any(
        name.endswith(".sqlite") for name in names
    )
    if tool not in {None, "sqlmap"} or (tool is None and not sqlmap_dir):
        return _fatal_report(source, "unknown_format", tool)
    if not entries:
        return _fatal_report(source, "empty_input", "sqlmap")
    findings: list[dict[str, object]] = []
    diagnostics: list[dict[str, object]] = []
    target: str | None = None
    files = sorted((entry for entry in entries if entry.is_file(follow_symlinks=False)), key=lambda item: item.name)
    links = [entry.name for entry in entries if entry.is_symlink()]
    for name in links:
        diagnostics.append(_diag("path_rejected", None, "rejected", name))
    for entry in entries:
        if entry.is_dir(follow_symlinks=False) and entry.name == "dump":
            diagnostics.append(_diag("sqlmap_dump_skipped", None, "warning", entry.name))
        elif entry.is_dir(follow_symlinks=False):
            diagnostics.append(_diag("unsupported_entry", None, "warning", entry.name))
    if len(files) > MAX_DIR_FILES:
        diagnostics.append(_diag("record_limit", None, "rejected", source))
        files = files[:MAX_DIR_FILES]
    target_file = next((entry for entry in files if entry.name == "target.txt"), None)
    if target_file is not None:
        loaded, fatal, _sha = _load_file(Path(target_file.path))
        if fatal:
            diagnostics.append(_diag(fatal, None, "fatal" if fatal != "empty_input" else "warning", target_file.name))
        elif loaded is not None:
            text, diagnostic = _decode(loaded, target_file.name)
            if diagnostic:
                diagnostics.append(diagnostic)
            elif text:
                first = text.strip().splitlines()[0] if text.strip() else ""
                target = _http_url(first)
    ordered = [entry for entry in files if entry.name != "target.txt"]
    hashes: list[str] = []
    for entry in ordered:
        child = Path(entry.path)
        if entry.name.endswith(".sqlite") or entry.name == "session.sqlite":
            header = _prefix(Path(entry.path), 16)
            if header is None:
                diagnostics.append(_diag("unreadable_input", None, "rejected", entry.name))
                continue
            if header.startswith(b"SQLite format 3"):
                diagnostics.append(_diag("session_pickle_refused", None, "rejected", entry.name))
            else:
                diagnostics.append(_diag("session_malformed", None, "rejected", entry.name))
            continue
        loaded, fatal, file_sha = _load_file(child)
        if file_sha:
            hashes.append(file_sha)
        if fatal:
            diagnostics.append(_diag(fatal, None, "fatal", entry.name))
            continue
        if loaded is None:
            diagnostics.append(_diag("unreadable_input", None, "rejected", entry.name))
            continue
        if entry.name == "log" or entry.name.endswith(".log"):
            text, diagnostic = _decode(loaded, entry.name)
            if diagnostic or text is None:
                diagnostics.append(diagnostic or _diag("encoding_invalid", None, "fatal", entry.name))
                continue
            child_report = _import_sqlmap_log(text, entry.name, file_sha, target)
        elif entry.name.endswith(".csv"):
            text, diagnostic = _decode(loaded, entry.name)
            if diagnostic or text is None:
                diagnostics.append(diagnostic or _diag("encoding_invalid", None, "fatal", entry.name))
                continue
            child_report = _import_sqlmap_csv(text, entry.name, file_sha, target)
        else:
            diagnostics.append(_diag("unsupported_entry", None, "warning", entry.name))
            continue
        child_findings = child_report["findings"]
        child_diagnostics = child_report["diagnostics"]
        if isinstance(child_findings, list):
            findings.extend(item for item in child_findings if isinstance(item, dict))
        if isinstance(child_diagnostics, list):
            diagnostics.extend(item for item in child_diagnostics if isinstance(item, dict))
    directory_sha = _digest("".join(hashes).encode()) if hashes else ""
    return _report(source, "sqlmap", directory_sha, findings, diagnostics, None)


def import_external(path: Path, *, tool: str | None = None) -> dict[str, object]:
    """Parse one local file or SQLMap output directory.

    Content failures become diagnostics. This function does not raise for
    malformed input and does not confirm a finding.
    """
    if tool is not None and tool not in _TOOLS:
        return _fatal_report(path.name, "unknown_tool", None)
    try:
        if path.is_dir():
            return _import_directory(path, tool)
        data, fatal, file_sha = _load_file(path)
        if fatal:
            return _fatal_report(path.name, fatal, tool if tool in _TOOLS else None, file_sha)
        if data is None:
            return _fatal_report(path.name, "unreadable_input", tool if tool in _TOOLS else None)
        return _import_loaded(path, data, path.name, file_sha, tool)
    except (OSError, ValueError, TypeError, UnicodeError, RecursionError, csv.Error, ET.ParseError):
        return _fatal_report(path.name, "import_failed", tool if tool in _TOOLS else None)


def import_external_paths(paths: Sequence[Path], *, tool: str | None = None) -> dict[str, object]:
    """Parse several local inputs. One bad input does not drop the others."""
    reports: list[dict[str, object]] = []
    if len(paths) > MAX_DIR_FILES:
        paths = list(paths)[:MAX_DIR_FILES]
        extra = True
    else:
        extra = False
        paths = list(paths)
    for path in paths:
        reports.append(import_external(path, tool=tool))
    findings: list[dict[str, object]] = []
    diagnostics: list[dict[str, object]] = []
    inputs: list[dict[str, object]] = []
    for report in reports:
        report_findings = report.get("findings")
        report_diagnostics = report.get("diagnostics")
        if isinstance(report_findings, list):
            findings.extend(_seal(item) for item in report_findings if isinstance(item, dict))
        if isinstance(report_diagnostics, list):
            diagnostics.extend(item for item in report_diagnostics if isinstance(item, dict))
        inputs.append(
            {
                "source_file": report.get("source_file"),
                "tool": report.get("tool"),
                "input_sha256": report.get("input_sha256"),
                "fatal": report.get("fatal"),
                "findings": len(report_findings) if isinstance(report_findings, list) else 0,
            }
        )
    if extra:
        diagnostics.append(_diag("record_limit", None, "rejected", ""))
    by_status = {name: 0 for name in ("candidate", "needs_review", "abstain")}
    by_tool: dict[str, int] = {}
    for finding in findings:
        status = finding.get("status")
        if isinstance(status, str) and status in by_status:
            by_status[status] += 1
        origin = finding.get("origin")
        if isinstance(origin, dict) and isinstance(origin.get("tool"), str):
            by_tool[origin["tool"]] = by_tool.get(origin["tool"], 0) + 1
    return {
        "schema": SCHEMA,
        "mode": "offline",
        "scope_modified": False,
        "rate_limit_modified": False,
        "human_approval_required": True,
        "active_testing": False,
        "network_requests_sent": 0,
        "access_confirmed": False,
        "vulnerabilities_confirmed": 0,
        "findings": findings,
        "diagnostics": diagnostics,
        "inputs": inputs,
        "summary": {
            "schema": SCHEMA,
            "inputs": len(inputs),
            "findings": len(findings),
            "by_status": by_status,
            "by_tool": by_tool,
            "diagnostics": len(diagnostics),
            "fatal_inputs": sum(1 for item in inputs if item.get("fatal")),
            "access_confirmed": False,
            "vulnerabilities_confirmed": 0,
            "network_requests_sent": 0,
            "scope_modified": False,
            "rate_limit_modified": False,
            "human_approval_required": True,
        },
    }


def _prefix(path: Path, count: int) -> bytes | None:
    """Read a short header without following links or loading the rest of the file."""
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError:
        return None
    try:
        return os.read(descriptor, count)
    finally:
        os.close(descriptor)
