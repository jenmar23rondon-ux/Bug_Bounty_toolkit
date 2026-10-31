"""Offline SSRF-prone parameter discovery and candidate test-idea generation.

Complements the live ``ssrf-check`` runner (fixed five payloads + canary bar).
This module reads a local HAR/capture and:

* finds SSRF-prone parameters (``url``, ``uri``, ``dest``, ``redirect``,
  ``fetch``, ``image``, ``webhook``, ``callback``, ``proxy``, ``host``,
  ``domain``, ``feed``, ``xml``, ``file``, …) across query / body / JSON /
  headers;
* emits **candidate** payload / test ideas for common SSRF classes (internal
  IPs, cloud metadata, localhost variants/encodings, gopher/file/dict schemes,
  DNS-rebinding and blind/OOB flagged **manual-only**).

Every item has ``finding_confirmed: false``. No network I/O. Scope and
redaction utilities are reused; secrets never appear in output.
"""

from __future__ import annotations

import json
import re
from typing import Any, Mapping
from urllib.parse import parse_qsl, urlsplit

from ..core.redaction import RedactionDestination, redact_text, redact_url
from .har_import import HarImportError, load_har_entries

SCHEMA = "bbtk-ssrf-analysis/1"
MAX_INPUT_BYTES = 1_000_000
MAX_PARAMS = 64
MAX_IDEAS = 128

_PARAM_RULES: tuple[tuple[re.Pattern[str], str, float], ...] = (
    (re.compile(r"(?i)^(url|uri|dest|destination|redirect|redirect_url|redirect_uri)$"), "url_like", 0.95),
    (re.compile(r"(?i)^(fetch|proxy|webhook|callback|target|endpoint|link|src|href)$"), "url_like", 0.9),
    (re.compile(r"(?i)^(image|img|avatar|thumbnail|icon|media|feed|rss|atom)$"), "resource_fetch", 0.85),
    (re.compile(r"(?i)^(host|hostname|domain|site|server)$"), "host_like", 0.85),
    (re.compile(r"(?i)^(file|path|document|xml|xslt|xinclude)$"), "file_xml", 0.8),
    (
        re.compile(r"(?i)(url|uri|dest|redirect|fetch|proxy|webhook|callback|image|feed|host|domain|file|xml)"),
        "url_like",
        0.65,
    ),
)

_SENSITIVE_NAME = re.compile(
    r"(?i)password|passwd|secret|token|api.?key|authorization|cookie|session|csrf|credential|bearer"
)

_HEADER_SSRF = re.compile(r"(?i)^(x-)?(forwarded-host|original-url|rewrite-url|middleware-start|destination|referer)$")

_DISCLAIMER = (
    "All items are CANDIDATES only. finding_confirmed stays false. "
    "Confirmation requires a lab loopback canary hit or manual in-scope proof. "
    "DNS-rebinding and blind/OOB ideas are manual-only and never executed here."
)

# Candidate ideas only — never sent by this module.
_IDEA_CATALOG: tuple[tuple[str, str, str, bool], ...] = (
    ("internal_ip", "http://127.0.0.1/", "Loopback IPv4", False),
    ("internal_ip", "http://127.0.0.1:80/", "Loopback with explicit port 80", False),
    ("internal_ip", "http://10.0.0.1/", "RFC1918 10/8 (candidate idea only)", False),
    ("internal_ip", "http://192.168.0.1/", "RFC1918 192.168/16 (candidate idea only)", False),
    ("internal_ip", "http://172.16.0.1/", "RFC1918 172.16/12 (candidate idea only)", False),
    ("cloud_metadata", "http://169.254.169.254/latest/meta-data/", "AWS/GCP-style link-local metadata", False),
    ("cloud_metadata", "http://169.254.169.254/metadata/instance", "Azure-style metadata path idea", False),
    ("localhost_variant", "http://localhost/", "localhost hostname", False),
    ("localhost_variant", "http://[::1]/", "IPv6 loopback", False),
    ("localhost_variant", "http://0.0.0.0/", "0.0.0.0 bind-all alias", False),
    ("localhost_encoding", "http://127.1/", "Short loopback form", False),
    ("localhost_encoding", "http://2130706433/", "Decimal-encoded 127.0.0.1", False),
    ("localhost_encoding", "http://0x7f000001/", "Hex-encoded 127.0.0.1", False),
    ("localhost_encoding", "http://127.0.0.1.nip.io/", "DNS alias to loopback (candidate)", False),
    ("alt_scheme", "gopher://127.0.0.1:6379/_INFO", "gopher scheme idea (often blocked)", False),
    ("alt_scheme", "file:///etc/passwd", "file scheme idea (often blocked)", False),
    ("alt_scheme", "dict://127.0.0.1:11211/stats", "dict scheme idea (often blocked)", False),
    ("dns_rebinding", "http://rebind.localtest.me/", "DNS-rebinding — manual-only, never auto-run", True),
    ("blind_oob", "http://<collaborator-host>/bbtk-ssrf", "Blind SSRF via out-of-band — manual-only", True),
)


def _classify_name(name: str) -> tuple[str, float] | None:
    leaf = name.rsplit(".", 1)[-1].rsplit("[", 1)[0]
    for pattern, category, confidence in _PARAM_RULES:
        if pattern.search(leaf) or pattern.search(name):
            return category, confidence
    return None


def _walk_json(obj: Any, prefix: str = "") -> list[tuple[str, Any]]:
    found: list[tuple[str, Any]] = []
    if isinstance(obj, dict):
        for key, value in obj.items():
            if not isinstance(key, str):
                continue
            path = f"{prefix}.{key}" if prefix else key
            found.append((path, value))
            found.extend(_walk_json(value, path))
    elif isinstance(obj, list):
        for index, value in enumerate(obj[:32]):
            found.extend(_walk_json(value, f"{prefix}[{index}]"))
    return found


def _parse_body(body: str | None, content_type: str) -> list[tuple[str, Any, str]]:
    if not body:
        return []
    ct = content_type.lower()
    out: list[tuple[str, Any, str]] = []
    if "json" in ct or body[:1] in "{[":
        try:
            parsed = json.loads(body)
        except ValueError:
            parsed = None
        if parsed is not None:
            for name, value in _walk_json(parsed):
                out.append((name, value, "json_body"))
            return out
    if "xml" in ct or body.lstrip().startswith("<"):
        # Surface tag-like names without a full XML parser (offline, bounded).
        for match in re.finditer(r"<([A-Za-z_][\w.-]{0,64})(?:\s|>)", body[:50_000]):
            out.append((match.group(1), "", "xml_body"))
        return out
    if "x-www-form-urlencoded" in ct or "=" in body:
        for key, value in parse_qsl(body, keep_blank_values=True):
            out.append((key, value, "form"))
    return out


def _redact_value(name: str, value: Any) -> str:
    if _SENSITIVE_NAME.search(name):
        return "[redacted]"
    text = value if isinstance(value, str) else json.dumps(value, default=str)
    redacted = redact_text(text, destination=RedactionDestination.MINIMIZED_ARTIFACT)
    if redacted is None:
        return "[redacted]"
    if len(redacted) > 64:
        return redacted[:61] + "..."
    return redacted


def _content_type(headers: Any) -> str:
    if isinstance(headers, list):
        for header in headers:
            if isinstance(header, dict) and isinstance(header.get("name"), str):
                if header["name"].lower() == "content-type":
                    value = header.get("value")
                    return value if isinstance(value, str) else ""
    elif isinstance(headers, Mapping):
        for key, value in headers.items():
            if str(key).lower() == "content-type":
                return str(value)
    return ""


def _header_pairs(headers: Any) -> list[tuple[str, str]]:
    pairs: list[tuple[str, str]] = []
    if isinstance(headers, list):
        for header in headers:
            if isinstance(header, dict) and isinstance(header.get("name"), str):
                value = header.get("value")
                pairs.append((header["name"], value if isinstance(value, str) else ""))
    elif isinstance(headers, Mapping):
        for key, value in headers.items():
            pairs.append((str(key), str(value) if value is not None else ""))
    return pairs


def _post_data_text(request: Mapping[str, Any]) -> str:
    post = request.get("postData")
    if isinstance(post, dict):
        text = post.get("text")
        if isinstance(text, str):
            return text
        params = post.get("params")
        if isinstance(params, list):
            pairs: list[str] = []
            for item in params:
                if isinstance(item, dict) and isinstance(item.get("name"), str):
                    pairs.append(f"{item['name']}={item.get('value', '')}")
            return "&".join(pairs)
    body = request.get("body")
    return body if isinstance(body, str) else ""


def _value_looks_url(value: Any) -> float:
    if not isinstance(value, str):
        return 0.0
    stripped = value.strip()
    if re.match(r"(?i)^(https?|ftp|file|gopher|dict)://", stripped) or stripped.startswith("//"):
        return 0.1
    if re.match(r"(?i)^[\w.-]+\.[a-z]{2,}(/|$)", stripped):
        return 0.05
    return 0.0


def extract_ssrf_parameters(entries: list[Any]) -> list[dict[str, Any]]:
    """Detect SSRF-prone parameters across query/body/JSON/headers."""
    seen: dict[tuple[str, str, str], dict[str, Any]] = {}
    for index, entry in enumerate(entries):
        if not isinstance(entry, Mapping):
            continue
        request = entry.get("request") if isinstance(entry.get("request"), Mapping) else None
        if request is None:
            continue
        raw_url = request.get("url")
        url = raw_url if isinstance(raw_url, str) else ""
        method = request.get("method") if isinstance(request.get("method"), str) else "GET"
        parsed = urlsplit(url)
        candidates: list[tuple[str, Any, str]] = []
        for key, value in parse_qsl(parsed.query, keep_blank_values=True):
            candidates.append((key, value, "query"))
        body = _post_data_text(request)
        ct = _content_type(request.get("headers"))
        if not ct and isinstance(request.get("postData"), dict):
            mime = request["postData"].get("mimeType")
            ct = mime if isinstance(mime, str) else ""
        candidates.extend(_parse_body(body, ct))
        for name, value in _header_pairs(request.get("headers")):
            if _HEADER_SSRF.match(name) or _classify_name(name):
                candidates.append((name, value, "header"))

        for name, value, location in candidates:
            classified = _classify_name(name)
            if classified is None:
                continue
            category, confidence = classified
            confidence = min(0.95, confidence + _value_looks_url(value))
            dedupe = (name, location, category)
            if dedupe in seen:
                continue
            seen[dedupe] = {
                "name": name,
                "location": location,
                "category": category,
                "confidence": round(confidence, 2),
                "sample_value_redacted": _redact_value(name, value),
                "request_index": index,
                "method": method,
                "url_redacted": redact_url(url, destination=RedactionDestination.MINIMIZED_ARTIFACT),
                "finding_confirmed": False,
            }
            if len(seen) >= MAX_PARAMS:
                return list(seen.values())
    return list(seen.values())


def generate_ssrf_ideas(parameters: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Build candidate payload/test ideas for detected parameters (never executed)."""
    ideas: list[dict[str, Any]] = []
    for param in parameters:
        name = str(param.get("name") or "")
        for idea_class, payload, detail, manual_only in _IDEA_CATALOG:
            ideas.append(
                {
                    "parameter": name,
                    "location": param.get("location"),
                    "category": param.get("category"),
                    "idea_class": idea_class,
                    "payload_idea": payload,
                    "detail": detail,
                    "manual_only": manual_only,
                    "url_redacted": param.get("url_redacted"),
                    "finding_confirmed": False,
                    "note": (
                        "Manual-only: do not automate DNS-rebinding or OOB against real targets."
                        if manual_only
                        else "Candidate idea for in-scope / loopback lab use only."
                    ),
                }
            )
            if len(ideas) >= MAX_IDEAS:
                return ideas
    return ideas


def plan_to_markdown(plan: Mapping[str, Any]) -> str:
    lines = [
        "# SSRF analysis (candidates)",
        "",
        _DISCLAIMER,
        "",
        f"Parameters: {plan.get('parameter_count', 0)} · Ideas: {plan.get('idea_count', 0)}",
        "",
        "## Parameters",
        "",
    ]
    params = plan.get("parameters") if isinstance(plan.get("parameters"), list) else []
    if not params:
        lines.append("_No SSRF-prone parameters detected._")
    else:
        for item in params:
            assert isinstance(item, Mapping)
            lines.append(
                f"- `{item.get('name')}` ({item.get('location')}, {item.get('category')}, "
                f"confidence={item.get('confidence')}) on `{item.get('url_redacted')}`"
            )
    lines.extend(["", "## Candidate ideas (not executed)", ""])
    ideas = plan.get("ideas") if isinstance(plan.get("ideas"), list) else []
    if not ideas:
        lines.append("_No ideas generated._")
    else:
        for item in ideas[:40]:
            assert isinstance(item, Mapping)
            flag = "manual-only" if item.get("manual_only") else "candidate"
            lines.append(
                f"- [{flag}] `{item.get('parameter')}` · {item.get('idea_class')}: `{item.get('payload_idea')}`"
            )
        if len(ideas) > 40:
            lines.append(f"- … {len(ideas) - 40} more ideas omitted from markdown")
    lines.append("")
    return "\n".join(lines)


def _normalize_record(record: Any) -> Any:
    if not isinstance(record, Mapping):
        return record
    if "request" in record:
        return record
    url = record.get("url") if isinstance(record.get("url"), str) else ""
    method = record.get("method") if isinstance(record.get("method"), str) else "GET"
    headers = record.get("headers") or []
    if isinstance(headers, Mapping):
        headers = [{"name": k, "value": str(v)} for k, v in headers.items()]
    body = record.get("body") if isinstance(record.get("body"), str) else ""
    ct = record.get("content_type") if isinstance(record.get("content_type"), str) else ""
    post: dict[str, Any] | None = None
    if body:
        post = {"mimeType": ct or "application/json", "text": body}
    return {"request": {"method": method, "url": url, "headers": headers, "postData": post or {}}}


def _load_entries(text: str) -> list[Any]:
    stripped = text.lstrip()
    if stripped.startswith("{") and '"log"' in stripped[:500]:
        try:
            return load_har_entries(text.encode("utf-8"), max_bytes=MAX_INPUT_BYTES)
        except HarImportError:
            pass
    try:
        data = json.loads(text)
    except ValueError as exc:
        raise ValueError("ssrf analysis input must be HAR or JSON captures.") from exc
    if isinstance(data, dict):
        for key in ("entries", "records", "captures", "requests"):
            if isinstance(data.get(key), list):
                return [_normalize_record(item) for item in data[key]]
        return [_normalize_record(data)]
    if isinstance(data, list):
        return [_normalize_record(item) for item in data]
    raise ValueError("ssrf analysis input must be HAR or JSON captures.")


def analyze_ssrf(text: str, *, source_label: str = "local-input") -> dict[str, Any]:
    """Offline SSRF parameter + candidate idea plan from HAR/captures."""
    entries = _load_entries(text)
    parameters = extract_ssrf_parameters(entries)
    ideas = generate_ssrf_ideas(parameters)
    plan: dict[str, Any] = {
        "schema": SCHEMA,
        "source": source_label,
        "finding_confirmed": False,
        "requests_sent": False,
        "disclaimer": _DISCLAIMER,
        "parameters": parameters,
        "parameter_count": len(parameters),
        "ideas": ideas,
        "idea_count": len(ideas),
        "manual_only_idea_count": sum(1 for item in ideas if item.get("manual_only")),
        "by_category": {},
        "note": (
            "Payload ideas are not sent. Live confirmation still requires "
            "ssrf-check lab_canary_hits or manual in-scope proof."
        ),
    }
    by_cat: dict[str, int] = {}
    for item in parameters:
        cat = str(item.get("category") or "unknown")
        by_cat[cat] = by_cat.get(cat, 0) + 1
    plan["by_category"] = by_cat
    plan["markdown"] = plan_to_markdown(plan)
    return plan
