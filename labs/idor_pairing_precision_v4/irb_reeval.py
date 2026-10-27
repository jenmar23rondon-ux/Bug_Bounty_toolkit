"""Re-score frozen IRB FINAL 45 with the opt-in compatibility evaluator.

Labels and capture bytes are read only. Proposal behaviour of ``object_handoff``
is not invoked and not modified. Session material is hashed before it is stored
on an evidence row; response bodies are not written to the result document.
"""

from __future__ import annotations

import base64
import hashlib
import json
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from bugbounty_toolkit.analysis.authorization_denial import parse_raw_response
from bugbounty_toolkit.analysis.idor_pairing_precision import evaluate_compatibility

IRB_ROOT = Path(__file__).resolve().parents[1] / "independent_research_eval" / "final"
PROGRAM = "irb-eval"


def load_labels(root: Path = IRB_ROOT) -> list[dict[str, Any]]:
    document = json.loads((root / "ground_truth.json").read_text(encoding="utf-8"))
    scenarios = document.get("scenarios")
    if not isinstance(scenarios, list):
        raise ValueError("IRB ground truth has no scenarios")
    return scenarios


def evidence_from_scenario(scenario: dict[str, Any], root: Path = IRB_ROOT) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for capture in scenario.get("captures") or []:
        path = root / str(capture)
        suffix = path.suffix.lower()
        if suffix == ".har":
            rows.extend(_har(path, str(scenario["id"])))
        elif suffix == ".xml":
            rows.extend(_burp(path, str(scenario["id"])))
        elif suffix == ".http":
            rows.extend(_raw_http(path, str(scenario["id"])))
        else:
            raise ValueError(f"unsupported IRB capture: {path.name}")
    return rows


def admitted_kinds(evidences: list[dict[str, Any]]) -> list[str]:
    """Kinds with at least one compatible, review-admitted pair. Opt-in evaluator only."""
    admitted: set[str] = set()
    total = len(evidences)
    for left in range(total):
        for right in range(left + 1, total):
            owner = evidences[left]
            actor = evidences[right]
            if owner.get("session_ref") and owner.get("session_ref") == actor.get("session_ref"):
                continue
            context = [evidences[index] for index in range(total) if index not in {left, right}]
            assessment = evaluate_compatibility(owner, actor, context=context)
            if assessment.pairing_decision and assessment.resource_kind:
                admitted.add(assessment.resource_kind)
    return sorted(admitted)


def _har(path: Path, scenario_id: str) -> list[dict[str, Any]]:
    document = json.loads(path.read_text(encoding="utf-8"))
    entries = (document.get("log") or {}).get("entries") or []
    rows: list[dict[str, Any]] = []
    for index, entry in enumerate(entries):
        if not isinstance(entry, dict):
            continue
        request = entry.get("request") or {}
        url = request.get("url")
        if not isinstance(url, str) or not url:
            continue
        headers = _pairs(request.get("headers"))
        response = entry.get("response") if isinstance(entry.get("response"), dict) else None
        rows.append(_row(scenario_id, f"{path.name}:{index}", request.get("method"), url, headers, response))
    return rows


def _burp(path: Path, scenario_id: str) -> list[dict[str, Any]]:
    root = ET.fromstring(path.read_text(encoding="utf-8"))
    rows: list[dict[str, Any]] = []
    for index, item in enumerate(root.findall("item")):
        url = item.findtext("url") or ""
        request_b64 = item.findtext("request") or ""
        response_b64 = item.findtext("response")
        request_raw = base64.b64decode(request_b64) if request_b64 else b""
        method, target, headers = _request_head(request_raw)
        absolute = target if target.startswith("http") else url
        response = None
        if response_b64:
            status, resp_headers, body = parse_raw_response(base64.b64decode(response_b64))
            response = {
                "status": status,
                "headers": [{"name": k, "value": v} for k, v in resp_headers.items()],
                "content": {"text": body},
            }
        rows.append(_row(scenario_id, f"{path.name}:{index}", method, absolute or url, headers, response))
    return rows


def _raw_http(path: Path, scenario_id: str) -> list[dict[str, Any]]:
    method, target, headers = _request_head(path.read_bytes())
    host = headers.get("host") or headers.get("Host") or "127.0.0.1"
    if target.startswith("http"):
        url = target
    else:
        url = f"http://{host}{target}"
    return [_row(scenario_id, path.name, method, url, headers, None)]


def _row(
    scenario_id: str,
    locator: str,
    method: object,
    url: str,
    request_headers: dict[str, str],
    response: dict[str, Any] | None,
) -> dict[str, Any]:
    parsed = urlsplit(url)
    origin = f"{parsed.scheme}://{parsed.netloc}" if parsed.scheme and parsed.netloc else None
    status = None
    body = None
    resp_headers: dict[str, str] = {}
    present = False
    if response is not None:
        status = response.get("status")
        content = response.get("content") if isinstance(response.get("content"), dict) else {}
        text = content.get("text") if isinstance(content, dict) else None
        body = text if isinstance(text, str) else None
        resp_headers = _pairs(response.get("headers"))
        present = body is not None or isinstance(status, int)
    safe_headers = {key: value for key, value in request_headers.items() if key.lower() in {"x-role", "x-privilege"}}
    return {
        "evidence_ref": f"{scenario_id}:{locator}",
        "program": PROGRAM,
        "origin": origin,
        "method": str(method or ""),
        "path": parsed.path or url,
        "session_ref": _session_ref(request_headers),
        "request_headers": safe_headers,
        "response_headers": resp_headers,
        "response_body": body,
        "response_present": present,
        "status_code": status if isinstance(status, int) else None,
        "accounts_attested": False,
    }


def _session_ref(headers: dict[str, str]) -> str | None:
    material = None
    for key, value in headers.items():
        if key.lower() == "authorization":
            material = value
            break
    if material is None:
        for key, value in headers.items():
            if key.lower() == "cookie":
                material = value
                break
    if not material:
        return None
    return "sess-" + hashlib.sha256(material.encode()).hexdigest()[:16]


def _pairs(headers: object) -> dict[str, str]:
    out: dict[str, str] = {}
    if isinstance(headers, dict):
        for key, value in headers.items():
            if isinstance(key, str) and isinstance(value, str):
                out[key] = value
        return out
    if isinstance(headers, list):
        for item in headers:
            if isinstance(item, dict) and isinstance(item.get("name"), str) and isinstance(item.get("value"), str):
                out[str(item["name"])] = str(item["value"])
    return out


def _request_head(raw: bytes) -> tuple[str, str, dict[str, str]]:
    text = raw.decode("utf-8", errors="replace")
    head = text.split("\r\n\r\n", 1)[0].split("\n\n", 1)[0]
    lines = head.splitlines()
    parts = lines[0].split() if lines else []
    method = parts[0] if parts else ""
    target = parts[1] if len(parts) > 1 else ""
    headers: dict[str, str] = {}
    for line in lines[1:]:
        if ":" not in line:
            continue
        name, value = line.split(":", 1)
        headers[name.strip()] = value.strip()
    return method, target, headers
