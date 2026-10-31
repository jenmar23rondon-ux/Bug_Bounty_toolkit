"""Offline CORS and open-redirect *impact* assessment from stored HAR/captures.

Presence of ACAO reflection or an external Location is already handled by the
live ``cors-check`` / ``open-redirect`` runners (candidate vs confirmed bar from
PR #67). This module answers the follow-up question researchers need for a
report to be accepted:

* CORS — would ACAO + ACAC actually allow a **cross-origin credentialed read**
  of sensitive-looking data? (reflected arbitrary / ``null`` origin with
  ``Access-Control-Allow-Credentials: true`` vs ``*`` which browsers block with
  credentials)
* Open redirect — is the redirect parameter **chainable** into an OAuth/SSO
  flow (``redirect_uri`` / ``return_to`` / ``next`` / ``callback`` near
  oauth/authorize/login) so it could lead to token/code theft?

Every result is a **CANDIDATE**. ``finding_confirmed`` stays false. Confirmation
requires manual in-scope testing. No network I/O.
"""

from __future__ import annotations

import json
import re
from typing import Any, Mapping
from urllib.parse import parse_qsl, urlsplit

from ..core.redaction import RedactionDestination, redact_url
from ..cors_check import acac_allows_credentials, attacker_origin_reflected
from .har_import import HarImportError, load_har_entries
from .information_disclosure import assess_disclosure

SCHEMA = "bbtk-cors-redirect-impact/1"
MAX_INPUT_BYTES = 1_000_000
MAX_FINDINGS = 64

IMPACT_EXPLOITABLE = "exploitable-credentialed-read"
IMPACT_INFO = "info-only"
IMPACT_NOT = "not-exploitable"

# Origins that are attacker-controlled when reflected (not the page's own origin).
_ATTACKER_ORIGIN = re.compile(r"(?i)^(null|https?://evil[.\w-]*|https?://[^/\s]+\.evil\.com)$")
_REDIRECT_PARAM = re.compile(
    r"(?i)^(redirect_uri|redirect_url|redirect|return_to|return_url|return|next|callback|continue|dest|destination|goto|url)$"
)
_OAUTH_PATH = re.compile(r"(?i)/(oauth|authorize|auth|sso|oidc|login|signin|connect)(/|$|\?)")

_DISCLAIMER = (
    "All items are CANDIDATES only. finding_confirmed stays false. "
    "Confirmation requires manual in-scope testing (browser credentialed read "
    "for CORS; live OAuth chain for open-redirect)."
)


def classify_cors_impact(
    *,
    allow_origin: str | None,
    allow_credentials: str | None,
    request_origin: str | None = None,
    body_has_sensitive: bool = False,
    sensitive_categories: list[str] | None = None,
) -> dict[str, Any]:
    """Classify CORS impact from stored ACAO/ACAC (+ optional body sensitivity).

    Browser rules (simplified, offline):
    - ``ACAO: *`` never allows credentialed reads (browsers ignore ACAC with *).
    - Reflected arbitrary / ``null`` origin **with** ``ACAC: true`` is the
      credentialed-read candidate class.
    - Reflection without ACAC is info-only (simple requests may still leak, but
      credentialed reads are blocked).
    """
    acao = (allow_origin or "").strip()
    acac = acac_allows_credentials(allow_credentials)
    categories = list(sensitive_categories or [])
    reasons: list[str] = []

    if not acao:
        return {
            "impact": IMPACT_NOT,
            "reasoning": "No Access-Control-Allow-Origin header observed.",
            "acao": None,
            "acac_true": acac,
            "credentialed_read_possible": False,
            "body_sensitive": body_has_sensitive,
            "sensitive_categories": categories,
            "finding_confirmed": False,
        }

    if acao == "*":
        reasons.append("Wildcard ACAO is blocked by browsers when credentials are included")
        impact = IMPACT_NOT
        if body_has_sensitive:
            reasons.append("Body looks sensitive but credentialed cross-origin read is not allowed with *")
            impact = IMPACT_INFO
        return {
            "impact": impact,
            "reasoning": "; ".join(reasons),
            "acao": "*",
            "acac_true": acac,
            "credentialed_read_possible": False,
            "body_sensitive": body_has_sensitive,
            "sensitive_categories": categories,
            "finding_confirmed": False,
        }

    reflected = False
    if request_origin:
        reflected = attacker_origin_reflected(request_origin, acao)
    elif _ATTACKER_ORIGIN.match(acao) or acao.lower() == "null":
        reflected = True
        reasons.append(f"ACAO reflects attacker-controlled origin {acao!r}")

    if request_origin and reflected:
        reasons.append(f"Request Origin {request_origin!r} reflected in ACAO")

    if reflected and acac:
        impact = IMPACT_EXPLOITABLE
        reasons.append("ACAC true with reflected/null origin → browsers allow credentialed cross-origin reads")
        if body_has_sensitive:
            reasons.append(
                "Response body contains sensitive-looking indicators: " + (", ".join(categories) or "present")
            )
        else:
            reasons.append("Body sensitivity not proven; treat as candidate until manual browser proof")
        return {
            "impact": impact,
            "reasoning": "; ".join(reasons),
            "acao": acao,
            "acac_true": True,
            "credentialed_read_possible": True,
            "body_sensitive": body_has_sensitive,
            "sensitive_categories": categories,
            "finding_confirmed": False,
        }

    if reflected and not acac:
        reasons.append("Origin reflected but ACAC is not true → credentialed reads blocked (info-only)")
        if body_has_sensitive:
            reasons.append("Sensitive-looking body present but not credential-readable cross-origin")
        return {
            "impact": IMPACT_INFO,
            "reasoning": "; ".join(reasons),
            "acao": acao,
            "acac_true": False,
            "credentialed_read_possible": False,
            "body_sensitive": body_has_sensitive,
            "sensitive_categories": categories,
            "finding_confirmed": False,
        }

    reasons.append("ACAO does not reflect an attacker Origin (same-origin allowlist or unrelated value)")
    return {
        "impact": IMPACT_NOT,
        "reasoning": "; ".join(reasons) if reasons else "No attacker-origin reflection",
        "acao": acao,
        "acac_true": acac,
        "credentialed_read_possible": False,
        "body_sensitive": body_has_sensitive,
        "sensitive_categories": categories,
        "finding_confirmed": False,
    }


def assess_redirect_chainability(
    *,
    url: str,
    parameter: str,
    location: str | None = None,
    status_code: int | None = None,
) -> dict[str, Any]:
    """Assess whether an open-redirect parameter could chain into OAuth/SSO token theft."""
    parsed = urlsplit(url)
    path_is_oauth = bool(_OAUTH_PATH.search(parsed.path) or _OAUTH_PATH.search(url))
    param_is_redirect = bool(_REDIRECT_PARAM.match(parameter))
    query_params = {k.lower() for k, _ in parse_qsl(parsed.query, keep_blank_values=True)}
    nearby_oauth_params = sorted(query_params & {"client_id", "response_type", "scope", "state", "nonce", "code"})
    chainable = param_is_redirect and (path_is_oauth or bool(nearby_oauth_params))

    chain_description: str | None = None
    if chainable:
        bits = [f"Parameter {parameter!r} on {parsed.path or '/'}"]
        if path_is_oauth:
            bits.append("looks like an OAuth/SSO/login endpoint")
        if nearby_oauth_params:
            bits.append("alongside OAuth params: " + ", ".join(nearby_oauth_params))
        bits.append(
            "Candidate chain: attacker-controlled redirect → victim completes auth → "
            "code/token delivered to attacker endpoint (manual confirmation required)"
        )
        chain_description = ". ".join(bits)

    leaves = False
    if location:
        dest = urlsplit(location if "://" in location or location.startswith("//") else f"https://{location}")
        base_host = (parsed.hostname or "").lower().rstrip(".")
        dest_host = (dest.hostname or "").lower().rstrip(".")
        leaves = bool(dest_host) and dest_host != base_host

    return {
        "parameter": parameter,
        "path_oauth_like": path_is_oauth,
        "param_redirect_like": param_is_redirect,
        "oauth_query_params": nearby_oauth_params,
        "chainable_candidate": chainable,
        "chain_description": chain_description,
        "external_location_observed": leaves,
        "status_code": status_code,
        "finding_confirmed": False,
        "note": "Chainability is a candidate signal only; confirmation requires manual in-scope OAuth testing.",
    }


def _header_map(headers: Any) -> dict[str, str]:
    out: dict[str, str] = {}
    if isinstance(headers, list):
        for item in headers:
            if isinstance(item, dict) and isinstance(item.get("name"), str):
                value = item.get("value")
                out[item["name"].lower()] = value if isinstance(value, str) else ""
    elif isinstance(headers, Mapping):
        for key, value in headers.items():
            out[str(key).lower()] = str(value) if value is not None else ""
    return out


def _response_body(response: Mapping[str, Any]) -> str:
    content = response.get("content")
    if isinstance(content, dict):
        text = content.get("text")
        if isinstance(text, str):
            return text
    body = response.get("body")
    return body if isinstance(body, str) else ""


def _request_origin(headers: Mapping[str, str]) -> str | None:
    origin = headers.get("origin")
    return origin if origin else None


def _body_sensitivity(url: str, body: str, content_type: str) -> tuple[bool, list[str]]:
    if not body.strip():
        return False, []
    record = {
        "id": "cors-impact",
        "url": url,
        "audience": "unknown",
        "response": {
            "status": 200,
            "headers": {"Content-Type": content_type or "application/json"},
            "body": body[:500_000],
        },
    }
    assessment = assess_disclosure(record)
    cats = list(assessment.categories)
    sensitive = bool(assessment.indicators)
    return sensitive, cats


def _redirect_params_from_url(url: str) -> list[str]:
    parsed = urlsplit(url)
    names: list[str] = []
    for key, _ in parse_qsl(parsed.query, keep_blank_values=True):
        if _REDIRECT_PARAM.match(key) and key not in names:
            names.append(key)
    return names


def analyze_cors_redirect_impact(text: str, *, source_label: str = "local-input") -> dict[str, Any]:
    """Analyze a HAR or capture JSON for CORS impact and open-redirect chainability."""
    entries = _load_entries(text)
    cors_findings: list[dict[str, Any]] = []
    redirect_findings: list[dict[str, Any]] = []

    for index, entry in enumerate(entries):
        if not isinstance(entry, Mapping):
            continue
        request = entry.get("request") if isinstance(entry.get("request"), Mapping) else {}
        response = entry.get("response") if isinstance(entry.get("response"), Mapping) else {}
        assert isinstance(request, Mapping)
        assert isinstance(response, Mapping)
        raw_url = request.get("url")
        url = raw_url if isinstance(raw_url, str) else ""
        if not url:
            continue
        req_headers = _header_map(request.get("headers"))
        resp_headers = _header_map(response.get("headers"))
        status = response.get("status") if isinstance(response.get("status"), int) else None
        body = _response_body(response)
        content_type = resp_headers.get("content-type", "")

        acao = resp_headers.get("access-control-allow-origin")
        acac = resp_headers.get("access-control-allow-credentials")
        if acao is not None or acac is not None:
            sensitive, cats = _body_sensitivity(url, body, content_type)
            # Prefer secret categories in the surfaced list.
            secret_cats = {"credentials", "token", "private_key", "env_vars"}
            secret_first = [c for c in cats if c in secret_cats] + [c for c in cats if c not in secret_cats]
            impact = classify_cors_impact(
                allow_origin=acao,
                allow_credentials=acac,
                request_origin=_request_origin(req_headers),
                body_has_sensitive=sensitive,
                sensitive_categories=secret_first,
            )
            cors_findings.append(
                {
                    "entry_index": index,
                    "url_redacted": redact_url(url, destination=RedactionDestination.MINIMIZED_ARTIFACT),
                    "request_origin": _request_origin(req_headers),
                    "status_code": status,
                    **impact,
                }
            )

        location = resp_headers.get("location")
        for param in _redirect_params_from_url(url):
            chain = assess_redirect_chainability(url=url, parameter=param, location=location, status_code=status)
            redirect_findings.append(
                {
                    "entry_index": index,
                    "url_redacted": redact_url(url, destination=RedactionDestination.MINIMIZED_ARTIFACT),
                    "location_redacted": (
                        redact_url(location, destination=RedactionDestination.MINIMIZED_ARTIFACT) if location else None
                    ),
                    **chain,
                }
            )
            if len(redirect_findings) >= MAX_FINDINGS:
                break

        if len(cors_findings) >= MAX_FINDINGS and len(redirect_findings) >= MAX_FINDINGS:
            break

    return {
        "schema": SCHEMA,
        "source": source_label,
        "finding_confirmed": False,
        "requests_sent": False,
        "disclaimer": _DISCLAIMER,
        "cors": {
            "findings": cors_findings[:MAX_FINDINGS],
            "count": len(cors_findings[:MAX_FINDINGS]),
            "by_impact": _count_by(cors_findings[:MAX_FINDINGS], "impact"),
        },
        "open_redirect": {
            "findings": redirect_findings[:MAX_FINDINGS],
            "count": len(redirect_findings[:MAX_FINDINGS]),
            "chainable_candidates": sum(
                1 for item in redirect_findings[:MAX_FINDINGS] if item.get("chainable_candidate")
            ),
        },
        "markdown": _to_markdown(cors_findings[:MAX_FINDINGS], redirect_findings[:MAX_FINDINGS]),
        "note": (
            "Impact classes are offline heuristics over stored captures. "
            "They do not prove browser readability or live OAuth token theft."
        ),
    }


def _count_by(rows: list[dict[str, Any]], key: str) -> dict[str, int]:
    counts: dict[str, int] = {}
    for row in rows:
        label = str(row.get(key) or "unknown")
        counts[label] = counts.get(label, 0) + 1
    return counts


def _to_markdown(cors: list[dict[str, Any]], redirects: list[dict[str, Any]]) -> str:
    lines = [
        "# CORS / open-redirect impact (candidates)",
        "",
        _DISCLAIMER,
        "",
        "## CORS impact",
        "",
    ]
    if not cors:
        lines.append("_No CORS headers observed in capture._")
    else:
        for item in cors:
            lines.append(f"- `{item.get('impact')}` on `{item.get('url_redacted')}` — {item.get('reasoning')}")
    lines.extend(["", "## Open-redirect chainability", ""])
    if not redirects:
        lines.append("_No redirect-like parameters observed._")
    else:
        for item in redirects:
            flag = "chainable-candidate" if item.get("chainable_candidate") else "not-chainable"
            desc = item.get("chain_description") or "No OAuth/SSO chain signals."
            lines.append(f"- `{flag}` param `{item.get('parameter')}` on `{item.get('url_redacted')}` — {desc}")
    lines.append("")
    return "\n".join(lines)


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
        raise ValueError("cors-redirect-impact input must be HAR or JSON captures.") from exc
    if isinstance(data, dict):
        for key in ("entries", "records", "captures", "responses"):
            if isinstance(data.get(key), list):
                return [_normalize_record(item) for item in data[key]]
        return [_normalize_record(data)]
    if isinstance(data, list):
        return [_normalize_record(item) for item in data]
    raise ValueError("cors-redirect-impact input must be HAR or JSON captures.")


def _normalize_record(record: Any) -> Any:
    """Accept either a HAR entry or a simplified {url, request, response} record."""
    if not isinstance(record, Mapping):
        return record
    if "request" in record and "response" in record:
        return record
    url = record.get("url") if isinstance(record.get("url"), str) else ""
    method = record.get("method") if isinstance(record.get("method"), str) else "GET"
    req_headers = record.get("request_headers") or record.get("headers") or []
    resp = record.get("response") if isinstance(record.get("response"), Mapping) else {}
    assert isinstance(resp, Mapping)
    status = resp.get("status", record.get("status", 200))
    resp_headers = resp.get("headers") or record.get("response_headers") or []
    body = resp.get("body") or ""
    if isinstance(resp_headers, Mapping):
        resp_headers = [{"name": k, "value": str(v)} for k, v in resp_headers.items()]
    if isinstance(req_headers, Mapping):
        req_headers = [{"name": k, "value": str(v)} for k, v in req_headers.items()]
    content: dict[str, Any] = {"text": body if isinstance(body, str) else ""}
    return {
        "request": {"method": method, "url": url, "headers": req_headers},
        "response": {"status": status, "headers": resp_headers, "content": content},
    }


def analyze_cors_redirect_impact_file(path_text: str, *, label: str | None = None) -> dict[str, Any]:
    from pathlib import Path

    path = Path(path_text)
    return analyze_cors_redirect_impact(path.read_text(encoding="utf-8"), source_label=label or str(path))
