"""Scripted manual checklist. It does not import bbtk detectors or ground-truth labels."""

from __future__ import annotations

import json
from typing import Any

from .capture import Capture, Exchange

Disposition = str


def classify(capture: Capture) -> tuple[Disposition, str]:
    if capture.workflow == "A":
        return _idor(capture)
    if capture.workflow == "B":
        return _xss(capture)
    if capture.workflow == "C":
        return _disclosure(capture)
    return "abstain", "unknown_workflow"


def _idor(capture: Capture) -> tuple[Disposition, str]:
    owner = capture.by_role("owner")
    actor = capture.by_role("actor")
    if owner is None or actor is None:
        return "abstain", "missing_pair"
    if actor.truncated or owner.truncated or actor.status >= 500:
        return "abstain", "actor_response_not_reliable"
    try:
        owner_body = json.loads(owner.body) if owner.body else {}
        actor_body = json.loads(actor.body) if actor.body else {}
    except json.JSONDecodeError:
        return "abstain", "body_not_json"
    if not isinstance(owner_body, dict) or not isinstance(actor_body, dict):
        return "abstain", "body_not_object"
    if "contradiction" in actor_body or "contradiction" in owner_body:
        return "abstain", "denial_text_contradicts_marker"
    if actor.status in {401, 403}:
        return "reject", "actor_denied"
    visibility = actor_body.get("visibility") or owner_body.get("visibility")
    if visibility in {"public", "shared"}:
        return "reject", "visibility_is_shared_or_public"
    marker = owner_body.get("marker")
    if actor.status == 200 and isinstance(marker, str) and marker and marker in actor.body:
        return "review", "actor_body_contains_owner_marker"
    if actor.status == 200:
        return "abstain", "http_200_without_owner_marker"
    return "reject", "no_cross_account_marker"


def _xss(capture: Capture) -> tuple[Disposition, str]:
    exchange = capture.exchanges[0] if capture.exchanges else None
    if exchange is None:
        return "abstain", "missing_response"
    if exchange.truncated:
        return "abstain", "truncated_response"
    body = exchange.body
    payload = capture.request_payload
    if payload:
        if payload in body and "<" in payload:
            return "review", "raw_payload_reflected"
        escaped = payload.replace("<", "&lt;").replace(">", "&gt;")
        if escaped in body and payload not in body:
            return "reject", "escaped_payload"
        if payload not in body:
            return "reject", "payload_not_reflected"
        return "abstain", "reflection_context_unclear"
    if "innerHTML" in body and "location.hash" in body:
        return "review", "static_dom_innerhtml_sink"
    if "textContent" in body and "location.hash" in body and "innerHTML" not in body:
        return "reject", "static_dom_textcontent_only"
    return "abstain", "reflection_context_unclear"


def _disclosure(capture: Capture) -> tuple[Disposition, str]:
    exchange = capture.exchanges[0] if capture.exchanges else None
    if exchange is None:
        return "abstain", "missing_response"
    if exchange.truncated or exchange.status >= 500 or exchange.status == 204 or not exchange.body:
        return "abstain", "disclosure_evidence_incomplete"
    path = _header(exchange, "X-BBTK-Path")
    if "/docs/" in path:
        return "reject", "documentation_path"
    audience = _header(exchange, "X-BBTK-Audience") or "unknown"
    try:
        body: Any = json.loads(exchange.body)
    except json.JSONDecodeError:
        body = {"_text": exchange.body}
    if audience == "authenticated_self":
        return "reject", "own_audience"
    if _sensitive(body) and audience == "public":
        return "review", "public_sensitive_shape"
    return "reject", "no_public_sensitive_shape"


def _header(exchange: Exchange, name: str) -> str:
    for key, value in exchange.headers.items():
        if key.lower() == name.lower():
            return value
    return ""


def _sensitive(body: Any) -> bool:
    if isinstance(body, dict):
        for key, value in body.items():
            lowered = str(key).lower()
            if lowered in {"password", "api_key", "token"} and isinstance(value, str) and len(value) >= 6:
                if value.startswith("example"):
                    continue
                return True
            if isinstance(value, str) and "BBTK_CANARY_" in value:
                return True
        return False
    if isinstance(body, str):
        return "BBTK_CANARY_" in body
    return False
