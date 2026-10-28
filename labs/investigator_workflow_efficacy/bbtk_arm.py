"""Score captures with existing bbtk modules. Those modules are not modified here."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any

from bugbounty_toolkit.analysis.information_disclosure import assess_disclosure
from bugbounty_toolkit.analysis.investigation_workflow import build_workflow
from bugbounty_toolkit.analysis.resource_kind_lineage import correlate_resources
from bugbounty_toolkit.reporting.dossier_verifier import verify_research_dossier
from bugbounty_toolkit.xss.context_classifier import classify_reflected_context
from bugbounty_toolkit.xss.evidence_record import DomObservation, classify_dom_state

from .capture import Capture, header

Disposition = str

_DOM_SOURCES = ("location.hash", "location.search", "location.href", "document.URL", "document.documentURI", "document.referrer", "window.name")
_DANGEROUS_DOM_SINKS = ("innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "document.writeln")
_SAFE_DOM_SINKS = ("textContent", "innerText", "createTextNode")


def _dom_signal(body: str) -> tuple[bool, bool, bool]:
    """Return source, dangerous-sink and safe-sink signals from captured script."""
    source_seen = any(source in body for source in _DOM_SOURCES)
    dangerous_seen = any(re.search(r"\b" + re.escape(sink) + r"\b", body) for sink in _DANGEROUS_DOM_SINKS)
    safe_seen = any(re.search(r"\b" + re.escape(sink) + r"\b", body) for sink in _SAFE_DOM_SINKS)
    return source_seen, dangerous_seen, safe_seen


def classify(capture: Capture) -> tuple[Disposition, str, bool]:
    """Return disposition, reason, and whether any module set finding_confirmed."""
    if capture.workflow == "A":
        return _idor(capture)
    if capture.workflow == "B":
        return _xss(capture)
    if capture.workflow == "C":
        return _disclosure(capture)
    return "abstain", "unknown_workflow", False


def _idor(capture: Capture) -> tuple[Disposition, str, bool]:
    owner = capture.by_role("owner")
    actor = capture.by_role("actor")
    if owner is None or actor is None:
        return "abstain", "missing_pair", False
    try:
        owner_body = json.loads(owner.body) if owner.body else {}
        actor_body = json.loads(actor.body) if actor.body else {}
    except json.JSONDecodeError:
        return "abstain", "body_not_json", False
    if not isinstance(owner_body, dict) or not isinstance(actor_body, dict):
        return "abstain", "body_not_object", False
    if "contradiction" in owner_body or "contradiction" in actor_body:
        return "abstain", "evidence_contradiction", False
    if actor.truncated or owner.truncated or actor.status >= 500:
        return "abstain", "actor_response_not_reliable", False
    if actor.status in {401, 403}:
        return "reject", "actor_denied", False
    relation = correlate_resources(_side(owner.body, "lab-owner"), _side(actor.body, "lab-actor"))
    confirmed = bool(relation.get("confirmed"))
    if relation.get("idor_review_signal"):
        return "review", "idor_review_signal", confirmed
    if relation.get("legitimate_shared"):
        return "reject", "legitimate_shared", confirmed
    if relation.get("relation") == "unknown":
        return "abstain", "relation_unknown", confirmed
    return "reject", "no_idor_review_signal", confirmed


def _side(body: str, account: str) -> dict[str, Any]:
    try:
        parsed = json.loads(body) if body else {}
    except json.JSONDecodeError:
        parsed = {}
    if not isinstance(parsed, dict):
        parsed = {}
    kind = parsed.get("kind") if isinstance(parsed.get("kind"), str) else None
    resource_id = parsed.get("id") if isinstance(parsed.get("id"), str) else None
    visibility = parsed.get("visibility") if parsed.get("visibility") in {"public", "shared", "private"} else None
    namespace = f"{kind}:{resource_id}" if kind and resource_id else None
    return {"kind": kind, "kind_status": "explicit" if kind else "unknown", "namespace_key": namespace, "account_ref": account, "distinct_accounts_attested": True, "session_ref": account, "visibility": visibility, "body_digest": hashlib.sha256(body.encode("utf-8")).hexdigest()}


def _xss(capture: Capture) -> tuple[Disposition, str, bool]:
    exchange = capture.exchanges[0] if capture.exchanges else None
    if exchange is None:
        return "abstain", "missing_response", False
    if capture.request_payload:
        content_type = header(exchange, "Content-Type") or "text/html"
        assessment = classify_reflected_context(exchange.body, capture.request_marker or capture.request_payload, capture.request_payload, content_type, truncated=exchange.truncated)
        decision = assessment.decision
        if decision in {"candidate", "needs_browser_confirmation"}:
            return "review", decision, bool(assessment.finding_confirmed)
        if decision in {"escaped_safe", "not_reflected"}:
            return "reject", decision, bool(assessment.finding_confirmed)
        return "abstain", decision, bool(assessment.finding_confirmed)
    if exchange.truncated:
        return "abstain", "truncated_dom_source", False
    source_seen, dangerous_seen, safe_seen = _dom_signal(exchange.body)
    if source_seen and safe_seen and not dangerous_seen:
        return "reject", "safe_text_sink_only", False
    observation = DomObservation(source_observed=source_seen, sinks=("dangerous_dom_sink",) if source_seen and dangerous_seen else (), marker_executed=False)
    state = classify_dom_state(observation)
    if state in {"sink_reached", "execution_observed"}:
        return "review", state, False
    if state == "sanitization_applied":
        return "reject", state, False
    return "abstain", state, False


def _disclosure(capture: Capture) -> tuple[Disposition, str, bool]:
    exchange = capture.exchanges[0] if capture.exchanges else None
    if exchange is None:
        return "abstain", "missing_response", False
    path = header(exchange, "X-BBTK-Path") or "/"
    audience = header(exchange, "X-BBTK-Audience") or "unknown"
    if exchange.truncated:
        return "abstain", "truncated_disclosure_response", False
    if exchange.status == 204 or not exchange.body:
        return "abstain", "empty_disclosure_response", False
    if audience == "authenticated_self":
        return "reject", "authenticated_self_profile", False
    record = {"id": capture.case_id, "audience": audience, "url": "http://127.0.0.1" + path, "request": {"query": ""}, "response": {"status": exchange.status, "headers": {"Content-Type": header(exchange, "Content-Type") or "application/json"}, "body": exchange.body, "truncated": exchange.truncated}}
    data = assess_disclosure(record).to_dict()
    confirmed = bool(data.get("finding_confirmed"))
    state = str(data.get("state"))
    if state in {"ready_for_manual_review", "access_control_validation_required"}:
        return "review", state, confirmed
    if state in {"public_or_intended_information", "not_observed"}:
        return "reject", state, confirmed
    return "abstain", state, confirmed


def verify_draft(root: Path, capture: Capture, disposition: str) -> dict[str, Any]:
    """Build a candidate ledger and dossier. Never confirms. Returns shareable fields only."""
    from bugbounty_toolkit.analysis.evidence_ledger import add_candidate, add_evidence, new_ledger, upsert_surface
    program = root / "program"
    evidence_dir = program / "evidence"
    evidence_dir.mkdir(parents=True, exist_ok=True)
    digest = hashlib.sha256("|".join(item.body for item in capture.exchanges).encode("utf-8")).hexdigest()
    evidence = {"case_id": capture.case_id, "statuses": [item.status for item in capture.exchanges], "body_sha256": digest, "disposition_recommendation": disposition, "finding_confirmed": False}
    rel = "evidence/case.json"
    (program / rel).write_text(json.dumps(evidence, sort_keys=True) + "\n", encoding="utf-8")
    ledger = new_ledger("iwe")
    upsert_surface(ledger, {"surface_id": "surf-case", "kind": "endpoint", "ref": "/lab/" + capture.case_id, "status": "investigated"})
    add_evidence(ledger, program, "ev-case", rel, tool="bbtk-iwe-lab")
    add_candidate(ledger, "cand-case", "surf-case", {"A": "idor", "B": "xss", "C": "disclosure"}.get(capture.workflow, "other"), "iwe-harness", ["ev-case"], title="Synthetic candidate for human review")
    package = {"candidate_id": "cand-case", "declared_ledger_state": "candidate", "expected_behavior": "Private resources stay on their owner; public docs stay public.", "expected_behavior_source": "lab_spec", "observed_behavior": disposition, "observed_behavior_refs": ["ev-case"], "reported_classification": disposition, "deterministic_result": {"classification": disposition}, "claims": [{"claim_id": "state", "kind": "ledger_state", "text": "candidate", "evidence_refs": ["ev-case"]}, {"claim_id": "seen", "kind": "observed_behavior", "text": disposition, "evidence_refs": ["ev-case"]}, {"claim_id": "repro", "kind": "reproduction_step", "text": "Replay the stored loopback exchange inside the disposable lab.", "evidence_refs": ["ev-case"]}]}
    dossier = verify_research_dossier(package, ledger, program_dir=program)
    return {"finding_confirmed": bool(dossier.get("finding_confirmed")), "validation_result": dossier.get("validation_result"), "reproducibility": dossier.get("reproducibility_status"), "network_requests_sent": dossier.get("network_requests_sent", 0)}


def workflow_stops_for_human(root: Path) -> dict[str, Any]:
    """One review-only graph. Human stages are left without a reviewer."""
    artifact_dir = root / "artifacts"
    artifact_dir.mkdir(parents=True, exist_ok=True)
    specs: dict[str, dict[str, str]] = {}
    for stage in ("evidence_import", "integrity_validation", "discovery", "ranking", "object_handoff", "eligibility_check"):
        payload: dict[str, Any] = {"stage": stage, "outcome": "ok", "evidence_refs": ["ev-demo"]}
        if stage == "evidence_import":
            payload["evidence_ids"] = ["ev-demo"]
            payload["bundle_id"] = "iwe-demo"
        text = json.dumps(payload, sort_keys=True)
        rel = f"artifacts/{stage}.json"
        (root / rel).write_text(text, encoding="utf-8")
        specs[stage] = {"path": rel, "sha256": hashlib.sha256(text.encode("utf-8")).hexdigest()}
    workflow = build_workflow(root, specs, candidate_id="cand-demo")
    return {"finding_confirmed": bool(workflow.get("finding_confirmed")), "auto_confirmations": workflow.get("auto_confirmations"), "network_requests_sent": workflow.get("network_requests_sent"), "executions": workflow.get("executions"), "next_reviewable_tasks": workflow.get("next_reviewable_tasks"), "documental_complete": workflow.get("documental_complete")}
