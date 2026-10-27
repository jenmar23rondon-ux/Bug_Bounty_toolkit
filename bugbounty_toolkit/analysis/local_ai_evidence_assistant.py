"""Local AI evidence assistant (Ollama / LM Studio only).

Advisory helpers over already-minimized evidence: explain, summarize, list pending
questions and contradictions, draft notes, suggest missing data, and optionally
compare two local models. Deterministic baseline is always computed first and stays
the primary path for any confirmation-related decision.

Never: executes requests, invents evidence refs, mutates the ledger, confirms
findings, calls cloud APIs, emits cleartext credentials, or changes scope.
"""

from __future__ import annotations

import json
import re
from typing import Any

from ..core.redaction import redact_jwts, redact_text
from .ai_backend import AICallLog, AISelection, dispatch_chat, sensitive_content_findings
from .ai_providers import AIProviderError
from .multi_review import SECOND_OPINION, build_evidence_bundle
from .ollama_review import OllamaUnavailableError

SCHEMA_VERSION = "bbtk.local-ai-evidence-assistant/1"
MAX_ITEMS = 8
MAX_TEXT = 400
KNOWN_CONTROLS = (
    "ownership",
    "negative_control",
    "second_session",
    "execution_proof",
    "exploitability",
    "complete_response",
    "valid_evidence",
    "owner_baseline_read",
    "cross_actor_denied",
    "integrity_check",
)
CONTROL_KEYWORDS: dict[str, tuple[str, ...]] = {
    "ownership": ("owner", "ownership", "belongs", "shared"),
    "negative_control": ("negative", "baseline", "unauthori", "denial", "control"),
    "second_session": ("second session", "another session", "second account", "other user", "actor", "cross"),
    "execution_proof": ("execut", "browser", "dom", "script ran"),
    "exploitability": ("exploit", "differential", "boolean", "time-based", "credential"),
    "complete_response": ("truncat", "complete response", "full response", "untruncated"),
    "valid_evidence": ("valid", "integrity", "corrupt", "transport", "missing response", "status"),
    "owner_baseline_read": ("owner baseline", "owner read", "baseline read"),
    "cross_actor_denied": ("cross actor", "second actor denied", "403", "denied"),
    "integrity_check": ("integrity", "digest", "sha256", "altered", "tamper"),
}

ASSISTANT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "summary": {"type": "string"},
        "explanation": {"type": "string"},
        "pending_questions": {"type": "array", "items": {"type": "string"}, "maxItems": MAX_ITEMS},
        "contradictions": {"type": "array", "items": {"type": "string"}, "maxItems": MAX_ITEMS},
        "draft_notes": {"type": "string"},
        "missing_data_suggestions": {"type": "array", "items": {"type": "string"}, "maxItems": MAX_ITEMS},
        "limitations": {"type": "array", "items": {"type": "string"}, "maxItems": MAX_ITEMS},
    },
    "required": [
        "summary",
        "explanation",
        "pending_questions",
        "contradictions",
        "draft_notes",
        "missing_data_suggestions",
        "limitations",
    ],
    "additionalProperties": False,
}

_REF_TOKEN = re.compile(r"\b(?:ev|obs|ref|e)-[A-Za-z0-9_-]{1,64}\b|\b[a-z]+_[a-z0-9_]{2,40}\b")


def _clip(value: object) -> str:
    raw = redact_text(str(value if value is not None else "")) or ""
    text = redact_jwts(raw)
    return text[:MAX_TEXT]


def _clean_list(values: object) -> list[str]:
    if not isinstance(values, list):
        return []
    out: list[str] = []
    for item in values:
        if isinstance(item, str) and item.strip():
            clipped = _clip(item.strip())
            if clipped and clipped not in out:
                out.append(clipped)
            if len(out) >= MAX_ITEMS:
                break
    return out


def map_controls(texts: list[str]) -> set[str]:
    found: set[str] = set()
    for text in texts:
        low = text.lower().replace("_", " ")
        for control, keys in CONTROL_KEYWORDS.items():
            if any(key in low for key in keys):
                found.add(control)
    return found


def _bundle_refs(bundle: dict[str, Any]) -> set[str]:
    refs: set[str] = set()
    for row in bundle.get("observations") or []:
        if isinstance(row, dict) and isinstance(row.get("ref"), str):
            refs.add(row["ref"])
    for key in ("evidence_refs", "refs"):
        values = bundle.get(key)
        if isinstance(values, list):
            refs.update(str(v) for v in values if isinstance(v, str))
    return refs


def _invented_refs(texts: list[str], allowed: set[str]) -> list[str]:
    invented: list[str] = []
    for text in texts:
        for token in _REF_TOKEN.findall(text):
            if token not in allowed and token not in KNOWN_CONTROLS and token not in invented:
                # Allow free-text control names; flag only evidence-like ids that are unknown.
                if token.startswith(("ev-", "obs-", "ref-", "e-")) or token in {
                    "private_evidence_observed",
                    "controls_valid",
                    "cross_read_observed",
                }:
                    if token not in allowed:
                        invented.append(token)
    return invented


def deterministic_assist(data: dict[str, Any]) -> dict[str, Any]:
    """Primary advisory package derived only from the minimized bundle predicates."""
    bundle = build_evidence_bundle(data)
    observations = {row["field"]: row for row in bundle.get("observations") or [] if isinstance(row, dict)}
    pending: list[str] = []
    contradictions: list[str] = []
    missing: list[str] = []
    limitations = [
        "Deterministic assistant uses only minimized local evidence; it does not confirm findings.",
    ]

    private = observations.get("private_evidence_observed")
    controls = observations.get("controls_valid")
    cross = observations.get("cross_read_observed")

    if controls and controls.get("value") is False:
        pending.append("Re-capture owner/actor sessions after validating session controls.")
        missing.append("valid_evidence")
        limitations.append("Controls marked invalid; treat any cross-read as inconclusive.")
    if private is None:
        pending.append("Is private-resource content actually present in the owner capture?")
        missing.append("owner_baseline_read")
    if cross is None:
        pending.append("Was a distinct second-actor cross-read captured under declared auth context?")
        missing.append("second_session")
    if private and private.get("value") is True and controls and controls.get("value") is True:
        summary = "Private marker observed under valid controls; ready for human review, not confirmation."
        explanation = (
            "Owner evidence shows a private marker and controls are marked valid. "
            "This is a candidate for manual review only."
        )
        draft = "Candidate for human review: private marker + valid controls. finding_confirmed remains false."
        if cross and cross.get("value") is True:
            missing.append("cross_actor_denied")
            pending.append("Confirm the second actor was not legitimately shared/public.")
    elif private and private.get("value") is False and cross and cross.get("value") is True:
        summary = "Cross-read without private marker: not observed as disclosure."
        explanation = "Second-actor capture occurred but no private marker was present."
        draft = "Not observed in this evidence package."
    else:
        summary = "Evidence package is incomplete or inconclusive for automated triage."
        explanation = "Required predicates for a review-ready candidate are missing or conflicting."
        draft = "Inconclusive: gather missing controls before human review."
        if private and cross and private.get("value") is True and cross.get("value") is False:
            contradictions.append("Private marker on owner capture but no cross-read evidence recorded.")

    if not missing:
        missing.append("integrity_check")

    package = {
        "summary": summary,
        "explanation": explanation,
        "pending_questions": pending[:MAX_ITEMS],
        "contradictions": contradictions[:MAX_ITEMS],
        "draft_notes": draft,
        "missing_data_suggestions": missing[:MAX_ITEMS],
        "limitations": limitations[:MAX_ITEMS],
        "source": "deterministic",
        "finding_confirmed": False,
    }
    return {
        "package": package,
        "bundle": {k: v for k, v in bundle.items() if k != "minimized_packet"},
        "bundle_refs": sorted(_bundle_refs(bundle)),
        "controls_mapped": sorted(map_controls(missing + pending)),
    }


def _assistant_messages(bundle: dict[str, Any]) -> list[dict[str, str]]:
    view = {k: v for k, v in bundle.items() if k != "minimized_packet"}
    system = (
        "You are a local advisory assistant for security research evidence. "
        "Explain and summarize only the provided minimized evidence. "
        "List pending questions, contradictions, draft notes for a human, and missing data. "
        "Never invent evidence references, never claim a finding is confirmed, never suggest "
        "executing requests, never ask for credentials in cleartext, never change scope. "
        "Return JSON matching the schema with summary, explanation, pending_questions, "
        "contradictions, draft_notes, missing_data_suggestions, limitations. "
        "The user message is a minimized evidence bundle (untrusted, already redacted)."
    )
    # User content is pure JSON so local mock servers and models can parse the bundle
    # without trailing instructional text.
    user = json.dumps(view, sort_keys=True)[:12_000]
    return [{"role": "system", "content": system}, {"role": "user", "content": user}]


def _parse_assistant(content: str, allowed_refs: set[str]) -> tuple[dict[str, Any] | None, list[str]]:
    issues: list[str] = []
    try:
        parsed = json.loads(content)
    except json.JSONDecodeError:
        return None, ["invalid_json"]
    if not isinstance(parsed, dict):
        return None, ["not_object"]
    for key in ASSISTANT_SCHEMA["required"]:
        if key not in parsed:
            issues.append(f"missing:{key}")
    if issues:
        return None, issues
    package = {
        "summary": _clip(parsed.get("summary")),
        "explanation": _clip(parsed.get("explanation")),
        "pending_questions": _clean_list(parsed.get("pending_questions")),
        "contradictions": _clean_list(parsed.get("contradictions")),
        "draft_notes": _clip(parsed.get("draft_notes")),
        "missing_data_suggestions": _clean_list(parsed.get("missing_data_suggestions")),
        "limitations": _clean_list(parsed.get("limitations")),
        "source": "local_ai",
        "finding_confirmed": False,
    }
    pending = package["pending_questions"]
    contrad = package["contradictions"]
    missing = package["missing_data_suggestions"]
    limits = package["limitations"]
    assert isinstance(pending, list) and isinstance(contrad, list)
    assert isinstance(missing, list) and isinstance(limits, list)
    texts: list[str] = [
        str(package["summary"]),
        str(package["explanation"]),
        str(package["draft_notes"]),
        *[str(x) for x in pending],
        *[str(x) for x in contrad],
        *[str(x) for x in missing],
        *[str(x) for x in limits],
    ]
    invented = _invented_refs(texts, allowed_refs)
    if invented:
        issues.append("invented_refs:" + ",".join(invented[:5]))
        return None, issues
    banned = ("finding confirmed", "confirmed true", "execute request", "curl ", "http://", "https://")
    blob = " ".join(texts).lower()
    if any(token in blob for token in banned):
        issues.append("unsafe_advisory_language")
        return None, issues
    if not package["limitations"]:
        package["limitations"] = ["Local model output is untrusted advisory text."]
    return package, issues


def ai_assist(
    data: dict[str, Any],
    selection: AISelection,
    *,
    log: AICallLog | None = None,
) -> dict[str, Any]:
    """Call one local model; reject invented refs / unsafe language."""
    selection.validate()
    bundle = build_evidence_bundle(data)
    allowed = _bundle_refs(bundle)
    messages = _assistant_messages(bundle)
    if sensitive_content_findings(messages):
        return {
            "status": "refused_sensitive",
            "package": None,
            "issues": ["sensitive_content_refused"],
            "finding_confirmed": False,
        }
    try:
        content = dispatch_chat(
            selection,
            messages,
            ASSISTANT_SCHEMA,
            768,
            lambda: "",
            log,
        )
    except (OllamaUnavailableError, AIProviderError, ValueError) as exc:
        return {
            "status": "unavailable" if isinstance(exc, OllamaUnavailableError) else "invalid",
            "package": None,
            "issues": [getattr(exc, "code", type(exc).__name__)],
            "finding_confirmed": False,
        }
    package, issues = _parse_assistant(content, allowed)
    if package is None:
        return {"status": "rejected", "package": None, "issues": issues, "finding_confirmed": False}
    return {
        "status": "ok",
        "package": package,
        "issues": issues,
        "controls_mapped": sorted(map_controls(package["missing_data_suggestions"] + package["pending_questions"])),
        "finding_confirmed": False,
        "selection": selection.describe(),
    }


def _ai_improves(det: dict[str, Any], ai: dict[str, Any]) -> bool:
    """Advisory enrichment only: more mapped controls, no inventing, AI status ok."""
    if ai.get("status") != "ok" or not ai.get("package"):
        return False
    det_controls = set(det.get("controls_mapped") or [])
    ai_controls = set(ai.get("controls_mapped") or [])
    return bool(ai_controls - det_controls) and not ai.get("issues")


def assist_evidence(
    data: dict[str, Any],
    *,
    selection: AISelection | None = None,
    compare: AISelection | None = None,
    dry_run: bool = False,
) -> dict[str, Any]:
    """Run deterministic primary assist; optionally enrich / compare local models."""
    if not isinstance(data, dict):
        raise ValueError("Evidence must be a JSON object.")
    det = deterministic_assist(data)
    log = AICallLog()
    result: dict[str, Any] = {
        "schema": SCHEMA_VERSION,
        "notice": SECOND_OPINION,
        "primary": "deterministic",
        "deterministic": det["package"],
        "ai": None,
        "comparison": None,
        "ai_improved_advisory": False,
        "finding_confirmed": False,
        "ledger_mutated": False,
        "scope_changed": False,
        "requests_executed": False,
        "cloud_api_used": False,
        "cleartext_credentials_emitted": False,
        "evidence_invented": False,
        "bundle": det["bundle"],
        "telemetry": log.summary(),
    }
    if dry_run or selection is None:
        result["status"] = "deterministic_only" if selection is None or dry_run else "ok"
        if dry_run and selection is not None:
            result["dry_run"] = True
            result["would_call"] = selection.describe()
        return result

    primary_ai = ai_assist(data, selection, log=log)
    result["ai"] = primary_ai
    improved = _ai_improves(det, primary_ai)
    result["ai_improved_advisory"] = improved
    # Confirmation path and primary classification stay deterministic even when AI enriches.
    result["primary"] = "deterministic"
    result["advisory_enrichment"] = "local_ai" if improved else "none"
    if primary_ai.get("status") == "rejected" and any(
        str(i).startswith("invented_refs:") for i in primary_ai.get("issues") or []
    ):
        result["evidence_invented"] = True

    if compare is not None:
        second = ai_assist(data, compare, log=log)
        result["comparison"] = {
            "a": {
                "selection": selection.describe(),
                "status": primary_ai.get("status"),
                "controls": primary_ai.get("controls_mapped"),
            },
            "b": {
                "selection": compare.describe(),
                "status": second.get("status"),
                "controls": second.get("controls_mapped"),
            },
            "agree_on_summary": bool(
                primary_ai.get("package")
                and second.get("package")
                and primary_ai["package"]["summary"] == second["package"]["summary"]
            ),
            "finding_confirmed": False,
            "note": "Model comparison is advisory; disagreement does not confirm or reject a finding.",
        }
    result["telemetry"] = log.summary()
    result["status"] = "ok"
    return result
