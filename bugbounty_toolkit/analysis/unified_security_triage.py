"""Unified read-only security-research triage across IDOR / XSS / disclosure.

Extends the existing dashboard triage, evidence-gap planner, investigation
workflow and dossier verifier into one view. Never executes requests, never
mutates the ledger, never confirms vulnerabilities, and never lets AI approve
a finding. Ranking prefers valid evidence, correlation completeness, complete
controls and low uncertainty — not invented severity.
"""

from __future__ import annotations

from typing import Any, Mapping, Sequence

from bugbounty_toolkit.analysis.evidence_gap_planner import build_plan
from bugbounty_toolkit.analysis.investigation_workflow import minimized_view
from bugbounty_toolkit.core.records import ProgramPaths
from bugbounty_toolkit.dashboard_triage import (
    FORBIDDEN_ACTIONS,
    build_triage,
    candidate_detail,
    load_ledger_view,
)
from bugbounty_toolkit.reporting.dossier_verifier import verify_research_dossier

ANALYSIS_VERSION = "unified-security-research-triage-v1"

SECURITY_STATES = (
    "idor_candidate",
    "xss_candidate",
    "disclosure_candidate",
    "correlation_candidate",
    "gap_blocked",
    "integrity_blocked",
    "duplicate",
    "positive_control",
    "negative_control",
    "inconclusive",
    "review_ready_dossier",
    "other_candidate",
)

_IDOR = frozenset({"access_control", "idor", "bola", "bfla"})
_XSS = frozenset({"xss", "reflected_xss", "dom_xss", "stored_xss"})
_DISCLOSURE = frozenset({"information_disclosure", "disclosure", "info_disclosure"})
_CORRELATION = frozenset({"disclosure_access", "idor_disclosure", "correlation"})

UNIFIED_FORBIDDEN = tuple(
    dict.fromkeys(
        (
            *FORBIDDEN_ACTIONS,
            "exploit",
            "run_exploit",
            "send_payload",
            "ai_approve_finding",
            "ai_confirm_vulnerability",
            "show_session_data",
            "render_executable_html",
        )
    )
)

RANKING = {
    "order": [
        "1. Review-ready dossiers with valid evidence and complete controls.",
        "2. Correlation / IDOR / XSS / disclosure candidates with usable evidence.",
        "3. Incomplete controls or gaps (gap_blocked / integrity_blocked).",
        "4. Inconclusive, duplicates, then controls (pos/neg).",
        "5. Lower uncertainty before higher; stable candidate id as tie-break.",
        "Never rank by invented severity.",
    ],
    "limits": [
        "Read-only: no exploit buttons, no ledger writes, no AI approval.",
        "Classification reasons cite evidence refs and missing controls only.",
        "Session cookies/tokens/bodies are never included in the view.",
        "finding_confirmed stays false in this view; human ledger confirmation is separate.",
    ],
}

_STATE_ORDER = {
    "review_ready_dossier": 0,
    "correlation_candidate": 1,
    "idor_candidate": 2,
    "xss_candidate": 3,
    "disclosure_candidate": 4,
    "other_candidate": 5,
    "gap_blocked": 6,
    "integrity_blocked": 7,
    "inconclusive": 8,
    "duplicate": 9,
    "positive_control": 10,
    "negative_control": 11,
}


def _category_family(category: str) -> str:
    cat = category.lower()
    if cat in _IDOR:
        return "idor"
    if cat in _XSS:
        return "xss"
    if cat in _DISCLOSURE:
        return "disclosure"
    if cat in _CORRELATION:
        return "correlation"
    return "other"


def _uncertainty(row: Mapping[str, Any]) -> str:
    usable = int((row.get("evidence_counts") or {}).get("usable") or 0)
    missing = len(row.get("missing_controls") or [])
    warnings = len(row.get("warnings") or [])
    if usable == 0 or missing >= 3 or warnings >= 2:
        return "high"
    if missing or warnings or usable < 2:
        return "medium"
    return "low"


def _control_kind(cand: Mapping[str, Any]) -> str | None:
    raw_meta = cand.get("meta")
    meta: Mapping[str, Any] = raw_meta if isinstance(raw_meta, Mapping) else {}
    kind = meta.get("control_kind") or cand.get("control_kind")
    if kind in {"positive", "negative"}:
        return str(kind)
    raw_tags = cand.get("tags")
    tags: list[Any] = list(raw_tags) if isinstance(raw_tags, list) else []
    if "positive_control" in tags:
        return "positive"
    if "negative_control" in tags:
        return "negative"
    return None


def _duplicate_of(cand: Mapping[str, Any]) -> str | None:
    raw_meta = cand.get("meta")
    meta: Mapping[str, Any] = raw_meta if isinstance(raw_meta, Mapping) else {}
    value = meta.get("duplicate_of") or cand.get("duplicate_of")
    return str(value) if isinstance(value, str) and value else None


def _security_state(
    *,
    family: str,
    displayed: str,
    evidence_status: str,
    missing_controls: Sequence[str],
    blockers: Sequence[str],
    rejection_reason: str | None,
    duplicate_of: str | None,
    control_kind: str | None,
    dossier_ready: bool,
    uncertainty: str,
) -> tuple[str, list[str]]:
    if control_kind == "positive":
        return "positive_control", ["labelled_positive_control"]
    if control_kind == "negative":
        return "negative_control", ["labelled_negative_control"]
    if duplicate_of:
        return "duplicate", [f"duplicate_of:{duplicate_of}"]
    if displayed == "rejected":
        return "negative_control", [f"rejected:{rejection_reason or 'unspecified'}"]
    blocker_text = " ".join(str(b) for b in blockers).lower()
    if evidence_status in {"broken", "stale"} or "integrity" in blocker_text:
        reasons = [f"evidence_status:{evidence_status}"]
        reasons.extend(f"blocker:{b}" for b in list(blockers)[:5])
        return "integrity_blocked", reasons or ["integrity_blocked"]
    if missing_controls or evidence_status == "missing":
        reasons = [f"missing_control:{c}" for c in list(missing_controls)[:8]]
        if evidence_status == "missing":
            reasons.append("evidence_missing")
        return "gap_blocked", reasons or ["controls_incomplete"]
    if uncertainty == "high" and displayed != "confirmed":
        return "inconclusive", ["high_uncertainty"]
    if dossier_ready and displayed in {"requires_validation", "candidate", "confirmed"}:
        return "review_ready_dossier", ["dossier_controls_complete", f"family:{family}"]
    mapping = {
        "idor": "idor_candidate",
        "xss": "xss_candidate",
        "disclosure": "disclosure_candidate",
        "correlation": "correlation_candidate",
    }
    state = mapping.get(family, "other_candidate")
    return state, [f"family:{family}", f"ledger_displayed:{displayed}"]


def _gap_blockers_for(paths: ProgramPaths, candidate_id: str) -> list[str]:
    try:
        plan = build_plan(paths)
    except Exception:  # noqa: BLE001 — planner is best-effort enrichment
        return ["gap_plan_unavailable"]
    out: list[str] = []
    for item in plan.get("candidates") or []:
        if not isinstance(item, Mapping):
            continue
        if str(item.get("candidate_id")) != candidate_id:
            continue
        eligibility = item.get("effective_eligibility")
        if isinstance(eligibility, Mapping):
            status = str(eligibility.get("status") or "")
        else:
            status = str(eligibility or item.get("status") or "")
        if status in {"integrity_blocked", "blocked"}:
            out.append(status)
        for gap in item.get("gaps") or []:
            if isinstance(gap, Mapping) and gap.get("code"):
                out.append(str(gap["code"]))
            elif isinstance(gap, Mapping) and gap.get("kind"):
                out.append(str(gap["kind"]))
    return out


def _dossier_info(
    package: Mapping[str, Any] | None,
    ledger: Mapping[str, Any],
    paths: ProgramPaths,
    row: Mapping[str, Any],
    uncertainty: str,
) -> tuple[bool, dict[str, Any] | None]:
    if package is not None and ledger:
        try:
            dossier = verify_research_dossier(package, ledger, program_dir=paths.program_dir)
        except Exception as exc:  # noqa: BLE001
            return False, {"error": type(exc).__name__, "review_ready": False}
        ready = str(dossier.get("validation_result")) == "complete_for_review"
        summary = {
            # Unified view never elevates confirmation; AI cannot approve.
            "finding_confirmed": False,
            "ledger_finding_confirmed": bool(dossier.get("finding_confirmed")),
            "validation_result": dossier.get("validation_result"),
            "issues": len(dossier.get("issues") or []),
            "review_ready": ready,
        }
        return ready, summary
    ready = (
        row.get("evidence_status") == "present"
        and not row.get("missing_controls")
        and row.get("displayed_state") in {"requires_validation", "candidate", "confirmed"}
        and uncertainty == "low"
    )
    return ready, None


def build_unified_security_triage(
    paths: ProgramPaths,
    *,
    category: str | None = None,
    family: str | None = None,
) -> dict[str, Any]:
    """Assemble the unified security-research triage view (read-only)."""
    if family is not None and family not in {"idor", "xss", "disclosure", "correlation", "other"}:
        raise ValueError("family must be idor|xss|disclosure|correlation|other")
    base = build_triage(paths, category=category)
    view = load_ledger_view(paths)
    raw_ledger = view.get("ledger")
    ledger: dict[str, Any] = dict(raw_ledger) if isinstance(raw_ledger, dict) else {}
    candidates_by_id = {
        str(c.get("candidate_id")): c
        for c in (ledger.get("candidates") or [])
        if isinstance(c, dict) and c.get("candidate_id")
    }

    unified: list[dict[str, Any]] = []
    for row in base.get("candidates") or []:
        if not isinstance(row, dict):
            continue
        cid = str(row["candidate_id"])
        cand = candidates_by_id.get(cid) or {}
        fam = _category_family(str(row.get("category") or "unknown"))
        if family is not None and fam != family:
            continue
        uncertainty = _uncertainty(row)
        detail = candidate_detail(paths, cid) or {}
        package = cand.get("dossier_package") if isinstance(cand.get("dossier_package"), Mapping) else None
        dossier_ready, dossier_summary = _dossier_info(package, ledger, paths, row, uncertainty)
        gap_blockers = _gap_blockers_for(paths, cid)
        blockers = list(row.get("missing_controls") or []) + gap_blockers
        sec_state, reasons = _security_state(
            family=fam,
            displayed=str(row.get("displayed_state") or "candidate"),
            evidence_status=str(row.get("evidence_status") or "missing"),
            missing_controls=list(row.get("missing_controls") or []),
            blockers=blockers,
            rejection_reason=row.get("rejection_reason") if isinstance(row.get("rejection_reason"), str) else None,
            duplicate_of=_duplicate_of(cand),
            control_kind=_control_kind(cand),
            dossier_ready=dossier_ready,
            uncertainty=uncertainty,
        )
        unified.append(
            {
                "candidate_id": cid,
                "title": row.get("title"),
                "category": row.get("category"),
                "family": fam,
                "security_state": sec_state,
                "classification_reasons": reasons,
                "ledger_state": row.get("ledger_state"),
                "displayed_state": row.get("displayed_state"),
                "evidence_status": row.get("evidence_status"),
                "evidence_counts": row.get("evidence_counts"),
                "missing_controls": list(row.get("missing_controls") or []),
                "blockers": blockers[:20],
                "uncertainty": uncertainty,
                "dossier": dossier_summary,
                "idor_flow": row.get("idor_flow"),
                "warnings": list(row.get("warnings") or []),
                "ai_may_confirm": False,
                "finding_confirmed": False,
                "session_data_included": False,
                "executable_html": False,
                "detail_available": bool(detail),
                "_sort": (
                    _STATE_ORDER.get(sec_state, 50),
                    {"low": 0, "medium": 1, "high": 2}.get(uncertainty, 3),
                    0 if row.get("evidence_status") == "present" else 1,
                    cid,
                ),
            }
        )

    unified.sort(key=lambda r: r["_sort"])
    for rank, row in enumerate(unified, start=1):
        row.pop("_sort", None)
        row["rank"] = rank

    workflow_view = minimized_view({"tasks": [], "stop_conditions": ["ai_cannot_approve"], "read_only": True})
    counts = {state: sum(1 for r in unified if r["security_state"] == state) for state in SECURITY_STATES}
    return {
        "type": "unified-security-research-triage",
        "analysis_version": ANALYSIS_VERSION,
        "program": paths.program,
        "read_only": True,
        "forbidden_actions": list(UNIFIED_FORBIDDEN),
        "ai_may_confirm_findings": False,
        "ranking": RANKING,
        "ledger_status": base.get("ledger_status"),
        "ledger_valid": base.get("ledger_valid"),
        "coverage": base.get("coverage"),
        "issues": base.get("issues") or [],
        "broken_references": base.get("broken_references", 0),
        "filters": {
            "families": ["idor", "xss", "disclosure", "correlation", "other"],
            "security_states": list(SECURITY_STATES),
            "applied": {"category": category, "family": family},
        },
        "security_state_counts": counts,
        "counts": {"total": len(unified), "shown": len(unified)},
        "candidates": unified[:500],
        "workflow": workflow_view,
        "network_requests_sent": 0,
        "finding_confirmed": False,
        "notes": [
            "Unified view aggregates dashboard_triage + gap planner + dossier verifier.",
            "No exploit actions; UI must use textContent only (no executable HTML).",
            "Session data is excluded by construction.",
        ],
    }
