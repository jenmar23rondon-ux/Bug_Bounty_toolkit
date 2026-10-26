"""Read-only triage views for the local dashboard.

Every value shown here is derived from artifacts that other bbtk commands already
write: the evidence ledger (``ledger/evidence-ledger.json``), saved prioritization
reports, AI review comparisons and the program's SQLite run index. This module
stores nothing, never changes a candidate state, never contacts the network and
never decides authorization or execution. Ledger validation reuses
:func:`analysis.evidence_ledger.validate_ledger` so the dashboard and the CLI
agree on what counts as a broken reference or an unsupported confirmation.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Mapping

from .analysis.evidence_ledger import (
    CANDIDATE_STATES,
    MAX_LEDGER_BYTES,
    REJECTION_REASONS,
    SURFACE_STATUSES,
    validate_ledger,
)
from .analysis.prioritization import _POTENTIAL_IMPACT
from .core.records import ProgramPaths
from .core.redaction import redact_jwts

MAX_ARTIFACT_BYTES = 8 * 1024 * 1024
MAX_SCANNED_REPORTS = 100
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_HEX = re.compile(r"^[0-9a-f]{64}$")
_IDOR_CATEGORIES = frozenset({"access_control", "idor", "bola", "bfla"})
_EVIDENCE_FILTERS = frozenset({"any", "present", "missing", "stale", "broken"})
_STATE_QUEUE_ORDER = {"requires_validation": 0, "candidate": 1, "confirmed": 2, "rejected": 3}
_IMPACT_ORDER = {"high": 0, "medium": 1, "low": 2, "unknown": 3}
# Issue codes produced by validate_ledger that mean a reference or evidence file is unusable.
_BROKEN_CODES = frozenset(
    {
        "broken_evidence_ref",
        "broken_surface_ref",
        "broken_investigation_ref",
        "broken_graph_ref",
        "broken_finding_ref",
        "broken_duplicate_ref",
        "evidence_missing",
        "evidence_digest_mismatch",
        "evidence_path_unsafe",
        "evidence_too_large",
        "evidence_invalidated_by_change",
    }
)
RANKING_EXPLANATION = {
    "order": [
        "1. Queue state: requires_validation, then candidate, then confirmed, then rejected.",
        "2. Candidates whose evidence is missing, stale or broken sort after those with usable evidence.",
        "3. Category potential-impact band from analysis.prioritization (heuristic, not demonstrated).",
        "4. Saved prioritization score when a report with the same group/candidate ID exists.",
        "5. Candidate ID as a stable tie-breaker.",
    ],
    "limits": [
        "Ranking is a reading order for human triage; it is not severity, confidence or proof.",
        "The impact band is a category heuristic and has not been demonstrated for any candidate.",
        "Only artifacts already saved under this program are considered; nothing is re-tested.",
        "A candidate is displayed as confirmed only when the ledger says so and validation raised no error for it.",
    ],
}
FORBIDDEN_ACTIONS = (
    "run_scanner",
    "approve_test",
    "confirm_vulnerability",
    "change_scope",
    "run_command",
    "upload_evidence_to_cloud",
)


_DISPLAY_SECRET = re.compile(
    r"(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]{6,}"
    r"|\b(authorization|proxy-authorization|cookie|set-cookie|x-api-key|api[_-]?key|access[_-]?token|"
    r"refresh[_-]?token|token|secret|password|passwd|session(?:[_-]?id)?|csrf[_-]?token)\b(\s*[:=]\s*)"
    r"(?:(?:bearer|basic)\s+)?(\"[^\"]{0,400}\"|'[^']{0,400}'|[^\s;&,\"']{1,400})"
)


def mask_display_secrets(value: str) -> str:
    """Display-layer masking on top of core redaction; never applied to stored evidence."""

    def _replace(match: re.Match[str]) -> str:
        if match.group(1):
            return f"{match.group(1)} [redacted]"
        return f"{match.group(2)}{match.group(3)}[redacted]"

    return _DISPLAY_SECRET.sub(_replace, redact_jwts(value))


def _text(value: object, limit: int = 200) -> str | None:
    """Printable, length-bounded, secret-masked display text (rendered with textContent only)."""
    if not isinstance(value, str):
        return None
    cleaned = "".join(ch for ch in value[: limit * 4] if ch.isprintable())
    return mask_display_secrets(cleaned)[:limit]


def _map(value: object) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _ident(value: object) -> str | None:
    return value if isinstance(value, str) and _ID.fullmatch(value) else None


def _read_json(path: Path, maximum: int) -> object:
    with path.open("rb") as handle:
        raw = handle.read(maximum + 1)
    if len(raw) > maximum:
        raise ValueError("artifact_too_large")
    try:
        return json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise ValueError("artifact_malformed") from exc


def _contained_file(root: Path, candidate: Path) -> bool:
    try:
        return candidate.is_file() and not candidate.is_symlink() and candidate.resolve().parent == root.resolve()
    except OSError:
        return False


def ledger_path(paths: ProgramPaths) -> Path:
    return paths.program_dir / "ledger" / "evidence-ledger.json"


def load_ledger_view(paths: ProgramPaths) -> dict[str, Any]:
    """Return ``{status, ledger, validation}`` without raising on missing/malformed files."""
    path = ledger_path(paths)
    if not path.exists():
        return {"status": "absent", "ledger": None, "validation": None}
    if not _contained_file(path.parent, path):
        return {"status": "error", "error": "ledger_path_rejected", "ledger": None, "validation": None}
    try:
        data = _read_json(path, MAX_LEDGER_BYTES)
    except (OSError, ValueError) as exc:
        return {
            "status": "error",
            "error": str(exc) if str(exc).startswith("artifact_") else "unreadable",
            "ledger": None,
            "validation": None,
        }
    if not isinstance(data, dict):
        return {"status": "error", "error": "artifact_malformed", "ledger": None, "validation": None}
    try:
        validation = validate_ledger(data, program_dir=paths.program_dir)
    except (TypeError, ValueError, AttributeError, KeyError):
        return {"status": "error", "error": "ledger_validation_failed", "ledger": None, "validation": None}
    return {"status": "ok", "ledger": data, "validation": validation}


def _issue_view(issue: Mapping[str, Any]) -> dict[str, object]:
    code = _text(issue.get("code"), 60) or "unknown"
    return {
        "severity": "error" if issue.get("severity") == "error" else "warning",
        "code": code,
        "ref": _text(issue.get("ref"), 130),
        "message": _text(issue.get("message"), 300),
        "broken_reference": code in _BROKEN_CODES or code.startswith("broken_"),
    }


def _prioritization_scores(paths: ProgramPaths) -> dict[str, dict[str, Any]]:
    scores: dict[str, dict[str, Any]] = {}
    for _name, data in _typed_reports(paths, "investigation-prioritization", limit=1):
        items = data.get("items")
        if not isinstance(items, list):
            continue
        for item in items[:500]:
            if not isinstance(item, dict):
                continue
            gid = _ident(item.get("group_id"))
            score = item.get("priority_score")
            if gid and type(score) is int:
                scores[gid] = {
                    "priority_score": score,
                    "research_priority": _text(item.get("research_priority"), 20),
                    "missing_controls": [
                        t
                        for t in (
                            (_text(c, 200))
                            for c in (item.get("evidence_quality") or {}).get("missing_controls", [])[:20]
                        )
                        if t
                    ]
                    if isinstance(item.get("evidence_quality"), dict)
                    and isinstance(item["evidence_quality"].get("missing_controls"), list)
                    else [],
                }
    return scores


def _typed_reports(paths: ProgramPaths, report_type: str, limit: int) -> list[tuple[str, dict[str, Any]]]:
    root = paths.reports_dir
    if not root.is_dir():
        return []
    try:
        files = sorted(
            (p for p in root.iterdir() if p.suffix.lower() == ".json" and _contained_file(root, p)),
            key=lambda p: (p.stat().st_mtime, p.name),
            reverse=True,
        )[:MAX_SCANNED_REPORTS]
    except OSError:
        return []
    found: list[tuple[str, dict[str, Any]]] = []
    for path in files:
        try:
            data = _read_json(path, MAX_ARTIFACT_BYTES)
        except (OSError, ValueError):
            continue
        if isinstance(data, dict) and data.get("type") == report_type:
            found.append((path.name, data))
            if len(found) >= limit:
                break
    return found


def _idor_flow(
    category: str, state: str, evidence_usable: int, blockers: list[str], reviewed: bool
) -> dict[str, object]:
    if category not in _IDOR_CATEGORIES:
        return {"applicable": False, "stage": None, "stages": []}
    stages = [
        ("candidate_raised", True),
        ("evidence_attached", evidence_usable > 0),
        ("controls_documented", evidence_usable > 0 and not blockers and state != "candidate"),
        ("human_review", reviewed),
    ]
    if state == "rejected":
        stage = "rejected"
    elif state == "confirmed" and reviewed:
        stage = "human_confirmed"
    else:
        stage = next((name for name, done in stages if not done), "human_review")
        stage = f"awaiting_{stage}"
    return {
        "applicable": True,
        "stage": stage,
        "stages": [{"name": name, "done": done} for name, done in stages],
        "note": "Flow state is read from the ledger; the dashboard cannot advance it.",
    }


def build_triage(
    paths: ProgramPaths,
    *,
    category: str | None = None,
    state: str | None = None,
    evidence: str | None = None,
) -> dict[str, Any]:
    """Assemble the prioritized candidate queue and investigation overview."""
    if state is not None and state not in CANDIDATE_STATES:
        raise ValueError("state filter must be one of: " + ", ".join(CANDIDATE_STATES))
    if evidence is not None and evidence not in _EVIDENCE_FILTERS:
        raise ValueError("evidence filter must be one of: " + ", ".join(sorted(_EVIDENCE_FILTERS)))
    if category is not None and not re.fullmatch(r"[a-z][a-z0-9_]{0,39}", category):
        raise ValueError("category filter must be a short lowercase identifier.")
    view = load_ledger_view(paths)
    base: dict[str, Any] = {
        "type": "dashboard-triage",
        "program": paths.program,
        "ledger_status": view["status"],
        "ranking": RANKING_EXPLANATION,
        "read_only": True,
        "forbidden_actions": list(FORBIDDEN_ACTIONS),
        "network_requests_sent": 0,
        "ollama_calls": 0,
        "auto_confirmations": 0,
    }
    if view["status"] != "ok":
        empty = {"surfaces_total": 0, "surface_status": {k: 0 for k in SURFACE_STATUSES}}
        message = (
            "No evidence ledger yet. Create one with `bbtk ledger init` and add candidates offline."
            if view["status"] == "absent"
            else "The evidence ledger could not be read; fix it with `bbtk ledger validate`."
        )
        return {
            **base,
            "error": view.get("error"),
            "message": message,
            "coverage": empty,
            "candidates": [],
            "issues": [],
            "filters": {},
            "counts": {"total": 0, "shown": 0},
        }
    ledger: dict[str, Any] = view["ledger"]
    validation: dict[str, Any] = view["validation"]
    issues = [_issue_view(i) for i in validation.get("issues", [])[:500] if isinstance(i, dict)]
    error_refs = {
        str(i.get("ref")) for i in validation.get("issues", []) if isinstance(i, dict) and i.get("severity") == "error"
    }
    summary = validation.get("summary") or {}
    stale = set(summary.get("stale_evidence") or [])
    evidence_rows = {e.get("evidence_id"): e for e in ledger.get("evidence") or [] if isinstance(e, dict)}
    surfaces = {s.get("surface_id"): s for s in ledger.get("surfaces") or [] if isinstance(s, dict)}
    broken_ev = {
        str(i.get("ref"))
        for i in validation.get("issues", [])
        if isinstance(i, dict) and str(i.get("code")) in _BROKEN_CODES
    }
    scores = _prioritization_scores(paths)

    rows: list[dict[str, Any]] = []
    categories: set[str] = set()
    for cand in ledger.get("candidates") or []:
        if not isinstance(cand, dict):
            continue
        cid = _ident(cand.get("candidate_id"))
        if cid is None:
            continue
        cat = (_text(cand.get("category"), 40) or "unknown").lower()
        categories.add(cat)
        state_value = cand.get("state")
        raw_state = state_value if isinstance(state_value, str) and state_value in CANDIDATE_STATES else "candidate"
        refs = [r for r in cand.get("evidence_refs") or [] if isinstance(r, str)][:100]
        missing = [r for r in refs if r not in evidence_rows]
        stale_refs = [r for r in refs if r in stale or r in broken_ev]
        usable = [r for r in refs if r in evidence_rows and r not in stale_refs]
        candidate_errors = cid in error_refs
        review = _map(cand.get("review")) or None
        displayed = raw_state
        warnings: list[str] = []
        if raw_state == "confirmed" and (candidate_errors or not usable or review is None):
            displayed = "requires_validation"
            warnings.append("Ledger says confirmed but validation failed; shown as requires_validation.")
        if missing:
            warnings.append(f"{len(missing)} evidence reference(s) do not exist in the ledger.")
        if stale_refs:
            warnings.append(f"{len(stale_refs)} evidence file(s) are stale, changed or unreadable.")
        ev_status = "broken" if missing else "stale" if stale_refs else "present" if usable else "missing"
        blockers = [t for t in (_text(b, 300) for b in (cand.get("blockers") or [])[:20]) if t]
        score = scores.get(cid) or scores.get(str(cand.get("dedup_key") or ""))
        missing_controls = list(blockers)
        if score:
            missing_controls += [c for c in score["missing_controls"] if c not in missing_controls]
        if displayed in {"candidate", "requires_validation"} and not usable:
            missing_controls.append("Attach at least one current, digest-verified evidence file.")
        if displayed in {"candidate", "requires_validation"} and review is None:
            missing_controls.append("Independent human review (not the raiser, not a model or tool).")
        surface = surfaces.get(cand.get("surface_id")) or {}
        rejection = _map(cand.get("rejection"))
        impact = _POTENTIAL_IMPACT.get(cat, "unknown")
        rows.append(
            {
                "candidate_id": cid,
                "title": _text(cand.get("title"), 200),
                "category": cat,
                "ledger_state": raw_state,
                "displayed_state": displayed,
                "confirmed": displayed == "confirmed",
                "surface": {
                    "surface_id": _ident(cand.get("surface_id")),
                    "kind": _text(surface.get("kind"), 20),
                    "ref": _text(surface.get("ref"), 200),
                    "status": surface.get("status") if surface.get("status") in SURFACE_STATUSES else "unknown",
                },
                "evidence_status": ev_status,
                "evidence_counts": {
                    "referenced": len(refs),
                    "usable": len(usable),
                    "missing": len(missing),
                    "stale_or_invalid": len(stale_refs),
                },
                "potential_impact_band": impact,
                "priority_score": score["priority_score"] if score else None,
                "missing_controls": missing_controls,
                "rejection_reason": rejection.get("reason") if rejection.get("reason") in REJECTION_REASONS else None,
                "reviewed_by_human": review is not None
                and displayed == "confirmed"
                or (review is not None and raw_state == "rejected"),
                "idor_flow": _idor_flow(cat, displayed, len(usable), blockers, review is not None),
                "warnings": warnings,
                "_sort": (
                    _STATE_QUEUE_ORDER.get(displayed, 9),
                    0 if ev_status == "present" else 1,
                    _IMPACT_ORDER.get(impact, 3),
                    -(int(score["priority_score"]) if score else -1),
                    cid,
                ),
            }
        )
    rows.sort(key=lambda r: r["_sort"])
    for rank, row in enumerate(rows, start=1):
        row.pop("_sort")
        row["rank"] = rank
    shown = [
        r
        for r in rows
        if (category is None or r["category"] == category)
        and (state is None or r["displayed_state"] == state)
        and (evidence in {None, "any"} or r["evidence_status"] == evidence)
    ]
    surface_status = summary.get("surface_status") or {}
    blocked = [
        {
            "surface_id": _ident(s.get("surface_id")),
            "ref": _text(s.get("ref"), 200),
            "blocker": _text(s.get("blocker"), 300),
        }
        for s in surfaces.values()
        if s.get("status") in {"blocked", "pending"}
    ][:200]
    return {
        **base,
        "ledger_valid": bool(validation.get("valid")),
        "coverage": {
            "surfaces_total": summary.get("surfaces_total", 0),
            "surface_status": {k: int(surface_status.get(k, 0)) for k in SURFACE_STATUSES},
            "coverage_ratio": summary.get("coverage_ratio", 0.0),
            "pending_or_blocked": blocked,
        },
        "candidate_states": {k: sum(1 for r in rows if r["displayed_state"] == k) for k in CANDIDATE_STATES},
        "issues": issues,
        "broken_references": sum(1 for i in issues if i["broken_reference"]),
        "filters": {
            "categories": sorted(categories),
            "states": list(CANDIDATE_STATES),
            "evidence": sorted(_EVIDENCE_FILTERS),
            "applied": {"category": category, "state": state, "evidence": evidence},
        },
        "counts": {"total": len(rows), "shown": len(shown)},
        "candidates": shown[:500],
        "message": None if rows else "The ledger has no candidates yet.",
    }


def candidate_detail(paths: ProgramPaths, candidate_id: str) -> dict[str, Any] | None:
    """Return one candidate with minimized evidence provenance (no paths, bodies or secrets)."""
    if not _ID.fullmatch(candidate_id):
        raise ValueError("Candidate ID is invalid.")
    triage = build_triage(paths)
    row = next((r for r in triage["candidates"] if r["candidate_id"] == candidate_id), None)
    if row is None:
        return None
    ledger: dict[str, Any] = load_ledger_view(paths)["ledger"] or {}
    cand = next(
        (c for c in ledger.get("candidates") or [] if isinstance(c, dict) and c.get("candidate_id") == candidate_id), {}
    )
    evidence_rows = {e.get("evidence_id"): e for e in ledger.get("evidence") or [] if isinstance(e, dict)}
    provenance: list[dict[str, object]] = []
    for ref in [r for r in cand.get("evidence_refs") or [] if isinstance(r, str)][:100]:
        ev = evidence_rows.get(ref)
        if ev is None:
            provenance.append({"evidence_id": _text(ref, 128), "status": "missing_from_ledger"})
            continue
        prov = _map(ev.get("provenance"))
        digest = ev.get("sha256")
        path = ev.get("path")
        provenance.append(
            {
                "evidence_id": _ident(ref),
                "status": "listed",
                "sha256_prefix": digest[:16] if isinstance(digest, str) and _HEX.fullmatch(digest) else None,
                "file_kind": Path(path).suffix.lower()[:10] if isinstance(path, str) else None,
                "tool": _text(prov.get("tool"), 80),
                "captured_at": _text(prov.get("captured_at"), 40),
                "bundle_id": _ident(prov.get("bundle_id")),
                "investigation_id": _ident(prov.get("investigation_id")),
                "graph_node_count": len(prov.get("graph_node_ids") or [])
                if isinstance(prov.get("graph_node_ids"), list)
                else 0,
            }
        )
    issues = [
        i
        for i in triage["issues"]
        if i["ref"] == candidate_id or i["ref"] in {p.get("evidence_id") for p in provenance}
    ]
    return {
        "type": "dashboard-triage-candidate",
        "candidate": row,
        "evidence_provenance": provenance,
        "provenance_notice": "Paths, bodies, headers and cookies are withheld; only IDs, digest prefixes and tool metadata are shown.",
        "issues": issues,
        "ranking": RANKING_EXPLANATION,
        "read_only": True,
        "network_requests_sent": 0,
    }


def ai_review_differences(paths: ProgramPaths) -> dict[str, Any]:
    """Summarize the latest saved two-reviewer comparison; agreement is never treated as proof."""
    reports = _typed_reports(paths, "ai-evidence-review-comparison", limit=1)
    if not reports:
        return {
            "latest": None,
            "message": "No saved AI review comparison. The dashboard works without Ollama.",
            "consensus_is_proof": False,
            "finding_confirmed": False,
        }
    name, data = reports[0]
    comp = _map(data.get("comparison"))

    def refs(key: str) -> list[str]:
        value = comp.get(key)
        return [t for t in (_text(v, 128) for v in value[:100]) if t] if isinstance(value, list) else []

    reviewers = []
    for review in (data.get("reviews") or [])[:2]:
        if isinstance(review, dict):
            reviewers.append(
                {
                    "provider": _text(review.get("provider"), 40),
                    "model": _text(review.get("model"), 80),
                    "decision": _text(review.get("decision"), 40),
                    "validation_status": _text(review.get("validation_status"), 40),
                }
            )
    independence = _map(comp.get("independence"))
    return {
        "latest": name,
        "reviewers": reviewers,
        "decision_agreement": comp.get("decision_agreement") is True,
        "both_reviews_valid": comp.get("both_reviews_valid") is True,
        "disputed_evidence": refs("disputed_evidence"),
        "cited_by_first_only": refs("cited_by_first_only"),
        "cited_by_second_only": refs("cited_by_second_only"),
        "missing_controls_union": refs("missing_controls_union"),
        "independent": independence.get("independent") is True,
        "consensus_weight": _text(comp.get("consensus_weight"), 40),
        "consensus_is_proof": False,
        "finding_confirmed": False,
    }


def compare_prioritization_runs(paths: ProgramPaths) -> dict[str, Any]:
    """Diff the two most recent saved prioritization reports (local runs only)."""
    reports = _typed_reports(paths, "investigation-prioritization", limit=2)
    if len(reports) < 2:
        return {
            "available": False,
            "reports": [n for n, _ in reports],
            "message": "Two saved prioritization reports are needed to compare runs.",
        }

    def scores(data: dict[str, Any]) -> dict[str, int]:
        out: dict[str, int] = {}
        for item in (data.get("items") or [])[:500]:
            if isinstance(item, dict) and _ident(item.get("group_id")) and type(item.get("priority_score")) is int:
                out[item["group_id"]] = item["priority_score"]
        return out

    (new_name, new), (old_name, old) = reports
    a, b = scores(old), scores(new)
    return {
        "available": True,
        "newer": new_name,
        "older": old_name,
        "added": sorted(set(b) - set(a)),
        "removed": sorted(set(a) - set(b)),
        "score_changes": [
            {"group_id": g, "before": a[g], "after": b[g]} for g in sorted(set(a) & set(b)) if a[g] != b[g]
        ],
        "status_before": _text(old.get("status"), 40),
        "status_after": _text(new.get("status"), 40),
    }


def review_queue_reports(paths: ProgramPaths, report_names: list[str]) -> dict[str, Any]:
    """Pair saved reports with the ledger's open review queue; never marks anything reviewed."""
    triage = build_triage(paths)
    needs_review = [r["candidate_id"] for r in triage["candidates"] if r["displayed_state"] == "requires_validation"]
    return {
        "reports": report_names[:500],
        "candidates_awaiting_human_review": needs_review,
        "ready_for_review": bool(report_names) and bool(needs_review),
        "notice": "A report is ready for human review, not for submission; the dashboard cannot approve it.",
    }
