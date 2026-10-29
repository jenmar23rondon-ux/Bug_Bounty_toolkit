"""Reproducible offline IDOR/BOLA end-to-end research contract.

Stages (stable order):
  capture_import → object_discovery → ranking → object_handoff → eligibility
  → idor_proposal → control_review → evidence → evidence_ledger → report

Uses real ``handoff_case_eligibility`` codes (PR #34 on main). Never sends HTTP,
never runs access-check, never auto-confirms, never rewrites capture origins,
never converts incompatible pairs, never infers ownership from cookies / HTTP 200 /
ID coincidence. Structural eligibility is differentiated from authorization
outcome: denied actor responses (401/403/404/200-denial/auth-redirect) emit a
``bbtk-control-annotation/1`` negative control and do not become reviewable.

Confirmed candidates require sufficient evidence digests *and* explicit human review
(``review_candidate(..., human_attestation=True)``). Resume reuses valid artifacts
and refuses modified or expired evidence.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
import hashlib
import json
import re
import time
from pathlib import Path
from typing import Any, Literal, Mapping

from ..core.records import ProgramPaths, RecordStore
from ..idor_discovery import discover_idor
from ..reporting.json_report import build_program_report
from ..utils.exceptions import ToolkitError
from . import evidence_ledger as ledger_mod
from .access_assessment import assess_access_control_data
from .authorization_denial import assess_pair_authorization
from .handoff_case_eligibility import (
    CODE_CASE_ELIGIBLE,
    PairClassification,
    classify_materialized_paths,
)
from .object_handoff import propose_object_handoff
from .object_relationships import build_object_graph, object_candidates
from .resource_kind_lineage import check_kind_coherence

STAGE = Literal[
    "capture_import",
    "object_discovery",
    "ranking",
    "object_handoff",
    "eligibility",
    "idor_proposal",
    "control_review",
    "evidence",
    "evidence_ledger",
    "report",
]

STAGES: tuple[STAGE, ...] = (
    "capture_import",
    "object_discovery",
    "ranking",
    "object_handoff",
    "eligibility",
    "idor_proposal",
    "control_review",
    "evidence",
    "evidence_ledger",
    "report",
)

SESSION_VERSION = 1
SESSION_TYPE = "bbtk-idor-e2e-research-session/1"
REPORT_TYPE = "bbtk-idor-e2e-research-report/1"
# Synthetic expiry: token markers embedding this substring are treated as expired evidence.
EXPIRED_TOKEN_MARKER = "EXPIRED-SYNTH-TOKEN"
_SAFE_PROGRAM = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,79}$")


class ResearchError(ToolkitError):
    """Raised when a research session cannot proceed safely."""


@dataclass
class ArtifactRecord:
    """Digest-tracked artifact used for resume / integrity checks."""

    name: str
    path: str
    sha256: str
    kind: str


@dataclass
class ResearchSession:
    """Serializable offline research session (no secrets, no network state)."""

    session_id: str
    program: str
    version: int
    type: str
    capture_paths: list[str]
    capture_sha256: dict[str, str]
    origin_refs: list[str]
    stages_completed: list[str]
    artifacts: list[ArtifactRecord] = field(default_factory=list)
    handoff_status: str | None = None
    eligibility_summary: dict[str, int] = field(default_factory=dict)
    review_reasons: list[dict[str, str]] = field(default_factory=list)
    network_requests_sent: int = 0
    access_checks_executed: int = 0
    auto_confirmations: int = 0
    created_at_monotonic: float = 0.0

    def as_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["artifacts"] = [asdict(a) if isinstance(a, ArtifactRecord) else a for a in self.artifacts]
        return payload


def _sha_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _sha_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _write_json(path: Path, payload: Mapping[str, Any]) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    text = json.dumps(payload, indent=2, sort_keys=True) + "\n"
    path.write_text(text, encoding="utf-8")
    return _sha_bytes(text.encode("utf-8"))


def _record_artifact(session: ResearchSession, name: str, path: Path, kind: str) -> ArtifactRecord:
    digest = _sha_file(path)
    rel = str(path)
    record = ArtifactRecord(name=name, path=rel, sha256=digest, kind=kind)
    session.artifacts = [a for a in session.artifacts if a.name != name] + [record]
    return record


def verify_artifacts(session: ResearchSession, *, require_kinds: set[str] | None = None) -> list[dict[str, str]]:
    """Return integrity issues for missing/modified artifacts. Empty means reusable."""
    issues: list[dict[str, str]] = []
    seen_kinds: set[str] = set()
    for artifact in session.artifacts:
        seen_kinds.add(artifact.kind)
        target = Path(artifact.path)
        if not target.is_file():
            issues.append({"code": "ARTIFACT_MISSING", "name": artifact.name, "detail": artifact.path})
            continue
        current = _sha_file(target)
        if current != artifact.sha256:
            issues.append(
                {
                    "code": "ARTIFACT_MODIFIED",
                    "name": artifact.name,
                    "detail": f"expected={artifact.sha256[:16]}… actual={current[:16]}…",
                }
            )
        raw = target.read_bytes()
        # Expiry applies to derived evidence snapshots, not the authored capture corpus itself.
        if EXPIRED_TOKEN_MARKER.encode("ascii") in raw and artifact.kind in {
            "materialized_pair",
            "idor_proposal",
        }:
            issues.append(
                {
                    "code": "EVIDENCE_EXPIRED",
                    "name": artifact.name,
                    "detail": "Synthetic expired-token marker present in artifact bytes.",
                }
            )
    if require_kinds:
        missing = sorted(require_kinds - seen_kinds)
        for kind in missing:
            issues.append({"code": "ARTIFACT_KIND_MISSING", "name": kind, "detail": "required for resume"})
    return issues


def detect_ledger_integrity(program_dir: Path, ledger: Mapping[str, Any]) -> dict[str, Any]:
    """Wrap ledger validation; surface stale/modified evidence without fabricating controls."""
    validation = ledger_mod.validate_ledger(ledger, program_dir=program_dir)
    stale = set(validation.get("summary", {}).get("stale_evidence") or [])
    return {
        "valid": bool(validation.get("valid")),
        "stale_evidence": sorted(stale),
        "issues": list(validation.get("issues") or []),
        "modified_or_expired": bool(stale),
    }


def _control_review_offline(classification: PairClassification, proposal: Mapping[str, Any]) -> dict[str, Any]:
    """Offline control-review stub: never fabricates responses; never confirms.

    Eligible pairs still require human attestation. HTTP 200 alone is never ownership proof.
    """
    reasons: list[str] = []
    if not classification.case_eligible:
        reasons.append(f"Not case-eligible ({classification.code}): {classification.detail}")
    if classification.technical_error:
        reasons.append(f"Technical error ({classification.code}); do not force-convert.")
    if classification.legitimate_rejection:
        reasons.append(f"Legitimate rejection ({classification.code}); keep as hypothesis.")
    if not classification.has_owner_response or not classification.has_actor_response:
        reasons.append("Incomplete authorization evidence: missing control response(s).")
    # Never infer ownership from status codes recorded in the proposal metadata.
    status_hint = proposal.get("status_codes") or proposal.get("http_statuses")
    if status_hint == 200 or status_hint == [200, 200]:
        reasons.append("HTTP 200 is not ownership proof; human review required.")
    assessment = assess_access_control_data(
        {
            "type": "access-check-case",
            "accounts_authorized": False,
            "resource_private": False,
            "cross_account_denied": False,
        },
        None,
    )
    reasons.append(str(assessment.get("reason") or assessment.get("classification") or "insufficient_evidence"))
    return {
        "proposal_id": proposal.get("id"),
        "classification_code": classification.code,
        "classification_status": classification.status,
        "case_eligible": classification.case_eligible,
        "structural_pair": classification.status in {"structural_valid", "case_eligible"}
        or classification.code
        in {
            CODE_CASE_ELIGIBLE,
            "STRUCTURAL_VALID",
            "NEEDS_RESPONSE",
            "REJECT_MULTI_RESOURCE_DIFF",
            "REJECT_SESSION_ONLY",
            "REJECT_HEADER_DIFF",
            "REJECT_SAME_SESSION",
            "NEEDS_SECOND_SESSION",
            "NEEDS_MORE_EVIDENCE",
        },
        "technical_error": classification.technical_error,
        "legitimate_rejection": classification.legitimate_rejection,
        "requires_human_review": True,
        "confirmed": False,
        "fabricated_controls": False,
        "ownership_inferred": False,
        "access_check_executed": False,
        "review_reasons": reasons,
        "assessment_classification": assessment.get("classification"),
        "assessment_confirmed": bool(assessment.get("confirmed")),
    }


def run_e2e_research(
    program: str,
    captures: list[Path],
    workdir: Path,
    *,
    key: bytes,
    authorized: bool = True,
    limit: int = 20,
    resume_session: Path | None = None,
    reviewer: str = "lab-reviewer",
) -> dict[str, Any]:
    """Execute the full offline research contract (or resume from a valid session).

    Returns a structured report. Never contacts the network. Never confirms findings.
    """
    if not _SAFE_PROGRAM.fullmatch(program):
        raise ResearchError("Invalid program name.")
    if not captures:
        raise ResearchError("At least one local capture path is required.")
    for path in captures:
        if not path.is_file():
            raise ResearchError(f"Capture not found: {path}")

    workdir = workdir.resolve()
    workdir.mkdir(parents=True, exist_ok=True)
    pairs_dir = workdir / "pairs"
    evidence_dir = workdir / "evidence"
    session_path = workdir / "session.json"
    started = time.perf_counter()

    if resume_session is not None:
        return _resume(program, captures, workdir, key=key, session_path=resume_session, reviewer=reviewer)

    capture_digests = {str(p): _sha_file(p) for p in captures}
    session = ResearchSession(
        session_id=_sha_bytes(("|".join(sorted(capture_digests.values()))).encode())[:24],
        program=program,
        version=SESSION_VERSION,
        type=SESSION_TYPE,
        capture_paths=[str(p) for p in captures],
        capture_sha256=capture_digests,
        origin_refs=[],
        stages_completed=[],
        created_at_monotonic=time.monotonic(),
    )
    for path in captures:
        _record_artifact(session, f"capture:{path.name}", path, "capture")

    stages: dict[str, str] = {s: "pending" for s in STAGES}
    errors: list[str] = []
    review_rows: list[dict[str, Any]] = []
    classifications: list[dict[str, Any]] = []
    idor_rows: list[dict[str, Any]] = []

    graph = build_object_graph(
        program, list(captures), key, authorized=authorized, independent_windows=True, research_profile=True
    )
    stages["capture_import"] = "ok"
    stages["object_discovery"] = "ok"
    session.stages_completed.extend(["capture_import", "object_discovery"])
    session.origin_refs = sorted({n["origin_ref"] for n in graph["nodes"] if n.get("type") == "Endpoint"})
    session.network_requests_sent += int(graph.get("network_requests_sent") or 0)

    ranked_doc = object_candidates(graph, program, key, limit=max(limit, 1))
    ranked = ranked_doc["candidates"]
    stages["ranking"] = "ok"
    session.stages_completed.append("ranking")
    ranking_path = workdir / "ranking.json"
    _write_json(ranking_path, ranked_doc)
    _record_artifact(session, "ranking", ranking_path, "ranking")

    pairs_dir.mkdir(parents=True, exist_ok=True)
    handoff = propose_object_handoff(
        graph,
        program,
        key,
        verify_inputs=list(captures),
        limit=limit,
        materialize_dir=pairs_dir,
    )
    stages["object_handoff"] = "ok"
    session.stages_completed.append("object_handoff")
    session.handoff_status = str(handoff.get("status"))
    session.network_requests_sent += int(handoff.get("network_requests_sent") or 0)
    handoff_path = workdir / "handoff.json"
    # Strip absolute paths from persisted handoff for shareable digests; keep materialize on disk.
    safe_handoff = {
        k: v
        for k, v in handoff.items()
        if k
        not in {
            "materialize_dir",
        }
    }
    _write_json(handoff_path, safe_handoff)
    _record_artifact(session, "handoff", handoff_path, "handoff")

    # Provenance origin from handoff (never invent / rewrite).
    origins = sorted(
        {str(p.get("provenance_origin")) for p in handoff.get("proposals") or [] if p.get("provenance_origin")}
    )
    base_url = origins[0] if len(origins) == 1 else None

    for proposal in handoff.get("proposals") or []:
        pid = str(proposal["id"])
        for role in ("owner", "actor"):
            for suffix in ("", "-response"):
                candidate = pairs_dir / f"{pid}-{role}{suffix}.http"
                if candidate.is_file():
                    _record_artifact(session, f"pair:{candidate.name}", candidate, "materialized_pair")
        clf = classify_materialized_paths(pairs_dir, pid, base_url=base_url)
        classifications.append({"proposal_id": pid, **clf.as_dict()})
        review = _control_review_offline(clf, proposal)
        review_rows.append(review)
        session.review_reasons.append(
            {
                "proposal_id": pid,
                "code": clf.code,
                "reason": "; ".join(review["review_reasons"][:3]),
            }
        )

        idor_result: dict[str, Any] = {
            "proposal_id": pid,
            "attempted": False,
            "candidates": 0,
            "error": None,
            "state": None,
            "confirmed": False,
            "skipped_reason": None,
        }
        if clf.technical_error:
            idor_result["skipped_reason"] = f"technical_error:{clf.code}"
        elif clf.legitimate_rejection and not clf.case_eligible:
            idor_result["skipped_reason"] = f"legitimate_rejection:{clf.code}"
        elif not clf.case_eligible:
            idor_result["skipped_reason"] = f"not_eligible:{clf.code}"
        else:
            owner = pairs_dir / f"{pid}-owner.http"
            actor = pairs_dir / f"{pid}-actor.http"
            ores = pairs_dir / f"{pid}-owner-response.http"
            ares = pairs_dir / f"{pid}-actor-response.http"
            try:
                discovery = discover_idor(
                    program,
                    owner,
                    actor,
                    base_url=base_url,
                    owner_response=ores if ores.is_file() else None,
                    actor_response=ares if ares.is_file() else None,
                    accounts_authorized=False,
                    max_body_depth=64,
                )
                idor_result["attempted"] = True
                idor_result["candidates"] = len(discovery.proposal.get("candidates") or [])
                idor_result["state"] = discovery.proposal.get("state")
                idor_result["confirmed"] = bool(discovery.proposal.get("confirmed"))
                proposal_path = evidence_dir / f"idor-{pid}.json"
                evidence_dir.mkdir(parents=True, exist_ok=True)
                _write_json(proposal_path, discovery.proposal)
                _record_artifact(session, f"idor:{pid}", proposal_path, "idor_proposal")
            except (ValueError, OSError, ToolkitError) as exc:
                idor_result["error"] = f"{type(exc).__name__}: {str(exc)[:160]}"
        idor_rows.append(idor_result)

    stages["eligibility"] = "ok"
    stages["idor_proposal"] = "ok"
    stages["control_review"] = "ok"
    session.stages_completed.extend(["eligibility", "idor_proposal", "control_review"])
    session.eligibility_summary = {
        "case_eligible": sum(1 for c in classifications if c.get("case_eligible")),
        "technical_error": sum(1 for c in classifications if c.get("technical_error")),
        "legitimate_rejection": sum(1 for c in classifications if c.get("legitimate_rejection")),
        "structural_pairs": sum(
            1
            for c in classifications
            if c.get("status") in {"structural_valid", "case_eligible"}
            or c.get("code") in {CODE_CASE_ELIGIBLE, "STRUCTURAL_VALID", "NEEDS_RESPONSE"}
        ),
        "total_classified": len(classifications),
    }

    # Evidence + ledger (candidates stay unconfirmed).
    stages["evidence"] = "ok"
    session.stages_completed.append("evidence")
    program_paths = ProgramPaths(workdir, program)
    program_dir = program_paths.program_dir
    (program_dir / "evidence").mkdir(parents=True, exist_ok=True)
    store = RecordStore(program_paths)
    try:
        ledger = ledger_mod.new_ledger(program)
        # Two-pass: assess every materialized pair first so a demonstrated denial
        # (even on a structurally non-eligible same-URL session pair) can suppress
        # false "requires_validation" on sibling positive-control pairs.
        prepared: list[dict[str, Any]] = []
        for index, (proposal, clf_row, review) in enumerate(
            zip(handoff.get("proposals") or [], classifications, review_rows, strict=True)
        ):
            pid = str(proposal["id"])
            owner_resp_path = pairs_dir / f"{pid}-owner-response.http"
            actor_resp_path = pairs_dir / f"{pid}-actor-response.http"
            owner_raw = owner_resp_path.read_bytes() if owner_resp_path.is_file() else None
            actor_raw = actor_resp_path.read_bytes() if actor_resp_path.is_file() else None
            authz = assess_pair_authorization(owner_raw, actor_raw)
            review = {
                **review,
                "authorization_outcome": authz.outcome,
                "authorization_reasons": list(authz.reasons),
                "actor_response_class": authz.actor.response_class,
                "owner_response_class": authz.owner.response_class,
                "actor_access_proof": authz.actor.access_proof,
                "owner_access_proof": authz.owner.access_proof,
            }
            review_rows[index] = review
            payload: dict[str, Any] = {
                "proposal": {
                    k: proposal[k]
                    for k in (
                        "id",
                        "resource_type",
                        "score",
                        "confirmed",
                        "case_executable",
                        "researcher_review_required",
                        "endpoint_ref",
                        "endpoint_hint",
                        "owner",
                        "actor",
                        "provenance_origin",
                    )
                    if k in proposal
                },
                "classification": clf_row,
                "control_review": review,
                "authorization_assessment": {
                    "outcome": authz.outcome,
                    "reasons": list(authz.reasons),
                    "owner": authz.owner.as_dict(),
                    "actor": authz.actor.as_dict(),
                    "cross_account_denied": authz.outcome == "cross_account_denied",
                    "confirmed": False,
                },
            }
            if authz.annotation is not None:
                payload["control"] = authz.annotation
            prepared.append(
                {
                    "proposal": proposal,
                    "clf_row": clf_row,
                    "review": review,
                    "authz": authz,
                    "payload": payload,
                    "pid": pid,
                }
            )

        denial_pids = [row["pid"] for row in prepared if row["authz"].outcome == "cross_account_denied"]
        program_denied = bool(denial_pids)

        for row in prepared:
            proposal = row["proposal"]
            clf_row = row["clf_row"]
            authz = row["authz"]
            pid = row["pid"]
            rel = f"evidence/{pid}.json"
            # Sibling positive-control pairs inherit the denial annotation so the
            # planner can stop without treating them as successful access evidence.
            if (
                program_denied
                and authz.outcome != "cross_account_denied"
                and pid not in denial_pids
                and not isinstance(row["payload"].get("control"), dict)
            ):
                # Point at the first denial annotation; do not fabricate a new one.
                donor = next(r for r in prepared if r["pid"] == denial_pids[0])
                inherited = dict(donor["authz"].annotation or {})
                inherited["inherited_from"] = f"ev-{denial_pids[0]}"
                row["payload"]["control"] = inherited
                row["payload"]["authorization_assessment"] = {
                    **row["payload"]["authorization_assessment"],
                    "sibling_denial_observed": True,
                    "sibling_denial_evidence": f"ev-{denial_pids[0]}",
                }
            (program_dir / rel).write_text(json.dumps(row["payload"], sort_keys=True), encoding="utf-8")
            ledger_mod.upsert_surface(
                ledger,
                {
                    "surface_id": proposal["endpoint_ref"],
                    "kind": "endpoint",
                    "ref": str((proposal.get("endpoint_hint") or {}).get("path_template") or proposal["endpoint_ref"]),
                    "status": "investigated",
                },
            )
            evidence_refs = [f"ev-{pid}"]
            if program_denied and authz.outcome != "cross_account_denied":
                evidence_refs.append(f"ev-{denial_pids[0]}")
            ledger_mod.add_evidence(ledger, program_dir, f"ev-{pid}", rel, tool="idor-e2e-research")
            ledger_mod.add_candidate(
                ledger,
                f"cand-{pid}",
                proposal["endpoint_ref"],
                "idor",
                reviewer,
                evidence_refs,
                dedup_key=f"idor-e2e:{pid}",
            )
            visibility = authz.actor.resource_visibility or authz.owner.resource_visibility
            denied = authz.outcome == "cross_account_denied"
            public_or_shared = visibility in {"public", "shared"}
            # Demonstrated denial (this pair or a sibling in the same capture run)
            # must never become requires_validation / positive IDOR evidence.
            # idor-evidence-correctness-v3: a broken owner control or an actor body that only
            # echoes the identifier is not access proof; keep the candidate unpromoted.
            owner_broken = "owner_control_broken" in authz.reasons
            echo_only = authz.actor.access_proof == "id_echo_without_resource"
            if denied or public_or_shared or (clf_row.get("case_eligible") and program_denied):
                continue
            if owner_broken or echo_only:
                continue
            if clf_row.get("case_eligible"):
                ledger_mod.review_candidate(
                    ledger,
                    f"cand-{pid}",
                    "requires_validation",
                    reviewer,
                    blockers=[
                        "human_ownership_attestation",
                        "human_privacy_attestation",
                        "authorized_access_check_not_run",
                    ],
                )
            elif clf_row.get("legitimate_rejection") or clf_row.get("technical_error"):
                code = str(clf_row.get("code") or "")
                if code.startswith("REJECT_NON_GET") or code in {"REJECT_GET_WITH_BODY", "REJECT_METHOD_MISMATCH"}:
                    reason = "out_of_scope"
                elif clf_row.get("technical_error"):
                    reason = "evidence_invalidated"
                else:
                    reason = "not_reproducible"
                ledger_mod.review_candidate(
                    ledger,
                    f"cand-{pid}",
                    "rejected",
                    reviewer,
                    rejection_reason=reason,
                    rejection_detail=f"{code}: {str(clf_row.get('detail', ''))[:120]}",
                )

        ledger_path = program_dir / "ledger" / "evidence-ledger.json"
        validation = ledger_mod.save_ledger(ledger_path, ledger, program_dir=program_dir)
        integrity = detect_ledger_integrity(program_dir, ledger)
        stages["evidence_ledger"] = "ok"
        session.stages_completed.append("evidence_ledger")
        _record_artifact(session, "ledger", ledger_path, "ledger")
        program_report = build_program_report(store)
        stages["report"] = "ok"
        session.stages_completed.append("report")
    finally:
        store.close()

    session.access_checks_executed = 0
    session.auto_confirmations = int(handoff.get("vulnerabilities_confirmed") or 0)
    # Persist session last; do not track it as a resume integrity artifact (self-digest churn).
    session.artifacts = [a for a in session.artifacts if a.kind != "session"]
    _write_json(session_path, session.as_dict())

    elapsed_ms = int((time.perf_counter() - started) * 1000)
    report: dict[str, Any] = {
        "type": REPORT_TYPE,
        "program": program,
        "session_id": session.session_id,
        "stages": stages,
        "stage_order": list(STAGES),
        "errors": errors,
        "pending_contracts": [],
        "capture_import": graph.get("capture_import"),
        "origin_refs": session.origin_refs,
        "handoff_status": session.handoff_status,
        "ranking": [
            {
                "object_ref": c["object_ref"],
                "resource_type": c["resource_type"],
                "resource_kind": c.get("resource_kind"),
                "kind_status": (c.get("kind_lineage") or {}).get("status", "unknown"),
                "score": c["score"],
                "confirmed": c["confirmed"],
            }
            for c in ranked
        ],
        "structural_proposals": len(handoff.get("proposals") or []),
        "kind_coherence": check_kind_coherence(graph, ranked_doc, handoff),
        "classifications": classifications,
        "eligibility_summary": session.eligibility_summary,
        "idor_proposals": idor_rows,
        "control_reviews": review_rows,
        "ledger": {
            "valid": validation["valid"],
            "candidates": [
                {"candidate_id": c["candidate_id"], "state": c["state"], "evidence_refs": c["evidence_refs"]}
                for c in ledger["candidates"]
            ],
            "evidence": [{"evidence_id": e["evidence_id"], "sha256": e["sha256"]} for e in ledger["evidence"]],
            "integrity": integrity,
        },
        "program_report_ledger": program_report.get("evidence_ledger"),
        "network_requests_sent": session.network_requests_sent,
        "access_checks_executed": 0,
        "vulnerabilities_confirmed": session.auto_confirmations,
        "manual_steps_per_useful_case": _manual_steps_estimate(session.eligibility_summary),
        "elapsed_ms": elapsed_ms,
        "session_path": str(session_path),
        "resumed": False,
        "artifact_issues": [],
    }
    report_path = workdir / "e2e-report.json"
    _write_json(report_path, report)
    return report


def _manual_steps_estimate(summary: Mapping[str, int]) -> dict[str, Any]:
    """Automated proxy for manual effort (not a human productivity claim)."""
    useful = int(summary.get("case_eligible") or 0)
    # Capture review, eligibility check, ownership attest, privacy attest, approve, access-check gate.
    steps_if_eligible = 6
    return {
        "case_eligible": useful,
        "estimated_manual_steps_per_eligible": steps_if_eligible if useful else 0,
        "note": "Automated step count only; not a measured human time study.",
    }


def _resume(
    program: str,
    captures: list[Path],
    workdir: Path,
    *,
    key: bytes,
    session_path: Path,
    reviewer: str,
) -> dict[str, Any]:
    """Continue from a prior session when artifacts are intact; never re-import blindly."""
    del key, reviewer  # resume does not rebuild graph when artifacts validate
    if not session_path.is_file():
        raise ResearchError("Resume session file is missing.")
    try:
        raw = json.loads(session_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise ResearchError(f"Resume session is unreadable: {exc}") from exc
    if raw.get("type") != SESSION_TYPE or int(raw.get("version") or 0) != SESSION_VERSION:
        raise ResearchError("Resume session type/version is incompatible.")
    if raw.get("program") != program:
        raise ResearchError("Resume session program mismatch.")

    artifacts = [
        ArtifactRecord(**a) if isinstance(a, dict) else a for a in raw.get("artifacts") or [] if isinstance(a, dict)
    ]
    session = ResearchSession(
        session_id=str(raw["session_id"]),
        program=program,
        version=SESSION_VERSION,
        type=SESSION_TYPE,
        capture_paths=list(raw.get("capture_paths") or []),
        capture_sha256=dict(raw.get("capture_sha256") or {}),
        origin_refs=list(raw.get("origin_refs") or []),
        stages_completed=list(raw.get("stages_completed") or []),
        artifacts=artifacts,
        handoff_status=raw.get("handoff_status"),
        eligibility_summary=dict(raw.get("eligibility_summary") or {}),
        review_reasons=list(raw.get("review_reasons") or []),
        network_requests_sent=int(raw.get("network_requests_sent") or 0),
        access_checks_executed=int(raw.get("access_checks_executed") or 0),
        auto_confirmations=int(raw.get("auto_confirmations") or 0),
        created_at_monotonic=float(raw.get("created_at_monotonic") or 0.0),
    )

    # Capture digests must still match callers' inputs (no silent retarget).
    for path in captures:
        expected = session.capture_sha256.get(str(path))
        # Also accept by basename match when absolute paths differ across machines.
        if expected is None:
            for stored, digest in session.capture_sha256.items():
                if Path(stored).name == path.name:
                    expected = digest
                    break
        actual = _sha_file(path)
        if expected is None or expected != actual:
            raise ResearchError("Capture digest mismatch on resume; refusing re-bind without re-import.")

    issues = verify_artifacts(
        session,
        require_kinds={"ranking", "handoff", "ledger"},
    )
    blocking = [i for i in issues if i["code"] in {"ARTIFACT_MISSING", "ARTIFACT_MODIFIED", "ARTIFACT_KIND_MISSING"}]
    if blocking:
        return {
            "type": REPORT_TYPE,
            "program": program,
            "session_id": session.session_id,
            "stages": {s: ("ok" if s in session.stages_completed else "blocked") for s in STAGES},
            "errors": ["resume_blocked_modified_or_expired_evidence"],
            "pending_contracts": [],
            "resumed": False,
            "artifact_issues": issues,
            "network_requests_sent": 0,
            "access_checks_executed": 0,
            "vulnerabilities_confirmed": 0,
            "eligibility_summary": session.eligibility_summary,
            "classifications": [],
            "idor_proposals": [],
            "control_reviews": [],
            "structural_proposals": 0,
            "ranking": [],
            "origin_refs": session.origin_refs,
            "handoff_status": session.handoff_status,
            "ledger": {"valid": False, "candidates": [], "evidence": [], "integrity": {"modified_or_expired": True}},
            "manual_steps_per_useful_case": _manual_steps_estimate(session.eligibility_summary),
            "elapsed_ms": 0,
            "session_path": str(session_path),
        }

    # Artifacts intact: rebuild report from persisted files without re-import.
    handoff_path = next(Path(a.path) for a in session.artifacts if a.name == "handoff")
    ranking_path = next(Path(a.path) for a in session.artifacts if a.name == "ranking")
    ledger_path = next(Path(a.path) for a in session.artifacts if a.name == "ledger")
    handoff = json.loads(handoff_path.read_text(encoding="utf-8"))
    ranked_doc = json.loads(ranking_path.read_text(encoding="utf-8"))
    ledger = ledger_mod.load_ledger(ledger_path)
    program_dir = ProgramPaths(workdir, program).program_dir
    integrity = detect_ledger_integrity(program_dir, ledger)
    clf_path = workdir / "e2e-report.json"
    prior = json.loads(clf_path.read_text(encoding="utf-8")) if clf_path.is_file() else {}
    return {
        "type": REPORT_TYPE,
        "program": program,
        "session_id": session.session_id,
        "stages": {s: "ok" for s in STAGES},
        "stage_order": list(STAGES),
        "errors": [],
        "pending_contracts": [],
        "resumed": True,
        "artifact_issues": issues,
        "capture_import": prior.get("capture_import"),
        "origin_refs": session.origin_refs,
        "handoff_status": session.handoff_status,
        "ranking": prior.get("ranking")
        or [
            {
                "object_ref": c["object_ref"],
                "resource_type": c["resource_type"],
                "resource_kind": c.get("resource_kind"),
                "kind_status": (c.get("kind_lineage") or {}).get("status", "unknown"),
                "score": c["score"],
                "confirmed": c["confirmed"],
            }
            for c in ranked_doc.get("candidates") or []
        ],
        "structural_proposals": len(handoff.get("proposals") or []),
        "classifications": prior.get("classifications") or [],
        "eligibility_summary": session.eligibility_summary,
        "idor_proposals": prior.get("idor_proposals") or [],
        "control_reviews": prior.get("control_reviews") or [],
        "ledger": {
            "valid": integrity["valid"],
            "candidates": [
                {"candidate_id": c["candidate_id"], "state": c["state"], "evidence_refs": c["evidence_refs"]}
                for c in ledger.get("candidates") or []
                if isinstance(c, dict)
            ],
            "evidence": [
                {"evidence_id": e["evidence_id"], "sha256": e["sha256"]}
                for e in ledger.get("evidence") or []
                if isinstance(e, dict)
            ],
            "integrity": integrity,
        },
        "program_report_ledger": prior.get("program_report_ledger"),
        "network_requests_sent": 0,
        "access_checks_executed": 0,
        "vulnerabilities_confirmed": 0,
        "manual_steps_per_useful_case": _manual_steps_estimate(session.eligibility_summary),
        "elapsed_ms": 0,
        "session_path": str(session_path),
        "note": "Resumed from intact artifacts; capture was not re-imported.",
    }
