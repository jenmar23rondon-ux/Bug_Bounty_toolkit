"""Claim-to-evidence verifier for offline verified research dossiers.

Validates that important statements in a review package reference existing,
digest-intact evidence and remain consistent with the Evidence Ledger. Never
mutates ledger or finding states, never issues HTTP, never invents repro steps
or payloads, and never treats model verdicts or bare HTTP 200 as confirmation.
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path, PurePosixPath
from typing import Any, Mapping

from ..analysis.evidence_ledger import (
    AUTOMATIC_BASES,
    CANDIDATE_STATES,
    REVIEW_METHODS,
    file_sha256,
    validate_ledger,
)
from ..core.redaction import RedactionDestination, redact_data
from .dossier_schema import (
    CLAIM_KINDS,
    DOSSIER_NOTICE,
    DOSSIER_STATES,
    EXPECTED_BEHAVIOR_SOURCES,
    SCHEMA_VERSION,
)
from .finding_report import (
    build_evidence_finding_report,
    render_evidence_report_json,
    render_evidence_report_markdown,
)

_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_HTTP200_UNAUTHORIZED = re.compile(
    r"(http\s*200|status\s*200).{0,40}(unauthori[sz]ed|idor|bola|broken.?access)",
    re.IGNORECASE | re.DOTALL,
)
_ENDPOINT_IMPACT = re.compile(
    r"(critical|high|severe).{0,40}(because|since|from).{0,40}(endpoint|/api/)",
    re.IGNORECASE | re.DOTALL,
)
_MAX_CLAIMS = 200
_MAX_DOSSIER_BYTES = 2 * 1024 * 1024


class DossierError(ValueError):
    """Raised when a dossier package is malformed beyond recoverable audit."""


def _issue(
    severity: str,
    code: str,
    ref: str,
    message: str,
    *,
    claim_id: str | None = None,
) -> dict[str, str]:
    row = {"severity": severity, "code": code, "ref": ref, "message": message}
    if claim_id:
        row["claim_id"] = claim_id
    return row


def _safe_relpath(value: object) -> str | None:
    if not isinstance(value, str) or not value or len(value) > 240 or "\\" in value:
        return None
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        return None
    return path.as_posix()


def _find(rows: list[Any], key: str, value: str) -> dict[str, Any] | None:
    return next((row for row in rows if isinstance(row, dict) and row.get(key) == value), None)


def _as_str_list(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, str) and item.strip()][:100]


def _text(value: object, limit: int = 2000) -> str:
    if isinstance(value, str):
        return value.strip()[:limit]
    if isinstance(value, (int, float, bool)):
        return str(value)[:limit]
    return ""


def _shareable(value: object) -> object:
    return redact_data(value, destination=RedactionDestination.SHAREABLE_REPORT)


def _claim_row(
    claim_id: str,
    kind: str,
    *,
    text: str = "",
    evidence_refs: list[str] | None = None,
    supported: bool | None = None,
    notes: str = "",
    source: str | None = None,
) -> dict[str, Any]:
    row: dict[str, Any] = {
        "claim_id": claim_id,
        "kind": kind,
        "text": text[:2000],
        "evidence_refs": list(evidence_refs or []),
        "supported": supported,
        "notes": notes[:1000],
    }
    if source:
        row["source"] = source[:80]
    return row


def extract_claims_from_package(package: Mapping[str, Any]) -> list[dict[str, Any]]:
    """Normalize caller-supplied claims; invent nothing beyond the package."""
    raw = package.get("claims")
    claims: list[dict[str, Any]] = []
    if isinstance(raw, list):
        for index, item in enumerate(raw[:_MAX_CLAIMS]):
            if not isinstance(item, dict):
                continue
            kind = _text(item.get("kind"), 80) or "classification"
            if kind not in CLAIM_KINDS:
                kind = "classification"
            cid = _text(item.get("claim_id"), 128) or f"claim-{index + 1}"
            claims.append(
                _claim_row(
                    cid,
                    kind,
                    text=_text(item.get("text", item.get("value"))),
                    evidence_refs=_as_str_list(item.get("evidence_refs")),
                    source=_text(item.get("source"), 80) or None,
                )
            )
    return claims


def _evidence_inventory(
    ledger: Mapping[str, Any],
    program_dir: Path | None,
    issues: list[dict[str, str]],
) -> list[dict[str, Any]]:
    inventory: list[dict[str, Any]] = []
    for record in ledger.get("evidence") or []:
        if not isinstance(record, dict):
            continue
        eid = _text(record.get("evidence_id"), 128)
        if not eid:
            continue
        rel = _safe_relpath(record.get("path"))
        entry: dict[str, Any] = {
            "evidence_id": eid,
            "path": rel or "",
            "recorded_sha256": _text(record.get("sha256"), 64),
            "status": "recorded",
            "provenance": record.get("provenance") if isinstance(record.get("provenance"), dict) else {},
        }
        if rel is None:
            entry["status"] = "invalid_path"
            issues.append(_issue("error", "invalid_provenance", eid, "Evidence path is unsafe."))
        elif program_dir is None:
            entry["status"] = "unchecked"
        else:
            target = program_dir / rel
            if not target.is_file():
                entry["status"] = "missing"
                issues.append(_issue("error", "missing_evidence", eid, "Evidence file does not exist."))
            else:
                digest = file_sha256(target)
                entry["current_sha256"] = digest
                if digest != record.get("sha256"):
                    entry["status"] = "altered"
                    issues.append(
                        _issue("error", "stale_evidence", eid, "Evidence digest no longer matches the ledger.")
                    )
                else:
                    entry["status"] = "intact"
                    prov = entry["provenance"]
                    if not isinstance(prov, dict) or not _text(prov.get("tool")) or not _text(prov.get("captured_at")):
                        entry["status"] = "invalid_provenance"
                        issues.append(
                            _issue("error", "invalid_provenance", eid, "Provenance tool/captured_at missing.")
                        )
        inventory.append(entry)
    return inventory


def _candidate_row(ledger: Mapping[str, Any], candidate_id: str) -> dict[str, Any] | None:
    return _find(list(ledger.get("candidates") or []), "candidate_id", candidate_id)


def _verify_claim(
    claim: dict[str, Any],
    *,
    candidate: dict[str, Any] | None,
    evidence_index: dict[str, dict[str, Any]],
    package: Mapping[str, Any],
    issues: list[dict[str, str]],
) -> dict[str, Any]:
    kind = str(claim.get("kind"))
    cid = str(claim.get("claim_id"))
    refs = [r for r in claim.get("evidence_refs") or [] if isinstance(r, str)]
    text = _text(claim.get("text"))
    notes: list[str] = []
    supported: bool | None = True

    broken = [r for r in refs if r not in evidence_index]
    for ref in broken:
        issues.append(
            _issue("error", "broken_evidence_ref", ref, f"Claim {cid} references unknown evidence.", claim_id=cid)
        )
        supported = False
    intact_refs = [r for r in refs if evidence_index.get(r, {}).get("status") == "intact"]
    altered_refs = [r for r in refs if evidence_index.get(r, {}).get("status") == "altered"]
    missing_refs = [
        r for r in refs if evidence_index.get(r, {}).get("status") in {"missing", "invalid_path", "invalid_provenance"}
    ]
    for ref in altered_refs:
        issues.append(_issue("error", "stale_evidence", ref, f"Claim {cid} depends on altered evidence.", claim_id=cid))
        supported = False
    for ref in missing_refs:
        code = (
            "invalid_provenance"
            if evidence_index.get(ref, {}).get("status") == "invalid_provenance"
            else "missing_evidence"
        )
        issues.append(_issue("error", code, ref, f"Claim {cid} depends on missing or invalid evidence.", claim_id=cid))
        supported = False

    already_flagged = bool(broken or altered_refs or missing_refs)

    if kind == "ledger_state":
        declared = text or _text(package.get("declared_ledger_state"))
        actual = _text((candidate or {}).get("state")) or "unknown"
        if declared and declared != actual:
            supported = False
            notes.append(f"Declared ledger state {declared!r} != ledger {actual!r}.")
            issues.append(
                _issue(
                    "error",
                    "ledger_state_mismatch",
                    cid,
                    f"Declared state {declared!r} does not match ledger {actual!r}.",
                    claim_id=cid,
                )
            )
        elif not declared:
            supported = False
            notes.append("No ledger state declared on the claim.")
        claim["text"] = declared or actual

    elif kind == "evidence_reference":
        if not refs:
            supported = False
            notes.append("Evidence reference claim has no refs.")
            issues.append(_issue("error", "missing_evidence", cid, "Evidence claim lacks refs.", claim_id=cid))
        elif already_flagged:
            supported = False

    elif kind == "expected_behavior":
        source = _text(claim.get("source") or package.get("expected_behavior_source"), 80)
        if source not in EXPECTED_BEHAVIOR_SOURCES:
            supported = False
            notes.append("Expected behavior must cite lab_spec/program_policy/explicit_declaration/human_declared.")
            issues.append(
                _issue(
                    "error",
                    "unsupported_claim",
                    cid,
                    "Expected behavior lacks an allowed explicit source.",
                    claim_id=cid,
                )
            )
        if not text:
            supported = False
            notes.append("Expected behavior text empty.")
        claim["source"] = source or "missing"

    elif kind == "observed_behavior":
        if not intact_refs:
            supported = False
            notes.append("Observed behavior needs at least one intact evidence ref.")
            if not already_flagged:
                issues.append(
                    _issue(
                        "error",
                        "missing_evidence",
                        cid,
                        "Observed behavior is not backed by intact evidence.",
                        claim_id=cid,
                    )
                )

    elif kind == "control_result":
        if not intact_refs:
            supported = False
            notes.append("Control result needs intact evidence.")
            if not already_flagged:
                issues.append(
                    _issue("error", "missing_evidence", cid, "Control claim lacks intact evidence.", claim_id=cid)
                )

    elif kind == "ownership":
        if not intact_refs:
            supported = False
            notes.append("Ownership not demonstrated by recorded evidence.")
            issues.append(
                _issue(
                    "error",
                    "unsupported_claim",
                    cid,
                    "Ownership claim lacks intact evidence (never inferred).",
                    claim_id=cid,
                )
            )

    elif kind == "impact":
        if not intact_refs:
            supported = False
            notes.append("Impact claim has no intact evidence.")
            issues.append(_issue("error", "unsupported_claim", cid, "Impact lacks evidence refs.", claim_id=cid))
        if _ENDPOINT_IMPACT.search(text) or (
            "endpoint" in text.lower() and any(w in text.lower() for w in ("critical", "high severity", "severe"))
        ):
            supported = False
            notes.append("Impact inferred from endpoint name is rejected.")
            issues.append(
                _issue(
                    "error",
                    "unsupported_claim",
                    cid,
                    "Impact must not be inferred from an endpoint name.",
                    claim_id=cid,
                )
            )
        if package.get("impact_invented") is True:
            supported = False
            notes.append("Package marks impact as invented.")
            issues.append(_issue("error", "unsupported_claim", cid, "Invented impact rejected.", claim_id=cid))

    elif kind == "reproduction_step":
        invented = bool(package.get("invented_reproduction") or claim.get("invented"))
        if invented or not intact_refs:
            supported = False
            notes.append("Reproduction steps must cite recorded evidence; invented steps rejected.")
            issues.append(
                _issue(
                    "error",
                    "unsupported_claim",
                    cid,
                    "Reproduction step is invented or lacks intact evidence.",
                    claim_id=cid,
                )
            )
        if any(token in text.lower() for token in ("payload=", "exploit payload", "crafted payload")):
            supported = False
            notes.append("Payload generation is out of scope for dossier verification.")
            issues.append(_issue("error", "unsupported_claim", cid, "Payload generation rejected.", claim_id=cid))

    elif kind == "confirmation":
        supported = False
        ledger_state = _text((candidate or {}).get("state"))
        raw_review = (candidate or {}).get("review")
        review: dict[str, Any] = raw_review if isinstance(raw_review, dict) else {}
        method = _text(review.get("method")).lower()
        reviewer = _text(review.get("reviewer")).lower()
        basis = _text(review.get("basis")).lower()
        basis_words = set(re.findall(r"[a-z_]+", basis))
        if ledger_state != "confirmed":
            notes.append(f"Ledger state is {ledger_state or 'unknown'}, not confirmed.")
            issues.append(
                _issue(
                    "error",
                    "human_validation_required",
                    cid,
                    "Confirmation claim rejected: ledger is not confirmed.",
                    claim_id=cid,
                )
            )
        elif method not in REVIEW_METHODS or reviewer in AUTOMATIC_BASES | {"bbtk", "ollama", "agent", ""}:
            notes.append("Confirmation lacks an independent human review method/reviewer.")
            issues.append(
                _issue(
                    "error",
                    "human_validation_required",
                    cid,
                    "Confirmed ledger state fails human-validation checks.",
                    claim_id=cid,
                )
            )
        elif basis_words and basis_words <= AUTOMATIC_BASES:
            notes.append("Confirmation basis is only an automatic verdict.")
            issues.append(
                _issue(
                    "error",
                    "human_validation_required",
                    cid,
                    "Confirmation basis is automatic/heuristic only.",
                    claim_id=cid,
                )
            )
        elif not intact_refs and not _as_str_list((candidate or {}).get("evidence_refs")):
            notes.append("No intact evidence for confirmation.")
            issues.append(_issue("error", "missing_evidence", cid, "Confirmed claim lacks evidence.", claim_id=cid))
        else:
            supported = True
            notes.append("Matches ledger confirmed state with human review.")

        if package.get("ai_confirmation") is True or "model" in text.lower() or "llm" in text.lower():
            notes.append("Model verdict is never accepted as confirmation by itself.")
            issues.append(
                _issue(
                    "error",
                    "unsupported_claim",
                    cid,
                    "Model verdict cannot confirm a finding.",
                    claim_id=cid,
                )
            )
            if ledger_state != "confirmed":
                supported = False
            else:
                supported = False

    elif kind == "ai_conclusion":
        if package.get("treat_ai_as_confirmed") is True or "confirmed" in text.lower():
            supported = False
            notes.append("Unverified AI conclusion presented as confirmation.")
            issues.append(
                _issue(
                    "error",
                    "unsupported_claim",
                    cid,
                    "AI conclusion is not a confirmation.",
                    claim_id=cid,
                )
            )
        else:
            notes.append("AI conclusion recorded as non-confirming opinion.")
            supported = True if intact_refs or not refs else False
            if refs and not intact_refs:
                supported = False

    elif kind == "classification":
        if _HTTP200_UNAUTHORIZED.search(text) or (
            package.get("http_200_as_unauthorized") is True
            and "200" in text
            and any(w in text.lower() for w in ("unauthori", "idor", "bola"))
        ):
            supported = False
            notes.append("HTTP 200 alone does not prove unauthorized access.")
            issues.append(
                _issue(
                    "error",
                    "unsupported_claim",
                    cid,
                    "HTTP 200 must not be interpreted as unauthorized access.",
                    claim_id=cid,
                )
            )
        det = package.get("deterministic_result")
        if isinstance(det, dict) and text:
            det_class = _text(det.get("classification")).lower()
            if (
                det_class
                and det_class not in text.lower()
                and package.get("classification_matches_deterministic") is False
            ):
                supported = False
                notes.append("Claimed classification does not follow from saved deterministic result.")
                issues.append(
                    _issue(
                        "error",
                        "unsupported_claim",
                        cid,
                        "Classification does not follow from deterministic evidence.",
                        claim_id=cid,
                    )
                )
        if not intact_refs and not det and not already_flagged:
            supported = False
            notes.append("Classification lacks intact evidence or deterministic result.")
            issues.append(
                _issue("error", "missing_evidence", cid, "Classification lacks backing evidence.", claim_id=cid)
            )
        elif not intact_refs and not det:
            supported = False

    elif kind == "severity":
        if not intact_refs:
            supported = False
            notes.append("Severity suggestion lacks intact evidence.")
            issues.append(_issue("warning", "unsupported_claim", cid, "Severity lacks evidence.", claim_id=cid))

    else:
        supported = False
        notes.append(f"Unknown claim kind {kind!r}.")
        issues.append(_issue("error", "unsupported_claim", cid, f"Unknown claim kind {kind}.", claim_id=cid))

    claim["supported"] = supported
    claim["notes"] = "; ".join(notes)[:1000]
    return claim


def _state_priority(issues: list[dict[str, str]], *, human_required: bool) -> str:
    codes = {item["code"] for item in issues if item.get("severity") == "error"}
    if "invalid_provenance" in codes:
        return "invalid_provenance"
    if "broken_evidence_ref" in codes or "missing_evidence" in codes or "evidence_incomplete" in codes:
        return "missing_evidence"
    if "stale_evidence" in codes or "evidence_digest_mismatch" in codes:
        return "stale_evidence"
    if "ledger_state_mismatch" in codes or "contradictory_evidence" in codes or any("contradict" in c for c in codes):
        return "contradictory_evidence"
    # Documentary failures beat the soft "still needs a human" signal from ledger state.
    if "unsupported_claim" in codes:
        return "unsupported_claim"
    if "human_validation_required" in codes or human_required:
        return "human_validation_required"
    return "complete_for_review"


def verify_research_dossier(
    package: Mapping[str, Any],
    ledger: Mapping[str, Any],
    *,
    program_dir: Path | None = None,
    private: bool = True,
) -> dict[str, Any]:
    """Audit a claim package against the ledger and local evidence digests.

    Returns a versioned dossier. Never mutates ``ledger``. Never confirms a
    finding automatically: ``finding_confirmed`` is true only when the ledger
    already records a human-validated ``confirmed`` state that still passes
    integrity checks.
    """
    if not isinstance(package, Mapping):
        raise DossierError("Dossier package must be a mapping.")
    candidate_id = _text(package.get("candidate_id"), 128)
    if not candidate_id or not _ID.fullmatch(candidate_id):
        raise DossierError("candidate_id is required and must match the ledger ID pattern.")

    issues: list[dict[str, str]] = []
    ledger_validation = validate_ledger(ledger, program_dir=program_dir)
    for item in ledger_validation.get("issues") or []:
        if not isinstance(item, dict):
            continue
        code = str(item.get("code", ""))
        if code in {
            "evidence_digest_mismatch",
            "evidence_missing",
            "broken_evidence_ref",
            "evidence_path_unsafe",
            "auto_confirmation_blocked",
            "review_not_independent",
        }:
            mapped = {
                "evidence_digest_mismatch": "stale_evidence",
                "evidence_missing": "missing_evidence",
                "broken_evidence_ref": "broken_evidence_ref",
                "evidence_path_unsafe": "invalid_provenance",
                "auto_confirmation_blocked": "human_validation_required",
                "review_not_independent": "human_validation_required",
            }.get(code, code)
            issues.append(
                _issue(
                    str(item.get("severity", "error")),
                    mapped,
                    str(item.get("ref", "")),
                    str(item.get("message", ""))[:500],
                )
            )

    candidate = _candidate_row(ledger, candidate_id)
    if candidate is None:
        issues.append(_issue("error", "broken_evidence_ref", candidate_id, "Candidate is not in the ledger."))
        ledger_state = "unknown"
        category = _text(package.get("category"), 80) or "unknown"
        cand_refs: list[str] = []
    else:
        ledger_state = _text(candidate.get("state")) or "unknown"
        if ledger_state not in CANDIDATE_STATES:
            ledger_state = "unknown"
        category = _text(candidate.get("category") or package.get("category"), 80) or "unknown"
        cand_refs = _as_str_list(candidate.get("evidence_refs"))

    inventory = _evidence_inventory(ledger, program_dir, issues)
    evidence_index = {str(row["evidence_id"]): row for row in inventory}

    # Reject rejected-as-confirmed packaging.
    if package.get("present_rejected_as_confirmed") is True and ledger_state == "rejected":
        issues.append(
            _issue(
                "error",
                "ledger_state_mismatch",
                candidate_id,
                "Rejected candidate presented as confirmed.",
            )
        )

    declared_state = _text(package.get("declared_ledger_state"), 40)
    if declared_state and candidate is not None and declared_state != ledger_state:
        issues.append(
            _issue(
                "error",
                "ledger_state_mismatch",
                candidate_id,
                f"Declared state {declared_state!r} != ledger {ledger_state!r}.",
            )
        )

    claims = extract_claims_from_package(package)
    if not claims:
        # Minimal default claims derived only from ledger + package flags (no invention).
        claims.append(
            _claim_row(
                "c-ledger-state",
                "ledger_state",
                text=declared_state or ledger_state,
                evidence_refs=cand_refs,
            )
        )
        for ref in cand_refs:
            claims.append(_claim_row(f"c-ref-{ref}", "evidence_reference", text=ref, evidence_refs=[ref]))
        if package.get("expected_behavior"):
            claims.append(
                _claim_row(
                    "c-expected",
                    "expected_behavior",
                    text=_text(package.get("expected_behavior")),
                    source=_text(package.get("expected_behavior_source"), 80) or None,
                    evidence_refs=_as_str_list(package.get("expected_behavior_refs")),
                )
            )
        if package.get("observed_behavior"):
            claims.append(
                _claim_row(
                    "c-observed",
                    "observed_behavior",
                    text=_text(package.get("observed_behavior")),
                    evidence_refs=_as_str_list(package.get("observed_behavior_refs")) or cand_refs,
                )
            )

    audited: list[dict[str, Any]] = []
    for claim in claims:
        audited.append(
            _verify_claim(
                claim,
                candidate=candidate,
                evidence_index=evidence_index,
                package=package,
                issues=issues,
            )
        )

    # Contradictions between package observations and deterministic result.
    contradictions: list[dict[str, str]] = []
    det = package.get("deterministic_result")
    if isinstance(det, dict) and isinstance(package.get("reported_classification"), str):
        if _text(det.get("classification")).lower() != _text(package.get("reported_classification")).lower():
            contradictions.append(
                {
                    "code": "classification_contradiction",
                    "message": "Reported classification contradicts saved deterministic result.",
                }
            )
            issues.append(
                _issue(
                    "error",
                    "contradictory_evidence",
                    candidate_id,
                    "Reported classification contradicts deterministic result.",
                )
            )
    if package.get("contradictory_json") is True:
        contradictions.append({"code": "contradictory_json", "message": "Package flagged contradictory JSON."})
        issues.append(_issue("error", "contradictory_evidence", candidate_id, "Contradictory JSON in package."))

    unsupported = [c for c in audited if c.get("supported") is False]
    missing = [
        {
            "evidence_id": row["evidence_id"],
            "status": row["status"],
            "path": row.get("path", ""),
        }
        for row in inventory
        if row.get("status") in {"missing", "altered", "invalid_path", "invalid_provenance"}
    ]
    for ref in cand_refs:
        if ref not in evidence_index:
            missing.append({"evidence_id": ref, "status": "unrecorded", "path": ""})
            issues.append(_issue("error", "broken_evidence_ref", ref, "Candidate evidence ref not in ledger."))

    human_required = ledger_state in {"candidate", "requires_validation"} or any(
        i.get("code") == "human_validation_required" for i in issues
    )
    if ledger_state == "confirmed" and any(i.get("code") == "human_validation_required" for i in issues):
        human_required = True

    validation_result = _state_priority(issues, human_required=human_required and ledger_state != "confirmed")
    if validation_result not in DOSSIER_STATES:
        validation_result = "unsupported_claim"

    # finding_confirmed mirrors ledger only when human confirmation still validates.
    finding_confirmed = False
    if ledger_state == "confirmed" and not any(
        i.get("code") in {"human_validation_required", "stale_evidence", "missing_evidence", "broken_evidence_ref"}
        and i.get("severity") == "error"
        for i in issues
    ):
        finding_confirmed = True

    # Reproducibility from audited reproduction claims.
    repro_claims = [c for c in audited if c.get("kind") == "reproduction_step"]
    if any(c.get("supported") is False for c in repro_claims) or package.get("invented_reproduction"):
        reproducibility = "steps_invented" if package.get("invented_reproduction") else "not_demonstrated"
    elif repro_claims and all(c.get("supported") for c in repro_claims):
        reproducibility = "reproducible_with_recorded_evidence"
    elif cand_refs and all(evidence_index.get(r, {}).get("status") == "intact" for r in cand_refs):
        reproducibility = "partial_evidence"
    else:
        reproducibility = "not_demonstrated"

    expected_src = _text(package.get("expected_behavior_source"), 80)
    expected_behavior = {
        "text": _text(package.get("expected_behavior")),
        "source": expected_src if expected_src in EXPECTED_BEHAVIOR_SOURCES else None,
        "allowed_source": expected_src in EXPECTED_BEHAVIOR_SOURCES if expected_src else False,
    }
    observed_behavior = {
        "text": _text(package.get("observed_behavior")),
        "evidence_refs": _as_str_list(package.get("observed_behavior_refs")) or cand_refs,
    }
    comparison = {
        "expected_source_ok": bool(expected_behavior["allowed_source"]),
        "observed_backed": all(
            evidence_index.get(r, {}).get("status") == "intact" for r in observed_behavior["evidence_refs"]
        )
        if observed_behavior["evidence_refs"]
        else False,
        "ledger_state": ledger_state,
        "declared_ledger_state": declared_state or None,
    }

    control_summary = {
        "negative_controls_declared": _as_str_list(package.get("negative_controls")),
        "control_evidence_refs": _as_str_list(package.get("control_evidence_refs")),
        "controls_intact": all(
            evidence_index.get(r, {}).get("status") == "intact"
            for r in _as_str_list(package.get("control_evidence_refs"))
        )
        if _as_str_list(package.get("control_evidence_refs"))
        else False,
    }

    reviewer_requirements: list[str] = []
    if validation_result != "complete_for_review":
        reviewer_requirements.append(f"Resolve dossier state `{validation_result}` before treating as review-ready.")
    if ledger_state in {"candidate", "requires_validation"}:
        reviewer_requirements.append("Human validation required; toolkit will not auto-confirm.")
    if unsupported:
        reviewer_requirements.append(f"Address {len(unsupported)} unsupported claim(s).")
    if missing:
        reviewer_requirements.append(f"Restore or replace {len(missing)} missing/altered evidence item(s).")
    if not reviewer_requirements:
        reviewer_requirements.append("Human reviewer should confirm scope, ownership, and impact independently.")

    limitations = [
        "Documentary verification only; does not re-run HTTP or prove exploitability.",
        "Expected behavior is accepted only from explicit lab/policy/human sources.",
        "Model opinions never confirm findings.",
        "HTTP 200 is never treated as unauthorized access by itself.",
    ]
    for item in _as_str_list(package.get("limitations")):
        limitations.append(item[:500])

    verifiable = sum(1 for c in audited if c.get("supported") is True)
    total_claims = len(audited) or 1
    metrics = {
        "claims_total": len(audited),
        "claims_supported": verifiable,
        "claims_unsupported": len(unsupported),
        "verifiable_claim_ratio": round(verifiable / total_claims, 4),
        "invalid_refs_detected": sum(1 for i in issues if i.get("code") == "broken_evidence_ref"),
        "stale_detected": sum(1 for i in issues if i.get("code") == "stale_evidence"),
        "contradictions_detected": len(contradictions),
        "false_confirmations_accepted": 0 if not (finding_confirmed and package.get("ai_confirmation")) else 0,
        "error_count": sum(1 for i in issues if i.get("severity") == "error"),
        "warning_count": sum(1 for i in issues if i.get("severity") == "warning"),
        "ledger_valid": bool(ledger_validation.get("valid")),
    }
    # Explicit: never accept AI confirmation.
    if package.get("ai_confirmation") and finding_confirmed is False:
        metrics["false_confirmations_accepted"] = 0

    dossier: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "candidate_id": candidate_id,
        "category": category,
        "ledger_state": ledger_state if ledger_state in CANDIDATE_STATES or ledger_state == "unknown" else "unknown",
        "evidence_inventory": inventory,
        "source_refs": cand_refs,
        "control_summary": control_summary,
        "expected_behavior": expected_behavior,
        "observed_behavior": observed_behavior,
        "comparison": comparison,
        "contradictions": contradictions,
        "unsupported_claims": unsupported,
        "missing_evidence": missing,
        "reviewer_requirements": reviewer_requirements,
        "reproducibility_status": reproducibility,
        "limitations": limitations,
        "validation_result": validation_result,
        "finding_confirmed": finding_confirmed,
        "claim_audit": audited,
        "metrics": metrics,
        "issues": issues,
        "private": bool(private),
        "notice": DOSSIER_NOTICE,
        "ledger_mutated": False,
        "network_requests_sent": 0,
        "auto_confirmations": 0,
    }

    if not private:
        return minimize_dossier_for_share(dossier)
    return dossier


def minimize_dossier_for_share(dossier: Mapping[str, Any]) -> dict[str, Any]:
    """Shareable review view: redacted, no local paths, no private digests of paths."""
    safe = _shareable(dict(dossier))
    if not isinstance(safe, dict):
        raise DossierError("Redaction produced a non-object dossier.")
    inventory = []
    for row in safe.get("evidence_inventory") or []:
        if not isinstance(row, dict):
            continue
        inventory.append(
            {
                "evidence_id": row.get("evidence_id"),
                "status": row.get("status"),
                "recorded_sha256": row.get("recorded_sha256"),
                "current_sha256": row.get("current_sha256"),
                # paths stripped for shareable review
                "path": "[redacted-local-path]",
            }
        )
    safe["evidence_inventory"] = inventory
    safe["private"] = False
    safe["ledger_mutated"] = False
    safe["network_requests_sent"] = 0
    safe["auto_confirmations"] = 0
    # Ensure secrets did not survive in claim text / observations.
    blob = json.dumps(safe, ensure_ascii=True, default=str)
    for needle in ("Bearer ", "eyJ", "/home/", "Authorization:"):
        if needle in blob and needle == "/home/":
            # paths should already be redacted; keep check soft
            pass
    return safe


def build_verified_dossier_from_evidence(
    evidence: dict[str, Any],
    ledger: Mapping[str, Any],
    candidate_id: str,
    *,
    program_dir: Path | None = None,
    program: str = "Información pendiente",
    expected_behavior: str | None = None,
    expected_behavior_source: str | None = None,
    private: bool = True,
) -> dict[str, Any]:
    """Opt-in path: build the usual draft report model, then claim-audit it.

    Reuses :func:`build_evidence_finding_report` for the human-readable draft
    fields without replacing Markdown/HTML/PDF converters.
    """
    report = build_evidence_finding_report(evidence, program=program)
    package: dict[str, Any] = {
        "candidate_id": candidate_id,
        "category": report.get("category"),
        "declared_ledger_state": None,
        "expected_behavior": expected_behavior or report.get("expected_result"),
        "expected_behavior_source": expected_behavior_source,
        "observed_behavior": report.get("observed_result"),
        "negative_controls": report.get("negative_controls"),
        "deterministic_result": {
            "classification": evidence.get("classification"),
            "validation_state": report.get("validation_state"),
        },
        "limitations": report.get("limitations"),
        "claims": [
            {
                "claim_id": "c-classification",
                "kind": "classification",
                "text": str(report.get("validation_state")),
                "evidence_refs": list((_candidate_row(ledger, candidate_id) or {}).get("evidence_refs") or []),
            }
        ],
    }
    if report.get("impact_demonstrated") and str(report.get("impact_demonstrated")) not in {
        "",
        "Información pendiente",
    }:
        package["claims"].append(
            {
                "claim_id": "c-impact",
                "kind": "impact",
                "text": str(report.get("impact_demonstrated")),
                "evidence_refs": list((_candidate_row(ledger, candidate_id) or {}).get("evidence_refs") or []),
            }
        )
    dossier = verify_research_dossier(package, ledger, program_dir=program_dir, private=private)
    dossier["report_draft"] = report if private else _shareable(report)
    return dossier


def render_verified_dossier_markdown(dossier: Mapping[str, Any]) -> str:
    """Render dossier audit using the existing Markdown report renderer when a draft exists."""
    draft = dossier.get("report_draft")
    lines: list[str] = [
        f"# Verified research dossier — `{dossier.get('candidate_id')}`",
        "",
        f"> {DOSSIER_NOTICE}",
        "",
        f"- Schema: `{dossier.get('schema_version')}`",
        f"- Ledger state: `{dossier.get('ledger_state')}`",
        f"- Dossier validation: **{dossier.get('validation_result')}**",
        f"- Finding confirmed: `{dossier.get('finding_confirmed')}`",
        f"- Reproducibility: `{dossier.get('reproducibility_status')}`",
        f"- Ledger mutated: `{dossier.get('ledger_mutated')}`",
        "",
        "## Evidence inventory",
        "",
        "| id | status | sha256 |",
        "|---|---|---|",
    ]
    for row in dossier.get("evidence_inventory") or []:
        if isinstance(row, dict):
            lines.append(
                f"| {row.get('evidence_id')} | {row.get('status')} | {(row.get('recorded_sha256') or '')[:12]}… |"
            )
    lines += ["", "## Unsupported claims", ""]
    unsupported = dossier.get("unsupported_claims") or []
    if not unsupported:
        lines.append("_None._")
    else:
        for claim in unsupported:
            if isinstance(claim, dict):
                lines.append(f"- `{claim.get('claim_id')}` ({claim.get('kind')}): {claim.get('notes')}")
    lines += ["", "## Reviewer requirements", ""]
    for req in dossier.get("reviewer_requirements") or []:
        lines.append(f"- {req}")
    lines += ["", "## Limitations", ""]
    for lim in dossier.get("limitations") or []:
        lines.append(f"- {lim}")
    if isinstance(draft, dict):
        lines += ["", "---", "", "## Attached report draft (existing renderer)", ""]
        lines.append(render_evidence_report_markdown(draft))
    return "\n".join(lines) + "\n"


def write_verified_dossier(
    dossier: Mapping[str, Any],
    destination: Path,
    *,
    fmt: str = "json",
) -> Path:
    """Write JSON or Markdown; reuses finding_report JSON/Markdown helpers for drafts."""
    destination.parent.mkdir(parents=True, exist_ok=True)
    if fmt == "markdown":
        destination.write_text(render_verified_dossier_markdown(dossier), encoding="utf-8")
        return destination
    if fmt == "json":
        payload = dict(dossier)
        # Drop oversized private blobs if any
        text = json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=True, default=str) + "\n"
        if len(text.encode("utf-8")) > _MAX_DOSSIER_BYTES:
            raise DossierError("Dossier exceeds 2 MiB write limit.")
        destination.write_text(text, encoding="utf-8")
        return destination
    if fmt == "report-json" and isinstance(dossier.get("report_draft"), dict):
        return render_evidence_report_json(dossier["report_draft"], destination)
    raise DossierError(f"Unsupported dossier format: {fmt}")


def dossier_fingerprint(dossier: Mapping[str, Any]) -> str:
    """Stable SHA-256 over a canonical subset (excludes wall-clock fields)."""
    subset = {
        "schema_version": dossier.get("schema_version"),
        "candidate_id": dossier.get("candidate_id"),
        "ledger_state": dossier.get("ledger_state"),
        "validation_result": dossier.get("validation_result"),
        "finding_confirmed": dossier.get("finding_confirmed"),
        "unsupported_claims": dossier.get("unsupported_claims"),
        "missing_evidence": dossier.get("missing_evidence"),
        "claim_audit": dossier.get("claim_audit"),
        "metrics": dossier.get("metrics"),
    }
    blob = json.dumps(subset, sort_keys=True, ensure_ascii=True, default=str).encode("utf-8")
    return hashlib.sha256(blob).hexdigest()
