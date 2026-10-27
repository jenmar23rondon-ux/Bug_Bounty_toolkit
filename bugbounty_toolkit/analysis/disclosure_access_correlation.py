"""Offline correlation of Information Disclosure indicators with IDOR/access evidence.

Correlates three *already stored* observations about one resource:

* **Actor A (owner)** — response that demonstrates the private resource (private marker).
* **Actor B (second account)** — response when B requests the same object.
* **Cross capture** — the B→A-object response that may carry a private marker / disclosure
  indicator A should alone have seen.

This module never issues HTTP requests, never invents evidence, never writes the ledger,
and never sets ``finding_confirmed`` to true. Secret values and private markers never leave
as cleartext: only salted one-way fingerprints and lengths are emitted. Public and
legitimately shared resources are distinguished from private ones. Altered, expired,
missing-ref, or cross-program evidence blocks advancement via ``integrity_blocked``.

Reuse (do not reimplement): :func:`assess_disclosure`, :func:`correlate_resources`,
:func:`provenance_digest`.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import hmac
import json
import time
from typing import Any, Mapping

from bugbounty_toolkit.analysis.information_disclosure import (
    assess_disclosure,
)
from bugbounty_toolkit.analysis.resource_kind_lineage import correlate_resources
from bugbounty_toolkit.core.redaction import provenance_digest

ANALYSIS_VERSION = "disclosure-access-correlation-v1"
MAX_CASE_BYTES = 1_000_000

STATES = (
    "insufficient_evidence",
    "auth_context_undeclared",
    "integrity_blocked",
    "public_resource",
    "shared_resource",
    "denied_correctly",
    "reflected_or_example",
    "fake_or_invalid_credential_shape",
    "contradiction",
    "correlation_candidate",
    "ready_for_manual_review",
    "invalid_evidence",
)

INTEGRITY_OK = "valid"
INTEGRITY_BLOCKERS = frozenset(
    {
        "altered",
        "expired",
        "missing_ref",
        "out_of_program",
        "cross_program",
        "incomplete_capture",
    }
)
VISIBILITIES = frozenset({"private", "shared", "public"})
ACCESS_PROOFS_PRIVATE = frozenset({"private_resource_200"})
ACCESS_PROOFS_DENIED = frozenset({"http_401", "http_403", "http_404", "login_redirect", "denial_in_200"})
_PLACEHOLDER_MARKERS = frozenset(
    {
        "YOUR_API_KEY_HERE",
        "changeme",
        "<token>",
        "xxxx",
        "example",
        "EXAMPLE",
        "placeholder",
    }
)


def _salted_fp(value: str, salt: str) -> str:
    """One-way salted fingerprint; not reversible to the secret/marker."""
    material = f"{salt}|{value}".encode("utf-8")
    return hmac.new(b"bbtk-dac-v1", material, hashlib.sha256).hexdigest()[:12]


def _as_mapping(value: Any, label: str) -> Mapping[str, Any] | None:
    if value is None:
        return None
    if isinstance(value, Mapping):
        return value
    raise TypeError(f"{label} must be a mapping")


@dataclass
class CorrelationResult:
    case_id: str
    state: str
    reasons: list[str] = field(default_factory=list)
    visibility: str | None = None
    resource_relation: str | None = None
    accounts: str | None = None
    owner_has_private_marker: bool = False
    cross_has_private_marker: bool = False
    cross_disclosure_categories: list[str] = field(default_factory=list)
    cross_disclosure_state: str | None = None
    integrity_blockers: list[str] = field(default_factory=list)
    contradictions: list[str] = field(default_factory=list)
    evidence_refs: dict[str, str] = field(default_factory=dict)
    marker_fingerprints: dict[str, str] = field(default_factory=dict)
    analysis_version: str = ANALYSIS_VERSION
    elapsed_ms: float = 0.0
    finding_confirmed: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "case_id": self.case_id,
            "state": self.state,
            "reasons": list(self.reasons),
            "visibility": self.visibility,
            "resource_relation": self.resource_relation,
            "accounts": self.accounts,
            "owner_has_private_marker": self.owner_has_private_marker,
            "cross_has_private_marker": self.cross_has_private_marker,
            "cross_disclosure_categories": list(self.cross_disclosure_categories),
            "cross_disclosure_state": self.cross_disclosure_state,
            "integrity_blockers": list(self.integrity_blockers),
            "contradictions": list(self.contradictions),
            "evidence_refs": dict(self.evidence_refs),
            "marker_fingerprints": dict(self.marker_fingerprints),
            "analysis_version": self.analysis_version,
            "elapsed_ms": self.elapsed_ms,
            "finding_confirmed": False,
            "network_requests": 0,
        }


def _integrity_of(side: Mapping[str, Any] | None, label: str) -> list[str]:
    if side is None:
        return [f"{label}:missing"]
    status = str(side.get("integrity") or INTEGRITY_OK)
    blockers: list[str] = []
    if status in INTEGRITY_BLOCKERS:
        blockers.append(f"{label}:{status}")
    if side.get("capture_ref") in (None, ""):
        blockers.append(f"{label}:missing_ref")
    return blockers


def _marker_present(side: Mapping[str, Any] | None) -> bool:
    if side is None:
        return False
    if "private_marker_present" in side:
        return bool(side["private_marker_present"])
    # Never accept raw marker values into output; presence only.
    raw = side.get("private_marker")
    if isinstance(raw, str) and raw and raw not in _PLACEHOLDER_MARKERS:
        return True
    return False


def _marker_fp(side: Mapping[str, Any] | None, salt: str) -> str | None:
    if side is None:
        return None
    raw = side.get("private_marker")
    if isinstance(raw, str) and raw and raw not in _PLACEHOLDER_MARKERS:
        return _salted_fp(raw, salt)
    fp = side.get("marker_fingerprint")
    if isinstance(fp, str) and len(fp) == 12 and all(c in "0123456789abcdef" for c in fp):
        return fp
    if _marker_present(side):
        # Presence attested without value: fingerprint the capture ref + body digest.
        material = f"{side.get('capture_ref')}|{side.get('body_digest')}|present"
        return _salted_fp(material, salt)
    return None


def correlate_disclosure_access(case: Mapping[str, Any], *, salt: str = "") -> CorrelationResult:
    """Correlate owner / second-actor / cross evidence with disclosure indicators.

    Required inputs (all offline, already captured):

    * ``auth_context.actor_a`` and ``auth_context.actor_b`` with declared ``account_ref``
      and ``attested: true`` (human declaration that accounts are distinct).
    * ``evidence.owner_a``, ``evidence.actor_b``, ``evidence.cross`` with ``capture_ref``,
      ``integrity``, optional ``private_marker_present`` / ``access_proof`` /
      ``body_digest`` / ``program_id``.
    * Optional ``evidence.cross.response`` for running :func:`assess_disclosure`, or a
      precomputed ``disclosure`` summary (categories + state only).
    * ``resource.visibility_declared`` in {private, shared, public}.
    """
    started = time.perf_counter()
    case_id = str(case.get("id") or "unknown")

    def finish(state: str, reasons: list[str], **kw: Any) -> CorrelationResult:
        return CorrelationResult(
            case_id=case_id,
            state=state,
            reasons=reasons,
            elapsed_ms=round((time.perf_counter() - started) * 1000, 3),
            finding_confirmed=False,
            **kw,
        )

    if not isinstance(case, Mapping):
        return finish("invalid_evidence", ["case_not_mapping"])

    auth = _as_mapping(case.get("auth_context"), "auth_context") or {}
    actor_a = _as_mapping(auth.get("actor_a"), "actor_a")
    actor_b = _as_mapping(auth.get("actor_b"), "actor_b")
    if not actor_a or not actor_b:
        return finish("auth_context_undeclared", ["missing_actor_a_or_b"])
    if not actor_a.get("attested") or not actor_b.get("attested"):
        return finish("auth_context_undeclared", ["actors_not_attested"])
    if not actor_a.get("account_ref") or not actor_b.get("account_ref"):
        return finish("auth_context_undeclared", ["missing_account_ref"])
    if actor_a.get("account_ref") == actor_b.get("account_ref"):
        return finish("auth_context_undeclared", ["actors_not_distinct"])

    evidence = _as_mapping(case.get("evidence"), "evidence") or {}
    owner = _as_mapping(evidence.get("owner_a"), "owner_a")
    actor = _as_mapping(evidence.get("actor_b"), "actor_b")
    cross = _as_mapping(evidence.get("cross"), "cross")
    if owner is None or actor is None or cross is None:
        return finish(
            "insufficient_evidence",
            ["require_owner_a_actor_b_and_cross"],
            evidence_refs={
                k: str(v.get("capture_ref"))
                for k, v in (("owner_a", owner), ("actor_b", actor), ("cross", cross))
                if isinstance(v, Mapping) and v.get("capture_ref")
            },
        )

    blockers = _integrity_of(owner, "owner_a") + _integrity_of(actor, "actor_b") + _integrity_of(cross, "cross")
    program = str(case.get("program_id") or "")
    for label, side in (("owner_a", owner), ("actor_b", actor), ("cross", cross)):
        side_prog = side.get("program_id")
        if program and side_prog and str(side_prog) != program:
            blockers.append(f"{label}:cross_program")
        elif side.get("integrity") == "cross_program":
            blockers.append(f"{label}:cross_program")

    refs = {
        "owner_a": str(owner.get("capture_ref")),
        "actor_b": str(actor.get("capture_ref")),
        "cross": str(cross.get("capture_ref")),
    }
    # Detect lost refs (declared then empty after integrity strip).
    for label, ref in list(refs.items()):
        if ref in ("", "None"):
            blockers.append(f"{label}:ref_loss")

    if blockers:
        return finish(
            "integrity_blocked",
            ["integrity_checks_failed"],
            integrity_blockers=sorted(set(blockers)),
            evidence_refs={k: v for k, v in refs.items() if v not in ("", "None")},
        )

    resource = _as_mapping(case.get("resource"), "resource") or {}
    visibility = str(resource.get("visibility_declared") or "").lower() or None
    if visibility not in VISIBILITIES:
        return finish("invalid_evidence", ["visibility_undeclared"], evidence_refs=refs)

    # Resource correlation (reuse lineage helper).
    owner_side = {
        "kind": resource.get("kind"),
        "kind_status": resource.get("kind_status") or "explicit",
        "namespace_key": resource.get("namespace_key"),
        "account_ref": actor_a.get("account_ref"),
        "distinct_accounts_attested": True,
        "session_ref": actor_a.get("session_ref"),
        "visibility": visibility,
        "body_digest": owner.get("body_digest"),
    }
    actor_side = {
        "kind": resource.get("kind"),
        "kind_status": resource.get("kind_status") or "explicit",
        "namespace_key": resource.get("namespace_key"),
        "account_ref": actor_b.get("account_ref"),
        "distinct_accounts_attested": True,
        "session_ref": actor_b.get("session_ref"),
        "visibility": visibility,
        "body_digest": cross.get("body_digest") or actor.get("body_digest"),
    }
    relation = correlate_resources(owner_side, actor_side)

    owner_marker = _marker_present(owner)
    cross_marker = _marker_present(cross)
    fps: dict[str, str] = {}
    ofp = _marker_fp(owner, salt or case_id)
    cfp = _marker_fp(cross, salt or case_id)
    if ofp:
        fps["owner_a"] = ofp
    if cfp:
        fps["cross"] = cfp

    contradictions: list[str] = []
    if owner_marker and visibility == "public":
        contradictions.append("private_marker_on_declared_public")
    if visibility == "private" and not owner_marker and owner.get("access_proof") in ACCESS_PROOFS_PRIVATE:
        contradictions.append("private_access_proof_without_marker")

    # Disclosure on the cross response (B reading A's object).
    disclosure_categories: list[str] = []
    disclosure_state: str | None = None
    pre = _as_mapping(case.get("disclosure"), "disclosure")
    if pre is not None:
        cats = pre.get("categories") or []
        if isinstance(cats, list):
            disclosure_categories = [str(c) for c in cats]
        disclosure_state = str(pre.get("state")) if pre.get("state") else None
        if pre.get("finding_confirmed") is True:
            contradictions.append("disclosure_claimed_confirmed")
    elif isinstance(cross.get("response"), Mapping) or "body" in cross:
        # Build a minimal disclosure record from the cross capture; never echo values out.
        audience = "cross_actor"
        record: dict[str, Any] = {
            "id": f"{case_id}-cross",
            "audience": audience,
            "response": cross.get("response")
            if isinstance(cross.get("response"), Mapping)
            else {
                "status": int(cross.get("status") or 200),
                "headers": cross.get("headers") or {"Content-Type": "application/json"},
                "body": cross.get("body"),
            },
        }
        if isinstance(cross.get("request"), Mapping):
            record["request"] = cross["request"]
        assessed = assess_disclosure(record, salt=salt or case_id)
        disclosure_categories = list(assessed.categories)
        disclosure_state = assessed.state
        body = record["response"].get("body")
        if isinstance(body, (str, bytes)):
            # Provenance digest only; never store the body in the correlation result.
            record_meta_digest = provenance_digest(body if isinstance(body, str) else body.decode("utf-8", "replace"))
            del record_meta_digest

    # Fake / example / reflected JWT handling.
    if cross.get("credential_shape") in {"fake_jwt", "example", "placeholder"}:
        return finish(
            "fake_or_invalid_credential_shape",
            ["credential_shape_not_evidence"],
            visibility=visibility,
            resource_relation=str(relation.get("relation")),
            accounts=str(relation.get("accounts")),
            owner_has_private_marker=owner_marker,
            cross_has_private_marker=cross_marker,
            cross_disclosure_categories=disclosure_categories,
            cross_disclosure_state=disclosure_state,
            evidence_refs=refs,
            marker_fingerprints=fps,
        )
    if disclosure_state == "public_or_intended_information" or cross.get("reflected_from_request"):
        return finish(
            "reflected_or_example",
            ["disclosure_suppressed_or_intended"],
            visibility=visibility,
            resource_relation=str(relation.get("relation")),
            accounts=str(relation.get("accounts")),
            owner_has_private_marker=owner_marker,
            cross_has_private_marker=cross_marker,
            cross_disclosure_categories=disclosure_categories,
            cross_disclosure_state=disclosure_state,
            evidence_refs=refs,
            marker_fingerprints=fps,
        )

    if contradictions:
        return finish(
            "contradiction",
            ["evidence_contradicts_declarations"],
            visibility=visibility,
            resource_relation=str(relation.get("relation")),
            accounts=str(relation.get("accounts")),
            owner_has_private_marker=owner_marker,
            cross_has_private_marker=cross_marker,
            cross_disclosure_categories=disclosure_categories,
            cross_disclosure_state=disclosure_state,
            contradictions=contradictions,
            evidence_refs=refs,
            marker_fingerprints=fps,
        )

    if visibility == "public" or relation.get("legitimate_shared") and visibility != "private":
        state = "public_resource" if visibility == "public" else "shared_resource"
        return finish(
            state,
            ["not_unauthorized_exposure"],
            visibility=visibility,
            resource_relation=str(relation.get("relation")),
            accounts=str(relation.get("accounts")),
            owner_has_private_marker=owner_marker,
            cross_has_private_marker=cross_marker,
            cross_disclosure_categories=disclosure_categories,
            cross_disclosure_state=disclosure_state,
            evidence_refs=refs,
            marker_fingerprints=fps,
        )

    if visibility == "shared":
        return finish(
            "shared_resource",
            ["declared_shared_access"],
            visibility=visibility,
            resource_relation=str(relation.get("relation")),
            accounts=str(relation.get("accounts")),
            owner_has_private_marker=owner_marker,
            cross_has_private_marker=cross_marker,
            cross_disclosure_categories=disclosure_categories,
            cross_disclosure_state=disclosure_state,
            evidence_refs=refs,
            marker_fingerprints=fps,
        )

    # Private resource path.
    actor_proof = str(actor.get("access_proof") or cross.get("access_proof") or "")
    if actor_proof in ACCESS_PROOFS_DENIED and not cross_marker:
        return finish(
            "denied_correctly",
            ["second_actor_denied_without_private_marker"],
            visibility=visibility,
            resource_relation=str(relation.get("relation")),
            accounts=str(relation.get("accounts")),
            owner_has_private_marker=owner_marker,
            cross_has_private_marker=False,
            cross_disclosure_categories=disclosure_categories,
            cross_disclosure_state=disclosure_state,
            evidence_refs=refs,
            marker_fingerprints=fps,
        )

    # Strong correlation: A owns private (marker), B cross sees same marker + disclosure.
    reasons: list[str] = []
    if owner_marker:
        reasons.append("owner_private_marker_observed")
    if cross_marker:
        reasons.append("cross_private_marker_observed")
    if ofp and cfp and ofp == cfp:
        reasons.append("marker_fingerprints_match")
    if disclosure_categories:
        reasons.append("cross_disclosure_indicators")
    if relation.get("idor_review_signal"):
        reasons.append("idor_review_signal")

    strong = (
        visibility == "private"
        and owner_marker
        and cross_marker
        and bool(
            disclosure_categories
            or disclosure_state
            in {
                "access_control_validation_required",
                "ready_for_manual_review",
                "indicator_detected",
            }
        )
    )
    if strong:
        return finish(
            "ready_for_manual_review",
            reasons or ["correlation_complete"],
            visibility=visibility,
            resource_relation=str(relation.get("relation")),
            accounts=str(relation.get("accounts")),
            owner_has_private_marker=True,
            cross_has_private_marker=True,
            cross_disclosure_categories=disclosure_categories,
            cross_disclosure_state=disclosure_state,
            evidence_refs=refs,
            marker_fingerprints=fps,
        )

    if owner_marker and cross_marker:
        return finish(
            "correlation_candidate",
            reasons or ["markers_present_disclosure_incomplete"],
            visibility=visibility,
            resource_relation=str(relation.get("relation")),
            accounts=str(relation.get("accounts")),
            owner_has_private_marker=True,
            cross_has_private_marker=True,
            cross_disclosure_categories=disclosure_categories,
            cross_disclosure_state=disclosure_state,
            evidence_refs=refs,
            marker_fingerprints=fps,
        )

    if owner_marker and not cross_marker and actor_proof not in ACCESS_PROOFS_DENIED:
        return finish(
            "insufficient_evidence",
            ["cross_missing_private_marker"],
            visibility=visibility,
            resource_relation=str(relation.get("relation")),
            accounts=str(relation.get("accounts")),
            owner_has_private_marker=True,
            cross_has_private_marker=False,
            cross_disclosure_categories=disclosure_categories,
            cross_disclosure_state=disclosure_state,
            evidence_refs=refs,
            marker_fingerprints=fps,
        )

    return finish(
        "insufficient_evidence",
        reasons or ["correlation_incomplete"],
        visibility=visibility,
        resource_relation=str(relation.get("relation")),
        accounts=str(relation.get("accounts")),
        owner_has_private_marker=owner_marker,
        cross_has_private_marker=cross_marker,
        cross_disclosure_categories=disclosure_categories,
        cross_disclosure_state=disclosure_state,
        evidence_refs=refs,
        marker_fingerprints=fps,
    )


def correlate_batch(cases: list[Mapping[str, Any]], *, salt: str = "") -> dict[str, Any]:
    results = [correlate_disclosure_access(case, salt=salt).to_dict() for case in cases]
    return {
        "analysis_version": ANALYSIS_VERSION,
        "count": len(results),
        "finding_confirmed": False,
        "network_requests": 0,
        "results": results,
    }


def load_cases(text: str) -> list[Mapping[str, Any]]:
    if len(text.encode("utf-8")) > MAX_CASE_BYTES:
        raise ValueError("input exceeds MAX_CASE_BYTES")
    data = json.loads(text)
    if isinstance(data, list):
        return [c for c in data if isinstance(c, Mapping)]
    if isinstance(data, Mapping):
        if isinstance(data.get("cases"), list):
            return [c for c in data["cases"] if isinstance(c, Mapping)]
        return [data]
    raise TypeError("input must be a case, list of cases, or {cases: [...]}")
