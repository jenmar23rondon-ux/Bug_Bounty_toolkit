"""Classify offline handoff capture pairs for read-case proposal eligibility.

Fully offline. Never sends HTTP, never approves, never confirms, never rewrites
capture origins. Statuses are human-review labels — not findings.

Statuses (stable):
  structural_valid | case_eligible | needs_more_evidence | security_rejected | technical_error

Integration with Evidence Graph / Investigation Memory / Evidence Ledger is only
through existing caller-driven interfaces; this module performs no auto state changes.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import re
from pathlib import Path
from typing import Any, Literal
from urllib.parse import urlsplit

from ..burp_import import MAX_EXCHANGE_BYTES, CapturedExchange, parse_captured_exchanges, read_capture_file
from ..case_generator import SESSION_HEADER, inspect_read_pair
from ..core.target import normalize_url
from ..utils.exceptions import ToolkitError

Status = Literal[
    "structural_valid",
    "case_eligible",
    "needs_more_evidence",
    "security_rejected",
    "technical_error",
]

# Stable machine codes (do not renumber casually; append new codes).
CODE_CASE_ELIGIBLE = "CASE_ELIGIBLE"
CODE_STRUCTURAL_VALID = "STRUCTURAL_VALID"
CODE_TECH_ORIGIN_OVERRIDE = "TECH_ORIGIN_OVERRIDE"
CODE_TECH_PARSE_FAILURE = "TECH_PARSE_FAILURE"
CODE_TECH_INCOMPLETE_CAPTURE = "TECH_INCOMPLETE_CAPTURE"
CODE_REJECT_ORIGIN_MISMATCH_SIDES = "REJECT_ORIGIN_MISMATCH_SIDES"
CODE_REJECT_NON_GET = "REJECT_NON_GET"
CODE_REJECT_GET_WITH_BODY = "REJECT_GET_WITH_BODY"
CODE_REJECT_METHOD_MISMATCH = "REJECT_METHOD_MISMATCH"
CODE_REJECT_MULTI_RESOURCE_DIFF = "REJECT_MULTI_RESOURCE_DIFF"
CODE_REJECT_SESSION_ONLY = "REJECT_SESSION_ONLY"
CODE_REJECT_HEADER_DIFF = "REJECT_HEADER_DIFF"
CODE_REJECT_SAME_SESSION = "REJECT_SAME_SESSION"
CODE_NEEDS_RESPONSE = "NEEDS_RESPONSE"
CODE_NEEDS_SECOND_SESSION = "NEEDS_SECOND_SESSION"
CODE_NEEDS_MORE_EVIDENCE = "NEEDS_MORE_EVIDENCE"

_ORIGIN_OVERRIDE = re.compile(
    r"authority must not be overridden|Host and destination disagree|origin differs|--base-url must match", re.I
)
_MULTI_DIFF = re.compile(r"differ only in one resource|differences found at", re.I)
_NON_GET = re.compile(r"requires GET|lab-write", re.I)
_GET_BODY = re.compile(r"GET captures with request bodies", re.I)
_METHOD_MISMATCH = re.compile(r"Request methods differ", re.I)
_SAME_ORIGIN = re.compile(r"same origin \(scheme, host and port\)", re.I)
_HEADER_DIFF = re.compile(r"differ outside the resource|session header names must match|non-session", re.I)
_SAME_SESSION = re.compile(r"probable same account|identical session", re.I)
_SESSION_QUERY = re.compile(r"Session-bearing query|Duplicate query", re.I)


@dataclass(frozen=True)
class PairClassification:
    """Deterministic eligibility label for one owner/actor capture pair."""

    status: Status
    code: str
    detail: str
    origin: str | None
    owner_request_sha256: str | None
    actor_request_sha256: str | None
    owner_response_sha256: str | None
    actor_response_sha256: str | None
    has_owner_response: bool
    has_actor_response: bool
    case_eligible: bool
    technical_error: bool
    legitimate_rejection: bool

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


def _sha(data: bytes | None) -> str | None:
    return None if data is None else hashlib.sha256(data).hexdigest()


def origin_from_raw_request(raw: str) -> str | None:
    """Best-effort scheme://host[:port] from a raw HTTP/1.x request (Host or absolute URL).

    Relative requests without an explicit scheme default to https (same as parse_raw_http_request).
    Callers that know the capture provenance should pass that origin as base_url instead.
    """
    try:
        first = raw.splitlines()[0] if raw else ""
        parts = first.split()
        if len(parts) >= 2 and parts[1].startswith(("http://", "https://")):
            parsed = urlsplit(normalize_url(parts[1]))
            return f"{parsed.scheme}://{parsed.netloc}"
        host = next(
            (line.split(":", 1)[1].strip() for line in raw.splitlines()[1:] if line.lower().startswith("host:")), None
        )
        if not host:
            return None
        return f"https://{host}"
    except (ValueError, ToolkitError, IndexError):
        return None


def provenance_origin(*raw_requests: str) -> str | None:
    """Return a single origin when every raw request agrees; else None."""
    found: list[str] = []
    for raw in raw_requests:
        if not raw:
            continue
        origin = origin_from_raw_request(raw)
        if origin is not None:
            found.append(origin)
    if not found:
        return None
    if len({item.lower() for item in found}) != 1:
        return None
    return found[0]


def _map_inspect_error(message: str) -> tuple[Status, str]:
    if _SAME_ORIGIN.search(message):
        return "technical_error", CODE_REJECT_ORIGIN_MISMATCH_SIDES
    if _ORIGIN_OVERRIDE.search(message):
        return "technical_error", CODE_TECH_ORIGIN_OVERRIDE
    if _NON_GET.search(message):
        return "security_rejected", CODE_REJECT_NON_GET
    if _GET_BODY.search(message):
        return "security_rejected", CODE_REJECT_GET_WITH_BODY
    if _METHOD_MISMATCH.search(message):
        return "security_rejected", CODE_REJECT_METHOD_MISMATCH
    if _MULTI_DIFF.search(message) or _SESSION_QUERY.search(message):
        return "needs_more_evidence", CODE_REJECT_MULTI_RESOURCE_DIFF
    if _SAME_SESSION.search(message):
        return "needs_more_evidence", CODE_REJECT_SAME_SESSION
    if _HEADER_DIFF.search(message):
        return "needs_more_evidence", CODE_REJECT_HEADER_DIFF
    return "needs_more_evidence", CODE_NEEDS_MORE_EVIDENCE


def _result(
    status: Status,
    code: str,
    detail: str,
    *,
    origin: str | None = None,
    owner_req: bytes | None = None,
    actor_req: bytes | None = None,
    owner_res: bytes | None = None,
    actor_res: bytes | None = None,
) -> PairClassification:
    return PairClassification(
        status=status,
        code=code,
        detail=detail[:240],
        origin=origin,
        owner_request_sha256=_sha(owner_req),
        actor_request_sha256=_sha(actor_req),
        owner_response_sha256=_sha(owner_res),
        actor_response_sha256=_sha(actor_res),
        has_owner_response=owner_res is not None,
        has_actor_response=actor_res is not None,
        case_eligible=status == "case_eligible",
        technical_error=status == "technical_error",
        legitimate_rejection=status in {"needs_more_evidence", "security_rejected"},
    )


def classify_capture_pair(
    owner_request: Path,
    actor_request: Path,
    *,
    owner_response: Path | None = None,
    actor_response: Path | None = None,
    base_url: str | None = None,
) -> PairClassification:
    """Classify one 4-way (or partial) capture pair for read-case proposal eligibility.

    Never infers different accounts from different cookies alone, and never infers
    ownership from response structure. Insufficient-control pairs remain hypotheses
    (needs_more_evidence), not findings.
    """
    try:
        owner_req = read_capture_file(owner_request, MAX_EXCHANGE_BYTES)
        actor_req = read_capture_file(actor_request, MAX_EXCHANGE_BYTES)
        owner_res = read_capture_file(owner_response, MAX_EXCHANGE_BYTES) if owner_response is not None else None
        actor_res = read_capture_file(actor_response, MAX_EXCHANGE_BYTES) if actor_response is not None else None
    except (ValueError, OSError) as exc:
        return _result("technical_error", CODE_TECH_INCOMPLETE_CAPTURE, str(exc))

    try:
        owners = parse_captured_exchanges(owner_req, base_url, owner_res)
        actors = parse_captured_exchanges(actor_req, base_url, actor_res)
    except ValueError as exc:
        message = str(exc)
        cause = exc.__cause__
        cause_text = str(cause) if cause is not None else ""
        blob = message + " " + cause_text
        if _ORIGIN_OVERRIDE.search(blob) or "inconsistent origin" in message.lower():
            return _result(
                "technical_error",
                CODE_TECH_ORIGIN_OVERRIDE,
                blob.strip() or message,
                owner_req=owner_req,
                actor_req=actor_req,
                owner_res=owner_res,
                actor_res=actor_res,
            )
        return _result(
            "technical_error",
            CODE_TECH_PARSE_FAILURE,
            blob.strip() or message,
            owner_req=owner_req,
            actor_req=actor_req,
            owner_res=owner_res,
            actor_res=actor_res,
        )

    if len(owners) != 1 or len(actors) != 1:
        return _result(
            "needs_more_evidence",
            CODE_NEEDS_MORE_EVIDENCE,
            "Classification expects exactly one owner exchange and one actor exchange.",
            owner_req=owner_req,
            actor_req=actor_req,
            owner_res=owner_res,
            actor_res=actor_res,
        )

    own: CapturedExchange = owners[0]
    act: CapturedExchange = actors[0]

    try:
        pair = inspect_read_pair(own.request, act.request, base_url)
    except ValueError as exc:
        status, code = _map_inspect_error(str(exc))
        left = {k.lower(): v for k, v in own.request.headers.items()}
        right = {k.lower(): v for k, v in act.request.headers.items()}
        session_changes = sum(
            left.get(name) != right.get(name) for name in left.keys() | right.keys() if SESSION_HEADER.search(name)
        )
        # Preserve security_rejected codes for non-GET / body / method mismatch even when URLs match.
        if (
            code
            not in {
                CODE_REJECT_NON_GET,
                CODE_REJECT_GET_WITH_BODY,
                CODE_REJECT_METHOD_MISMATCH,
                CODE_REJECT_ORIGIN_MISMATCH_SIDES,
                CODE_TECH_ORIGIN_OVERRIDE,
            }
            and own.request.prepared_url() == act.request.prepared_url()
            and session_changes
        ):
            return _result(
                "needs_more_evidence",
                CODE_REJECT_SESSION_ONLY,
                "Captures share a URL and differ only in session material; not a resource read-case.",
                origin=None,
                owner_req=owner_req,
                actor_req=actor_req,
                owner_res=owner_res,
                actor_res=actor_res,
            )
        return _result(
            status,
            code,
            str(exc),
            owner_req=owner_req,
            actor_req=actor_req,
            owner_res=owner_res,
            actor_res=actor_res,
        )

    if owner_res is None or actor_res is None:
        return _result(
            "needs_more_evidence",
            CODE_NEEDS_RESPONSE,
            "Structural read pair is valid but both own-resource responses are required for a reviewable case.",
            origin=pair.origin,
            owner_req=owner_req,
            actor_req=actor_req,
            owner_res=owner_res,
            actor_res=actor_res,
        )

    return _result(
        "case_eligible",
        CODE_CASE_ELIGIBLE,
        "Structurally valid GET read pair with matching origin and both control responses.",
        origin=pair.origin,
        owner_req=owner_req,
        actor_req=actor_req,
        owner_res=owner_res,
        actor_res=actor_res,
    )


def classify_materialized_paths(
    pairs_dir: Path,
    proposal_id: str,
    *,
    base_url: str | None = None,
) -> PairClassification:
    """Classify files written by object_handoff ``--materialize-dir`` for one proposal id."""
    owner = pairs_dir / f"{proposal_id}-owner.http"
    actor = pairs_dir / f"{proposal_id}-actor.http"
    ores = pairs_dir / f"{proposal_id}-owner-response.http"
    ares = pairs_dir / f"{proposal_id}-actor-response.http"
    if not owner.is_file() or not actor.is_file():
        return _result(
            "technical_error", CODE_TECH_INCOMPLETE_CAPTURE, "Materialized owner/actor request files are missing."
        )
    return classify_capture_pair(
        owner,
        actor,
        owner_response=ores if ores.is_file() else None,
        actor_response=ares if ares.is_file() else None,
        base_url=base_url,
    )
