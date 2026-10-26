"""Deterministic authorization-denial classifier for offline IDOR/BOLA cases.

Differentiates *structural* case eligibility (matching GET pair + sessions) from
*evidence of successful cross-account access*. A denied actor response must never
become positive IDOR/BOLA evidence or a ``requires_validation`` / reviewable case.

Fully offline. Never sends HTTP, never auto-confirms, never records secrets.
Status alone is never conclusive: a 403 that still returns private owner data
stays inconclusive (see A06-style contradictory captures).
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
import json
import re
from typing import Any, Literal, Mapping

Outcome = Literal[
    "cross_account_denied",
    "possible_access",
    "inconclusive",
]
ResponseClass = Literal[
    "http_denial",
    "content_denial",
    "auth_redirect",
    "successful_looking",
    "public_or_shared",
    "empty_or_unknown",
    "error_ambiguous",
]

ANNOTATION_VERSION = "bbtk-control-annotation/1"

# Explicit denial tokens (JSON keys/values or plain-text phrases).
_DENIAL_TOKEN = re.compile(
    r"(?i)\b("
    r"forbidden|unauthorized|unauthenticated|not[_ -]?authorized|"
    r"access[_ -]?denied|permission[_ -]?denied|not[_ -]?permitted|"
    r"not[_ -]?allowed|denied|login[_ -]?required|auth(?:entication)?[_ -]?required|"
    r"insufficient[_ -]?permissions?|not[_ -]?found"
    r")\b"
)
_DENIAL_ERROR_KEYS = frozenset(
    {
        "error",
        "err",
        "message",
        "detail",
        "reason",
        "code",
        "status",
        "error_code",
        "error_message",
    }
)
_SUCCESS_KEYS = frozenset(
    {
        "ok",
        "success",
        "data",
        "result",
        "payload",
        "resource",
        "item",
        "object",
        "record",
        "entity",
        "statement",
        "payslip",
        "contract",
        "claim",
        "ledger",
        "prescription",
        "quote",
        "document",
        "catalog",
        "category",
        "order",
        "invoice",
        "profile",
        "account",
        "user",
        "basket",
        "wishlist",
        "cart",
    }
)
_VISIBILITY_PUBLIC = re.compile(r'(?i)"(?:visibility|acl|access|scope)"\s*:\s*"(public|shared)"')
_SHARED_ACL = re.compile(r'(?i)"shared_with"\s*:\s*\[')
_LOGIN_REDIRECT = re.compile(
    r"(?i)(?:^|[/?#])(?:login|signin|sign-in|auth(?:entication)?|sso|oauth|session)(?:$|[/?#])"
)
_STATUS_LINE = re.compile(r"^HTTP/1\.[01]\s+(\d{3})\b", re.I)


@dataclass(frozen=True)
class ResponseAssessment:
    """Classification of one captured HTTP response (status + body + headers)."""

    status_code: int | None
    response_class: ResponseClass
    denial_demonstrated: bool
    access_demonstrated: bool
    content_denial: bool
    resource_visibility: str | None
    redirect_location: str | None
    reasons: tuple[str, ...]

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class AuthorizationOutcome:
    """Pair-level outcome: structural eligibility is orthogonal to this."""

    outcome: Outcome
    owner: ResponseAssessment
    actor: ResponseAssessment
    annotation: dict[str, Any] | None
    reasons: tuple[str, ...]

    def as_dict(self) -> dict[str, Any]:
        return {
            "outcome": self.outcome,
            "owner": self.owner.as_dict(),
            "actor": self.actor.as_dict(),
            "annotation": self.annotation,
            "reasons": list(self.reasons),
            "cross_account_denied": self.outcome == "cross_account_denied",
            "possible_access": self.outcome == "possible_access",
            "inconclusive": self.outcome == "inconclusive",
        }


def parse_raw_response(raw: str | bytes | None) -> tuple[int | None, dict[str, str], str]:
    """Best-effort parse of a raw HTTP/1.x response into (status, headers, body)."""
    if raw is None:
        return None, {}, ""
    text = raw.decode("utf-8", errors="replace") if isinstance(raw, (bytes, bytearray)) else str(raw)
    if not text.strip():
        return None, {}, ""
    head, _, body = text.partition("\r\n\r\n")
    if _ == "":
        head, _, body = text.partition("\n\n")
    lines = head.splitlines()
    status: int | None = None
    if lines:
        match = _STATUS_LINE.match(lines[0].strip())
        if match:
            status = int(match.group(1))
    headers: dict[str, str] = {}
    for line in lines[1:]:
        if ":" not in line:
            continue
        name, value = line.split(":", 1)
        key = name.strip().lower()
        # Keep first Location; last-wins for others is fine for classification.
        if key == "location" and key in headers:
            continue
        headers[key] = value.strip()
    return status, headers, body


def _json_root(body: str) -> Any | None:
    text = body.strip()
    if not text or text[0] not in "{[":
        return None
    try:
        return json.loads(text)
    except (ValueError, RecursionError):
        return None


def _walk_strings(value: Any, *, limit: int = 64) -> list[str]:
    out: list[str] = []

    def visit(node: Any) -> None:
        if len(out) >= limit:
            return
        if isinstance(node, str):
            out.append(node)
        elif isinstance(node, dict):
            for key, item in node.items():
                if isinstance(key, str):
                    out.append(key)
                visit(item)
        elif isinstance(node, list):
            for item in node[:32]:
                visit(item)

    visit(value)
    return out


def _json_shows_denial(root: Any) -> bool:
    if not isinstance(root, dict):
        return False
    # Explicit failure flags.
    for key in ("ok", "success", "authorized", "allowed", "permitted"):
        if key in root and root[key] is False:
            return True
    for key in _DENIAL_ERROR_KEYS:
        value = root.get(key)
        if isinstance(value, str) and _DENIAL_TOKEN.search(value):
            return True
        if isinstance(value, (int, float)) and int(value) in {401, 403, 404}:
            return True
    # Nested error object.
    err = root.get("error")
    if isinstance(err, dict):
        blob = " ".join(_walk_strings(err))
        if _DENIAL_TOKEN.search(blob):
            return True
    return False


def _json_shows_access(root: Any) -> bool:
    """True when the body looks like a successful resource payload (not merely an error envelope)."""
    if not isinstance(root, dict):
        return False
    if root.get("ok") is False or root.get("success") is False:
        # Still allow contradictory payloads that nest a resource next to ok:false —
        # those are handled by the caller (access wins over denial for safety).
        pass
    # Resource-shaped object with an id / marker / owner label.
    for key, value in root.items():
        if key.lower() in _SUCCESS_KEYS and isinstance(value, dict):
            if any(k in value for k in ("id", "uuid", "marker", "owner_label", "owner", "user_id")):
                return True
            if len(value) >= 2:
                return True
        if key.lower() in {"data", "result", "payload", "record"} and value not in (None, "", [], {}):
            return True
    if root.get("ok") is True and any(
        isinstance(root.get(k), (dict, list)) and root.get(k) not in ({}, []) for k in root if k != "ok"
    ):
        return True
    return False


def _visibility(body: str, root: Any | None) -> str | None:
    if root is None:
        match = _VISIBILITY_PUBLIC.search(body)
        return match.group(1).lower() if match else None
    if not isinstance(root, dict):
        return None

    def from_mapping(node: Mapping[str, Any]) -> str | None:
        for key in ("visibility", "acl", "access", "scope"):
            value = node.get(key)
            if isinstance(value, str) and value.lower() in {"public", "shared"}:
                return value.lower()
        if isinstance(node.get("shared_with"), list) and node.get("shared_with"):
            return "shared"
        return None

    direct = from_mapping(root)
    if direct:
        return direct
    for value in root.values():
        if isinstance(value, dict):
            nested = from_mapping(value)
            if nested:
                return nested
    if _SHARED_ACL.search(body):
        return "shared"
    return None


def assess_response(
    status_code: int | None,
    body: str = "",
    headers: Mapping[str, str] | None = None,
) -> ResponseAssessment:
    """Classify one response. Ambiguous inputs stay inconclusive (never 'denied')."""
    headers = {str(k).lower(): str(v) for k, v in (headers or {}).items()}
    location = headers.get("location")
    reasons: list[str] = []
    root = _json_root(body)
    visibility = _visibility(body, root)
    access = bool(root is not None and _json_shows_access(root))
    denial_body = bool(
        (root is not None and _json_shows_denial(root)) or (body and _DENIAL_TOKEN.search(body) and not access)
    )
    # Contradictory: denial status/body alongside a successful-looking resource payload.
    if access and (denial_body or (status_code in {401, 403, 404})):
        reasons.append("contradictory_denial_status_with_resource_body")
        return ResponseAssessment(
            status_code=status_code,
            response_class="successful_looking",
            denial_demonstrated=False,
            access_demonstrated=True,
            content_denial=False,
            resource_visibility=visibility,
            redirect_location=location,
            reasons=tuple(reasons),
        )
    if visibility in {"public", "shared"}:
        reasons.append(f"resource_visibility:{visibility}")
        return ResponseAssessment(
            status_code=status_code,
            response_class="public_or_shared",
            denial_demonstrated=False,
            access_demonstrated=False,
            content_denial=False,
            resource_visibility=visibility,
            redirect_location=location,
            reasons=tuple(reasons),
        )
    if status_code in {301, 302, 303, 307, 308} and location and _LOGIN_REDIRECT.search(location):
        reasons.append("auth_redirect")
        return ResponseAssessment(
            status_code=status_code,
            response_class="auth_redirect",
            denial_demonstrated=True,
            access_demonstrated=False,
            content_denial=False,
            resource_visibility=None,
            redirect_location=location,
            reasons=tuple(reasons),
        )
    if status_code in {401, 403, 404}:
        reasons.append(f"http_{status_code}")
        if denial_body:
            reasons.append("denial_body")
        return ResponseAssessment(
            status_code=status_code,
            response_class="http_denial",
            denial_demonstrated=True,
            access_demonstrated=False,
            content_denial=False,
            resource_visibility=None,
            redirect_location=location,
            reasons=tuple(reasons),
        )
    if status_code == 200 and denial_body and not access:
        reasons.append("content_denial")
        return ResponseAssessment(
            status_code=status_code,
            response_class="content_denial",
            denial_demonstrated=True,
            access_demonstrated=False,
            content_denial=True,
            resource_visibility=None,
            redirect_location=location,
            reasons=tuple(reasons),
        )
    if access or (status_code == 200 and body.strip()):
        if access:
            reasons.append("resource_payload")
        else:
            reasons.append("non_empty_200")
        return ResponseAssessment(
            status_code=status_code,
            response_class="successful_looking",
            denial_demonstrated=False,
            access_demonstrated=access,
            content_denial=False,
            resource_visibility=visibility,
            redirect_location=location,
            reasons=tuple(reasons),
        )
    if status_code is not None and status_code >= 500:
        reasons.append("server_error")
        return ResponseAssessment(
            status_code=status_code,
            response_class="error_ambiguous",
            denial_demonstrated=False,
            access_demonstrated=False,
            content_denial=False,
            resource_visibility=None,
            redirect_location=location,
            reasons=tuple(reasons),
        )
    reasons.append("empty_or_unknown")
    return ResponseAssessment(
        status_code=status_code,
        response_class="empty_or_unknown",
        denial_demonstrated=False,
        access_demonstrated=False,
        content_denial=False,
        resource_visibility=None,
        redirect_location=location,
        reasons=tuple(reasons),
    )


def assess_raw_response(raw: str | bytes | None) -> ResponseAssessment:
    """Classify a raw HTTP/1.x response capture."""
    status, headers, body = parse_raw_response(raw)
    return assess_response(status, body, headers)


def _annotation_for(
    outcome: Outcome,
    owner: ResponseAssessment,
    actor: ResponseAssessment,
) -> dict[str, Any] | None:
    """Build a ``bbtk-control-annotation/1`` block for the evidence ledger / planner."""
    if outcome == "cross_account_denied":
        control: dict[str, Any] = {
            "annotation_version": ANNOTATION_VERSION,
            "role": "negative_control",
            "provides": ["owner_response", "actor_response", "negative_control"],
            "contradicts_hypothesis": True,
            "owner_status_class": owner.response_class,
            "actor_status_class": actor.response_class,
            "owner_status_code": owner.status_code,
            "actor_status_code": actor.status_code,
        }
        if actor.content_denial or owner.content_denial:
            control["content_denial"] = True
        if actor.redirect_location:
            control["redirect_location_class"] = "auth_login"
        return control
    if actor.resource_visibility in {"public", "shared"} or owner.resource_visibility in {"public", "shared"}:
        visibility = actor.resource_visibility or owner.resource_visibility
        return {
            "annotation_version": ANNOTATION_VERSION,
            "role": "capture_pair",
            "provides": ["owner_response", "actor_response"],
            "resource_visibility": visibility,
            "owner_status_class": owner.response_class,
            "actor_status_class": actor.response_class,
            "owner_status_code": owner.status_code,
            "actor_status_code": actor.status_code,
        }
    if outcome == "possible_access":
        return {
            "annotation_version": ANNOTATION_VERSION,
            "role": "capture_pair",
            "provides": ["owner_response", "actor_response"],
            "owner_status_class": owner.response_class,
            "actor_status_class": actor.response_class,
            "owner_status_code": owner.status_code,
            "actor_status_code": actor.status_code,
            # Explicit: possible access is NOT confirmation.
            "access_confirmed": False,
        }
    return {
        "annotation_version": ANNOTATION_VERSION,
        "role": "capture_pair",
        "provides": ["owner_response", "actor_response"],
        "owner_status_class": owner.response_class,
        "actor_status_class": actor.response_class,
        "owner_status_code": owner.status_code,
        "actor_status_code": actor.status_code,
        "authorization_outcome": "inconclusive",
    }


def assess_pair_authorization(
    owner_raw_response: str | bytes | None,
    actor_raw_response: str | bytes | None,
) -> AuthorizationOutcome:
    """Combine owner/actor response assessments into a pair-level authorization outcome.

    Positive control (owner success) and negative control (actor denial) stay
    differentiated. Ambiguous actor responses stay ``inconclusive``.
    """
    owner = assess_raw_response(owner_raw_response)
    actor = assess_raw_response(actor_raw_response)
    reasons: list[str] = []

    # Public / shared resources: not cross-account authorization failures.
    if actor.resource_visibility in {"public", "shared"} or owner.resource_visibility in {"public", "shared"}:
        reasons.append("public_or_shared_resource")
        outcome: Outcome = "inconclusive"
        return AuthorizationOutcome(
            outcome=outcome,
            owner=owner,
            actor=actor,
            annotation=_annotation_for(outcome, owner, actor),
            reasons=tuple(reasons),
        )

    if actor.denial_demonstrated and (owner.access_demonstrated or owner.response_class == "successful_looking"):
        reasons.append("actor_denied_with_owner_positive_control")
        outcome = "cross_account_denied"
        return AuthorizationOutcome(
            outcome=outcome,
            owner=owner,
            actor=actor,
            annotation=_annotation_for(outcome, owner, actor),
            reasons=tuple(reasons),
        )

    # Actor denial without a usable owner positive control — keep inconclusive.
    if actor.denial_demonstrated and not owner.access_demonstrated:
        reasons.append("actor_denied_but_owner_control_weak")
        outcome = "inconclusive"
        return AuthorizationOutcome(
            outcome=outcome,
            owner=owner,
            actor=actor,
            annotation=_annotation_for(outcome, owner, actor),
            reasons=tuple(reasons),
        )

    if actor.access_demonstrated and owner.access_demonstrated:
        reasons.append("both_sides_successful_looking")
        outcome = "possible_access"
        return AuthorizationOutcome(
            outcome=outcome,
            owner=owner,
            actor=actor,
            annotation=_annotation_for(outcome, owner, actor),
            reasons=tuple(reasons),
        )

    reasons.append("ambiguous_authorization_evidence")
    outcome = "inconclusive"
    return AuthorizationOutcome(
        outcome=outcome,
        owner=owner,
        actor=actor,
        annotation=_annotation_for(outcome, owner, actor),
        reasons=tuple(reasons),
    )


__all__ = [
    "ANNOTATION_VERSION",
    "AuthorizationOutcome",
    "ResponseAssessment",
    "assess_pair_authorization",
    "assess_raw_response",
    "assess_response",
    "parse_raw_response",
]
