"""DOM/browser observation states and minimized, hashed XSS evidence records.

Integrates with the already-merged opt-in ``--dom-local`` probes
(``bugbounty_toolkit.xss.dom_local``) and the ``PlaywrightExecutionChecker``
observation dictionary. It does **not** reimplement either; it consumes their
outputs and adds:

* a precise DOM state classification that keeps *source observed*, *sink
  reached*, *sanitization applied*, *execution observed*, *execution blocked by
  CSP*, *interaction required* and *inconclusive* distinct; and
* a minimized evidence record (case id, context, source, sink, execution result,
  relevant CSP, technical errors, capture refs, evidence hashes).

Execution is NEVER inferred from a sink alone: reaching ``innerHTML`` without an
observed marker execution stays ``sink_reached``. Observed execution only means
the innocuous marker ran under known laboratory conditions. Every record keeps
``finding_confirmed=False``.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass, field
from typing import Any, Mapping, Sequence

from ..core.redaction import redact_text

DOM_STATES = (
    "execution_observed",
    "execution_blocked_csp",
    "interaction_required",
    "sanitization_applied",
    "sink_reached",
    "source_observed",
    "inconclusive",
    "inconclusive_browser_error",
)

# Fields that must never be stored in a shareable evidence record.
_FORBIDDEN_KEYS = frozenset(
    {
        "cookie",
        "cookies",
        "set-cookie",
        "authorization",
        "token",
        "tokens",
        "session",
        "sessionid",
        "localstorage",
        "local_storage",
        "sessionstorage",
        "session_storage",
        "html",
        "body",
        "raw_html",
        "response_body",
        "headers",
    }
)

_CSP_ERROR = re.compile(r"content security policy|refused to (execute|load)|csp", re.IGNORECASE)
_MAX_ERRORS = 5
_MAX_ERROR_LEN = 200


@dataclass(frozen=True)
class DomObservation:
    """Normalized browser observation for one DOM probe."""

    source_observed: bool = False
    sinks: tuple[str, ...] = ()
    marker_executed: bool = False
    sanitized: bool = False
    csp_blocked: bool = False
    interaction_required: bool = False
    browser_failed: bool = False


def _bool(value: object) -> bool:
    return bool(value)


def observation_from_checker(evidence: Mapping[str, Any], *, csp_header: str | None = None) -> DomObservation:
    """Build a ``DomObservation`` from a ``PlaywrightExecutionChecker.confirm`` dict.

    CSP blocking is inferred only from browser-reported CSP errors (console/page
    errors) when no execution was observed, never from the header alone.
    """
    sinks_raw = evidence.get("dom_sinks", [])
    sinks = tuple(sorted(s for s in sinks_raw if isinstance(s, str))) if isinstance(sinks_raw, list) else ()
    executed = _bool(evidence.get("marker_observed")) or _bool(evidence.get("alert_observed"))
    errors = [str(item) for item in evidence.get("console_errors", []) or []]
    errors += [str(item) for item in evidence.get("page_errors", []) or []]
    csp_error = any(_CSP_ERROR.search(item) for item in errors)
    return DomObservation(
        source_observed=_bool(evidence.get("source_marker_present")),
        sinks=sinks,
        marker_executed=executed,
        sanitized=_bool(evidence.get("sanitized")),
        csp_blocked=csp_error and not executed and bool(csp_header or csp_error),
        interaction_required=_bool(evidence.get("interaction_required")),
        browser_failed=_bool(evidence.get("browser_failed")),
    )


def classify_dom_state(observation: DomObservation) -> str:
    """Return the most specific defensible DOM state. Order matters.

    Execution must be directly observed (marker/alert). Sinks alone never imply
    execution.
    """
    if observation.browser_failed:
        return "inconclusive_browser_error"
    if observation.marker_executed:
        return "execution_observed"
    if observation.csp_blocked:
        return "execution_blocked_csp"
    if observation.interaction_required:
        return "interaction_required"
    if observation.sanitized:
        return "sanitization_applied"
    if observation.sinks:
        return "sink_reached"
    if observation.source_observed:
        return "source_observed"
    return "inconclusive"


def assess_dom_result(result: Mapping[str, Any], *, csp_header: str | None = None) -> dict[str, object]:
    """Add a precise DOM assessment to a merged ``run_dom_local`` result dict.

    Consumes the existing result shape (``source_marker_present``, ``dom_sinks``,
    ``browser_execution_observed``, ``classification``) without changing it.
    """
    if result.get("classification") == "error":
        observation = DomObservation(browser_failed=True)
    else:
        sinks_raw = result.get("dom_sinks", [])
        sinks = tuple(sorted(s for s in sinks_raw if isinstance(s, str))) if isinstance(sinks_raw, list) else ()
        observation = DomObservation(
            source_observed=_bool(result.get("source_marker_present")),
            sinks=sinks,
            marker_executed=_bool(result.get("browser_execution_observed")),
            sanitized=_bool(result.get("sanitized")),
            csp_blocked=_bool(result.get("csp_blocked")),
            interaction_required=_bool(result.get("interaction_required")),
        )
    state = classify_dom_state(observation)
    return {
        "dom_state": state,
        "source_observed": observation.source_observed,
        "sink_reached": bool(observation.sinks),
        "execution_observed": state == "execution_observed",
        "csp": _relevant_csp(csp_header),
        "finding_confirmed": False,
    }


def _relevant_csp(csp_header: str | None) -> dict[str, object] | None:
    """Keep only XSS-relevant CSP directives; never store the full header verbatim if huge."""
    if not csp_header:
        return None
    directives: dict[str, str] = {}
    for part in csp_header.split(";"):
        part = part.strip()
        if not part:
            continue
        name, _, value = part.partition(" ")
        name = name.lower()
        if name in {"script-src", "script-src-elem", "script-src-attr", "default-src", "require-trusted-types-for"}:
            directives[name] = value.strip()[:200]
    restrictive = any(
        "'unsafe-inline'" not in value and "*" not in value.split()
        for key, value in directives.items()
        if key.startswith("script-src") or key == "default-src"
    )
    return {"directives": directives, "restrictive_for_inline": restrictive}


def _sha256(data: bytes | str) -> str:
    raw = data.encode("utf-8") if isinstance(data, str) else data
    return hashlib.sha256(raw).hexdigest()


def _scrub_errors(errors: Sequence[object]) -> list[str]:
    out: list[str] = []
    for item in list(errors)[:_MAX_ERRORS]:
        text = redact_text(str(item)) or ""
        out.append(text[:_MAX_ERROR_LEN])
    return out


@dataclass(frozen=True)
class BrowserEvidence:
    case_id: str
    context: str
    observed_source: str | None
    observed_sink: str | None
    execution_result: str
    csp: dict[str, object] | None
    technical_errors: list[str]
    capture_refs: list[str]
    evidence_hashes: dict[str, str]
    finding_confirmed: bool = False
    human_review_required: bool = True
    note: str = field(
        default=(
            "Observed execution only means an innocuous marker ran under known lab conditions; "
            "it is not automatically a reportable vulnerability."
        )
    )

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def build_browser_evidence(
    *,
    case_id: str,
    context: str,
    execution_result: str,
    observed_source: str | None = None,
    observed_sink: str | None = None,
    csp_header: str | None = None,
    technical_errors: Sequence[object] = (),
    capture_refs: Sequence[str] = (),
    capture_bytes: Mapping[str, bytes | str] | None = None,
) -> BrowserEvidence:
    """Create a minimized evidence record.

    ``capture_bytes`` are hashed (SHA-256) for provenance and then discarded; the
    raw content (which may be private HTML) is never stored in the record.
    """
    if execution_result not in DOM_STATES and execution_result not in {
        "not_executed",
        "executed",
        "not_tested",
    }:
        raise ValueError("Unknown execution_result.")
    hashes = {ref: _sha256(content) for ref, content in (capture_bytes or {}).items()}
    record = BrowserEvidence(
        case_id=case_id,
        context=context,
        observed_source=observed_source,
        observed_sink=observed_sink,
        execution_result=execution_result,
        csp=_relevant_csp(csp_header),
        technical_errors=_scrub_errors(technical_errors),
        capture_refs=[str(ref) for ref in capture_refs],
        evidence_hashes=hashes,
    )
    record_hash = _sha256(json.dumps(record.to_dict(), sort_keys=True))
    hashes_with_record = dict(record.evidence_hashes)
    hashes_with_record["record_sha256"] = record_hash
    return BrowserEvidence(
        case_id=record.case_id,
        context=record.context,
        observed_source=record.observed_source,
        observed_sink=record.observed_sink,
        execution_result=record.execution_result,
        csp=record.csp,
        technical_errors=record.technical_errors,
        capture_refs=record.capture_refs,
        evidence_hashes=hashes_with_record,
    )


def assert_minimized(record: Mapping[str, Any]) -> None:
    """Raise if a record leaks forbidden session/private fields at any depth.

    Keys under ``evidence_hashes`` are exempt (they name hashed captures; values
    must be hex digests). Raw HTML/bodies must never appear as string values of
    forbidden keys.
    """

    def walk(value: object, path: str, *, under_hashes: bool = False) -> None:
        if isinstance(value, Mapping):
            for key, inner in value.items():
                key_l = str(key).lower()
                next_under = under_hashes or key_l == "evidence_hashes"
                if not under_hashes and key_l in _FORBIDDEN_KEYS:
                    raise ValueError(f"Forbidden field in evidence record: {path}{key}")
                walk(inner, f"{path}{key}.", under_hashes=next_under)
        elif isinstance(value, list):
            for item in value:
                walk(item, path, under_hashes=under_hashes)
        elif under_hashes and isinstance(value, str):
            if len(value) != 64 or any(ch not in "0123456789abcdef" for ch in value.lower()):
                raise ValueError(f"evidence_hashes values must be SHA-256 hex digests: {path}")

    walk(record, "")
