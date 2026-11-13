"""Advisory review order for external findings, hypotheses, and ledger candidates.

The score reuses :func:`bugbounty_toolkit.analysis.prioritization._score` for
evidence and vulnerability-class impact. Tool severity is never a term.
A row is abstained, not guessed, when a field needed to compare it is missing,
ambiguous, or contradictory. Nothing in this module confirms a finding or
sends a request.
"""

from __future__ import annotations

import json
import math
import re
from pathlib import Path
from typing import Any, Mapping, Sequence

from ..core.private_files import local_path
from ..core.redaction import redact_text
from ..core.scope import ScopeRule, normalize_host, normalized_path, validate_rule
from .actor_provenance import classify_session_controls
from .external_importers import SCHEMA as EXTERNAL_SCHEMA
from .external_importers import _CONTRADICTIONS
from .hypotheses import _validate_hypothesis
from .prioritization import _CATEGORY_TO_SKILL, _IMPACT_POINTS, _POTENTIAL_IMPACT, _priority, _score
from .skill_router import SKILL_REGISTRY, SkillDefinition

SCHEMA = "bbtk.review-prioritization/1"
MAX_INPUT_BYTES = 2_000_000
MAX_SCOPE_BYTES = 100_000
MAX_ITEMS = 2_000
MAX_SCOPE_RULES = 200
CORROBORATION_POINTS = 6
SESSION_CLARITY_POINTS = 4
_CONTROL_BONUS = 10
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_GROUP_ID = re.compile(r"^[a-f0-9]{24}$")
_METHOD = re.compile(r"^[A-Za-z]{1,16}$")

ABSTAIN_REASONS: tuple[str, ...] = (
    "missing_scope",
    "out_of_scope",
    "closed_review",
    "missing_origin",
    "ambiguous_origin",
    "contradictory_origin",
    "missing_location",
    "ambiguous_location",
    "contradictory_location",
    "missing_vulnerability_class",
    "ambiguous_vulnerability_class",
    "contradictory_vulnerability_class",
    "contradictory_session",
    "ambiguous_session",
    "contradictory_evidence",
    "ambiguous_evidence",
    "severity_without_supporting_evidence",
    "missing_evidence",
    "contradictory_corroboration",
    "ambiguous_corroboration",
)
FACTORS: tuple[str, ...] = (
    "origin",
    "location",
    "evidence_strength",
    "session_actor",
    "corroboration",
    "vulnerability_class_impact",
    "contradictions",
)
# Aliases of categories that already have a band in ``_POTENTIAL_IMPACT``.
# Unmapped tool classes abstain instead of receiving an invented band.
_CLASS_ALIASES = {
    "access_control": "access_control",
    "idor": "access_control",
    "bola": "access_control",
    "sqli": "sqli",
    "sql_injection": "sqli",
    "jwt": "jwt",
    "xss": "xss",
    "cross_site_scripting": "xss",
    "cors": "cors",
    "info_disclosure": "info_disclosure",
    "information_disclosure": "info_disclosure",
    "information_exposure": "info_disclosure",
    "open_redirect": "open_redirect",
}
_KNOWN_TOOLS = frozenset({"nuclei", "zap", "ffuf", "sqlmap", "bbtk"})
_CLEAR_SESSION = frozenset(
    {
        "owner_control_valid",
        "second_account_control_valid",
        "anonymous_control",
        "cross_control_observed",
    }
)
_AMBIGUOUS_SESSION = frozenset({"invalid_session", "possibly_expired_session"})
_REJECTION_CONTRADICTION = frozenset({"false_positive", "evidence_invalidated", "control_invalid", "not_reproducible"})


class _Item:
    """One comparable review subject. Not part of the public report."""

    def __init__(self, item_id: str, kind: str) -> None:
        self.item_id = item_id
        self.kind = kind
        self.tool: str | None = None
        self.source: str | None = None
        self.record_index: int | None = None
        self.origin_tools: tuple[str, ...] = ()
        self.host: str | None = None
        self.endpoint: str | None = None
        self.method: str | None = None
        self.url: str | None = None
        self.location_ambiguous = False
        self.location_conflict = False
        self.category: str | None = None
        self.raw_class: str | None = None
        self.class_missing = False
        self.class_ambiguous = False
        self.claimed = False
        self.severity: str | None = None
        self.support_count = 0
        self.evidence_state = "missing"
        self.missing_controls: list[str] | None = None
        self.session_state = "unknown"
        self.session_detail = "No session or actor attestation was supplied, so none was inferred."
        self.summary = ""
        self.importer_status: str | None = None
        self.closed_review = False
        self.surface_out_of_scope = False
        self.reasons: set[str] = set()
        self.confirmation_claim = False

    @property
    def origin_key(self) -> tuple[str, str, int] | None:
        if self.tool is None or self.source is None or self.record_index is None:
            return None
        return (self.tool, self.source, self.record_index)

    @property
    def source_key(self) -> tuple[str, str] | None:
        if self.tool is None or self.source is None:
            return None
        return (self.tool, self.source)


def _program(value: str) -> None:
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,79}", value):
        raise ValueError("A valid program name is required.")


def _budget(max_tests: int) -> None:
    if type(max_tests) is not int or max_tests <= 0:
        raise ValueError("--max-tests must be a positive integer.")


def _rate(value: float) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError("requests_per_second must be a positive finite number.")
    number = float(value)
    if not math.isfinite(number) or number <= 0:
        raise ValueError("requests_per_second must be a positive finite number.")
    return number


def _read_json(path: Path) -> Any:
    resolved = local_path(path)
    try:
        size = resolved.stat().st_size
    except OSError as exc:
        raise ValueError("Input must be a readable local file.") from exc
    if size > MAX_INPUT_BYTES:
        raise ValueError(f"Input exceeds the {MAX_INPUT_BYTES}-byte limit.")
    try:
        text = resolved.read_text(encoding="utf-8")
        return json.loads(text)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("Input must be readable UTF-8 JSON.") from exc


def load_scope_lines(path: Path) -> list[str]:
    """Read explicit scope rules. An empty file is returned as an empty list."""
    resolved = local_path(path)
    try:
        info = resolved.stat()
    except OSError as exc:
        raise ValueError("Scope file must be a readable local file.") from exc
    if info.st_size > MAX_SCOPE_BYTES:
        raise ValueError(f"Scope file exceeds the {MAX_SCOPE_BYTES}-byte limit.")
    try:
        return resolved.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError) as exc:
        raise ValueError("Scope file must be readable UTF-8 text.") from exc


def _rules(lines: Sequence[str]) -> list[ScopeRule]:
    if len(lines) > MAX_SCOPE_RULES:
        raise ValueError(f"Scope exceeds the {MAX_SCOPE_RULES}-rule limit.")
    rules: list[ScopeRule] = []
    for line in lines:
        clean = line.strip()
        if not clean or clean.startswith("#"):
            continue
        allowed = True
        if clean.startswith(("!", "-")):
            allowed = False
            clean = clean[1:].strip()
        validate_rule(clean)
        rules.append(ScopeRule(clean, allowed=allowed))
    return rules


def _label(value: Mapping[str, Any], fallback: str, seen: set[str]) -> tuple[str, bool]:
    raw = value.get("review_id")
    base = raw if isinstance(raw, str) and _ID.fullmatch(raw) else fallback
    if base not in seen:
        seen.add(base)
        return base, False
    number = 2
    while f"{base}~{number}" in seen:
        number += 1
    assigned = f"{base}~{number}"
    seen.add(assigned)
    return assigned, True


def _basename(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    text = value.replace("\\", "/").strip()
    if not text or text.startswith("/") or ".." in text.split("/"):
        return None
    name = text.rsplit("/", 1)[-1]
    if not name or len(name) > 255:
        return None
    return name


def _class_name(value: object) -> tuple[str | None, str | None, bool, bool]:
    """Return category, raw label, missing, ambiguous."""
    if value is None or value == "":
        return None, None, True, False
    if not isinstance(value, str):
        return None, None, False, True
    raw = value.strip().casefold().replace(" ", "_").replace("-", "_")
    if not raw or raw == "unknown":
        return None, raw or None, True, False
    category = _CLASS_ALIASES.get(raw)
    if category is None:
        return None, raw, False, True
    return category, raw, False, False


def _method(value: object) -> tuple[str | None, bool]:
    if value is None or value == "":
        return None, False
    if isinstance(value, str) and _METHOD.fullmatch(value):
        return value.upper(), False
    return None, True


def _location_parts(
    host: object, endpoint: object, method: object, url: object
) -> tuple[str | None, str | None, str | None, str | None, bool, bool]:
    """Return host, endpoint, method, url, ambiguous, contradictory."""
    ambiguous = False
    conflict = False
    parsed_method, method_bad = _method(method)
    ambiguous = ambiguous or method_bad
    host_text = host if isinstance(host, str) and host.strip() else None
    endpoint_text = endpoint if isinstance(endpoint, str) and endpoint.strip() else None
    url_text = url if isinstance(url, str) and url.startswith(("http://", "https://")) and len(url) <= 4096 else None
    if isinstance(endpoint, list) or isinstance(url, list) or isinstance(host, list):
        ambiguous = True
    path = endpoint_text
    if path is not None and (not path.startswith("/") or path in {"/[unavailable]", "/[redacted]"} or "\\" in path):
        ambiguous = True
        path = None
    if host_text in {"[unavailable]", "[redacted]"}:
        ambiguous = True
        host_text = None
    url_path = None
    if url_text is not None:
        try:
            from urllib.parse import urlsplit

            split = urlsplit(url_text)
            url_path = normalized_path(split.path or "/")
            if host_text is None and split.hostname:
                host_text = split.hostname
        except (ValueError, UnicodeError):
            ambiguous = True
            url_text = None
    if path is not None:
        try:
            path = normalized_path(path)
        except (ValueError, UnicodeError):
            ambiguous = True
            path = None
    if path is None and url_path is not None:
        path = url_path
    elif path is not None and url_path is not None and path != url_path:
        conflict = True
    if host_text is not None:
        try:
            lowered = normalize_host(host_text)
        except (ValueError, UnicodeError):
            lowered = ""
        if not lowered:
            ambiguous = True
            host_text = None
        else:
            host_text = lowered
    return host_text, path, parsed_method, url_text, ambiguous, conflict


def _target(item: _Item) -> str | None:
    if item.url and item.host and item.endpoint and not item.location_conflict:
        return item.url
    if item.host and item.endpoint:
        return f"http://{item.host}{item.endpoint}"
    if item.url and not item.location_conflict:
        return item.url
    return None


def _scope_state(target: str | None, rules: Sequence[ScopeRule]) -> str:
    if not rules:
        return "missing_scope"
    if target is None:
        return "unchecked"
    try:
        if any((not rule.allowed) and rule.matches(target) for rule in rules):
            return "out_of_scope"
        if any(rule.allowed and rule.matches(target) for rule in rules):
            return "in_scope"
    except (ValueError, UnicodeError):
        return "unchecked"
    return "out_of_scope"


def _support_ids(items: object) -> tuple[int, bool]:
    if not isinstance(items, list):
        return 0, True
    seen: set[str] = set()
    bad = False
    for item in items:
        if not isinstance(item, dict):
            bad = True
            continue
        record_id = item.get("record_id")
        why = item.get("why")
        if not isinstance(record_id, str) or not record_id or not isinstance(why, str):
            bad = True
            continue
        seen.add(record_id)
    return len(seen), bad


def _session(value: object, claims: list[int]) -> tuple[str, str]:
    if value is None:
        return "unknown", "No session or actor attestation was supplied, so none was inferred."
    if not isinstance(value, list) or any(not isinstance(row, dict) for row in value):
        return "ambiguous", "Session observations were not a list of records, so the actor was not guessed."
    if not value:
        return "unknown", "Session observations were empty, so no actor was inferred."
    by_ref: dict[str, set[str]] = {}
    for row in value:
        ref = row.get("session_ref")
        label = row.get("label")
        if row.get("account_attested") is True and isinstance(ref, str) and isinstance(label, str):
            by_ref.setdefault(ref, set()).add(label)
    if any(len(labels) > 1 for labels in by_ref.values()):
        return "contradictory", "One session_ref was attested to more than one actor."
    try:
        assessed = classify_session_controls(value)
    except (TypeError, ValueError):
        return "ambiguous", "Session observations could not be classified."
    if assessed.get("confirmed") is True:
        claims[0] += 1
    sessions = assessed.get("sessions")
    if not isinstance(sessions, dict) or not sessions:
        return "ambiguous", "Session classification did not name a session."
    classes = sorted(
        {
            str(row.get("classification"))
            for row in sessions.values()
            if isinstance(row, dict) and isinstance(row.get("classification"), str)
        }
    )
    if any(name in _AMBIGUOUS_SESSION for name in classes):
        return "ambiguous", "Session control was invalid or possibly expired (" + ", ".join(classes) + ")."
    clear = [name for name in classes if name in _CLEAR_SESSION]
    unknown = [name for name in classes if name not in _CLEAR_SESSION]
    if clear and unknown:
        return "ambiguous", "Session observations mixed a clear control with an unproven actor."
    if clear:
        return "clear", "Session control classified as " + ", ".join(clear) + ". This is not confirmation."
    return "unknown", "Actor identity is unproven. Cookies alone were not treated as an actor."


def _apply_session_reason(item: _Item) -> None:
    if item.session_state == "contradictory":
        item.reasons.add("contradictory_session")
    elif item.session_state == "ambiguous":
        item.reasons.add("ambiguous_session")


def _evidence_from_external(evidence: Mapping[str, Any]) -> tuple[str, int]:
    diagnostics = evidence.get("ingestion_diagnostics")
    codes = [code for code in diagnostics if isinstance(code, str)] if isinstance(diagnostics, list) else []
    if any(code in _CONTRADICTIONS for code in codes):
        return "contradictory", 0
    confidence = evidence.get("ingestion_confidence")
    if confidence in {"ambiguous", "partial"}:
        return "ambiguous", 0
    observed = confidence == "observed" and (
        evidence.get("response_present") is True or type(evidence.get("status_code")) is int
    )
    if observed:
        return "observed", 1
    if confidence is None:
        return "missing", 0
    return "ambiguous", 0


def _take_external(finding: Mapping[str, Any], seen: set[str], encounter: int) -> _Item:
    origin = finding.get("origin") if isinstance(finding.get("origin"), dict) else {}
    evidence = finding.get("evidence") if isinstance(finding.get("evidence"), dict) else {}
    hypothesis = finding.get("hypothesis") if isinstance(finding.get("hypothesis"), dict) else {}
    tool = origin.get("tool") if isinstance(origin, dict) else None
    source = _basename(origin.get("source_file")) if isinstance(origin, dict) else None
    index = origin.get("record_index") if isinstance(origin, dict) else None
    record_index = index if type(index) is int and index >= 1 else None
    fallback = (
        f"external:{tool if isinstance(tool, str) else 'unknown'}:{source or 'source'}:{record_index or 0}:{encounter}"
    )
    item_id, duplicated = _label(finding, fallback, seen)
    item = _Item(item_id, "external")
    if duplicated:
        item.reasons.add("ambiguous_origin")
    tools: list[str] = []
    if isinstance(tool, str):
        tools.append(tool)
    extra = origin.get("tools") if isinstance(origin, dict) else None
    if isinstance(extra, list):
        tools.extend(entry for entry in extra if isinstance(entry, str))
    item.origin_tools = tuple(dict.fromkeys(tools))
    if len(item.origin_tools) > 1:
        item.reasons.add("contradictory_origin")
    elif len(item.origin_tools) == 1 and item.origin_tools[0] in _KNOWN_TOOLS and source and record_index:
        item.tool = item.origin_tools[0]
        item.source = source
        item.record_index = record_index
    elif not item.origin_tools or item.origin_tools[0] not in _KNOWN_TOOLS:
        if not isinstance(tool, str) or not tool:
            item.reasons.add("missing_origin")
        else:
            item.reasons.add("ambiguous_origin")
    else:
        item.reasons.add("missing_origin")
    host, endpoint, method, url, ambiguous, conflict = _location_parts(
        evidence.get("host") if isinstance(evidence, dict) else None,
        evidence.get("endpoint") if isinstance(evidence, dict) else None,
        evidence.get("method") if isinstance(evidence, dict) else None,
        evidence.get("url") if isinstance(evidence, dict) else None,
    )
    item.host, item.endpoint, item.method, item.url = host, endpoint, method, url
    item.location_ambiguous = ambiguous
    item.location_conflict = conflict
    category, raw, missing, class_ambiguous = _class_name(
        hypothesis.get("vulnerability_class") if isinstance(hypothesis, dict) else None
    )
    item.category, item.raw_class = category, raw
    item.class_missing, item.class_ambiguous = missing, class_ambiguous
    item.claimed = hypothesis.get("vulnerability_claimed") is True if isinstance(hypothesis, dict) else False
    severity = hypothesis.get("severity_claimed") if isinstance(hypothesis, dict) else None
    item.severity = severity if isinstance(severity, str) and severity.strip() else None
    if isinstance(evidence, dict):
        state, count = _evidence_from_external(evidence)
        codes = evidence.get("ingestion_diagnostics")
        if isinstance(codes, list) and "ambiguous_session" in codes:
            item.session_state = "contradictory"
            item.session_detail = "The capture reported ambiguous session material."
    else:
        state, count = "missing", 0
    item.evidence_state = state
    item.support_count = count
    status = finding.get("status")
    item.importer_status = status if isinstance(status, str) else None
    if finding.get("access_confirmed") is True:
        item.confirmation_claim = True
    count_claimed = finding.get("vulnerabilities_confirmed")
    if isinstance(count_claimed, int) and count_claimed != 0:
        item.confirmation_claim = True
    claim = hypothesis.get("claim") if isinstance(hypothesis, dict) else None
    item.summary = claim if isinstance(claim, str) else ""
    return item


def _take_hypothesis(group: Mapping[str, Any], seen: set[str], encounter: int, claims: list[int]) -> _Item:
    group_id = group.get("group_id")
    safe_group = group_id if isinstance(group_id, str) and _GROUP_ID.fullmatch(group_id) else f"group-{encounter}"
    item_id, duplicated = _label(group, f"hypothesis:{safe_group}", seen)
    item = _Item(item_id, "hypothesis")
    if duplicated:
        item.reasons.add("ambiguous_origin")
    item.tool = "bbtk"
    item.source = _basename(group.get("source_file")) or "ai-hypotheses.json"
    item.record_index = encounter
    origin = group.get("origin") if isinstance(group.get("origin"), dict) else None
    if origin is not None:
        tool = origin.get("tool")
        tools = [tool] if isinstance(tool, str) else []
        extra = origin.get("tools")
        if isinstance(extra, list):
            tools.extend(entry for entry in extra if isinstance(entry, str))
        item.origin_tools = tuple(dict.fromkeys(tools))
        if len(set(item.origin_tools)) > 1:
            item.reasons.add("contradictory_origin")
            item.tool = None
        elif item.origin_tools and item.origin_tools[0] not in _KNOWN_TOOLS:
            item.reasons.add("ambiguous_origin")
            item.tool = None
        elif item.origin_tools:
            item.tool = item.origin_tools[0]
    hypothesis = group.get("hypothesis")
    try:
        validated = _validate_hypothesis(hypothesis)
    except ValueError:
        item.reasons.add("ambiguous_evidence")
        item.evidence_state = "ambiguous"
        _apply_hypothesis_location(item, group)
        return item
    category, raw, missing, class_ambiguous = _class_name(validated.get("category"))
    item.category, item.raw_class = category, raw
    item.class_missing, item.class_ambiguous = missing, class_ambiguous
    item.claimed = True
    support, bad_support = _support_ids(validated.get("evidence_for"))
    against, bad_against = _support_ids(validated.get("evidence_against"))
    item.support_count = support
    if bad_support or bad_against:
        item.evidence_state = "ambiguous"
    elif against:
        item.evidence_state = "contradictory"
    elif support:
        item.evidence_state = "observed"
    else:
        item.evidence_state = "missing"
    controls = validated.get("missing_controls")
    item.missing_controls = (
        [entry for entry in controls if isinstance(entry, str)] if isinstance(controls, list) else []
    )
    summary = validated.get("summary")
    item.summary = summary if isinstance(summary, str) else ""
    _apply_hypothesis_location(item, group)
    state, detail = _session(group.get("session_observations"), claims)
    item.session_state, item.session_detail = state, detail
    return item


def _apply_hypothesis_location(item: _Item, group: Mapping[str, Any]) -> None:
    location = group.get("endpoint") if isinstance(group.get("endpoint"), dict) else None
    alternate = group.get("location") if isinstance(group.get("location"), dict) else None
    if location is not None and alternate is not None and location != alternate:
        item.location_conflict = True
    chosen = location or alternate or {}
    methods = chosen.get("methods") if isinstance(chosen, dict) else None
    method: object = chosen.get("method") if isinstance(chosen, dict) else None
    if method is None and isinstance(methods, list):
        method = methods if len(methods) != 1 else methods[0]
    host, endpoint, parsed_method, url, ambiguous, conflict = _location_parts(
        chosen.get("host") if isinstance(chosen, dict) else None,
        chosen.get("path_template")
        if isinstance(chosen, dict) and chosen.get("path_template") is not None
        else (chosen.get("endpoint") if isinstance(chosen, dict) else None),
        method,
        chosen.get("url") if isinstance(chosen, dict) else None,
    )
    item.host, item.endpoint, item.method, item.url = host, endpoint, parsed_method, url
    item.location_ambiguous = item.location_ambiguous or ambiguous
    item.location_conflict = item.location_conflict or conflict


def _surface_map(ledger: Mapping[str, Any]) -> dict[str, Mapping[str, Any]]:
    rows = ledger.get("surfaces")
    found: dict[str, Mapping[str, Any]] = {}
    if not isinstance(rows, list):
        return found
    for row in rows:
        if isinstance(row, dict) and isinstance(row.get("surface_id"), str):
            found[row["surface_id"]] = row
    return found


def _take_candidate(
    candidate: Mapping[str, Any], surfaces: Mapping[str, Mapping[str, Any]], seen: set[str], encounter: int
) -> _Item:
    candidate_id = candidate.get("candidate_id")
    fallback = (
        f"candidate:{candidate_id}"
        if isinstance(candidate_id, str) and _ID.fullmatch(candidate_id)
        else f"candidate:row-{encounter}"
    )
    item_id, duplicated = _label(candidate, fallback, seen)
    item = _Item(item_id, "candidate")
    if duplicated:
        item.reasons.add("ambiguous_origin")
    raised = candidate.get("raised_by")
    item.source = "evidence-ledger.json"
    item.record_index = encounter
    if not isinstance(raised, str) or not raised.strip():
        item.reasons.add("missing_origin")
    else:
        token = raised.strip().casefold()
        item.tool = token if token in _KNOWN_TOOLS else "bbtk"
        item.origin_tools = (item.tool,)
    state = candidate.get("state")
    if state == "confirmed":
        item.closed_review = True
        item.confirmation_claim = True
    elif state == "rejected":
        rejection = candidate.get("rejection") if isinstance(candidate.get("rejection"), dict) else {}
        reason = rejection.get("reason") if isinstance(rejection, dict) else None
        if reason == "out_of_scope":
            item.surface_out_of_scope = True
        elif reason == "duplicate":
            item.reasons.add("ambiguous_corroboration")
        elif reason in _REJECTION_CONTRADICTION or not isinstance(reason, str):
            item.evidence_state = "contradictory"
        else:
            item.closed_review = True
    elif state not in {"candidate", "requires_validation"}:
        item.reasons.add("ambiguous_evidence")
    category, raw, missing, class_ambiguous = _class_name(candidate.get("category"))
    item.category, item.raw_class = category, raw
    item.class_missing, item.class_ambiguous = missing, class_ambiguous
    item.claimed = True
    refs = candidate.get("evidence_refs")
    if not isinstance(refs, list):
        item.evidence_state = "ambiguous"
    else:
        usable = [ref for ref in refs if isinstance(ref, str) and ref]
        item.support_count = len(dict.fromkeys(usable))
        if item.evidence_state != "contradictory":
            item.evidence_state = "observed" if item.support_count else "missing"
    surface_id = candidate.get("surface_id")
    surface = surfaces.get(surface_id) if isinstance(surface_id, str) else None
    if surface is None:
        item.reasons.add("missing_location")
    else:
        if surface.get("status") == "out_of_scope":
            item.surface_out_of_scope = True
        ref = surface.get("ref")
        kind = surface.get("kind")
        if kind != "endpoint" or not isinstance(ref, str):
            item.location_ambiguous = True
        else:
            host, endpoint, method, url, ambiguous, conflict = _location_parts(None, None, None, ref)
            item.host, item.endpoint, item.method, item.url = host, endpoint, method, url
            item.location_ambiguous = ambiguous
            item.location_conflict = conflict
    title = candidate.get("title")
    item.summary = title if isinstance(title, str) else ""
    return item


def _finish_individual(item: _Item, rules: Sequence[ScopeRule]) -> None:
    _apply_session_reason(item)
    if item.location_conflict:
        item.reasons.add("contradictory_location")
    elif item.location_ambiguous:
        item.reasons.add("ambiguous_location")
    scope = _scope_state(_target(item), rules)
    if scope == "missing_scope":
        item.reasons.add("missing_scope")
    elif item.surface_out_of_scope or scope == "out_of_scope":
        if item.host or item.url:
            item.reasons.add("out_of_scope")
    if scope == "unchecked" and not item.location_ambiguous and not item.location_conflict:
        if item.host is None or item.endpoint is None:
            item.reasons.add("missing_location")
    if item.closed_review:
        item.reasons.add("closed_review")
    if item.class_missing or (not item.claimed and item.kind == "external"):
        item.reasons.add("missing_vulnerability_class")
    elif item.class_ambiguous:
        item.reasons.add("ambiguous_vulnerability_class")
    if item.evidence_state == "contradictory" or item.importer_status == "abstain":
        item.reasons.add("contradictory_evidence")
    elif item.evidence_state == "ambiguous":
        item.reasons.add("ambiguous_evidence")
    elif item.support_count <= 0 or item.evidence_state == "missing":
        if item.severity:
            item.reasons.add("severity_without_supporting_evidence")
        else:
            item.reasons.add("missing_evidence")
    if item.importer_status not in {None, "candidate", "needs_review", "abstain", "hypothesis"}:
        item.reasons.add("ambiguous_evidence")


def _location_key(item: _Item) -> tuple[str, str, str] | None:
    if item.host is None or item.endpoint is None or item.location_conflict or item.location_ambiguous:
        return None
    return (item.host, item.endpoint, item.method or "")


def _comparable(item: _Item) -> bool:
    return not item.reasons and item.category is not None and item.evidence_state == "observed"


def _relate(items: Sequence[_Item]) -> None:
    by_location: dict[tuple[str, str, str], list[_Item]] = {}
    for item in items:
        if not _comparable(item):
            continue
        key = _location_key(item)
        if key is not None:
            by_location.setdefault(key, []).append(item)
    for group in by_location.values():
        classes = {item.category for item in group}
        if len(classes) > 1:
            for item in group:
                item.reasons.add("contradictory_vulnerability_class")
    poisoned: set[tuple[str, str, str, str]] = set()
    for item in items:
        if "contradictory_evidence" not in item.reasons or item.category is None:
            continue
        key = _location_key(item)
        if key is not None:
            poisoned.add((*key, item.category))
    for item in items:
        if not _comparable(item) or item.category is None:
            continue
        key = _location_key(item)
        if key is not None and (*key, item.category) in poisoned:
            item.reasons.add("contradictory_corroboration")
    by_origin: dict[tuple[str, str, int], list[_Item]] = {}
    for item in items:
        if not _comparable(item):
            continue
        origin = item.origin_key
        if origin is not None:
            by_origin.setdefault(origin, []).append(item)
    for group in by_origin.values():
        if len(group) > 1:
            for item in group:
                item.reasons.add("ambiguous_corroboration")


def _primary(reasons: set[str]) -> str:
    for reason in ABSTAIN_REASONS:
        if reason in reasons:
            return reason
    raise RuntimeError("Abstain reason was not in the closed set.")


def _components(item: _Item, corroboration: int, session_points: int) -> dict[str, int]:
    category = item.category or "unknown"
    impact = _POTENTIAL_IMPACT[category]
    view = {
        "evidence_for": [{}] * item.support_count,
        "evidence_against": [],
        "missing_controls": item.missing_controls if item.missing_controls is not None else [],
    }
    raw = int(_score(view, impact, 0, 0))
    evidence_points = min(item.support_count, 3) * 10
    if item.missing_controls is None:
        control_points = 0
        base = max(0, raw - _CONTROL_BONUS)
    else:
        control_points = max(0, _CONTROL_BONUS - min(len(item.missing_controls), 5) * 2)
        base = raw
    impact_points = int(_IMPACT_POINTS[impact])
    total = max(0, min(100, base + corroboration + session_points))
    return {
        "evidence_points": evidence_points,
        "control_points": control_points,
        "impact_points": impact_points,
        "corroboration_points": corroboration,
        "session_points": session_points,
        "execution_penalty": 0,
        "severity_points": 0,
        "reused_score": raw,
        "priority_score": total,
    }


def _skill(category: str | None) -> SkillDefinition:
    name = _CATEGORY_TO_SKILL.get(category or "", "bugbounty-executor")
    return SKILL_REGISTRY[name]


def _clean_summary(value: str) -> str:
    try:
        cleaned = redact_text(value)
    except (TypeError, ValueError):
        return ""
    if not isinstance(cleaned, str):
        return ""
    return " ".join(cleaned.split())[:300]


def _factor_block(item: _Item, scope: str, components: dict[str, int] | None, sources: int) -> dict[str, Any]:
    if item.tool and item.source:
        origin_state = "contradictory" if "contradictory_origin" in item.reasons else "known"
        if item.kind == "hypothesis":
            origin_detail = f"bbtk hypothesis {item.item_id} in {item.source}."
        elif item.kind == "candidate":
            origin_detail = f"{item.tool} candidate {item.item_id} in {item.source}."
        else:
            origin_detail = f"{item.tool} record {item.record_index} in {item.source}."
    elif "ambiguous_origin" in item.reasons or "contradictory_origin" in item.reasons:
        origin_state = "contradictory" if "contradictory_origin" in item.reasons else "ambiguous"
        origin_detail = "Origin was not a single known source, so it was not guessed."
    else:
        origin_state = "missing"
        origin_detail = "Origin tool or source file was missing."
    if item.location_conflict:
        location_state = "contradictory"
        location_detail = "Location fields named more than one resource."
    elif item.location_ambiguous:
        location_state = "ambiguous"
        location_detail = "Location was present but not a single host and endpoint."
    elif item.host and item.endpoint:
        location_state = "known"
        location_detail = f"{item.method or 'method unset'} {item.host}{item.endpoint}; scope check {scope}."
    else:
        location_state = "missing"
        location_detail = "Host or endpoint was missing."
    if item.evidence_state == "observed":
        evidence_state = "observed"
        evidence_detail = f"{item.support_count} observed supporting record(s)."
    elif item.evidence_state == "contradictory":
        evidence_state = "contradictory"
        evidence_detail = "Supporting and contradicting evidence were both present."
    elif item.evidence_state == "ambiguous":
        evidence_state = "ambiguous"
        evidence_detail = "Evidence confidence was partial, ambiguous, or not a usable record list."
    else:
        evidence_state = "missing"
        evidence_detail = "No observed supporting evidence was available."
    if item.severity:
        evidence_detail += f" Tool severity {item.severity!r} was not used."
    else:
        evidence_detail += " No tool severity was supplied, and none was inferred."
    if "contradictory_vulnerability_class" in item.reasons:
        class_state = "contradictory"
        class_detail = "Another in-scope source named a different vulnerability class at this location."
        band = None
        impact_points = None
    elif item.category:
        class_state = "known"
        band = _POTENTIAL_IMPACT[item.category]
        impact_points = None if components is None else components["impact_points"]
        class_detail = (
            f"{item.category} has existing band {band}. "
            "The band is a category heuristic; impact has not been demonstrated."
        )
    elif item.class_ambiguous:
        class_state = "ambiguous"
        band = None
        impact_points = None
        class_detail = f"Class {item.raw_class!r} has no existing impact band, so none was invented."
    else:
        class_state = "missing"
        band = None
        impact_points = None
        class_detail = "No vulnerability class was available to compare."
    if "contradictory_corroboration" in item.reasons:
        corroboration_state = "contradictory"
        corroboration_detail = "An independent source at this location and class contradicted the claim."
    elif "ambiguous_corroboration" in item.reasons:
        corroboration_state = "ambiguous"
        corroboration_detail = "Origin identity collided, so the rows were not treated as independent sources."
    elif sources > 1:
        corroboration_state = "corroborated"
        corroboration_detail = f"{sources} independent origins agreed on this location and class."
    else:
        corroboration_state = "single_source"
        corroboration_detail = "No second origin agreed with this location and class."
    contradiction_state = (
        "present"
        if item.reasons
        & {
            "contradictory_origin",
            "contradictory_location",
            "contradictory_vulnerability_class",
            "contradictory_session",
            "contradictory_evidence",
            "contradictory_corroboration",
        }
        else "none"
    )
    return {
        "origin": {"state": origin_state, "tool": item.tool, "source": item.source, "detail": origin_detail},
        "location": {
            "state": location_state,
            "host": item.host,
            "endpoint": item.endpoint,
            "method": item.method,
            "scope": scope,
            "detail": location_detail,
        },
        "evidence_strength": {
            "state": evidence_state,
            "supporting_records": item.support_count,
            "points": None if components is None else components["evidence_points"],
            "severity_claimed": item.severity,
            "severity_used": False,
            "detail": evidence_detail,
        },
        "session_actor": {
            "state": item.session_state,
            "points": 0 if components is None else components["session_points"],
            "detail": item.session_detail,
        },
        "corroboration": {
            "state": corroboration_state,
            "independent_sources": sources,
            "points": 0 if components is None else components["corroboration_points"],
            "detail": corroboration_detail,
        },
        "vulnerability_class_impact": {
            "state": class_state,
            "class": item.category,
            "band": band,
            "points": impact_points,
            "basis": "category heuristic only; impact has not been demonstrated",
            "detail": class_detail,
        },
        "contradictions": {
            "state": contradiction_state,
            "detail": "A comparison field contradicted another source."
            if contradiction_state == "present"
            else "No contradictory comparison field was recorded.",
        },
    }


def _explain(decision: str, reason: str | None, rank: int | None, factors: Mapping[str, Any], score: int | None) -> str:
    if decision == "abstain":
        lead = f"Abstain ({reason})."
    else:
        lead = f"Rank {rank}. Advisory review order with priority score {score}."
    sentences = [
        lead,
        f"Origin: {factors['origin']['detail']}",
        f"Location: {factors['location']['detail']}",
        f"Evidence strength: {factors['evidence_strength']['detail']}",
        f"Session/actor: {factors['session_actor']['detail']}",
        f"Corroboration: {factors['corroboration']['detail']}",
        f"Vulnerability class: {factors['vulnerability_class_impact']['detail']}",
        f"Contradictions: {factors['contradictions']['detail']}",
        "This ranking does not confirm access or a vulnerability.",
    ]
    return " ".join(sentences)


def _row(
    item: _Item,
    *,
    decision: str,
    reason: str | None,
    rank: int | None,
    rules: Sequence[ScopeRule],
    components: dict[str, int] | None,
    sources: int,
    program: str,
    budget_status: str | None,
) -> dict[str, Any]:
    scope = _scope_state(_target(item), rules)
    factors = _factor_block(item, scope, components, sources)
    score = None if components is None else components["priority_score"]
    skill = _skill(item.category) if decision == "rank" and item.category else None
    ordered = [name for name in ABSTAIN_REASONS if name in item.reasons]
    return {
        "item_id": item.item_id,
        "kind": item.kind,
        "decision": decision,
        "reason": reason,
        "reasons": ordered,
        "rank": rank,
        "research_priority": None if score is None else _priority(score),
        "priority_score": score,
        "score_components": components,
        "access_confirmed": False,
        "vulnerabilities_confirmed": 0,
        "demonstrated_severity": "not_assessed",
        "finding_confirmed": False,
        "severity_used_in_score": False,
        "human_approval_required": True,
        "execution_status": "not_started_requires_human_approval",
        "budget_status": budget_status,
        "scope_status": scope,
        "summary": _clean_summary(item.summary),
        "factors": factors,
        "explanation": _explain(decision, reason, rank, factors, score),
        "suggested_check": None
        if skill is None
        else {
            "skill": skill.name,
            "command_template": skill.commands[0].format(program=program),
            "estimated_request_units": skill.budget_cost,
            "approval_required": True,
            "note": "Template only. The command is not executed.",
        },
    }


def _collect(
    *,
    external: Sequence[Mapping[str, Any]] | None,
    hypotheses: Mapping[str, Any] | None,
    ledger: Mapping[str, Any] | None,
    program: str,
) -> tuple[list[_Item], int]:
    items: list[_Item] = []
    seen: set[str] = set()
    claims = [0]
    encounter = 0
    documents: list[Mapping[str, Any]] = []
    if external is not None:
        if not isinstance(external, Sequence) or isinstance(external, (str, bytes)):
            raise ValueError("External findings must be a list.")
        for entry in external:
            if isinstance(entry, Mapping) and isinstance(entry.get("findings"), list):
                documents.extend(finding for finding in entry["findings"] if isinstance(finding, Mapping))
                for finding in entry["findings"]:
                    if not isinstance(finding, Mapping):
                        encounter += 1
                        item = _Item(f"external:invalid:{encounter}", "external")
                        item.reasons.add("ambiguous_evidence")
                        items.append(item)
            elif isinstance(entry, Mapping):
                documents.append(entry)
            else:
                encounter += 1
                item = _Item(f"external:invalid:{encounter}", "external")
                item.reasons.add("ambiguous_evidence")
                items.append(item)
        for finding in documents:
            encounter += 1
            items.append(_take_external(finding, seen, encounter))
    if hypotheses is not None:
        if not isinstance(hypotheses, Mapping) or hypotheses.get("type") != "ai-hypotheses":
            raise ValueError("Input must be the JSON output from `bbtk ai hypotheses`.")
        groups = hypotheses.get("groups")
        if not isinstance(groups, list):
            raise ValueError("Input must be the JSON output from `bbtk ai hypotheses`.")
        if len(groups) > MAX_ITEMS:
            raise ValueError(f"Review queue exceeds the {MAX_ITEMS}-item limit.")
        for group in groups:
            encounter += 1
            if not isinstance(group, Mapping):
                item = _Item(f"hypothesis:invalid:{encounter}", "hypothesis")
                item.reasons.add("ambiguous_evidence")
                items.append(item)
                continue
            items.append(_take_hypothesis(group, seen, encounter, claims))
    if ledger is not None:
        if not isinstance(ledger, Mapping) or ledger.get("schema_version") != "bbtk-evidence-ledger/1":
            raise ValueError("Ledger input must be a bbtk-evidence-ledger/1 document.")
        if ledger.get("program") != program:
            raise ValueError("Ledger belongs to another program.")
        surfaces = _surface_map(ledger)
        candidates = ledger.get("candidates")
        if not isinstance(candidates, list):
            raise ValueError("Ledger candidates must be a list.")
        for candidate in candidates:
            encounter += 1
            if not isinstance(candidate, Mapping):
                item = _Item(f"candidate:invalid:{encounter}", "candidate")
                item.reasons.add("ambiguous_evidence")
                items.append(item)
                continue
            items.append(_take_candidate(candidate, surfaces, seen, encounter))
    if len(items) > MAX_ITEMS:
        raise ValueError(f"Review queue exceeds the {MAX_ITEMS}-item limit.")
    return items, claims[0]


def prioritize_review(
    program: str,
    scope_rules: Sequence[str],
    max_tests: int,
    *,
    external: Sequence[Mapping[str, Any]] | None = None,
    hypotheses: Mapping[str, Any] | None = None,
    ledger: Mapping[str, Any] | None = None,
    requests_per_second: float = 1.0,
    dry_run: bool = True,
) -> dict[str, Any]:
    """Rank a local review queue. Abstain instead of guessing. Confirm nothing."""
    _program(program)
    _budget(max_tests)
    rate = _rate(requests_per_second)
    rules = _rules(scope_rules)
    items, ignored_claims = _collect(external=external, hypotheses=hypotheses, ledger=ledger, program=program)
    for item in items:
        _finish_individual(item, rules)
        if item.confirmation_claim:
            ignored_claims += 1
    _relate(items)
    rankable = [item for item in items if not item.reasons]
    source_counts: dict[tuple[str, str, str, str], set[tuple[str, str]]] = {}
    for item in rankable:
        key = _location_key(item)
        source = item.source_key
        if key is None or source is None or item.category is None:
            continue
        source_counts.setdefault((*key, item.category), set()).add(source)
    scored: list[tuple[_Item, dict[str, int], int]] = []
    for item in rankable:
        key = _location_key(item)
        sources = 0
        if key is not None and item.category is not None:
            sources = len(source_counts.get((*key, item.category), set()))
        corroboration = CORROBORATION_POINTS if sources > 1 else 0
        session_points = SESSION_CLARITY_POINTS if item.session_state == "clear" else 0
        scored.append((item, _components(item, corroboration, session_points), sources))
    scored.sort(key=lambda row: (-row[1]["priority_score"], row[0].item_id))
    remaining = max_tests
    ranked: list[dict[str, Any]] = []
    for index, (item, components, sources) in enumerate(scored, start=1):
        skill = _skill(item.category)
        cost = int(skill.budget_cost)
        if cost <= remaining:
            remaining -= cost
            budget_status = "within_budget"
        else:
            budget_status = "deferred_over_budget"
        ranked.append(
            _row(
                item,
                decision="rank",
                reason=None,
                rank=index,
                rules=rules,
                components=components,
                sources=sources,
                program=program,
                budget_status=budget_status,
            )
        )
    abstained: list[dict[str, Any]] = []
    for item in items:
        if not item.reasons:
            continue
        abstained.append(
            _row(
                item,
                decision="abstain",
                reason=_primary(item.reasons),
                rank=None,
                rules=rules,
                components=None,
                sources=1,
                program=program,
                budget_status=None,
            )
        )
    abstained.sort(key=lambda row: (str(row["reason"]), str(row["item_id"])))
    missing = [
        "Verify program authorization and the scope file before any later HTTP check.",
        "Ranking is advisory. access_confirmed stays false and vulnerabilities_confirmed stays 0.",
    ]
    if not rules:
        missing.append("No scope rules were loaded. Every item abstains with missing_scope.")
    if not items:
        missing.append("No external findings, hypotheses, or candidates were supplied.")
    return {
        "schema": SCHEMA,
        "type": "review-prioritization",
        "notice": "Advisory review order only. This is not confirmation and no request was sent.",
        "program": program,
        "status": "review_required" if ranked else "insufficient_input",
        "dry_run": dry_run,
        "access_confirmed": False,
        "vulnerabilities_confirmed": 0,
        "confirmations_created": 0,
        "confirmation_claims_ignored": ignored_claims,
        "network_requests_sent": 0,
        "ollama_calls": 0,
        "human_approval_required": True,
        "scope_validated": False,
        "scope_rules_loaded": len(rules),
        "max_tests": max_tests,
        "estimated_budget_remaining": remaining,
        "rate_limit": {
            "requests_per_second": rate,
            "max_tests": max_tests,
            "requests_sent": 0,
            "note": "The rate limit and test budget are recorded and not spent. This command sends no requests.",
        },
        "items_seen": len(items),
        "ranked_count": len(ranked),
        "abstained_count": len(abstained),
        "missing_inputs": missing,
        "ranked": ranked,
        "abstained": abstained,
    }


def prioritize_review_files(
    program: str,
    scope_file: Path,
    max_tests: int,
    *,
    external_paths: Sequence[Path] = (),
    hypotheses_path: Path | None = None,
    ledger_path: Path | None = None,
    requests_per_second: float = 1.0,
    dry_run: bool = True,
) -> dict[str, Any]:
    """Load local JSON and scope text, then rank without writing or sending requests."""
    external_documents: list[Mapping[str, Any]] = []
    for path in external_paths:
        loaded = _read_json(path)
        if isinstance(loaded, list):
            for entry in loaded:
                if isinstance(entry, Mapping):
                    external_documents.append(entry)
                else:
                    external_documents.append({"status": "not-an-object"})
        elif isinstance(loaded, Mapping):
            external_documents.append(loaded)
        else:
            raise ValueError("External input must be a JSON object or list.")
    hypotheses = _read_json(hypotheses_path) if hypotheses_path is not None else None
    ledger = _read_json(ledger_path) if ledger_path is not None else None
    if hypotheses is not None and not isinstance(hypotheses, Mapping):
        raise ValueError("Input must be the JSON output from `bbtk ai hypotheses`.")
    if ledger is not None and not isinstance(ledger, Mapping):
        raise ValueError("Ledger input must be a bbtk-evidence-ledger/1 document.")
    return prioritize_review(
        program,
        load_scope_lines(scope_file),
        max_tests,
        external=external_documents,
        hypotheses=hypotheses,
        ledger=ledger,
        requests_per_second=requests_per_second,
        dry_run=dry_run,
    )


def external_schema() -> str:
    """Return the imported finding schema this ranker reads. Present for traceability."""
    return EXTERNAL_SCHEMA
