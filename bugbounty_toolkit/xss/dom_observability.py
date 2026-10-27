"""DOM observability v3 for disposable loopback laboratories.

Additive to DOM local v2 (``dom_local.run_dom_local`` and
``PlaywrightExecutionChecker``). This module does not change those results.
It records a stricter observation:

* hooks are modeled as installed before page script when generation is ``v3``
* a marker sitting in the URL is ``source_available``, never ``source_observed``
* ``innerHTML`` (or any other sink) is not execution
* same-origin frames can be read with the page's own access
* isolated / cross-origin frames stay ``unsupported`` (no Same-Origin Policy bypass)
* ``finding_confirmed`` is always false

Offline traces and the live loopback observer in ``dom_observer`` share
``decide_outcome`` and ``assemble_record`` so the integrity fields match.
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Mapping, Sequence

from .evidence_record import DomObservation, assert_minimized, classify_dom_state

SCHEMA = "bbtk.dom-observability.v3"
OUTCOMES = ("observed", "not_observed", "inconclusive", "unsupported")
INSTRUMENTATION_STATUSES = (
    "installed_before_page",
    "installed_late",
    "partial",
    "failed",
    "unsupported",
)
FRAME_RELATIONS = (
    "main",
    "same_origin",
    "isolated",
    "no_access",
    "missing",
    "unmounted",
    "swapped",
)
EXECUTION_MECHANISMS = ("marker_assignment", "dialog")

# PlaywrightExecutionChecker local_only wait_for_function cap (milliseconds).
V2_ASYNC_BUDGET_MS = 300
# Bounded window for async sinks after navigation start. Not an exploit delay.
V3_ASYNC_BUDGET_MS = 1500

V2_HOOKED_SINKS = frozenset(
    {
        "innerHTML",
        "outerHTML",
        "insertAdjacentHTML",
        "document.write",
        "document.writeln",
    }
)
V3_HOOKED_SINKS = V2_HOOKED_SINKS | frozenset(
    {
        "createContextualFragment",
        "eval",
        "setHTML",
        "Function",
        "iframe.srcdoc",
    }
)
# Assignments that must never be reported as script sinks or execution.
NON_SCRIPT_SINKS = frozenset({"textContent", "innerText", "textContent.setter"})

_MARKER_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
_EVENT_TYPES = frozenset(
    {
        "document_start",
        "domcontentloaded",
        "inline_script",
        "source_read",
        "sink",
        "execution",
        "sanitize",
        "csp_block",
        "instrumentation_error",
        "fetch",
        "event",
        "frame_removed",
        "navigation_partial",
        "property_write",
        "hook_failed",
    }
)
_T_REL_KEYS = (
    "navigation_start",
    "instrumentation_installed",
    "source_read",
    "sink_call",
    "execution",
    "observation_end",
)


def validate_marker(marker: str) -> str:
    """Accept only a short inert token. The hook script JSON-encodes it."""
    if not isinstance(marker, str) or _MARKER_RE.fullmatch(marker) is None:
        raise ValueError("DOM marker must be 1–64 characters from [A-Za-z0-9_-].")
    return marker


def early_hook_script(marker: str) -> str:
    """JavaScript installed with ``context.add_init_script`` before page code.

    The script records source reads and sink calls. It does not assign
    ``window.__bbtk_xss_marker``, does not call ``eval`` on the marker, and does
    not turn ``textContent`` into HTML.
    """
    token = validate_marker(marker)
    return _EARLY_HOOK_TEMPLATE.replace("__BBTK_MARKER_JSON__", json.dumps(token))


def frame_policy(frame: Mapping[str, Any]) -> str:
    """Return ``observe``, ``unsupported``, or ``inconclusive``.

    Cross-origin and sandboxed opaque frames are ``unsupported``. Callers must
    not fall back to a debugger-protocol read of those frames.
    """
    relation = str(frame.get("relation") or "")
    if relation not in FRAME_RELATIONS:
        raise ValueError(f"Unknown frame relation: {relation}")
    sandbox = frame.get("sandbox")
    if isinstance(sandbox, str) and "allow-same-origin" not in sandbox.split():
        return "unsupported"
    if relation in {"no_access", "isolated"}:
        return "unsupported"
    if relation in {"missing", "unmounted"}:
        return "inconclusive"
    accessible = bool(frame.get("accessible", relation == "main"))
    if relation in {"main", "same_origin", "swapped"} and accessible:
        return "observe"
    if not accessible:
        return "unsupported"
    return "inconclusive"


def decide_outcome(
    *,
    policy: str,
    instrumentation_status: str,
    source_refs: Sequence[str],
    sink_refs: Sequence[str],
    executed: bool,
    sanitized: bool,
    csp_blocked: bool,
    partial_navigation_unreliable: bool,
    dropped_sink_without_signal: bool,
) -> str:
    """Map signals to an observability outcome. Sinks alone are not execution.

    Events outside the generation's window are invisible. They do not upgrade a
    quiet window into ``inconclusive``; the observer did not see them.
    """
    if policy == "unsupported":
        return "unsupported"
    if policy == "inconclusive":
        return "inconclusive"
    if instrumentation_status == "failed" and not executed:
        return "inconclusive"
    if partial_navigation_unreliable or dropped_sink_without_signal:
        return "inconclusive"
    if executed or sink_refs or source_refs or sanitized or csp_blocked:
        return "observed"
    return "not_observed"


def assemble_record(
    *,
    case_id: str,
    navigation_id: str,
    frame_id: str,
    frame_relation: str,
    instrumentation_status: str,
    source_available: bool,
    source_refs: Sequence[str],
    property_reads: Sequence[str],
    sink_refs: Sequence[str],
    executed: bool,
    execution_mechanism: str | None,
    sanitized: bool,
    csp_blocked: bool,
    t_rel_ms: Mapping[str, int | None],
    limitations: Sequence[str],
    outcome: str,
    external_requests: int,
    technical_errors: Sequence[str] | None = None,
) -> dict[str, Any]:
    """Build one integrity-checked observation. ``finding_confirmed`` is false."""
    if outcome not in OUTCOMES:
        raise ValueError(f"Unknown outcome: {outcome}")
    if instrumentation_status not in INSTRUMENTATION_STATUSES:
        raise ValueError(f"Unknown instrumentation status: {instrumentation_status}")
    if frame_relation not in FRAME_RELATIONS:
        raise ValueError(f"Unknown frame relation: {frame_relation}")
    if executed and execution_mechanism not in EXECUTION_MECHANISMS:
        raise ValueError("Execution requires marker_assignment or dialog evidence.")
    if not executed:
        execution_mechanism = None
    if outcome == "unsupported" and (source_refs or sink_refs or executed):
        raise ValueError("unsupported observations cannot carry source, sink, or execution claims.")
    source_list = sorted({str(item) for item in source_refs})
    sink_list = sorted({str(item) for item in sink_refs if str(item) not in NON_SCRIPT_SINKS})
    reads = sorted({str(item) for item in property_reads})
    source_observed = bool(source_list)
    if executed and execution_mechanism == "innerHTML":
        raise ValueError("Refusing to treat innerHTML as an execution mechanism.")
    dom_state = classify_dom_state(
        DomObservation(
            source_observed=source_observed,
            sinks=tuple(sink_list),
            marker_executed=executed,
            sanitized=sanitized and not executed,
            csp_blocked=csp_blocked and not executed,
            browser_failed=instrumentation_status == "failed" and not executed,
        )
    )
    if outcome in {"unsupported", "not_observed"} and dom_state == "source_observed" and not source_observed:
        dom_state = "inconclusive"
    times = {key: t_rel_ms.get(key) for key in _T_REL_KEYS}
    if times["navigation_start"] is None:
        times["navigation_start"] = 0
    record: dict[str, Any] = {
        "schema": SCHEMA,
        "case_id": case_id,
        "navigation_id": navigation_id,
        "frame_id": frame_id,
        "frame_relation": frame_relation,
        "t_rel_ms": times,
        "instrumentation_status": instrumentation_status,
        "source_available": bool(source_available),
        "source_observed": source_observed,
        "source_refs": source_list,
        "sink_refs": sink_list,
        "property_reads": reads,
        "execution_evidence": {
            "executed": executed,
            "mechanism": execution_mechanism,
            "claimed_from_innerhtml_alone": False,
        },
        "csp_flags": {"csp_blocked": bool(csp_blocked) and not executed, "restrictive_for_inline": None},
        "sanitized": bool(sanitized) and not executed,
        "outcome": outcome,
        "dom_state": dom_state,
        "limitations": sorted({str(item) for item in limitations}),
        "technical_errors": [str(item)[:200] for item in list(technical_errors or [])[:5]],
        "external_requests": int(external_requests),
        "finding_confirmed": False,
        "human_review_required": True,
    }
    record["artifact_hash"] = artifact_hash(record)
    assert_observation_integrity(record)
    return record


def artifact_hash(record: Mapping[str, Any]) -> str:
    body = {key: value for key, value in record.items() if key != "artifact_hash"}
    raw = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def assert_observation_integrity(record: Mapping[str, Any]) -> None:
    """Raise if an observation is missing integrity fields or confirms a finding."""
    required = (
        "schema",
        "case_id",
        "navigation_id",
        "frame_id",
        "frame_relation",
        "t_rel_ms",
        "instrumentation_status",
        "source_available",
        "source_observed",
        "source_refs",
        "sink_refs",
        "property_reads",
        "execution_evidence",
        "csp_flags",
        "outcome",
        "dom_state",
        "artifact_hash",
        "finding_confirmed",
        "limitations",
    )
    missing = [key for key in required if key not in record]
    if missing:
        raise ValueError(f"Observation missing integrity fields: {', '.join(missing)}")
    if record.get("schema") != SCHEMA:
        raise ValueError("Unexpected observability schema.")
    if record.get("finding_confirmed") is not False:
        raise ValueError("finding_confirmed must stay false.")
    if record.get("outcome") not in OUTCOMES:
        raise ValueError("Invalid outcome.")
    evidence = record.get("execution_evidence")
    if not isinstance(evidence, Mapping):
        raise ValueError("execution_evidence must be an object.")
    if evidence.get("claimed_from_innerhtml_alone") is not False:
        raise ValueError("Execution must not be claimed from innerHTML alone.")
    if evidence.get("executed") and evidence.get("mechanism") not in EXECUTION_MECHANISMS:
        raise ValueError("Executed observations need marker or dialog evidence.")
    if record.get("source_observed") and not list(record.get("source_refs") or []):
        raise ValueError("source_observed requires a source ref; URL presence is not enough.")
    if not record.get("source_observed") and list(record.get("source_refs") or []):
        raise ValueError("source refs require source_observed.")
    if record.get("outcome") == "unsupported":
        evidence_now = record.get("execution_evidence")
        if list(record.get("source_refs") or []) or list(record.get("sink_refs") or []):
            raise ValueError("unsupported observations cannot carry source or sink refs.")
        if isinstance(evidence_now, Mapping) and evidence_now.get("executed"):
            raise ValueError("unsupported observations cannot claim execution.")
    times = record.get("t_rel_ms")
    if not isinstance(times, Mapping) or any(key not in times for key in _T_REL_KEYS):
        raise ValueError("t_rel_ms is missing relative timestamps.")
    flags = record.get("csp_flags")
    if not isinstance(flags, Mapping) or "csp_blocked" not in flags:
        raise ValueError("csp_flags.csp_blocked is required.")
    if artifact_hash(record) != record.get("artifact_hash"):
        raise ValueError("artifact_hash does not match the observation.")
    assert_minimized(record)


def classify_case(case: Mapping[str, Any], *, generation: str = "v3") -> dict[str, Any]:
    """Classify one scripted laboratory trace as v2 or v3 would observe it."""
    if generation not in {"v2", "v3"}:
        raise ValueError("generation must be v2 or v3.")
    normalized = _normalize_case(case)
    frame_records: list[dict[str, Any]] = []
    for frame in normalized["frames"]:
        frame_records.append(_classify_frame(normalized, frame, generation))
    focus_id = normalized["focus_frame_id"]
    focus = next((item for item in frame_records if item["frame_id"] == focus_id), None)
    if focus is None:
        raise ValueError(f"focus_frame_id {focus_id} is not in the trace.")
    legacy = _legacy_v2(normalized) if generation == "v2" else None
    external = sum(int(item["external_requests"]) for item in frame_records)
    limitations = sorted({item for record in frame_records for item in record["limitations"]})
    parent: dict[str, Any] = {
        "schema": SCHEMA,
        "case_id": focus["case_id"],
        "navigation_id": focus["navigation_id"],
        "frame_id": focus["frame_id"],
        "frame_relation": focus["frame_relation"],
        "t_rel_ms": focus["t_rel_ms"],
        "instrumentation_status": focus["instrumentation_status"],
        "source_available": focus["source_available"],
        "source_observed": focus["source_observed"],
        "source_refs": focus["source_refs"],
        "sink_refs": focus["sink_refs"],
        "property_reads": focus["property_reads"],
        "execution_evidence": focus["execution_evidence"],
        "csp_flags": focus["csp_flags"],
        "sanitized": focus["sanitized"],
        "outcome": focus["outcome"],
        "dom_state": focus["dom_state"],
        "limitations": limitations,
        "technical_errors": focus["technical_errors"],
        "external_requests": external,
        "finding_confirmed": False,
        "human_review_required": True,
        "generation": generation,
        "frames": frame_records,
        "legacy_v2": legacy,
    }
    parent["artifact_hash"] = artifact_hash(parent)
    assert_observation_integrity(parent)
    return parent


def _normalize_case(case: Mapping[str, Any]) -> dict[str, Any]:
    frames = case.get("frames")
    if not isinstance(frames, list) or not frames:
        raise ValueError("Trace requires at least one frame.")
    instrumentation = str(case.get("v2_instrumentation") or "init")
    if instrumentation not in {"init", "late"}:
        raise ValueError("v2_instrumentation must be init or late.")
    normalized_frames: list[dict[str, Any]] = []
    for frame in frames:
        if not isinstance(frame, Mapping):
            raise ValueError("Frame entries must be objects.")
        events = frame.get("events") or []
        if not isinstance(events, list):
            raise ValueError("Frame events must be a list.")
        checked: list[dict[str, Any]] = []
        for event in events:
            if not isinstance(event, Mapping) or "type" not in event:
                raise ValueError("Event must be an object with a type.")
            if str(event["type"]) not in _EVENT_TYPES:
                raise ValueError(f"Unknown event type: {event['type']}")
            checked.append(dict(event))
        normalized_frames.append(
            {
                "frame_id": str(frame["frame_id"]),
                "relation": str(frame["relation"]),
                "accessible": frame.get("accessible"),
                "sandbox": frame.get("sandbox"),
                "marker_in_url": frame.get("marker_in_url"),
                "events": checked,
            }
        )
    focus = str(case.get("focus_frame_id") or normalized_frames[0]["frame_id"])
    return {
        "case_id": str(case["case_id"]),
        "navigation_id": str(case["navigation_id"]),
        "focus_frame_id": focus,
        "marker_in_url": bool(case.get("marker_in_url", False)),
        "declared_interactions": [str(item) for item in case.get("declared_interactions") or []],
        "v2_instrumentation": instrumentation,
        "frames": normalized_frames,
    }


def _performed(case: Mapping[str, Any], generation: str) -> set[str]:
    declared = set(case["declared_interactions"])
    if generation == "v3":
        return declared
    # DOM local v2 clicks only a reflected javascript: link, never lab buttons.
    return {"javascript_link"} if "javascript_link" in declared else set()


def _dcl_ms(events: Sequence[Mapping[str, Any]]) -> int:
    for event in events:
        if event.get("type") == "domcontentloaded":
            return _ms(event.get("t_ms", 0))
    return 0


def _ms(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError("t_ms must be a number.")
    return int(round(float(value)))


def _requires_ok(event: Mapping[str, Any], performed: set[str]) -> bool:
    raw = event.get("requires") or []
    if not isinstance(raw, list):
        raise ValueError("event.requires must be a list.")
    return all(str(item) in performed for item in raw)


def _budget_end(case: Mapping[str, Any], events: Sequence[Mapping[str, Any]], generation: str) -> int:
    if generation == "v2":
        return _dcl_ms(events) + V2_ASYNC_BUDGET_MS
    return V3_ASYNC_BUDGET_MS


def _hook_time(case: Mapping[str, Any], events: Sequence[Mapping[str, Any]], generation: str) -> int:
    if generation == "v3":
        return 0
    if case["v2_instrumentation"] == "late":
        return _dcl_ms(events)
    return 0


def _in_window(
    event: Mapping[str, Any], hook_time: int, budget_end: int, performed: set[str], *, gate_hook: bool
) -> bool:
    if not _requires_ok(event, performed):
        return False
    stamp = _ms(event.get("t_ms", 0))
    if stamp > budget_end:
        return False
    if gate_hook and stamp < hook_time:
        return False
    return True


def _source_available(case: Mapping[str, Any], frame: Mapping[str, Any]) -> bool:
    if frame.get("marker_in_url") is not None:
        return bool(frame.get("marker_in_url"))
    if frame["relation"] == "main":
        return bool(case["marker_in_url"])
    return False


def _status_for(case: Mapping[str, Any], generation: str) -> str:
    if generation == "v2" and case["v2_instrumentation"] == "late":
        return "installed_late"
    return "installed_before_page"


def _empty_frame(
    case: Mapping[str, Any],
    frame: Mapping[str, Any],
    *,
    generation: str,
    outcome: str,
    status: str,
    limitations: Sequence[str],
    budget_end: int,
) -> dict[str, Any]:
    return assemble_record(
        case_id=case["case_id"],
        navigation_id=case["navigation_id"],
        frame_id=frame["frame_id"],
        frame_relation=frame["relation"],
        instrumentation_status=status,
        source_available=False,
        source_refs=(),
        property_reads=(),
        sink_refs=(),
        executed=False,
        execution_mechanism=None,
        sanitized=False,
        csp_blocked=False,
        t_rel_ms={
            "navigation_start": 0,
            "instrumentation_installed": None if status in {"failed", "unsupported"} else 0,
            "source_read": None,
            "sink_call": None,
            "execution": None,
            "observation_end": 0 if outcome != "not_observed" else budget_end,
        },
        limitations=limitations,
        outcome=outcome,
        external_requests=0,
    )


def _classify_frame(case: Mapping[str, Any], frame: Mapping[str, Any], generation: str) -> dict[str, Any]:
    policy = frame_policy(frame)
    events: list[dict[str, Any]] = list(frame["events"])
    performed = _performed(case, generation)
    hook_time = _hook_time(case, events, generation)
    budget_end = _budget_end(case, events, generation)
    status = _status_for(case, generation)

    # DOM local v2 never reads child frames. Same-origin signals are missed;
    # opaque frames stay unsupported rather than being opened via the debugger.
    if generation == "v2" and frame["relation"] != "main":
        if policy == "unsupported":
            return _empty_frame(
                case,
                frame,
                generation=generation,
                outcome="unsupported",
                status="unsupported",
                limitations=["sop_not_bypassed"],
                budget_end=budget_end,
            )
        if policy == "inconclusive":
            limitation = "frame_unmounted" if frame["relation"] == "unmounted" else "frame_missing"
            return _empty_frame(
                case,
                frame,
                generation=generation,
                outcome="inconclusive",
                status="unsupported",
                limitations=[limitation],
                budget_end=budget_end,
            )
        return _empty_frame(
            case,
            frame,
            generation=generation,
            outcome="not_observed",
            status=status,
            limitations=["frame_not_in_v2_view"],
            budget_end=budget_end,
        )

    if policy == "unsupported":
        return _empty_frame(
            case,
            frame,
            generation=generation,
            outcome="unsupported",
            status="unsupported",
            limitations=["sop_not_bypassed"],
            budget_end=budget_end,
        )
    if policy == "inconclusive":
        limitation = "frame_unmounted" if frame["relation"] == "unmounted" else "frame_missing"
        return _empty_frame(
            case,
            frame,
            generation=generation,
            outcome="inconclusive",
            status="unsupported",
            limitations=[limitation],
            budget_end=budget_end,
        )

    limitations: list[str] = []
    visible_sinks: list[tuple[int, str]] = []
    visible_reads: list[tuple[int, str]] = []
    visible_exec: list[tuple[int, str]] = []
    sanitized = False
    csp_blocked = False
    external = 0
    failed = False
    dropped_sink = False
    partial_unreliable = False
    never_fired = False
    tech: list[str] = []
    failed_hooks = {
        str(event.get("sink") or "")
        for event in events
        if event.get("type") == "hook_failed" and _in_window(event, 0, budget_end, performed, gate_hook=False)
    }
    if failed_hooks:
        status = "partial"
    hooked = V3_HOOKED_SINKS if generation == "v3" else V2_HOOKED_SINKS

    for event in events:
        etype = str(event["type"])
        if etype == "instrumentation_error":
            failed = True
            status = "failed"
            detail = event.get("detail")
            if isinstance(detail, str) and detail:
                tech.append(detail[:200])
            limitations.append("instrumentation_failed")
        elif etype == "fetch" and _requires_ok(event, performed):
            if not bool(event.get("loopback", False)):
                external += 1
        elif etype == "event" and event.get("fired") is False:
            never_fired = True
        elif (
            etype == "csp_block"
            and generation == "v3"
            and _in_window(event, hook_time, budget_end, performed, gate_hook=False)
        ):
            csp_blocked = True
        elif (
            etype == "sanitize"
            and generation == "v3"
            and _in_window(event, hook_time, budget_end, performed, gate_hook=True)
        ):
            sanitized = True
        elif (
            etype == "source_read"
            and generation == "v3"
            and _in_window(event, hook_time, budget_end, performed, gate_hook=True)
        ):
            visible_reads.append((_ms(event.get("t_ms", 0)), str(event.get("api") or "source")))
        elif etype == "sink" and _in_window(event, hook_time, budget_end, performed, gate_hook=True):
            name = str(event.get("sink") or "")
            if name in NON_SCRIPT_SINKS or name not in hooked:
                continue
            if name in failed_hooks:
                dropped_sink = True
                continue
            raw = bool(event.get("raw_marker", True))
            escaped = bool(event.get("escaped_marker", False))
            # v2's string-includes hook does not see a sanitized value.
            if generation == "v2" and not raw:
                continue
            if escaped and not raw:
                sanitized = True
            if raw or escaped:
                visible_sinks.append((_ms(event.get("t_ms", 0)), name))
        elif etype == "execution" and _in_window(event, 0, budget_end, performed, gate_hook=False):
            event_mechanism = str(event.get("mechanism") or "")
            if event_mechanism in EXECUTION_MECHANISMS:
                visible_exec.append((_ms(event.get("t_ms", 0)), event_mechanism))

    partials = [
        event
        for event in events
        if event["type"] == "navigation_partial" and _in_window(event, 0, budget_end, performed, gate_hook=False)
    ]
    if partials:
        boundary = min(_ms(event.get("t_ms", 0)) for event in partials)
        after = _later(visible_reads, boundary) + _later(visible_sinks, boundary) + _later(visible_exec, boundary)
        if not after:
            partial_unreliable = True
            limitations.append("partial_navigation")
            visible_reads, visible_sinks, visible_exec = [], [], []
            sanitized = False
            csp_blocked = False
    if failed and not visible_exec:
        visible_reads, visible_sinks = [], []
        sanitized = False
        csp_blocked = False
    if never_fired and not visible_reads and not visible_sinks and not visible_exec:
        limitations.append("event_never_fired")
    if dropped_sink and not visible_reads and not visible_sinks and not visible_exec:
        limitations.append("hook_failed")
    if any(name == "innerHTML" for _, name in visible_sinks) and not visible_exec:
        limitations.append("execution_not_inferred_from_innerhtml")

    source_available = _source_available(case, frame)
    if source_available and not visible_reads:
        limitations.append("source_in_url_is_not_a_read")
    executed = bool(visible_exec)
    mechanism: str | None = visible_exec[0][1] if executed else None
    outcome = decide_outcome(
        policy="observe",
        instrumentation_status=status,
        source_refs=[name for _, name in visible_reads],
        sink_refs=[name for _, name in visible_sinks],
        executed=executed,
        sanitized=sanitized,
        csp_blocked=csp_blocked,
        partial_navigation_unreliable=partial_unreliable,
        dropped_sink_without_signal=dropped_sink and not visible_reads and not visible_sinks and not executed,
    )
    if outcome == "inconclusive" and partial_unreliable:
        visible_reads, visible_sinks, visible_exec = [], [], []
        executed = False
        mechanism = None
        sanitized = False
        csp_blocked = False
    if outcome == "inconclusive" and status == "failed":
        visible_reads, visible_sinks = [], []
        sanitized = False
        csp_blocked = False
    times: dict[str, int | None] = {
        "navigation_start": 0,
        "instrumentation_installed": None if status in {"failed", "unsupported"} else hook_time,
        "source_read": min((stamp for stamp, _ in visible_reads), default=None),
        "sink_call": min((stamp for stamp, _ in visible_sinks), default=None),
        "execution": min((stamp for stamp, _ in visible_exec), default=None) if executed else None,
        "observation_end": budget_end,
    }
    return assemble_record(
        case_id=case["case_id"],
        navigation_id=case["navigation_id"],
        frame_id=frame["frame_id"],
        frame_relation=frame["relation"],
        instrumentation_status=status,
        source_available=source_available,
        source_refs=[name for _, name in visible_reads],
        property_reads=[name for _, name in visible_reads],
        sink_refs=[name for _, name in visible_sinks],
        executed=executed,
        execution_mechanism=mechanism,
        sanitized=sanitized,
        csp_blocked=csp_blocked,
        t_rel_ms=times,
        limitations=limitations,
        outcome=outcome,
        external_requests=external,
        technical_errors=tech,
    )


def _later(pairs: Sequence[tuple[int, str]], boundary: int) -> list[tuple[int, str]]:
    return [pair for pair in pairs if pair[0] > boundary]


def _legacy_v2(case: Mapping[str, Any]) -> dict[str, Any]:
    """DOM local v2 classification for the main frame only.

    Mirrors ``run_dom_local``: execution, else hooked sink, else URL presence,
    else inconclusive. URL presence is not a source read. ``confirmed`` stays
    false here; ``browser_execution_observed`` carries the execution bit.
    ``finding_confirmed`` stays false.
    """
    main = next((frame for frame in case["frames"] if frame["relation"] == "main"), None)
    record = _classify_frame(case, main, "v2") if main is not None else None
    executed = bool(record and record["execution_evidence"]["executed"])
    sinks = list(record["sink_refs"]) if record else []
    present = bool(case["marker_in_url"] or (main and main.get("marker_in_url")))
    if executed:
        classification = "execution_observed"
    elif sinks:
        classification = "sink_reached"
    elif present:
        classification = "source_present_only"
    else:
        classification = "inconclusive"
    return {
        "classification": classification,
        "source_marker_present": present,
        "dom_sinks": sinks,
        "browser_execution_observed": executed,
        "confirmed": False,
        "finding_confirmed": False,
    }


def signals_of(record: Mapping[str, Any]) -> set[str]:
    found = {f"source:{name}" for name in record.get("source_refs") or []}
    found.update(f"sink:{name}" for name in record.get("sink_refs") or [])
    evidence = record.get("execution_evidence") or {}
    if isinstance(evidence, Mapping) and evidence.get("executed"):
        found.add(f"execution:{evidence.get('mechanism')}")
    return found


_EARLY_HOOK_TEMPLATE = r"""(() => {
  const marker = __BBTK_MARKER_JSON__;
  const state = {
    schema: "bbtk.dom-observability.v3",
    installed_at_ms: 0,
    status: "installed_before_page",
    errors: [],
    reads: [],
    property_reads: [],
    sinks: [],
    sanitized: false,
    csp: false,
    events: [],
    external_attempts: 0
  };
  let inInstrumentation = 0;
  const rel = () => {
    try { return Math.round(performance.now() * 1000) / 1000; } catch (e) { return 0; }
  };
  const recordRead = (api, value) => {
    if (inInstrumentation) return;
    let text = "";
    try { text = String(value); } catch (e) { text = ""; }
    if (state.property_reads.indexOf(api) === -1) state.property_reads.push(api);
    if (text.indexOf(marker) !== -1) state.reads.push({ api: api, t_ms: rel() });
  };
  const recordSink = (name, value) => {
    let text = "";
    try { text = String(value); } catch (e) {
      state.errors.push("sink_stringify");
      return;
    }
    if (text.indexOf(marker) !== -1) {
      state.sinks.push({ sink: name, t_ms: rel(), raw_marker: true, escaped_marker: false });
      return;
    }
    const escaped = marker.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
    if (escaped !== marker && text.indexOf(escaped) !== -1) {
      state.sanitized = true;
      state.sinks.push({ sink: name, t_ms: rel(), raw_marker: false, escaped_marker: true });
    }
  };
  const wrapGetter = (proto, prop, api) => {
    try {
      const desc = Object.getOwnPropertyDescriptor(proto, prop);
      if (!desc || !desc.get || !desc.configurable) {
        state.errors.push(api + "_unhookable");
        state.status = "partial";
        return;
      }
      Object.defineProperty(proto, prop, {
        configurable: true,
        enumerable: desc.enumerable,
        get() {
          const value = desc.get.call(this);
          recordRead(api, value);
          return value;
        },
        set: desc.set ? function (v) { return desc.set.call(this, v); } : undefined
      });
    } catch (e) {
      state.errors.push(api + "_hook_failed");
      state.status = "partial";
    }
  };
  try {
    ["hash", "search", "href"].forEach((prop) => {
      const onProto = Object.getOwnPropertyDescriptor(Location.prototype, prop);
      if (onProto && onProto.get && onProto.configurable) {
        wrapGetter(Location.prototype, prop, "location." + prop);
        return;
      }
      const onInstance = Object.getOwnPropertyDescriptor(location, prop);
      if (!onInstance || !onInstance.configurable) {
        state.errors.push("location." + prop + "_unhookable");
        state.status = "partial";
        return;
      }
      wrapGetter(location, prop, "location." + prop);
    });
  } catch (e) {
    state.errors.push("location_hook_failed");
    state.status = "partial";
  }
  wrapGetter(Document.prototype, "URL", "document.URL");
  wrapGetter(Document.prototype, "documentURI", "document.documentURI");
  const wrapHtmlSetter = (proto, prop) => {
    try {
      const desc = Object.getOwnPropertyDescriptor(proto, prop);
      if (!desc || !desc.set || !desc.configurable) {
        state.errors.push(prop + "_unhookable");
        state.status = "partial";
        return;
      }
      Object.defineProperty(proto, prop, {
        configurable: true,
        enumerable: desc.enumerable,
        get: desc.get,
        set(value) {
          recordSink(prop, value);
          return desc.set.call(this, value);
        }
      });
    } catch (e) {
      state.errors.push(prop + "_hook_failed");
      state.status = "partial";
    }
  };
  wrapHtmlSetter(Element.prototype, "innerHTML");
  wrapHtmlSetter(Element.prototype, "outerHTML");
  try {
    const insertAdjacent = Element.prototype.insertAdjacentHTML;
    if (typeof insertAdjacent === "function") {
      Element.prototype.insertAdjacentHTML = function (position, value) {
        recordSink("insertAdjacentHTML", value);
        return insertAdjacent.call(this, position, value);
      };
    }
  } catch (e) {
    state.errors.push("insertAdjacentHTML_hook_failed");
    state.status = "partial";
  }
  try {
    ["write", "writeln"].forEach((name) => {
      const original = Document.prototype[name];
      if (typeof original !== "function") return;
      Document.prototype[name] = function () {
        recordSink("document." + name, Array.prototype.join.call(arguments, ""));
        return original.apply(this, arguments);
      };
    });
  } catch (e) {
    state.errors.push("document_write_hook_failed");
    state.status = "partial";
  }
  try {
    const fragment = Range.prototype.createContextualFragment;
    if (typeof fragment === "function") {
      Range.prototype.createContextualFragment = function (value) {
        recordSink("createContextualFragment", value);
        return fragment.call(this, value);
      };
    }
  } catch (e) {
    state.errors.push("createContextualFragment_hook_failed");
    state.status = "partial";
  }
  try {
    if (typeof Element.prototype.setHTML === "function") {
      const setHTML = Element.prototype.setHTML;
      Element.prototype.setHTML = function () {
        recordSink("setHTML", arguments[0]);
        return setHTML.apply(this, arguments);
      };
    }
  } catch (e) {
    state.errors.push("setHTML_hook_failed");
    state.status = "partial";
  }
  try {
    const originalEval = window.eval;
    window.eval = function (code) {
      recordSink("eval", code);
      return originalEval.call(window, code);
    };
  } catch (e) {
    state.errors.push("eval_hook_failed");
    state.status = "partial";
  }
  try {
    window.addEventListener("securitypolicyviolation", () => { state.csp = true; });
    window.addEventListener("hashchange", () => { state.events.push({ name: "hashchange", t_ms: rel(), fired: true }); });
    window.addEventListener("popstate", () => { state.events.push({ name: "popstate", t_ms: rel(), fired: true }); });
  } catch (e) {
    state.errors.push("listener_hook_failed");
    state.status = "partial";
  }
  try {
    if (typeof window.fetch === "function") {
      const originalFetch = window.fetch;
      window.fetch = function (input, init) {
        let raw = "";
        try { raw = typeof input === "string" ? input : (input && input.url) || ""; } catch (e) { raw = ""; }
        let loopback = false;
        inInstrumentation++;
        try {
          const url = new URL(raw, "http://127.0.0.1/");
          loopback = url.hostname === "127.0.0.1" || url.hostname === "::1";
        } catch (e) {
          loopback = false;
        } finally {
          inInstrumentation--;
        }
        if (!loopback) {
          state.external_attempts += 1;
          return Promise.reject(new TypeError("blocked non-loopback fetch"));
        }
        return originalFetch.apply(this, arguments);
      };
    }
  } catch (e) {
    state.errors.push("fetch_hook_failed");
    state.status = "partial";
  }
  window.__bbtk_obs_v3 = state;
})();
"""
