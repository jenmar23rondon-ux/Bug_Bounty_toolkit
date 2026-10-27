"""Hand-labeled synthetic traces for DOM observability v3.

Labels describe what a correct observer should report. They are not generated
from the classifier output. DEV and FINAL use the same scenario types with
different ids and timings that stay on the same side of the v2 300ms window.
"""

from __future__ import annotations

from typing import Any


def _frame(
    frame_id: str,
    relation: str,
    events: list[dict[str, Any]],
    *,
    accessible: bool | None = None,
    sandbox: str | None = None,
) -> dict[str, Any]:
    frame: dict[str, Any] = {
        "frame_id": frame_id,
        "relation": relation,
        "accessible": relation in {"main", "same_origin", "swapped"} if accessible is None else accessible,
        "events": events,
    }
    if sandbox is not None:
        frame["sandbox"] = sandbox
    return frame


def _main(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [_frame("main", "main", events)]


def _case(
    case_id: str,
    events: list[dict[str, Any]],
    *,
    expected_outcome: str,
    expected_source_observed: bool,
    expected_executed: bool,
    expected_dom_state: str,
    previously_missed: bool,
    negative: bool,
    source_was_read: bool,
    marker_in_url: bool = False,
    interactions: list[str] | None = None,
    instrumentation: str = "init",
    innerhtml_without_execution: bool = False,
    frames: list[dict[str, Any]] | None = None,
    focus: str = "main",
) -> dict[str, Any]:
    return {
        "case_id": case_id,
        "navigation_id": f"nav-{case_id}",
        "focus_frame_id": focus,
        "marker_in_url": marker_in_url,
        "declared_interactions": interactions or [],
        "v2_instrumentation": instrumentation,
        "frames": frames if frames is not None else _main(events),
        "expected_outcome": expected_outcome,
        "expected_source_observed": expected_source_observed,
        "expected_executed": expected_executed,
        "expected_dom_state": expected_dom_state,
        "previously_missed": previously_missed,
        "negative": negative,
        "source_was_read": source_was_read,
        "innerhtml_without_execution": innerhtml_without_execution,
    }


def build_cases(split: str) -> list[dict[str, Any]]:
    """Return the frozen scenario list for ``dev`` or ``final``."""
    if split not in {"dev", "final"}:
        raise ValueError("split must be dev or final.")
    prefix = "dev" if split == "dev" else "final"
    # Both timings are after DOM local v2's 300ms budget and inside v3's 1500ms budget.
    async_at = 450 if split == "dev" else 520
    promise_at = 480 if split == "dev" else 610
    fetch_at = 500 if split == "dev" else 640
    render_at = 600 if split == "dev" else 720
    insert_at = 700 if split == "dev" else 880
    dcl = 8 if split == "dev" else 11
    pre_sink = 2 if split == "dev" else 3
    return [
        _case(
            f"{prefix}-prehook-inert",
            [
                {"t_ms": 1, "type": "source_read", "api": "document.URL"},
                {"t_ms": pre_sink, "type": "sink", "sink": "innerHTML", "raw_marker": True},
                {"t_ms": dcl, "type": "domcontentloaded"},
            ],
            expected_outcome="observed",
            expected_source_observed=True,
            expected_executed=False,
            expected_dom_state="sink_reached",
            previously_missed=True,
            negative=True,
            source_was_read=True,
            marker_in_url=True,
            instrumentation="late",
            innerhtml_without_execution=True,
        ),
        _case(
            f"{prefix}-settimeout",
            [
                {"t_ms": 5, "type": "domcontentloaded"},
                {"t_ms": async_at, "type": "sink", "sink": "innerHTML", "raw_marker": True},
                {"t_ms": async_at + 1, "type": "execution", "mechanism": "marker_assignment"},
            ],
            expected_outcome="observed",
            expected_source_observed=False,
            expected_executed=True,
            expected_dom_state="execution_observed",
            previously_missed=True,
            negative=False,
            source_was_read=False,
        ),
        _case(
            f"{prefix}-promise",
            [
                {"t_ms": 5, "type": "domcontentloaded"},
                {"t_ms": promise_at, "type": "sink", "sink": "insertAdjacentHTML", "raw_marker": True},
                {"t_ms": promise_at + 1, "type": "execution", "mechanism": "marker_assignment"},
            ],
            expected_outcome="observed",
            expected_source_observed=False,
            expected_executed=True,
            expected_dom_state="execution_observed",
            previously_missed=True,
            negative=False,
            source_was_read=False,
        ),
        _case(
            f"{prefix}-local-fetch",
            [
                {"t_ms": 5, "type": "domcontentloaded"},
                {"t_ms": 10, "type": "fetch", "loopback": True},
                {"t_ms": fetch_at, "type": "sink", "sink": "innerHTML", "raw_marker": True},
                {"t_ms": fetch_at + 1, "type": "execution", "mechanism": "dialog"},
            ],
            expected_outcome="observed",
            expected_source_observed=False,
            expected_executed=True,
            expected_dom_state="execution_observed",
            previously_missed=True,
            negative=False,
            source_was_read=False,
        ),
        _case(
            f"{prefix}-button-click",
            [
                {"t_ms": dcl, "type": "domcontentloaded"},
                {
                    "t_ms": 40 if split == "dev" else 70,
                    "type": "sink",
                    "sink": "insertAdjacentHTML",
                    "raw_marker": True,
                    "requires": ["click:#go"],
                },
            ],
            expected_outcome="observed",
            expected_source_observed=False,
            expected_executed=False,
            expected_dom_state="sink_reached",
            previously_missed=True,
            negative=True,
            source_was_read=False,
            interactions=["click:#go"],
        ),
        _case(
            f"{prefix}-delayed-render",
            [
                {"t_ms": 5, "type": "domcontentloaded"},
                {"t_ms": render_at, "type": "sink", "sink": "outerHTML", "raw_marker": True},
            ],
            expected_outcome="observed",
            expected_source_observed=False,
            expected_executed=False,
            expected_dom_state="sink_reached",
            previously_missed=True,
            negative=True,
            source_was_read=False,
        ),
        _case(
            f"{prefix}-spa-route",
            [
                {"t_ms": dcl, "type": "domcontentloaded"},
                {
                    "t_ms": 50 if split == "dev" else 80,
                    "type": "sink",
                    "sink": "innerHTML",
                    "raw_marker": True,
                    "requires": ["spa:#/item"],
                },
                {
                    "t_ms": 51 if split == "dev" else 81,
                    "type": "execution",
                    "mechanism": "marker_assignment",
                    "requires": ["spa:#/item"],
                },
            ],
            expected_outcome="observed",
            expected_source_observed=False,
            expected_executed=True,
            expected_dom_state="execution_observed",
            previously_missed=True,
            negative=False,
            source_was_read=False,
            interactions=["spa:#/item"],
        ),
        _case(
            f"{prefix}-hashchange",
            [
                {"t_ms": dcl, "type": "domcontentloaded"},
                {
                    "t_ms": 40 if split == "dev" else 65,
                    "type": "source_read",
                    "api": "location.hash",
                    "requires": ["hashchange"],
                },
                {
                    "t_ms": 42 if split == "dev" else 67,
                    "type": "sink",
                    "sink": "innerHTML",
                    "raw_marker": True,
                    "requires": ["hashchange"],
                },
            ],
            expected_outcome="observed",
            expected_source_observed=True,
            expected_executed=False,
            expected_dom_state="sink_reached",
            previously_missed=True,
            negative=True,
            source_was_read=True,
            marker_in_url=True,
            interactions=["hashchange"],
            innerhtml_without_execution=True,
        ),
        _case(
            f"{prefix}-popstate",
            [
                {"t_ms": dcl, "type": "domcontentloaded"},
                {
                    "t_ms": 60 if split == "dev" else 90,
                    "type": "sink",
                    "sink": "document.write",
                    "raw_marker": True,
                    "requires": ["popstate"],
                },
            ],
            expected_outcome="observed",
            expected_source_observed=False,
            expected_executed=False,
            expected_dom_state="sink_reached",
            previously_missed=True,
            negative=True,
            source_was_read=False,
            interactions=["popstate"],
        ),
        _case(
            f"{prefix}-late-insert",
            [
                {"t_ms": 5, "type": "domcontentloaded"},
                {"t_ms": insert_at, "type": "sink", "sink": "insertAdjacentHTML", "raw_marker": True},
            ],
            expected_outcome="observed",
            expected_source_observed=False,
            expected_executed=False,
            expected_dom_state="sink_reached",
            previously_missed=True,
            negative=True,
            source_was_read=False,
        ),
        _case(
            f"{prefix}-contextual-fragment",
            [
                {"t_ms": 4, "type": "sink", "sink": "createContextualFragment", "raw_marker": True},
                {"t_ms": dcl, "type": "domcontentloaded"},
            ],
            expected_outcome="observed",
            expected_source_observed=False,
            expected_executed=False,
            expected_dom_state="sink_reached",
            previously_missed=True,
            negative=True,
            source_was_read=False,
        ),
        _case(
            f"{prefix}-eval-inert",
            [
                {"t_ms": 6, "type": "sink", "sink": "eval", "raw_marker": True},
                {"t_ms": dcl, "type": "domcontentloaded"},
            ],
            expected_outcome="observed",
            expected_source_observed=False,
            expected_executed=False,
            expected_dom_state="sink_reached",
            previously_missed=True,
            negative=True,
            source_was_read=False,
        ),
        _case(
            f"{prefix}-same-origin-frame",
            [],
            frames=[
                _frame("main", "main", [{"t_ms": dcl, "type": "domcontentloaded"}]),
                _frame(
                    "child",
                    "same_origin",
                    [
                        {"t_ms": 4, "type": "source_read", "api": "document.URL"},
                        {"t_ms": 5, "type": "sink", "sink": "innerHTML", "raw_marker": True},
                        {"t_ms": 6, "type": "execution", "mechanism": "marker_assignment"},
                    ],
                ),
            ],
            focus="child",
            expected_outcome="observed",
            expected_source_observed=True,
            expected_executed=True,
            expected_dom_state="execution_observed",
            previously_missed=True,
            negative=False,
            source_was_read=True,
        ),
        _case(
            f"{prefix}-swapped-frame",
            [],
            frames=[
                _frame("main", "main", [{"t_ms": dcl, "type": "domcontentloaded"}]),
                _frame(
                    "frame-b",
                    "swapped",
                    [{"t_ms": 20, "type": "sink", "sink": "innerHTML", "raw_marker": True}],
                ),
            ],
            focus="frame-b",
            expected_outcome="observed",
            expected_source_observed=False,
            expected_executed=False,
            expected_dom_state="sink_reached",
            previously_missed=True,
            negative=True,
            source_was_read=False,
            innerhtml_without_execution=True,
        ),
        _case(
            f"{prefix}-sanitized",
            [
                {"t_ms": 2, "type": "source_read", "api": "document.URL"},
                {"t_ms": 3, "type": "sink", "sink": "innerHTML", "raw_marker": False, "escaped_marker": True},
                {"t_ms": 4, "type": "sanitize"},
                {"t_ms": dcl, "type": "domcontentloaded"},
            ],
            expected_outcome="observed",
            expected_source_observed=True,
            expected_executed=False,
            expected_dom_state="sanitization_applied",
            previously_missed=True,
            negative=True,
            source_was_read=True,
        ),
        _case(
            f"{prefix}-isolated-frame",
            [],
            frames=[
                _frame(
                    "sand",
                    "isolated",
                    [
                        {"t_ms": 4, "type": "sink", "sink": "innerHTML", "raw_marker": True},
                        {"t_ms": 6, "type": "execution", "mechanism": "marker_assignment"},
                    ],
                    accessible=False,
                    sandbox="",
                )
            ],
            focus="sand",
            expected_outcome="unsupported",
            expected_source_observed=False,
            expected_executed=False,
            expected_dom_state="inconclusive",
            previously_missed=False,
            negative=True,
            source_was_read=False,
        ),
        _case(
            f"{prefix}-no-access-frame",
            [],
            frames=[
                _frame(
                    "other",
                    "no_access",
                    [{"t_ms": 4, "type": "sink", "sink": "eval", "raw_marker": True}],
                    accessible=False,
                )
            ],
            focus="other",
            expected_outcome="unsupported",
            expected_source_observed=False,
            expected_executed=False,
            expected_dom_state="inconclusive",
            previously_missed=False,
            negative=True,
            source_was_read=False,
        ),
        _case(
            f"{prefix}-missing-frame",
            [],
            frames=[_frame("gone", "missing", [], accessible=False)],
            focus="gone",
            expected_outcome="inconclusive",
            expected_source_observed=False,
            expected_executed=False,
            expected_dom_state="inconclusive",
            previously_missed=False,
            negative=True,
            source_was_read=False,
        ),
        _case(
            f"{prefix}-unmounted-frame",
            [],
            frames=[
                _frame(
                    "temp",
                    "unmounted",
                    [{"t_ms": 4, "type": "sink", "sink": "innerHTML", "raw_marker": True}],
                    accessible=False,
                )
            ],
            focus="temp",
            expected_outcome="inconclusive",
            expected_source_observed=False,
            expected_executed=False,
            expected_dom_state="inconclusive",
            previously_missed=False,
            negative=True,
            source_was_read=False,
            innerhtml_without_execution=True,
        ),
        _case(
            f"{prefix}-partial-navigation",
            [{"t_ms": dcl, "type": "domcontentloaded"}, {"t_ms": 30, "type": "navigation_partial"}],
            expected_outcome="inconclusive",
            expected_source_observed=False,
            expected_executed=False,
            expected_dom_state="inconclusive",
            previously_missed=False,
            negative=True,
            source_was_read=False,
        ),
        _case(
            f"{prefix}-never-fired",
            [
                {"t_ms": dcl, "type": "domcontentloaded"},
                {"t_ms": 15, "type": "event", "name": "click", "fired": False},
            ],
            expected_outcome="not_observed",
            expected_source_observed=False,
            expected_executed=False,
            expected_dom_state="inconclusive",
            previously_missed=False,
            negative=True,
            source_was_read=False,
        ),
        _case(
            f"{prefix}-url-unread",
            [{"t_ms": 0, "type": "document_start"}, {"t_ms": dcl, "type": "domcontentloaded"}],
            expected_outcome="not_observed",
            expected_source_observed=False,
            expected_executed=False,
            expected_dom_state="inconclusive",
            previously_missed=False,
            negative=True,
            source_was_read=False,
            marker_in_url=True,
        ),
        _case(
            f"{prefix}-innerhtml-early",
            [
                {"t_ms": 1, "type": "source_read", "api": "document.URL"},
                {"t_ms": pre_sink, "type": "sink", "sink": "innerHTML", "raw_marker": True},
                {"t_ms": dcl, "type": "domcontentloaded"},
            ],
            expected_outcome="observed",
            expected_source_observed=True,
            expected_executed=False,
            expected_dom_state="sink_reached",
            previously_missed=False,
            negative=True,
            source_was_read=True,
            marker_in_url=True,
            innerhtml_without_execution=True,
        ),
        _case(
            f"{prefix}-textcontent",
            [
                {"t_ms": 2, "type": "property_write", "sink": "textContent"},
                {"t_ms": 3, "type": "sink", "sink": "textContent", "raw_marker": True},
                {"t_ms": dcl, "type": "domcontentloaded"},
            ],
            expected_outcome="not_observed",
            expected_source_observed=False,
            expected_executed=False,
            expected_dom_state="inconclusive",
            previously_missed=False,
            negative=True,
            source_was_read=False,
            marker_in_url=True,
        ),
        _case(
            f"{prefix}-immediate-exec",
            [
                {"t_ms": 2, "type": "sink", "sink": "innerHTML", "raw_marker": True},
                {"t_ms": 3, "type": "execution", "mechanism": "marker_assignment"},
                {"t_ms": dcl, "type": "domcontentloaded"},
            ],
            expected_outcome="observed",
            expected_source_observed=False,
            expected_executed=True,
            expected_dom_state="execution_observed",
            previously_missed=False,
            negative=False,
            source_was_read=False,
        ),
        _case(
            f"{prefix}-csp",
            [
                {"t_ms": 2, "type": "sink", "sink": "innerHTML", "raw_marker": True},
                {"t_ms": 3, "type": "csp_block"},
                {"t_ms": dcl, "type": "domcontentloaded"},
            ],
            expected_outcome="observed",
            expected_source_observed=False,
            expected_executed=False,
            expected_dom_state="execution_blocked_csp",
            previously_missed=False,
            negative=True,
            source_was_read=False,
            innerhtml_without_execution=True,
        ),
        _case(
            f"{prefix}-instrumentation-error",
            [{"t_ms": 0, "type": "instrumentation_error", "detail": "defineProperty failed"}],
            expected_outcome="inconclusive",
            expected_source_observed=False,
            expected_executed=False,
            expected_dom_state="inconclusive_browser_error",
            previously_missed=False,
            negative=True,
            source_was_read=False,
        ),
    ]
