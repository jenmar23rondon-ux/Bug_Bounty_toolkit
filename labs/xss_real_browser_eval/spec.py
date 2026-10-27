"""Frozen scenario definitions for the disposable XSS browser lab.

DEV and FINAL share endpoint behavior and differ by marker token. Parser
expectations are what ``classify_reflected_context`` is specified to emit for
these fixtures. They are not Chromium results. Browser expectations are the
observation class a correct instrumentation pass must report. FINAL is hashed
by ``freeze.py`` before the first FINAL metrics run.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any
from urllib.parse import quote, urlencode, urlsplit, urlunsplit

LETTERS = tuple("ABCDEFGHIJKLMNOP")

# Documentation range (RFC 5737). Literal IP so the probe does not need DNS.
EXTERNAL_PROBE_HTTP = "http://203.0.113.10/bbtk-xss-probe"
EXTERNAL_PROBE_WS = "ws://203.0.113.10/bbtk-xss-probe"

PAYLOAD_KINDS = ("html_event", "attr_breakout", "js_breakout", "plain")
PLACEMENTS = ("query", "hash")


@dataclass(frozen=True)
class Scenario:
    letter: str
    name: str
    path: str
    marker: str
    payload_kind: str
    placement: str
    expected_browser_state: str
    expected_parser_context: str
    expected_parser_decision: str
    expect_execution: bool
    reflected_in_body: bool
    metric_groups: tuple[str, ...]
    timeout_ms: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "letter": self.letter,
            "name": self.name,
            "path": self.path,
            "marker": self.marker,
            "payload_kind": self.payload_kind,
            "placement": self.placement,
            "expected_browser_state": self.expected_browser_state,
            "expected_parser_context": self.expected_parser_context,
            "expected_parser_decision": self.expected_parser_decision,
            "expect_execution": self.expect_execution,
            "reflected_in_body": self.reflected_in_body,
            "metric_groups": list(self.metric_groups),
            "timeout_ms": self.timeout_ms,
        }


def _marker(split: str, letter: str) -> str:
    prefix = "bbtkxssdev" if split == "dev" else "bbtkxssfin"
    return f"{prefix}{letter.lower()}"


def execution_js(marker: str) -> str:
    """Innocuous in-page marker. No cookies, storage, or network."""
    if not marker.startswith("bbtkxss") or not marker.isalnum():
        raise ValueError("marker must be a synthetic bbtkxss token")
    return f"window.__bbtk_xss_marker='{marker}'"


def payload_for(kind: str, marker: str) -> str:
    js = execution_js(marker)
    if kind == "html_event":
        return f'<img src=x onerror="{js}">'
    if kind == "attr_breakout":
        return f'"><img src=x onerror="{js}"><input value="'
    if kind == "js_breakout":
        return f'";{js};//'
    if kind == "plain":
        return marker
    raise ValueError(f"unknown payload kind: {kind}")


def _case(
    split: str,
    letter: str,
    name: str,
    *,
    payload_kind: str,
    placement: str,
    expected_browser_state: str,
    expected_parser_context: str,
    expected_parser_decision: str,
    expect_execution: bool,
    reflected_in_body: bool,
    metric_groups: tuple[str, ...],
    timeout_ms: int = 4000,
) -> Scenario:
    return Scenario(
        letter=letter,
        name=name,
        path="/" + letter.lower(),
        marker=_marker(split, letter),
        payload_kind=payload_kind,
        placement=placement,
        expected_browser_state=expected_browser_state,
        expected_parser_context=expected_parser_context,
        expected_parser_decision=expected_parser_decision,
        expect_execution=expect_execution,
        reflected_in_body=reflected_in_body,
        metric_groups=metric_groups,
        timeout_ms=timeout_ms,
    )


def _split_cases(split: str) -> tuple[Scenario, ...]:
    """Endpoint behavior is identical across splits; markers are not."""
    return (
        _case(
            split,
            "A",
            "reflected_vuln",
            payload_kind="html_event",
            placement="query",
            expected_browser_state="execution_observed",
            expected_parser_context="html_attribute",
            expected_parser_decision="candidate",
            expect_execution=True,
            reflected_in_body=True,
            metric_groups=("exec_positive",),
        ),
        _case(
            split,
            "B",
            "reflected_escaped",
            payload_kind="html_event",
            placement="query",
            expected_browser_state="reflection_observed",
            expected_parser_context="html_text",
            expected_parser_decision="escaped_safe",
            expect_execution=False,
            reflected_in_body=True,
            metric_groups=("exec_negative",),
        ),
        _case(
            split,
            "C",
            "attr_safe",
            payload_kind="attr_breakout",
            placement="query",
            expected_browser_state="reflection_observed",
            expected_parser_context="html_attribute",
            expected_parser_decision="escaped_safe",
            expect_execution=False,
            reflected_in_body=True,
            metric_groups=("exec_negative",),
        ),
        _case(
            split,
            "D",
            "attr_vuln",
            payload_kind="attr_breakout",
            placement="query",
            expected_browser_state="execution_observed",
            expected_parser_context="html_attribute",
            expected_parser_decision="candidate",
            expect_execution=True,
            reflected_in_body=True,
            metric_groups=("exec_positive",),
        ),
        _case(
            split,
            "E",
            "js_safe",
            payload_kind="js_breakout",
            placement="query",
            expected_browser_state="reflection_observed",
            expected_parser_context="js_string",
            expected_parser_decision="escaped_safe",
            expect_execution=False,
            reflected_in_body=True,
            metric_groups=("exec_negative",),
        ),
        _case(
            split,
            "F",
            "js_vuln",
            payload_kind="js_breakout",
            placement="query",
            expected_browser_state="execution_observed",
            expected_parser_context="js_string",
            expected_parser_decision="escaped_safe",
            expect_execution=True,
            reflected_in_body=True,
            metric_groups=("exec_positive",),
        ),
        _case(
            split,
            "G",
            "json_non_executing",
            payload_kind="html_event",
            placement="query",
            expected_browser_state="reflection_observed",
            expected_parser_context="json",
            expected_parser_decision="escaped_safe",
            expect_execution=False,
            reflected_in_body=True,
            metric_groups=("exec_negative",),
        ),
        _case(
            split,
            "H",
            "dom_hash",
            payload_kind="html_event",
            placement="hash",
            expected_browser_state="execution_observed",
            expected_parser_context="not_reflected",
            expected_parser_decision="not_reflected",
            expect_execution=True,
            reflected_in_body=False,
            metric_groups=("exec_positive",),
        ),
        _case(
            split,
            "I",
            "dom_search",
            payload_kind="html_event",
            placement="query",
            expected_browser_state="execution_observed",
            expected_parser_context="not_reflected",
            expected_parser_decision="not_reflected",
            expect_execution=True,
            reflected_in_body=False,
            metric_groups=("exec_positive",),
        ),
        _case(
            split,
            "J",
            "sanitize_before_sink",
            payload_kind="html_event",
            placement="query",
            expected_browser_state="sanitized",
            expected_parser_context="not_reflected",
            expected_parser_decision="not_reflected",
            expect_execution=False,
            reflected_in_body=False,
            metric_groups=("sanitized",),
        ),
        _case(
            split,
            "K",
            "text_content_safe",
            payload_kind="html_event",
            placement="query",
            expected_browser_state="source_observed",
            expected_parser_context="not_reflected",
            expected_parser_decision="not_reflected",
            expect_execution=False,
            reflected_in_body=False,
            metric_groups=("exec_negative", "safe_sink"),
        ),
        _case(
            split,
            "L",
            "inner_html_dangerous",
            payload_kind="html_event",
            placement="query",
            expected_browser_state="execution_observed",
            expected_parser_context="js_string",
            expected_parser_decision="escaped_safe",
            expect_execution=True,
            reflected_in_body=True,
            metric_groups=("exec_positive",),
        ),
        _case(
            split,
            "M",
            "csp_block",
            payload_kind="html_event",
            placement="query",
            expected_browser_state="execution_blocked",
            expected_parser_context="html_attribute",
            expected_parser_decision="candidate",
            expect_execution=False,
            reflected_in_body=True,
            metric_groups=("csp",),
        ),
        _case(
            split,
            "N",
            "marker_not_executed",
            payload_kind="plain",
            placement="query",
            expected_browser_state="reflection_observed",
            expected_parser_context="html_text",
            expected_parser_decision="escaped_safe",
            expect_execution=False,
            reflected_in_body=True,
            metric_groups=("exec_negative",),
        ),
        _case(
            split,
            "O",
            "external_navigation_blocked",
            payload_kind="plain",
            placement="query",
            expected_browser_state="reflection_observed",
            expected_parser_context="html_text",
            expected_parser_decision="escaped_safe",
            expect_execution=False,
            reflected_in_body=True,
            metric_groups=("external_block", "exec_negative"),
        ),
        _case(
            split,
            "P",
            "timeout_hung_page",
            payload_kind="plain",
            placement="query",
            expected_browser_state="inconclusive_browser_error",
            expected_parser_context="html_text",
            expected_parser_decision="escaped_safe",
            expect_execution=False,
            reflected_in_body=True,
            metric_groups=("timeout",),
            timeout_ms=1000,
        ),
    )


def scenarios_for(split: str) -> tuple[Scenario, ...]:
    if split not in {"dev", "final"}:
        raise ValueError("split must be dev or final")
    cases = _split_cases(split)
    letters = tuple(case.letter for case in cases)
    if letters != LETTERS:
        raise ValueError("scenarios must be A–P in order")
    return cases


def scenario_document(split: str) -> dict[str, Any]:
    return {
        "lab": "xss_real_browser_eval",
        "split": split,
        "finding_confirmed": False,
        "cases": [case.to_dict() for case in scenarios_for(split)],
    }


def canonical_json(split: str) -> str:
    return json.dumps(scenario_document(split), indent=2, sort_keys=True) + "\n"


def scenario_url(base_url: str, case: Scenario) -> str:
    """Navigation URL. The fragment is not sent on the HTTP request."""
    payload = payload_for(case.payload_kind, case.marker)
    parsed = urlsplit(base_url)
    if case.placement == "hash":
        return urlunsplit((parsed.scheme, parsed.netloc, case.path, "", quote(payload, safe="")))
    query = urlencode({"q": payload})
    return urlunsplit((parsed.scheme, parsed.netloc, case.path, query, ""))
