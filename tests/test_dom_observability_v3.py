"""DOM observability v3: early hooks, async sinks, frames. No auto-confirm."""

from __future__ import annotations

import json
import unittest

import bugbounty_toolkit
from bugbounty_toolkit.xss.dom_observability import (
    V2_ASYNC_BUDGET_MS,
    V3_ASYNC_BUDGET_MS,
    assemble_record,
    classify_case,
    early_hook_script,
    validate_marker,
)

MARKER = "bbtkxssaabbcc"


def _case(
    events: list[dict[str, object]],
    *,
    case_id: str = "case-main",
    marker_in_url: bool = False,
    interactions: list[str] | None = None,
    instrumentation: str = "init",
    frames: list[dict[str, object]] | None = None,
    focus: str = "main",
) -> dict[str, object]:
    body: dict[str, object] = {
        "case_id": case_id,
        "navigation_id": "nav-1",
        "focus_frame_id": focus,
        "marker_in_url": marker_in_url,
        "declared_interactions": interactions or [],
        "v2_instrumentation": instrumentation,
        "frames": frames
        or [
            {
                "frame_id": "main",
                "relation": "main",
                "accessible": True,
                "events": events,
            }
        ],
    }
    return body


class DomObservabilityRulesTests(unittest.TestCase):
    def test_version_stays_0_2_2(self) -> None:
        self.assertEqual(bugbounty_toolkit.__version__, "0.2.2")

    def test_url_presence_is_not_a_source_read(self) -> None:
        case = _case(
            [{"t_ms": 0, "type": "document_start"}, {"t_ms": 5, "type": "domcontentloaded"}],
            marker_in_url=True,
        )
        v3 = classify_case(case, generation="v3")
        v2 = classify_case(case, generation="v2")
        self.assertTrue(v3["source_available"])
        self.assertFalse(v3["source_observed"])
        self.assertEqual(v3["source_refs"], [])
        self.assertEqual(v3["outcome"], "not_observed")
        self.assertFalse(v3["finding_confirmed"])
        self.assertEqual(v2["legacy_v2"]["classification"], "source_present_only")
        self.assertTrue(v2["legacy_v2"]["source_marker_present"])
        self.assertFalse(v2["source_observed"])
        self.assertFalse(v2["legacy_v2"]["finding_confirmed"])
        self.assertNotIn(MARKER, json.dumps(v3))

    def test_innerhtml_alone_is_not_execution(self) -> None:
        case = _case(
            [
                {"t_ms": 1, "type": "source_read", "api": "location.hash"},
                {"t_ms": 2, "type": "sink", "sink": "innerHTML", "raw_marker": True},
                {"t_ms": 3, "type": "execution", "mechanism": "innerHTML"},
                {"t_ms": 8, "type": "domcontentloaded"},
            ],
            marker_in_url=True,
        )
        v3 = classify_case(case, generation="v3")
        self.assertEqual(v3["sink_refs"], ["innerHTML"])
        self.assertFalse(v3["execution_evidence"]["executed"])
        self.assertFalse(v3["execution_evidence"]["claimed_from_innerhtml_alone"])
        self.assertEqual(v3["dom_state"], "sink_reached")
        self.assertIn("execution_not_inferred_from_innerhtml", v3["limitations"])

    def test_real_execution_requires_marker_or_dialog(self) -> None:
        case = _case(
            [
                {"t_ms": 2, "type": "sink", "sink": "innerHTML", "raw_marker": True},
                {"t_ms": 3, "type": "execution", "mechanism": "marker_assignment"},
                {"t_ms": 8, "type": "domcontentloaded"},
            ]
        )
        v3 = classify_case(case, generation="v3")
        self.assertTrue(v3["execution_evidence"]["executed"])
        self.assertEqual(v3["execution_evidence"]["mechanism"], "marker_assignment")
        self.assertEqual(v3["dom_state"], "execution_observed")
        self.assertFalse(v3["finding_confirmed"])

    def test_late_hooks_miss_inert_sink_and_v3_sees_it(self) -> None:
        case = _case(
            [
                {"t_ms": 1, "type": "source_read", "api": "location.hash"},
                {"t_ms": 2, "type": "sink", "sink": "innerHTML", "raw_marker": True},
                {"t_ms": 9, "type": "domcontentloaded"},
            ],
            marker_in_url=True,
            instrumentation="late",
        )
        v2 = classify_case(case, generation="v2")
        v3 = classify_case(case, generation="v3")
        self.assertEqual(v2["outcome"], "not_observed")
        self.assertEqual(v2["sink_refs"], [])
        self.assertEqual(v2["legacy_v2"]["classification"], "source_present_only")
        self.assertEqual(v2["instrumentation_status"], "installed_late")
        self.assertEqual(v3["outcome"], "observed")
        self.assertEqual(v3["instrumentation_status"], "installed_before_page")
        self.assertEqual(v3["sink_refs"], ["innerHTML"])
        self.assertTrue(v3["source_observed"])
        self.assertFalse(v3["execution_evidence"]["executed"])

    def test_v2_still_sees_early_global_within_budget(self) -> None:
        case = _case(
            [
                {"t_ms": 2, "type": "execution", "mechanism": "dialog"},
                {"t_ms": 9, "type": "domcontentloaded"},
            ],
            instrumentation="late",
        )
        v2 = classify_case(case, generation="v2")
        self.assertTrue(v2["execution_evidence"]["executed"])
        self.assertEqual(v2["legacy_v2"]["classification"], "execution_observed")
        self.assertFalse(v2["legacy_v2"]["confirmed"])

    def test_async_sink_after_v2_window(self) -> None:
        self.assertEqual(V2_ASYNC_BUDGET_MS, 300)
        self.assertGreater(V3_ASYNC_BUDGET_MS, 300)
        case = _case(
            [
                {"t_ms": 5, "type": "domcontentloaded"},
                {"t_ms": 450, "type": "sink", "sink": "innerHTML", "raw_marker": True},
                {"t_ms": 451, "type": "execution", "mechanism": "marker_assignment"},
            ]
        )
        v2 = classify_case(case, generation="v2")
        v3 = classify_case(case, generation="v3")
        self.assertFalse(v2["execution_evidence"]["executed"])
        self.assertEqual(v2["outcome"], "not_observed")
        self.assertTrue(v3["execution_evidence"]["executed"])
        self.assertEqual(v3["outcome"], "observed")

    def test_interaction_gated_sinks_need_the_declared_event(self) -> None:
        events = [
            {"t_ms": 10, "type": "domcontentloaded"},
            {
                "t_ms": 40,
                "type": "sink",
                "sink": "insertAdjacentHTML",
                "raw_marker": True,
                "requires": ["click:#go"],
            },
        ]
        missed = classify_case(_case(events), generation="v2")
        seen = classify_case(_case(events, interactions=["click:#go"]), generation="v3")
        self.assertEqual(missed["outcome"], "not_observed")
        self.assertEqual(seen["sink_refs"], ["insertAdjacentHTML"])
        self.assertFalse(seen["execution_evidence"]["executed"])

    def test_unhooked_v2_sink_is_visible_to_v3(self) -> None:
        case = _case(
            [
                {"t_ms": 4, "type": "sink", "sink": "createContextualFragment", "raw_marker": True},
                {"t_ms": 8, "type": "domcontentloaded"},
            ]
        )
        self.assertEqual(classify_case(case, generation="v2")["outcome"], "not_observed")
        self.assertEqual(classify_case(case, generation="v3")["sink_refs"], ["createContextualFragment"])

    def test_textcontent_is_not_a_script_sink(self) -> None:
        case = _case(
            [
                {"t_ms": 2, "type": "property_write", "sink": "textContent"},
                {"t_ms": 3, "type": "sink", "sink": "textContent", "raw_marker": True},
                {"t_ms": 8, "type": "domcontentloaded"},
            ],
            marker_in_url=True,
        )
        v3 = classify_case(case, generation="v3")
        self.assertEqual(v3["outcome"], "not_observed")
        self.assertEqual(v3["sink_refs"], [])
        self.assertFalse(v3["execution_evidence"]["executed"])

    def test_same_origin_frame_and_sop_refusal(self) -> None:
        frames = [
            {
                "frame_id": "main",
                "relation": "main",
                "accessible": True,
                "events": [{"t_ms": 5, "type": "domcontentloaded"}],
            },
            {
                "frame_id": "child",
                "relation": "same_origin",
                "accessible": True,
                "events": [
                    {"t_ms": 4, "type": "sink", "sink": "innerHTML", "raw_marker": True},
                    {"t_ms": 6, "type": "execution", "mechanism": "marker_assignment"},
                ],
            },
            {
                "frame_id": "sand",
                "relation": "isolated",
                "accessible": False,
                "sandbox": "",
                "events": [
                    {"t_ms": 4, "type": "sink", "sink": "innerHTML", "raw_marker": True},
                    {"t_ms": 6, "type": "execution", "mechanism": "marker_assignment"},
                ],
            },
        ]
        child = _case([], frames=frames, focus="child")
        sand = _case(
            [],
            frames=[
                {
                    "frame_id": "sand",
                    "relation": "isolated",
                    "accessible": False,
                    "sandbox": "",
                    "events": [
                        {"t_ms": 4, "type": "sink", "sink": "innerHTML", "raw_marker": True},
                        {"t_ms": 6, "type": "execution", "mechanism": "marker_assignment"},
                    ],
                }
            ],
            focus="sand",
        )
        v3_child = classify_case(child, generation="v3")
        v2_child = classify_case(child, generation="v2")
        v3_sand = classify_case(sand, generation="v3")
        self.assertEqual(v3_child["outcome"], "observed")
        self.assertTrue(v3_child["execution_evidence"]["executed"])
        self.assertEqual(v2_child["outcome"], "not_observed")
        self.assertEqual(v3_sand["outcome"], "unsupported")
        self.assertEqual(v3_sand["sink_refs"], [])
        self.assertFalse(v3_sand["execution_evidence"]["executed"])
        self.assertIn("sop_not_bypassed", v3_sand["limitations"])
        self.assertNotIn("marker_assignment", json.dumps(v3_sand))

    def test_missing_and_unmounted_are_inconclusive(self) -> None:
        missing = _case(
            [],
            frames=[{"frame_id": "gone", "relation": "missing", "accessible": False, "events": []}],
            focus="gone",
        )
        unmounted = _case(
            [],
            frames=[
                {
                    "frame_id": "temp",
                    "relation": "unmounted",
                    "accessible": False,
                    "events": [{"t_ms": 4, "type": "sink", "sink": "innerHTML", "raw_marker": True}],
                }
            ],
            focus="temp",
        )
        self.assertEqual(classify_case(missing)["outcome"], "inconclusive")
        self.assertEqual(classify_case(unmounted)["sink_refs"], [])
        self.assertEqual(classify_case(unmounted)["outcome"], "inconclusive")

    def test_partial_navigation_and_never_fired_and_hook_failure(self) -> None:
        partial = _case([{"t_ms": 10, "type": "domcontentloaded"}, {"t_ms": 20, "type": "navigation_partial"}])
        quiet = _case(
            [
                {"t_ms": 10, "type": "domcontentloaded"},
                {"t_ms": 15, "type": "event", "name": "click", "fired": False},
            ]
        )
        broken = _case([{"t_ms": 0, "type": "instrumentation_error", "detail": "defineProperty failed"}])
        self.assertEqual(classify_case(partial)["outcome"], "inconclusive")
        self.assertEqual(classify_case(quiet)["outcome"], "not_observed")
        self.assertIn("event_never_fired", classify_case(quiet)["limitations"])
        failed = classify_case(broken)
        self.assertEqual(failed["outcome"], "inconclusive")
        self.assertEqual(failed["instrumentation_status"], "failed")
        self.assertFalse(failed["finding_confirmed"])

    def test_sanitized_and_csp_do_not_confirm(self) -> None:
        sanitized = _case(
            [
                {"t_ms": 2, "type": "source_read", "api": "location.search"},
                {"t_ms": 3, "type": "sink", "sink": "innerHTML", "raw_marker": False, "escaped_marker": True},
                {"t_ms": 4, "type": "sanitize"},
                {"t_ms": 8, "type": "domcontentloaded"},
            ]
        )
        blocked = _case(
            [
                {"t_ms": 2, "type": "sink", "sink": "innerHTML", "raw_marker": True},
                {"t_ms": 3, "type": "csp_block"},
                {"t_ms": 8, "type": "domcontentloaded"},
            ]
        )
        safe = classify_case(sanitized)
        csp = classify_case(blocked)
        self.assertEqual(safe["dom_state"], "sanitization_applied")
        self.assertFalse(safe["execution_evidence"]["executed"])
        self.assertEqual(classify_case(sanitized, generation="v2")["outcome"], "not_observed")
        self.assertEqual(csp["dom_state"], "execution_blocked_csp")
        self.assertFalse(csp["execution_evidence"]["executed"])
        self.assertFalse(csp["finding_confirmed"])

    def test_external_fetch_is_counted_and_not_stored(self) -> None:
        case = _case(
            [
                {"t_ms": 5, "type": "domcontentloaded"},
                {"t_ms": 6, "type": "fetch", "loopback": False, "url": "http://203.0.113.10/secret"},
            ]
        )
        record = classify_case(case)
        self.assertEqual(record["external_requests"], 1)
        self.assertNotIn("203.0.113.10", json.dumps(record))
        self.assertNotIn("secret", json.dumps(record))

    def test_hook_script_is_inert(self) -> None:
        script = early_hook_script(MARKER)
        self.assertIn(json.dumps(MARKER), script)
        self.assertNotIn("__bbtk_xss_marker", script)
        self.assertNotIn("https://", script)
        self.assertNotIn("example.com", script)
        self.assertIn("http://127.0.0.1/", script)
        self.assertNotIn("textContent", script)
        with self.assertRaises(ValueError):
            validate_marker("bad marker")
        with self.assertRaises(ValueError):
            early_hook_script("<script>")

    def test_assemble_rejects_innerhtml_execution_mechanism(self) -> None:
        with self.assertRaises(ValueError):
            assemble_record(
                case_id="c",
                navigation_id="n",
                frame_id="main",
                frame_relation="main",
                instrumentation_status="installed_before_page",
                source_available=False,
                source_refs=(),
                property_reads=(),
                sink_refs=("innerHTML",),
                executed=True,
                execution_mechanism="innerHTML",
                sanitized=False,
                csp_blocked=False,
                t_rel_ms={
                    "navigation_start": 0,
                    "instrumentation_installed": 0,
                    "source_read": None,
                    "sink_call": 1,
                    "execution": 1,
                    "observation_end": 10,
                },
                limitations=(),
                outcome="observed",
                external_requests=0,
            )


if __name__ == "__main__":
    unittest.main()
