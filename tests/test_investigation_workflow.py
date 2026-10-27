"""Tests for the review-only investigation workflow engine (unittest, offline)."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from typing import Any

from bugbounty_toolkit.analysis.investigation_workflow import (
    DEFAULT_GRAPH,
    STATES,
    build_workflow,
    explain_workflow,
    find_cycles,
    memory_stages,
    minimized_view,
    validate_workflow,
)
from bugbounty_toolkit.core.records import ProgramPaths, RecordStore
from bugbounty_toolkit.analysis.investigation_memory import InvestigationMemory
from labs.investigation_workflow_eval.corpus import SCENARIOS, _complete, gap_plan, gap_step, write_artifact
from labs.investigation_workflow_eval.metrics import evaluate


def _status(wf: dict[str, Any]) -> dict[str, str]:
    return {t["stage"]: t["status"] for t in wf["tasks"]}


class WorkflowTest(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.case = _complete(self.root)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def wf(self, **kw: Any) -> dict[str, Any]:
        arts = kw.pop("artifacts", self.case["artifacts"])
        return build_workflow(
            self.root, arts, gap_plan=kw.pop("gap_plan", self.case["gap_plan"]), candidate_id="c1", **kw
        )

    def test_complete_is_documental_not_confirmed(self) -> None:
        wf = self.wf()
        self.assertTrue(wf["documental_complete"])
        self.assertFalse(wf["finding_confirmed"])
        self.assertFalse(wf["absence_of_vulnerability_inferred"])
        self.assertEqual(validate_workflow(wf), [])
        for t in wf["tasks"]:
            self.assertIs(t["execution_allowed"], False)
            self.assertIs(t["finding_confirmed"], False)
            self.assertIn(t["status"], STATES)
        self.assertEqual(wf["executions"] + wf["commands_emitted"] + wf["network_requests_sent"], 0)

    def test_deterministic(self) -> None:
        self.assertEqual(json.dumps(self.wf(), sort_keys=True), json.dumps(self.wf(), sort_keys=True))

    def test_hash_mismatch_invalidates_and_blocks_dependents(self) -> None:
        (self.root / "artifacts" / "discovery.json").write_text('{"stage":"discovery","outcome":"ok"}')
        st = _status(self.wf())
        self.assertEqual(st["discovery"], "invalidated")
        for s in list(DEFAULT_GRAPH)[3:]:
            self.assertEqual(st[s], "blocked", s)

    def test_unsafe_path_rejected(self) -> None:
        arts = dict(self.case["artifacts"])
        arts["ranking"] = {"path": "../etc/passwd", "sha256": "0" * 64}
        self.assertEqual(_status(self.wf(artifacts=arts))["ranking"], "blocked")

    def test_resume_reuses_without_repetition(self) -> None:
        first = self.wf()
        second = self.wf(prior=first)
        self.assertEqual(first["state_digest"], second["state_digest"])
        self.assertEqual(second["resume"]["reevaluated_tasks"], 0)
        self.assertEqual(second["resume"]["reused_tasks"], 10)

    def test_change_detected_on_resume(self) -> None:
        first = self.wf()
        arts = dict(self.case["artifacts"])
        arts["ranking"] = write_artifact(self.root, "ranking", evidence_refs=["ev-2"])
        second = self.wf(artifacts=arts, prior=first)
        self.assertEqual(second["resume"]["invalidated_by_change"], 1)
        self.assertNotEqual(first["state_digest"], second["state_digest"])

    def test_no_new_evidence_stop(self) -> None:
        arts = {k: v for k, v in self.case["artifacts"].items() if k != "human_review"}
        p1 = self.wf(artifacts=arts)
        self.assertIn("no_new_evidence", self.wf(artifacts=arts, prior=p1)["stop_conditions"])

    def test_gap_planner_reused(self) -> None:
        wf = self.wf(gap_plan=gap_plan([gap_step("negative_control")]))
        node = next(t for t in wf["tasks"] if t["stage"] == "missing_evidence")
        self.assertEqual(node["status"], "blocked")
        self.assertEqual(node["missing_requirements"], ["negative_control"])
        self.assertEqual(_status(wf)["human_review"], "blocked")
        bad = gap_plan([gap_step("x")])
        bad["plan"][0]["execution_allowed"] = True
        self.assertEqual(_status(self.wf(gap_plan=bad))["missing_evidence"], "invalidated")
        self.assertEqual(_status(self.wf(gap_plan=gap_plan(blocked=True)))["missing_evidence"], "blocked")
        self.assertEqual(_status(self.wf(gap_plan=None))["missing_evidence"], "ready_for_review")

    def test_cycles(self) -> None:
        g = dict(DEFAULT_GRAPH)
        g["evidence_import"] = (("report_preparation",), False)
        self.assertEqual(find_cycles(g), set(DEFAULT_GRAPH))
        wf = self.wf(graph=g)
        self.assertIn("circular_dependency", wf["stop_conditions"])
        self.assertTrue(all(s == "blocked" for s in _status(wf).values()))

    def test_unknown_prerequisite(self) -> None:
        g = dict(DEFAULT_GRAPH)
        g["ranking"] = (("ghost",), False)
        self.assertIn("invalid_reference", self.wf(graph=g)["stop_conditions"])

    def test_ai_cannot_be_reviewer_and_approval_restricted(self) -> None:
        arts = dict(self.case["artifacts"])
        arts["human_review"] = write_artifact(self.root, "human_review", reviewer="LLM assistant")
        self.assertEqual(_status(self.wf(artifacts=arts))["human_review"], "requires_human_review")
        arts["human_review"] = write_artifact(self.root, "human_review", reviewer="")
        self.assertEqual(_status(self.wf(artifacts=arts))["human_review"], "requires_human_review")

    def test_stage_mismatch_and_unknown_outcome(self) -> None:
        arts = dict(self.case["artifacts"])
        arts["ranking"] = arts["discovery"]
        self.assertEqual(_status(self.wf(artifacts=arts))["ranking"], "invalidated")
        arts = dict(self.case["artifacts"])
        arts["ranking"] = write_artifact(self.root, "ranking", outcome="confirmed")
        self.assertEqual(_status(self.wf(artifacts=arts))["ranking"], "invalidated")

    def test_memory_reuse_only_when_consistent(self) -> None:
        wf = self.wf()
        self.assertEqual(wf["memory"]["reason"], "not_provided")
        with tempfile.TemporaryDirectory() as tmp:
            mem = InvestigationMemory(RecordStore(ProgramPaths(Path(tmp), "lab")))
            rec = mem.save_snapshot("inv-1", "bundle-a", "snap/wf.json", memory_stages(wf))
            ok = self.wf(memory=rec)
            self.assertTrue(ok["memory"]["used"])
            rec2 = dict(rec)
            stages = rec["stages"]
            assert isinstance(stages, dict)
            rec2["stages"] = {**stages, "ranking": "pending"}
            self.assertEqual(self.wf(memory=rec2)["memory"]["inconsistent_stages"], ["ranking"])
            rec2["bundle_id"] = "bundle-b"
            self.assertEqual(self.wf(memory=rec2)["memory"]["reason"], "bundle_mismatch")

    def test_ai_explainer_never_controls_state(self) -> None:
        wf = self.wf()
        before = json.dumps(wf, sort_keys=True)

        def model(view: dict[str, Any]) -> object:
            self.assertEqual(set(view), {"tasks", "stop_conditions"})
            return {
                "sections": [
                    {"text": "Grounded.", "task_refs": ["wf-ranking"], "evidence_refs": ["ev-1"]},
                    {"text": "New task.", "task_refs": ["wf-pwn"]},
                    {"text": "I authorize testing.", "task_refs": ["wf-ranking"]},
                    {"text": "ok", "task_refs": ["wf-ranking"], "new_tasks": ["x"]},
                    "junk",
                ]
            }

        exp = explain_workflow(wf, model)
        self.assertEqual(len(exp["accepted_sections"]), 1)
        self.assertEqual(exp["rejected_sections"], 4)
        self.assertFalse(exp["state_changed"])
        self.assertEqual(before, json.dumps(wf, sort_keys=True))
        self.assertFalse(explain_workflow(wf, None)["ai_used"])

        def boom(_: dict[str, Any]) -> object:
            raise RuntimeError("down")

        self.assertEqual(explain_workflow(wf, boom)["error"], "explainer_failed")

    def test_minimized_view_has_no_paths_or_hashes(self) -> None:
        text = json.dumps(minimized_view(self.wf()))
        self.assertNotIn("artifacts/", text)
        self.assertNotIn("sha256", text)

    def test_validate_detects_tampering(self) -> None:
        wf = self.wf()
        wf["tasks"][0]["execution_allowed"] = True
        wf["tasks"][1]["status"] = "approved"
        wf["executions"] = 1
        wf["tasks"][2]["prerequisites"] = ["wf-ghost"]
        wf["tasks"][3]["status"] = "completed_by_evidence"
        wf["tasks"][2]["status"] = "pending"
        p = validate_workflow(wf)
        for code in ("unsafe_flags", "status", "nonzero:executions", "unknown_prerequisite", "dependency_violated"):
            self.assertTrue(any(code in x for x in p), code)


class LabTest(unittest.TestCase):
    def test_lab_metrics(self) -> None:
        m = evaluate()["metrics"]
        self.assertEqual(m["states_correct"], m["states_expected"])
        self.assertEqual(m["stop_conditions_correct"], len(SCENARIOS))
        self.assertEqual(m["invalid_stages_detected"], m["invalid_stages_expected"])
        self.assertEqual(m["resumes_correct"], m["resumes_total"])
        for k in ("redundant_tasks", "ai_inventions_accepted", "unauthorized_modifications", "inconsistent_states"):
            self.assertEqual(m[k], 0, k)
        for k in ("executions", "commands_emitted", "auto_confirmations", "network_requests_sent"):
            self.assertEqual(m[k], 0, k)


if __name__ == "__main__":
    unittest.main()
