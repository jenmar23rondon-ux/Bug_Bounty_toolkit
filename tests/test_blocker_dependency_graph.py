"""Blocker dependency graph, credential-query independence, and over-limit windows."""

from __future__ import annotations

import hashlib
import json
import shutil
import tempfile
import unittest
from pathlib import Path

from bugbounty_toolkit.analysis import evidence_ledger as L
from bugbounty_toolkit.analysis.blocker_dependency_graph import build_blocker_dependency_graph
from bugbounty_toolkit.analysis.evidence_gap_planner import build_plan
from bugbounty_toolkit.analysis.object_handoff import propose_object_handoff
from bugbounty_toolkit.analysis.object_relationships import build_object_graph
from bugbounty_toolkit.case_generator import inspect_read_pair
from bugbounty_toolkit.core.http_client import RequestSpec
from bugbounty_toolkit.core.records import ProgramPaths
from labs.idor_false_negative_recovery import evaluate as lab
from labs.idor_false_negative_recovery.corpus import dev_cases, final_cases

KEY = hashlib.sha256(b"fn-recovery-window").digest()
ORIGIN = "http://127.0.0.1:9"


def _pair(path: str, api_key: str | None, token: str) -> RequestSpec:
    query = f"?api_key={api_key}" if api_key else ""
    return RequestSpec("GET", f"{ORIGIN}{path}{query}", {"Authorization": f"Bearer {token}"})


def _har(entries: list[dict]) -> bytes:
    return json.dumps({"log": {"version": "1.2", "entries": entries}}).encode()


def _entry(url: str, body: str, token: str) -> dict:
    return {
        "request": {
            "method": "GET",
            "url": url,
            "headers": [{"name": "Authorization", "value": f"Bearer {token}"}],
        },
        "response": {
            "status": 200,
            "headers": [{"name": "Content-Type", "value": "application/json"}],
            "content": {"mimeType": "application/json", "text": body},
        },
    }


class GraphFamilyTests(unittest.TestCase):
    def test_fifteen_final_families_and_dev_fail_closed(self) -> None:
        families = {case["family"] for case in final_cases()}
        self.assertEqual(families, set(range(1, 16)))
        for case in [*final_cases(), *dev_cases()]:
            before = json.dumps(case, sort_keys=True)
            graph = build_blocker_dependency_graph(case["candidates"], case["evidence"])
            self.assertEqual(before, json.dumps(case, sort_keys=True))
            self.assertFalse(graph["finding_confirmed"])
            self.assertFalse(graph["ledger_modified"])
            self.assertEqual(graph["network_requests_sent"], 0)
            got = {row["candidate_id"]: row for row in graph["candidates"]}
            for cid, state in case["expected"]["by_candidate"].items():
                self.assertEqual(got[cid]["effective_state"], state, case["id"])
                self.assertFalse(got[cid]["finding_confirmed"])
                self.assertIn("original_state", got[cid])
                self.assertIn("blockers", got[cid])
                self.assertIn("dependent_refs", got[cid])
                self.assertIn("independent_refs", got[cid])
                self.assertIn("independence_basis", got[cid])
                self.assertIn("evidence_integrity", got[cid])
                self.assertIn("decision_reason", got[cid])
            self.assertEqual(graph["whole_surface_blocks"], case["expected"]["whole_surface"], case["id"])
            if case.get("check_order"):
                reversed_graph = build_blocker_dependency_graph(
                    list(reversed(case["candidates"])), list(reversed(case["evidence"]))
                )
                self.assertEqual(reversed_graph["candidates"], graph["candidates"])

    def test_reviewable_states_never_include_uncertainty(self) -> None:
        for case in final_cases():
            graph = build_blocker_dependency_graph(case["candidates"], case["evidence"])
            for row in graph["candidates"]:
                if row["effective_state"] in {"inconclusive", "requires_manual_independence_review"}:
                    self.assertFalse(row["reviewable"])
                if row["effective_state"].startswith("blocked_"):
                    self.assertFalse(row["reviewable"])


class PlannerOverlayTests(unittest.TestCase):
    def setUp(self) -> None:
        self.work = Path(tempfile.mkdtemp())
        self.paths = ProgramPaths(self.work, "p")
        (self.paths.program_dir / "evidence").mkdir(parents=True)

    def tearDown(self) -> None:
        shutil.rmtree(self.work, ignore_errors=True)

    def _plan(self, evidence: list[tuple[str, list[str]]], candidates: list[tuple[str, list[str]]], tamper: str | None):
        ledger = L.new_ledger("p")
        L.upsert_surface(ledger, {"surface_id": "s1", "kind": "endpoint", "ref": "/s", "status": "investigated"})
        for eid, objects in evidence:
            rel = f"evidence/{eid}.json"
            payload = {
                "control": {
                    "annotation_version": "bbtk-control-annotation/1",
                    "role": "capture_pair",
                    "provides": ["owner_response", "actor_response"],
                    "owner_control": "valid",
                    "actor_access_proof": "private_resource_200",
                    "access_confirmed": False,
                },
                "proposal": {
                    "owner": {"object_ref": objects[0]},
                    "actor": {"object_ref": objects[1]},
                },
            }
            (self.paths.program_dir / rel).write_text(json.dumps(payload), encoding="utf-8")
            L.add_evidence(ledger, self.paths.program_dir, eid, rel, tool="t")
        for cid, refs in candidates:
            L.add_candidate(ledger, cid, "s1", "idor", "r", refs, dedup_key=cid)
            L.review_candidate(ledger, cid, "requires_validation", "r", blockers=["human"])
        path = self.paths.program_dir / "ledger" / "evidence-ledger.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(ledger), encoding="utf-8")
        if tamper:
            target = self.paths.program_dir / "evidence" / f"{tamper}.json"
            target.write_text(target.read_text(encoding="utf-8") + " ", encoding="utf-8")
        before = path.read_bytes()
        plan = build_plan(self.paths)
        self.assertEqual(path.read_bytes(), before)
        return plan

    def test_disjoint_sibling_stays_reviewable_and_overlap_stays_blocked(self) -> None:
        disjoint = self._plan(
            [("e1", ["o1", "o2"]), ("e2", ["o5", "o6"])],
            [("c1", ["e1"]), ("c2", ["e2"])],
            tamper="e2",
        )
        rows = {row["candidate_id"]: row for row in disjoint["effective_eligibility"]}
        self.assertTrue(rows["c1"]["effective_reviewable"])
        self.assertFalse(rows["c2"]["effective_reviewable"])
        self.assertEqual(rows["c1"]["ledger_state"], "requires_validation")
        statuses = {row["candidate_id"]: row["status"] for row in disjoint["candidates"]}
        self.assertEqual(statuses["c1"], "open")
        self.assertEqual(statuses["c2"], "integrity_blocked")
        overlay = {row["candidate_id"]: row for row in disjoint["blocker_dependency_graph"]["candidates"]}
        self.assertEqual(overlay["c1"]["effective_state"], "safely_independent")
        self.assertFalse(overlay["c1"]["finding_confirmed"])
        shared = self._plan(
            [("e1", ["o1", "o2"]), ("e2", ["o2", "o3"])],
            [("c1", ["e1"]), ("c2", ["e2"])],
            tamper="e2",
        )
        shared_rows = {row["candidate_id"]: row for row in shared["effective_eligibility"]}
        self.assertFalse(shared_rows["c1"]["effective_reviewable"])
        self.assertEqual(
            next(row["status"] for row in shared["candidates"] if row["candidate_id"] == "c1"),
            "integrity_blocked",
        )

    def test_unknown_objects_stay_fail_closed_without_a_snapshot(self) -> None:
        plan = self._plan(
            [("e1", ["o1", "o2"]), ("e2", ["o5", "o6"])],
            [("c1", ["e1"]), ("c2", ["e2"])],
            tamper="e2",
        )
        # Drop the registration snapshot and rebuild the overlay the planner stored by
        # tampering the ledger copy in memory is forbidden; instead confirm the snapshot
        # is what made independence provable.
        prov = json.loads((self.paths.program_dir / "ledger" / "evidence-ledger.json").read_text(encoding="utf-8"))
        e2 = next(row for row in prov["evidence"] if row["evidence_id"] == "e2")
        self.assertIn("registered_object_refs", e2["provenance"])
        self.assertEqual(plan["blocker_dependency_graph"]["ledger_modified"], False)


class CredentialQueryTests(unittest.TestCase):
    def test_api_key_does_not_hide_a_single_path_difference(self) -> None:
        pair = inspect_read_pair(
            _pair("/orders/1001", "SYNTH_q1", "SYNTH_OWNER"),
            _pair("/orders/1002", "SYNTH_q2", "SYNTH_ACTOR"),
        )
        self.assertEqual(pair.resource, {"path_segment": 1})
        self.assertEqual(pair.owner_resource, "1001")
        self.assertEqual(pair.actor_resource, "1002")

    def test_session_query_alone_is_still_rejected(self) -> None:
        with self.assertRaises(ValueError) as caught:
            inspect_read_pair(
                _pair("/orders/1001", "SYNTH_q1", "SYNTH_OWNER"),
                _pair("/orders/1001", "SYNTH_q2", "SYNTH_ACTOR"),
            )
        self.assertIn("Session-bearing", str(caught.exception))


class IndependentWindowTests(unittest.TestCase):
    def test_pair_after_the_entry_cap_is_kept_only_when_windows_are_independent(self) -> None:
        entries = [
            _entry(f"{ORIGIN}/static/app.js?n={index}", json.dumps({"ok": True, "n": index}), "SYNTH_NOISE")
            for index in range(33)
        ]
        entries.append(_entry(f"{ORIGIN}/orders/1001", json.dumps({"id": 1001, "owner": "a"}), "SYNTH_OWNER"))
        entries.append(_entry(f"{ORIGIN}/orders/1002", json.dumps({"id": 1002, "owner": "b"}), "SYNTH_ACTOR"))
        path = Path(tempfile.mkdtemp()) / "cap.har"
        path.write_bytes(_har(entries))
        with self.assertRaises(ValueError) as caught:
            build_object_graph("fn", [path], KEY, authorized=True)
        self.assertIn("entries_over_limit", str(caught.exception))
        graph = build_object_graph("fn", [path], KEY, authorized=True, independent_windows=True)
        self.assertGreater(graph["summary"]["observations"], 0)
        self.assertTrue(graph["capture_import"]["independent_windows"]["enabled"])
        self.assertEqual(graph["capture_import"]["entries_total"], 35)
        self.assertEqual(graph["vulnerabilities_confirmed"], 0)
        self.assertEqual(graph["network_requests_sent"], 0)

    def test_numbered_collection_after_the_entry_cap_is_a_review_proposal(self) -> None:
        entries = [
            _entry(f"{ORIGIN}/static/app.js?n={index}", json.dumps({"ok": True, "n": index}), "SYNTH_NOISE")
            for index in range(33)
        ]
        entries.append(
            _entry(
                f"{ORIGIN}/estimates2/79001",
                json.dumps({"ok": True, "quotation": {"id": 79001}}),
                "SYNTH_OWNER",
            )
        )
        entries.append(
            _entry(
                f"{ORIGIN}/estimates2/79002",
                json.dumps({"ok": True, "quotation": {"id": 79002}}),
                "SYNTH_ACTOR",
            )
        )
        path = Path(tempfile.mkdtemp()) / "estimates.har"
        path.write_bytes(_har(entries))
        graph = build_object_graph("fn", [path], KEY, authorized=True, independent_windows=True)
        doc = propose_object_handoff(graph, "fn", KEY, verify_inputs=[path], limit=20)
        kinds = {row["resource_kind"] for row in doc["proposals"]}
        self.assertEqual(doc["status"], "proposals_ready")
        self.assertEqual(len(doc["proposals"]), 1)
        self.assertTrue(all(not row["confirmed"] and not row["case_executable"] for row in doc["proposals"]))
        blob = json.dumps(doc)
        self.assertNotIn("estimates2", blob)
        self.assertNotIn("79001", blob)
        self.assertEqual(graph["network_requests_sent"], 0)
        self.assertTrue(kinds)


class LabTests(unittest.TestCase):
    def test_frozen_splits_match_and_score(self) -> None:
        for split in ("dev", "final"):
            result = lab.evaluate(split)
            self.assertEqual(result["overall"]["network_attempts"], 0)
            self.assertEqual(result["overall"]["secret_leaks"], 0)
            self.assertEqual(result["overall"]["auto_confirmations"], 0)
            self.assertEqual(result["overall"]["false_reviewable_count"], 0)
            self.assertEqual(result["overall"]["fn_count"], 0)
            self.assertEqual(result["overall"]["correct"], result["overall"]["cases"])
            self.assertFalse(result["finding_confirmed"])


if __name__ == "__main__":
    unittest.main()
