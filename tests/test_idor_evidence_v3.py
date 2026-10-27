"""idor-evidence-correctness-v3: integrity view, session control, access proof, ids, correlation."""

from __future__ import annotations

import base64
import json
import shutil
import tempfile
import unittest
from pathlib import Path

from bugbounty_toolkit.analysis import evidence_ledger as L
from bugbounty_toolkit.analysis.actor_provenance import classify_session_controls
from bugbounty_toolkit.analysis.authorization_denial import (
    assess_pair_authorization,
    assess_raw_response,
    assess_response,
)
from bugbounty_toolkit.analysis.evidence_gap_planner import build_plan, validate_plan
from bugbounty_toolkit.analysis.object_handoff import normalize_captured_identifier
from bugbounty_toolkit.analysis.resource_kind_lineage import correlate_resources
from bugbounty_toolkit.core.records import ProgramPaths
from labs.idor_evidence_v3_eval import evaluate as V3

PRIVATE = 'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{"data":{"id":"7","owner_label":"a","total":"1"}}'
OK = {
    "role": "capture_pair",
    "provides": ["owner_response", "actor_response"],
    "owner_control": "valid",
    "actor_access_proof": "private_resource_200",
}


class AccessProofTests(unittest.TestCase):
    def test_classes(self) -> None:
        self.assertEqual(assess_raw_response(PRIVATE).access_proof, "private_resource_200")
        self.assertEqual(assess_response(200, '{"data":{"id":"7"}}').access_proof, "id_echo_without_resource")
        self.assertEqual(assess_response(200, '{"ok":false,"error":"denied"}').access_proof, "denial_in_200")
        self.assertEqual(assess_response(403, "").access_proof, "http_403")
        self.assertEqual(assess_response(404, "").access_proof, "http_404")
        self.assertEqual(assess_response(302, "", {"Location": "/login"}).access_proof, "login_redirect")
        self.assertEqual(assess_response(500, "x").access_proof, "ambiguous")
        self.assertEqual(
            assess_response(200, '{"data":{"id":"7","visibility":"public","t":"x"}}').access_proof, "public_200"
        )

    def test_echo_respects_requested_id(self) -> None:
        self.assertEqual(assess_response(200, '{"id":"8"}', requested_id="7").access_proof, "ambiguous")
        echo = assess_response(200, '{"id":"7"}', requested_id="7")
        self.assertEqual(echo.access_proof, "id_echo_without_resource")
        self.assertFalse(echo.access_demonstrated)

    def test_pair_echo_and_owner_401_never_promote(self) -> None:
        echo = assess_pair_authorization(PRIVATE, 'HTTP/1.1 200 OK\r\n\r\n{"requested_id":"7","status":"ok"}')
        self.assertEqual(echo.outcome, "inconclusive")
        self.assertEqual((echo.annotation or {})["actor_access_proof"], "id_echo_without_resource")
        broken = assess_pair_authorization("HTTP/1.1 401 Unauthorized\r\n\r\n", PRIVATE)
        self.assertEqual(broken.outcome, "inconclusive")
        self.assertIn("owner_control_broken", broken.reasons)
        self.assertEqual((broken.annotation or {})["owner_control"], "broken")
        ok = assess_pair_authorization(PRIVATE, PRIVATE)
        self.assertEqual(ok.outcome, "possible_access")
        self.assertFalse((ok.annotation or {})["access_confirmed"])


class SessionControlTests(unittest.TestCase):
    def obs(self, s: str, label: str, proof: str, *, att: bool = True, target: str | None = None) -> dict[str, object]:
        row: dict[str, object] = {"session_ref": s, "label": label, "account_attested": att, "access_proof": proof}
        if target:
            row["target_label"] = target
        return row

    def test_isolated_401_is_not_expiry(self) -> None:
        out = classify_session_controls(
            [self.obs("s1", "owner", "private_resource_200"), self.obs("s1", "owner", "http_401")]
        )
        self.assertEqual(out["sessions"]["s1"]["classification"], "identity_unproven")
        self.assertIn("isolated_401_not_expiry", out["sessions"]["s1"]["notes"])
        self.assertFalse(out["sessions"]["s1"]["expiry_proven"])

    def test_owner_loss_makes_later_results_inconclusive(self) -> None:
        out = classify_session_controls(
            [
                self.obs("s1", "owner", "private_resource_200"),
                self.obs("s2", "second_account", "private_resource_200", target="owner"),
                self.obs("s1", "owner", "http_401"),
                self.obs("s1", "owner", "http_401"),
                self.obs("s2", "second_account", "private_resource_200", target="owner"),
            ]
        )
        self.assertEqual(out["sessions"]["s1"]["classification"], "possibly_expired_session")
        self.assertEqual([d["result"] for d in out["dependent_results"]], ["evaluable", "inconclusive"])

    def test_cookies_alone_do_not_prove_identity(self) -> None:
        out = classify_session_controls([self.obs("s1", "owner", "private_resource_200", att=False)])
        self.assertEqual(out["sessions"]["s1"]["classification"], "identity_unproven")
        self.assertFalse(out["owner_control_intact"])


class IdentifierTests(unittest.TestCase):
    def test_opt_in_and_capture_bound(self) -> None:
        v = base64.b64encode(b"42").decode()
        self.assertEqual(normalize_captured_identifier(v, captured_values={v})["status"], "disabled")
        self.assertEqual(
            normalize_captured_identifier("43", captured_values={"42"}, enabled=True)["status"],
            "refused_not_in_capture",
        )
        out = normalize_captured_identifier(v, captured_values={v}, kind="order", enabled=True)
        self.assertEqual(out["namespace_key"], "order:numeric:42")
        self.assertEqual(out["transforms"], ["base64_decode", "canonicalize_numeric"])
        self.assertEqual(out["generated_values"], 0)

    def test_json_then_base64url_and_failed_decode(self) -> None:
        v = base64.urlsafe_b64encode(json.dumps({"id": "0099"}).encode()).decode().rstrip("=")
        out = normalize_captured_identifier(v, captured_values={v}, kind="t", enabled=True)
        self.assertEqual(out["namespace_key"], "t:numeric:99")
        bad = normalize_captured_identifier("@@", captured_values={"@@"}, enabled=True)
        self.assertEqual(bad["status"], "undecodable")
        self.assertFalse(bad["denial_evidence"])


class CorrelationTests(unittest.TestCase):
    def side(self, **kw: object) -> dict[str, object]:
        base: dict[str, object] = {
            "kind": "kind:order",
            "kind_status": "explicit",
            "namespace_key": "order:numeric:1",
            "account_ref": "a",
            "distinct_accounts_attested": True,
            "session_ref": "s1",
            "visibility": "private",
            "body_digest": "d1",
        }
        base.update(kw)
        return base

    def test_rules(self) -> None:
        other_kind = correlate_resources(self.side(), self.side(kind="kind:user", namespace_key="user:numeric:1"))
        self.assertEqual(other_kind["relation"], "different_kind")
        cookies = correlate_resources(
            self.side(account_ref=None, distinct_accounts_attested=False),
            self.side(account_ref=None, distinct_accounts_attested=False, session_ref="s2"),
        )
        self.assertEqual(cookies["accounts"], "unknown")
        shared = correlate_resources(self.side(visibility="shared"), self.side(account_ref="b", visibility="shared"))
        self.assertTrue(shared["legitimate_shared"])
        self.assertFalse(shared["idor_review_signal"])
        amb = correlate_resources(self.side(kind_status="ambiguous"), self.side(account_ref="b"))
        self.assertEqual(amb["relation"], "unknown")
        good = correlate_resources(self.side(), self.side(account_ref="b", session_ref="s2", body_digest="d2"))
        self.assertTrue(good["idor_review_signal"])
        self.assertEqual(good["resource_kind"], "kind:order")
        self.assertFalse(good["confirmed"])


class EffectiveEligibilityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.work = Path(tempfile.mkdtemp())
        self.paths = ProgramPaths(self.work, "p")
        (self.paths.program_dir / "evidence").mkdir(parents=True)

    def tearDown(self) -> None:
        shutil.rmtree(self.work, ignore_errors=True)

    def _ledger(self, controls: dict[str, dict[str, object]], cands: dict[str, list[str]]) -> Path:
        led = L.new_ledger("p")
        L.upsert_surface(led, {"surface_id": "s1", "kind": "endpoint", "ref": "/x", "status": "investigated"})
        for eid, ctl in controls.items():
            rel = f"evidence/{eid}.json"
            body = {"control": {"annotation_version": "bbtk-control-annotation/1", **ctl}}
            (self.paths.program_dir / rel).write_text(json.dumps(body), encoding="utf-8")
            L.add_evidence(led, self.paths.program_dir, eid, rel, tool="t")
        for cid, refs in cands.items():
            L.add_candidate(led, cid, "s1", "idor", "r", refs, dedup_key=cid)
            L.review_candidate(led, cid, "requires_validation", "r", blockers=["human"])
        path = self.paths.program_dir / "ledger" / "evidence-ledger.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(led), encoding="utf-8")
        return path

    def test_tamper_blocks_without_rewriting_history(self) -> None:
        path = self._ledger({"e1": OK}, {"c1": ["e1"]})
        plan = build_plan(self.paths)
        self.assertTrue(plan["effective_eligibility"][0]["effective_reviewable"])
        ev = self.paths.program_dir / "evidence" / "e1.json"
        ev.write_text(ev.read_text(encoding="utf-8") + " ", encoding="utf-8")
        before = path.read_bytes()
        plan = build_plan(self.paths)
        row = plan["effective_eligibility"][0]
        self.assertEqual((row["ledger_state"], row["effective_state"]), ("requires_validation", "blocked"))
        self.assertFalse(row["effective_reviewable"])
        self.assertEqual(path.read_bytes(), before)
        self.assertEqual(validate_plan(plan), [])

    def test_broken_ref_with_valid_ref_is_integrity_blocked(self) -> None:
        self._ledger({"e1": OK}, {"c1": ["e1", "ghost"]})
        plan = build_plan(self.paths)
        self.assertEqual(plan["candidates"][0]["status"], "integrity_blocked")

    def test_out_of_program_and_owner_control(self) -> None:
        self._ledger(
            {"e1": {**OK, "program": "other"}, "e2": {**OK, "owner_control": "broken"}}, {"c1": ["e1"], "c2": ["e2"]}
        )
        rows = {r["candidate_id"]: r for r in build_plan(self.paths)["effective_eligibility"]}
        self.assertFalse(rows["c1"]["effective_reviewable"])
        self.assertIn("session_control", rows["c2"]["blockers"])


class LabTests(unittest.TestCase):
    def test_v3_final_frozen_and_safe(self) -> None:
        result = V3.evaluate()
        o = result["overall"]
        self.assertEqual(o["network_attempts"], 0)
        self.assertEqual(o["false_reviewable_cases"], 0)
        self.assertTrue(o["ledger_history_unmodified"])
        self.assertGreaterEqual(o["outcome_accuracy"], 0.95)

    def test_v3_tamper_detected(self) -> None:
        d = Path(tempfile.mkdtemp())
        try:
            shutil.copytree(V3.HERE / "final", d / "final")
            (d / "final" / "scenarios.json").write_text("{}", encoding="utf-8")
            with self.assertRaises(V3.FrozenCorpusError):
                V3.load_scenarios(d / "final")
        finally:
            shutil.rmtree(d, ignore_errors=True)


class IrbIntegrityRegressionTests(unittest.TestCase):
    """The six historical integrity false-reviewables (IRB FINAL D11-D16, labels frozen)."""

    def test_d11_to_d16_not_reviewable(self) -> None:
        from labs.independent_research_eval import evaluate as irb

        split = irb.HERE / "final"
        self.assertEqual(irb.manifest_mismatches(split), [])
        gt = json.loads((split / "ground_truth.json").read_text(encoding="utf-8"))
        for sc in gt["scenarios"]:
            if sc["id"] in {"D11", "D12", "D13", "D14", "D15", "D16"}:
                row = irb.score(sc, irb.run_scenario(split, sc))
                self.assertFalse(row["predicted_reviewable"], sc["id"])
                self.assertTrue(row["ledger_raw_reviewable"], sc["id"])  # history kept as recorded
                self.assertTrue(row["outcome_correct"], sc["id"])


if __name__ == "__main__":
    unittest.main()
