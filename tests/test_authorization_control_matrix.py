"""Authorization control matrix: cells, session continuity, and fail-closed comparisons."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
import unittest

import bugbounty_toolkit
from bugbounty_toolkit.analysis import authorization_control_matrix as matrix_module
from bugbounty_toolkit.analysis.authorization_control_matrix import (
    ANNOTATION_SCHEMA,
    CONTROL_TYPES,
    OBSERVATION_FIELDS,
    REASON_CODES,
    SCHEMA,
    evaluate_control_matrix,
)
from bugbounty_toolkit.analysis.authorization_denial import assess_response
from labs.authorization_control_matrix_eval.evaluate import run_split

PRIVATE = '{"ok": true, "data": {"id": "SYNTH_obj", "marker": "synthetic-private"}}'
SECOND_PRIVATE = '{"ok": true, "data": {"id": "SYNTH_obj_b", "marker": "synthetic-private"}}'
DENY_BODY = '{"ok": false, "error": "access denied"}'
ECHO = '{"id": "SYNTH_obj", "status": "ok"}'
PUBLIC = '{"visibility": "public", "data": {"id": "SYNTH_pub", "marker": "synthetic-public"}}'
SHARED = '{"visibility": "shared", "shared_with": ["SYNTH_acct_b"], "data": {"id": "SYNTH_sh", "marker": "synthetic"}}'


def _cap(
    evidence: str,
    actor: str,
    resource: str,
    owner: str,
    order: int,
    status: int,
    body: str,
    *,
    session: str,
    token: str,
    account: str,
    attested: bool = True,
    control_type: str | None = None,
    negative: bool = False,
    recheck: bool = False,
    timestamp: str | None = None,
    timestamp_reliable: bool = True,
    integrity: str = "intact",
    session_change_proven: bool = False,
    identity_change_proven: bool = False,
    requested_id: str | None = None,
    expected: str = "unknown",
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    row: dict[str, Any] = {
        "evidence_ref": evidence,
        "actor_label": actor,
        "resource_ref": resource,
        "resource_owner_label": owner,
        "capture_order": order,
        "observed_status": status,
        "body": body,
        "headers": {},
        "integrity_status": integrity,
        "session_ref": session,
        "token_ref": token,
        "expected_access_declared": expected,
        "timestamp": timestamp,
        "timestamp_reliable": timestamp_reliable,
        "provenance": {
            "account_attested": attested,
            "declared_account_ref": account,
            "session_change_proven": session_change_proven,
            "identity_change_proven": identity_change_proven,
        },
    }
    if control_type:
        row["control_type"] = control_type
    if negative:
        row["is_negative_control"] = True
        row["control_type"] = "negative_control"
    if recheck:
        row["is_recheck"] = True
        row["control_type"] = "owner_recheck"
    if requested_id:
        row["requested_id"] = requested_id
    if extra:
        row.update(extra)
    return row


def _trio(cross_status: int = 403, cross_body: str = '{"error": "forbidden"}') -> list[dict[str, Any]]:
    return [
        _cap(
            "ev-owner",
            "owner",
            "SYNTH_res_owner",
            "owner",
            0,
            200,
            PRIVATE,
            session="SYNTH_sess_owner",
            token="SYNTH_tok_owner",
            account="SYNTH_acct_owner",
        ),
        _cap(
            "ev-second",
            "second",
            "SYNTH_res_second",
            "second",
            1,
            200,
            SECOND_PRIVATE,
            session="SYNTH_sess_second",
            token="SYNTH_tok_second",
            account="SYNTH_acct_second",
        ),
        _cap(
            "ev-cross",
            "second",
            "SYNTH_res_owner",
            "owner",
            2,
            cross_status,
            cross_body,
            session="SYNTH_sess_second",
            token="SYNTH_tok_second",
            account="SYNTH_acct_second",
            expected="deny",
        ),
    ]


class ControlMatrixTests(unittest.TestCase):
    def test_schema_and_reason_catalog(self) -> None:
        self.assertEqual(SCHEMA, "bbtk.authorization-control-matrix/1")
        self.assertEqual(len(CONTROL_TYPES), 7)
        self.assertIn("COMPLETE_CONTROL_SET", REASON_CODES)
        result = evaluate_control_matrix(_trio())
        self.assertFalse(result["finding_confirmed"])
        self.assertFalse(result["negative_finding"])
        self.assertFalse(result["annotation"]["finding_confirmed"])
        self.assertTrue(result["annotation"]["safe_to_ignore"])
        self.assertEqual(result["annotation"]["schema"], ANNOTATION_SCHEMA)
        self.assertEqual(result["external_requests"], 0)
        self.assertFalse(result["actors_invented"])
        for record in result["observations"]:
            self.assertEqual(tuple(OBSERVATION_FIELDS), tuple(record))

    def test_complete_denial_is_not_a_finding(self) -> None:
        result = evaluate_control_matrix(_trio())
        self.assertEqual(result["disposition"], "complete")
        self.assertTrue(result["denial_consistent"])
        self.assertFalse(result["negative_finding"])
        self.assertFalse(result["access_claim"])
        self.assertIn("COMPLETE_CONTROL_SET", result["reason_codes"])
        self.assertIn("owner_valid_before_cross", result["rules_fired"])
        self.assertNotIn("SESSION_POSSIBLY_EXPIRED", result["reason_codes"])
        self.assertEqual(result["sessions"]["SYNTH_sess_owner"]["state"], "valid")
        self.assertFalse(result["sessions"]["SYNTH_sess_owner"]["expiry_proven"])

    def test_private_cross_access_stays_unconfirmed(self) -> None:
        result = evaluate_control_matrix(_trio(200, PRIVATE))
        self.assertEqual(result["disposition"], "complete")
        self.assertFalse(result["denial_consistent"])
        self.assertTrue(result["access_review_supported"])
        self.assertFalse(result["access_claim"])
        self.assertFalse(result["finding_confirmed"])
        self.assertFalse(result["access_unsupported"])

    def test_missing_owner_is_blocked_not_negative(self) -> None:
        result = evaluate_control_matrix(_trio()[1:])
        self.assertEqual(result["disposition"], "blocked")
        self.assertIn("OWNER_CONTROL_MISSING", result["reason_codes"])
        self.assertFalse(result["denial_consistent"])
        self.assertFalse(result["negative_finding"])
        self.assertNotIn("COMPLETE_CONTROL_SET", result["reason_codes"])

    def test_missing_cross_and_missing_actor(self) -> None:
        owner_and_second = _trio()[:2]
        missing_cross = evaluate_control_matrix(owner_and_second)
        self.assertIn("CROSS_CAPTURE_MISSING", missing_cross["reason_codes"])
        self.assertEqual(missing_cross["disposition"], "blocked")
        self.assertFalse(missing_cross["denial_consistent"])
        missing_actor = evaluate_control_matrix([_trio()[0], _trio()[2]])
        self.assertIn("ACTOR_CONTROL_MISSING", missing_actor["reason_codes"])
        self.assertFalse(missing_actor["negative_finding"])

    def test_isolated_401_is_not_expiration(self) -> None:
        rows = _trio()
        rows.insert(
            1,
            _cap(
                "ev-iso",
                "owner",
                "SYNTH_res_owner",
                "owner",
                1,
                401,
                '{"error": "unauthorized"}',
                session="SYNTH_sess_owner",
                token="SYNTH_tok_owner",
                account="SYNTH_acct_owner",
            ),
        )
        rows[2]["capture_order"] = 2
        rows[3]["capture_order"] = 3
        result = evaluate_control_matrix(rows)
        self.assertIn("isolated_401", result["rules_fired"])
        self.assertNotIn("SESSION_POSSIBLY_EXPIRED", result["reason_codes"])
        self.assertNotIn("possibly_expired_session", result["rules_fired"])
        self.assertEqual(result["sessions"]["SYNTH_sess_owner"]["state"], "valid")
        self.assertFalse(result["sessions"]["SYNTH_sess_owner"]["expiry_proven"])
        self.assertTrue(result["denial_consistent"])

    def test_repeated_401_is_possibly_expired_and_unproven(self) -> None:
        rows = [
            _cap(
                "ev-owner",
                "owner",
                "SYNTH_res_owner",
                "owner",
                0,
                200,
                PRIVATE,
                session="SYNTH_sess_owner",
                token="SYNTH_tok_owner",
                account="SYNTH_acct_owner",
            ),
            _cap(
                "ev-a",
                "owner",
                "SYNTH_res_owner",
                "owner",
                1,
                401,
                '{"error": "unauthorized"}',
                session="SYNTH_sess_owner",
                token="SYNTH_tok_owner",
                account="SYNTH_acct_owner",
            ),
            _cap(
                "ev-b",
                "owner",
                "SYNTH_res_owner",
                "owner",
                2,
                401,
                '{"error": "unauthorized"}',
                session="SYNTH_sess_owner",
                token="SYNTH_tok_owner",
                account="SYNTH_acct_owner",
            ),
            _cap(
                "ev-second",
                "second",
                "SYNTH_res_second",
                "second",
                3,
                200,
                SECOND_PRIVATE,
                session="SYNTH_sess_second",
                token="SYNTH_tok_second",
                account="SYNTH_acct_second",
            ),
            _cap(
                "ev-cross",
                "second",
                "SYNTH_res_owner",
                "owner",
                4,
                403,
                '{"error": "forbidden"}',
                session="SYNTH_sess_second",
                token="SYNTH_tok_second",
                account="SYNTH_acct_second",
            ),
        ]
        result = evaluate_control_matrix(rows)
        self.assertEqual(result["sessions"]["SYNTH_sess_owner"]["state"], "possibly_expired")
        self.assertFalse(result["sessions"]["SYNTH_sess_owner"]["expiry_proven"])
        self.assertIn("SESSION_POSSIBLY_EXPIRED", result["reason_codes"])
        self.assertIn("repeated_401", result["rules_fired"])
        self.assertFalse(result["denial_consistent"])
        self.assertEqual(result["disposition"], "inconclusive")

    def test_login_redirect_after_success_is_not_proven_expiry(self) -> None:
        rows = _trio()
        rows.insert(
            1,
            _cap(
                "ev-login",
                "owner",
                "SYNTH_res_owner",
                "owner",
                1,
                302,
                "",
                session="SYNTH_sess_owner",
                token="SYNTH_tok_owner",
                account="SYNTH_acct_owner",
                extra={"headers": {"Location": "/login"}},
            ),
        )
        rows[2]["capture_order"] = 2
        rows[3]["capture_order"] = 3
        result = evaluate_control_matrix(rows)
        self.assertIn("login_redirect", result["rules_fired"])
        self.assertIn("possibly_expired_session", result["rules_fired"])
        self.assertFalse(result["session_continuity"]["expiry_proven"])
        self.assertFalse(result["denial_consistent"])

    def test_owner_and_actor_invalid_sessions(self) -> None:
        owner_invalid = _trio()
        owner_invalid[0]["observed_status"] = 401
        owner_invalid[0]["body"] = '{"error": "unauthorized"}'
        owner = evaluate_control_matrix(owner_invalid)
        self.assertEqual(owner["sessions"]["SYNTH_sess_owner"]["state"], "invalid")
        self.assertIn("owner_invalid", owner["rules_fired"])
        self.assertIn("OWNER_CONTROL_BROKEN", owner["reason_codes"])
        self.assertIn("owner_control_broken", owner["reused_reason_codes"])
        self.assertNotIn("SESSION_POSSIBLY_EXPIRED", owner["reason_codes"])
        self.assertFalse(owner["denial_consistent"])
        actor_invalid = _trio()
        actor_invalid[1]["observed_status"] = 401
        actor_invalid[1]["body"] = '{"error": "unauthorized"}'
        actor = evaluate_control_matrix(actor_invalid)
        self.assertEqual(actor["sessions"]["SYNTH_sess_second"]["state"], "invalid")
        self.assertIn("actor_invalid", actor["rules_fired"])
        self.assertIn("ACTOR_CONTROL_MISSING", actor["reason_codes"])
        self.assertFalse(actor["denial_consistent"])

    def test_token_change_without_proof_is_not_a_new_identity(self) -> None:
        rows = _trio()
        rows[0]["token_ref"] = "SYNTH_tok_owner_a"
        rows.insert(
            1,
            _cap(
                "ev-rot",
                "owner",
                "SYNTH_res_owner",
                "owner",
                1,
                200,
                PRIVATE,
                session="SYNTH_sess_owner",
                token="SYNTH_tok_owner_b",
                account="SYNTH_acct_owner",
            ),
        )
        rows[2]["capture_order"] = 2
        rows[3]["capture_order"] = 3
        result = evaluate_control_matrix(rows)
        self.assertIn("rotated_token", result["rules_fired"])
        self.assertFalse(result["session_continuity"]["identity_changed"])
        self.assertFalse(result["actors_invented"])
        self.assertTrue(result["denial_consistent"])
        blob = json.dumps(result)
        self.assertNotIn("SYNTH_tok_owner_a", blob)
        self.assertNotIn("SYNTH_tok_owner_b", blob)

    def test_proven_identity_change_does_not_invent_an_actor(self) -> None:
        rows = _trio()
        rows.insert(
            1,
            _cap(
                "ev-id",
                "owner",
                "SYNTH_res_owner",
                "owner",
                1,
                200,
                PRIVATE,
                session="SYNTH_sess_owner",
                token="SYNTH_tok_owner_b",
                account="SYNTH_acct_other",
                identity_change_proven=True,
            ),
        )
        rows[0]["token_ref"] = "SYNTH_tok_owner_a"
        rows[2]["capture_order"] = 2
        rows[3]["capture_order"] = 3
        result = evaluate_control_matrix(rows)
        self.assertTrue(result["session_continuity"]["identity_changed"])
        self.assertFalse(result["denial_consistent"])
        self.assertEqual(result["disposition"], "inconclusive")
        labels = {row["actor_label"] for row in result["observations"]}
        self.assertTrue(labels <= {"owner", "second", "anonymous", "unknown"})

    def test_public_shared_echo_and_body_denial(self) -> None:
        public = evaluate_control_matrix(
            [
                _cap(
                    "ev-pub",
                    "owner",
                    "SYNTH_res_pub",
                    "owner",
                    0,
                    200,
                    PUBLIC,
                    session="SYNTH_sess_owner",
                    token="SYNTH_tok_owner",
                    account="SYNTH_acct_owner",
                    expected="public",
                ),
                _cap(
                    "ev-pub-b",
                    "second",
                    "SYNTH_res_pub",
                    "owner",
                    1,
                    200,
                    PUBLIC,
                    session="SYNTH_sess_second",
                    token="SYNTH_tok_second",
                    account="SYNTH_acct_second",
                    expected="public",
                ),
            ]
        )
        self.assertIn("PUBLIC_RESOURCE_CONTROL", public["reason_codes"])
        self.assertIn("public_or_shared_resource", public["reused_reason_codes"])
        self.assertIn("public_resource", public["rules_fired"])
        self.assertFalse(public["denial_consistent"])
        self.assertFalse(public["negative_finding"])
        self.assertTrue(public["cells"]["public_shared_control"]["present"])
        shared = evaluate_control_matrix(
            [
                _cap(
                    "ev-sh",
                    "owner",
                    "SYNTH_res_sh",
                    "owner",
                    0,
                    200,
                    SHARED,
                    session="SYNTH_sess_owner",
                    token="SYNTH_tok_owner",
                    account="SYNTH_acct_owner",
                    expected="shared",
                ),
            ]
        )
        self.assertIn("SHARED_RESOURCE_CONTROL", shared["reason_codes"])
        self.assertIn("shared_resource", shared["rules_fired"])
        echo_rows = _trio(200, ECHO)
        echo_rows[2]["requested_id"] = "SYNTH_obj"
        echo = evaluate_control_matrix(echo_rows)
        self.assertIn("ID_ECHO_ONLY", echo["reason_codes"])
        self.assertIn("id_echo_without_resource", echo["reused_reason_codes"])
        self.assertEqual(echo["disposition"], "inconclusive")
        self.assertFalse(echo["denial_consistent"])
        self.assertFalse(echo["access_claim"])
        body_denial = evaluate_control_matrix(_trio(200, DENY_BODY))
        self.assertTrue(body_denial["denial_consistent"])
        self.assertEqual(body_denial["disposition"], "complete")
        self.assertFalse(body_denial["finding_confirmed"])

    def test_deleted_resource_and_confirmed_404_denial(self) -> None:
        deleted_rows = [
            _cap(
                "ev-owner",
                "owner",
                "SYNTH_res_owner",
                "owner",
                0,
                200,
                PRIVATE,
                session="SYNTH_sess_owner",
                token="SYNTH_tok_owner",
                account="SYNTH_acct_owner",
            ),
            _cap(
                "ev-second",
                "second",
                "SYNTH_res_second",
                "second",
                1,
                200,
                SECOND_PRIVATE,
                session="SYNTH_sess_second",
                token="SYNTH_tok_second",
                account="SYNTH_acct_second",
            ),
            _cap(
                "ev-cross",
                "second",
                "SYNTH_res_owner",
                "owner",
                2,
                404,
                '{"error": "not found"}',
                session="SYNTH_sess_second",
                token="SYNTH_tok_second",
                account="SYNTH_acct_second",
            ),
            _cap(
                "ev-re",
                "owner",
                "SYNTH_res_owner",
                "owner",
                3,
                404,
                '{"error": "not found"}',
                session="SYNTH_sess_owner",
                token="SYNTH_tok_owner",
                account="SYNTH_acct_owner",
            ),
        ]
        deleted = evaluate_control_matrix(deleted_rows)
        self.assertIn("deleted_resource", deleted["rules_fired"])
        self.assertNotIn("SESSION_POSSIBLY_EXPIRED", deleted["reason_codes"])
        self.assertFalse(deleted["denial_consistent"])
        self.assertEqual(deleted["disposition"], "inconclusive")
        confirmed = evaluate_control_matrix(
            [
                deleted_rows[0],
                deleted_rows[1],
                deleted_rows[2],
                _cap(
                    "ev-re",
                    "owner",
                    "SYNTH_res_owner",
                    "owner",
                    3,
                    200,
                    PRIVATE,
                    session="SYNTH_sess_owner",
                    token="SYNTH_tok_owner",
                    account="SYNTH_acct_owner",
                ),
            ]
        )
        self.assertTrue(confirmed["denial_consistent"])
        self.assertNotIn("deleted_resource", confirmed["rules_fired"])
        self.assertTrue(confirmed["cells"]["owner_recheck"]["present"])

    def test_session_change_and_unreliable_or_ambiguous_order(self) -> None:
        changed = _trio()
        changed.insert(
            1,
            _cap(
                "ev-new",
                "owner",
                "SYNTH_res_owner",
                "owner",
                1,
                200,
                PRIVATE,
                session="SYNTH_sess_owner_b",
                token="SYNTH_tok_owner",
                account="SYNTH_acct_owner",
                session_change_proven=True,
            ),
        )
        changed[2]["capture_order"] = 2
        changed[3]["capture_order"] = 3
        proven = evaluate_control_matrix(changed)
        self.assertIn("session_change_mid_capture", proven["rules_fired"])
        self.assertFalse(proven["session_continuity"]["identity_changed"])
        self.assertTrue(proven["denial_consistent"])
        changed[1]["provenance"]["session_change_proven"] = False
        unproven = evaluate_control_matrix(changed)
        self.assertTrue(unproven["session_continuity"]["unproven_session_change"])
        self.assertFalse(unproven["session_continuity"]["identity_changed"])
        self.assertEqual(unproven["disposition"], "inconclusive")
        self.assertFalse(unproven["denial_consistent"])

        unreliable = _trio()
        for index, row in enumerate(unreliable):
            row["timestamp"] = f"2026-10-27T00:00:0{2 - index}Z"
            row["timestamp_reliable"] = False
        unreliable_result = evaluate_control_matrix(unreliable)
        self.assertIn("unreliable_timestamps", unreliable_result["rules_fired"])
        self.assertNotIn("CAPTURE_ORDER_AMBIGUOUS", unreliable_result["reason_codes"])
        self.assertTrue(unreliable_result["denial_consistent"])

        ambiguous = _trio()
        for index, row in enumerate(ambiguous):
            row["timestamp"] = f"2026-10-27T00:00:0{2 - index}Z"
            row["timestamp_reliable"] = True
        ambiguous_result = evaluate_control_matrix(ambiguous)
        self.assertIn("CAPTURE_ORDER_AMBIGUOUS", ambiguous_result["reason_codes"])
        self.assertIn("out_of_order_captures", ambiguous_result["rules_fired"])
        self.assertFalse(ambiguous_result["denial_consistent"])
        self.assertEqual(ambiguous_result["disposition"], "inconclusive")

    def test_out_of_order_owner_recheck_is_not_a_negative(self) -> None:
        rows = [
            _cap(
                "ev-re",
                "owner",
                "SYNTH_res_owner",
                "owner",
                0,
                200,
                PRIVATE,
                session="SYNTH_sess_owner",
                token="SYNTH_tok_owner",
                account="SYNTH_acct_owner",
                recheck=True,
            ),
            _cap(
                "ev-second",
                "second",
                "SYNTH_res_second",
                "second",
                1,
                200,
                SECOND_PRIVATE,
                session="SYNTH_sess_second",
                token="SYNTH_tok_second",
                account="SYNTH_acct_second",
            ),
            _cap(
                "ev-cross",
                "second",
                "SYNTH_res_owner",
                "owner",
                2,
                403,
                '{"error": "forbidden"}',
                session="SYNTH_sess_second",
                token="SYNTH_tok_second",
                account="SYNTH_acct_second",
            ),
        ]
        result = evaluate_control_matrix(rows)
        self.assertIn("OWNER_CONTROL_MISSING", result["reason_codes"])
        self.assertIn("CAPTURE_ORDER_AMBIGUOUS", result["reason_codes"])
        self.assertIn("out_of_order_captures", result["rules_fired"])
        self.assertEqual(result["disposition"], "blocked")
        self.assertFalse(result["denial_consistent"])
        self.assertFalse(result["negative_finding"])

    def test_optional_cells_and_anonymous_scope(self) -> None:
        rows = _trio()
        rows.append(
            _cap(
                "ev-neg",
                "second",
                "SYNTH_res_other",
                "owner",
                3,
                403,
                '{"error": "forbidden"}',
                session="SYNTH_sess_second",
                token="SYNTH_tok_second",
                account="SYNTH_acct_second",
                negative=True,
                expected="deny",
            )
        )
        result = evaluate_control_matrix(rows)
        self.assertTrue(result["cells"]["negative_control"]["present"])
        self.assertTrue(result["cells"]["negative_control"]["usable"])
        self.assertTrue(result["denial_consistent"])
        anon_rows = list(rows)
        anon_rows.append(
            _cap(
                "ev-anon",
                "anonymous",
                "SYNTH_res_owner",
                "owner",
                4,
                401,
                '{"error": "unauthorized"}',
                session="",
                token="SYNTH_tok_anon",
                account="SYNTH_acct_anon",
                attested=False,
            )
        )
        anon_rows[-1]["session_ref"] = None
        covered = evaluate_control_matrix(anon_rows, comparison_scope="owner_second_anonymous")
        self.assertTrue(covered["cells"]["anonymous"]["usable"])
        self.assertEqual(covered["sessions"]["anonymous"]["state"], "anonymous")
        missing_anon = evaluate_control_matrix(rows, comparison_scope="owner_second_anonymous")
        self.assertEqual(missing_anon["disposition"], "blocked")
        self.assertFalse(missing_anon["denial_consistent"])

    def test_second_account_alias_and_secret_material_is_withheld(self) -> None:
        rows = _trio()
        rows[1]["actor_label"] = "second_account"
        rows[2]["actor_label"] = "actor"
        result = evaluate_control_matrix(rows)
        self.assertTrue(result["denial_consistent"])
        self.assertEqual({row["actor_label"] for row in result["observations"][1:]}, {"second"})
        leaked = _trio()
        leaked[0]["token_ref"] = "CANARY_SECRET_do_not_copy"
        leaked[0]["authorization"] = "Bearer CANARY_SECRET_do_not_copy"
        leaked[0]["body"] = PRIVATE + " CANARY_SECRET_do_not_copy"
        withheld = evaluate_control_matrix(leaked)
        blob = json.dumps(withheld)
        self.assertNotIn("CANARY_SECRET", blob)
        self.assertNotIn("Bearer", blob)
        self.assertIn("token_ref_withheld", withheld["observations"][0]["uncertainty"])

    def test_input_is_not_mutated_and_denial_authority_is_reused(self) -> None:
        rows = _trio()
        snapshot = json.dumps(rows)
        evaluate_control_matrix(rows)
        self.assertEqual(json.dumps(rows), snapshot)
        proof = assess_response(200, ECHO, requested_id="SYNTH_obj").access_proof
        self.assertEqual(proof, "id_echo_without_resource")

    def test_unattested_session_does_not_become_valid(self) -> None:
        rows = _trio()
        rows[0]["provenance"]["account_attested"] = False
        result = evaluate_control_matrix(rows)
        self.assertEqual(result["sessions"]["SYNTH_sess_owner"]["state"], "identity_unproven")
        self.assertIn("OWNER_CONTROL_MISSING", result["reason_codes"])
        self.assertFalse(result["denial_consistent"])
        self.assertTrue(result["provenance_complete"])
        self.assertIsNotNone(result["observations"][0]["evidence_ref"])

    def test_module_does_not_call_ranking_or_pairing(self) -> None:
        source = matrix_module.__file__
        assert source is not None
        text = Path(source).read_text(encoding="utf-8")
        self.assertNotIn("content_ranking", text)
        self.assertNotIn("access_control.comparison", text)
        self.assertNotIn("object_handoff", text)
        self.assertNotIn("prioritization", text)
        self.assertEqual(bugbounty_toolkit.__version__, "0.2.2")


class ControlMatrixLabTests(unittest.TestCase):
    def test_frozen_dev_and_final_metrics(self) -> None:
        dev = run_split("dev")
        final = run_split("final")
        for report in (dev, final):
            self.assertEqual(report["failures"], [])
            self.assertEqual(report["external_requests"], 0)
            self.assertEqual(report["secret_leaks"], 0)
            self.assertFalse(report["finding_confirmed"])
            metrics = report["matrix"]
            self.assertEqual(metrics["session_control_accuracy"], 1.0)
            self.assertEqual(metrics["access_control_coverage"], 1.0)
            self.assertEqual(metrics["correct_inconclusive_rate"], 1.0)
            self.assertEqual(metrics["false_denial_inference_rate"], 0.0)
            self.assertEqual(metrics["unsupported_access_claims"], 0)
            self.assertEqual(metrics["missing_control_recall"], 1.0)
            self.assertEqual(metrics["invalid_session_inference_rate"], 1.0)
            self.assertEqual(metrics["provenance_completeness"], 1.0)
            self.assertEqual(metrics["finding_confirmed_true_count"], 0)
            self.assertEqual(len(metrics["cells_covered"]), 7)
        baseline = final["naive_baseline"]
        self.assertGreater(baseline["false_denial_inference_rate"], 0)
        self.assertGreater(baseline["unsupported_access_claims"], 0)
        self.assertLess(baseline["session_control_accuracy"], 1)
        self.assertEqual(baseline["missing_control_recall"], 0)


if __name__ == "__main__":
    unittest.main()
