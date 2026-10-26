"""Unit + corpus tests for authorization-denial-aware case assessment."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from bugbounty_toolkit.analysis.authorization_denial import (
    ANNOTATION_VERSION,
    assess_pair_authorization,
    assess_raw_response,
    assess_response,
)
from bugbounty_toolkit.analysis.idor_e2e_research import run_e2e_research
from bugbounty_toolkit.analysis.evidence_gap_planner import build_plan
from bugbounty_toolkit.core.records import ProgramPaths

LAB = Path(__file__).resolve().parents[1] / "labs" / "authorization_denial_eval"
IRB_FINAL = Path(__file__).resolve().parents[1] / "labs" / "independent_research_eval" / "final" / "captures"
KEY = b"\x00" * 32


def _raw(status: int, body: str, *, location: str | None = None) -> str:
    headers = ["Content-Type: application/json"]
    if location:
        headers.append(f"Location: {location}")
    return f"HTTP/1.1 {status} X\r\n" + "\r\n".join(headers) + "\r\n\r\n" + body


def test_http_403_with_denial_body_is_denied() -> None:
    a = assess_response(403, '{"error":"forbidden","ok":false}')
    assert a.denial_demonstrated is True
    assert a.response_class == "http_denial"


def test_http_401_and_404_are_denied() -> None:
    assert assess_response(401, '{"error":"unauthenticated","ok":false}').denial_demonstrated
    assert assess_response(404, '{"error":"not_found","ok":false}').denial_demonstrated


def test_http_200_with_denial_body_is_content_denial() -> None:
    a = assess_response(200, '{"contract":null,"error":"not_authorized","ok":false}')
    assert a.denial_demonstrated is True
    assert a.content_denial is True
    assert a.response_class == "content_denial"


def test_http_200_with_resource_payload_is_not_denial() -> None:
    a = assess_response(
        200,
        '{"ok":true,"statement":{"id":1,"marker":"m","owner_label":"owner"}}',
    )
    assert a.denial_demonstrated is False
    assert a.access_demonstrated is True


def test_contradictory_403_with_owner_data_stays_inconclusive() -> None:
    """A06-style: status says denied but body returns private resource data."""
    a = assess_response(
        403,
        '{"claim":{"id":74302,"marker":"irb-claim-owner-74302","owner_label":"owner"},"ok":true}',
    )
    assert a.denial_demonstrated is False
    assert a.access_demonstrated is True
    assert a.response_class == "successful_looking"


def test_auth_redirect_302_to_login_is_denied() -> None:
    a = assess_response(302, "", {"location": "http://127.0.0.1:8177/login"})
    assert a.denial_demonstrated is True
    assert a.response_class == "auth_redirect"


def test_public_visibility_is_not_cross_account_denial() -> None:
    a = assess_response(200, '{"item":{"id":1,"visibility":"public"},"ok":true}')
    assert a.resource_visibility == "public"
    assert a.denial_demonstrated is False


def test_pair_owner_success_actor_denied_is_negative_control() -> None:
    owner = _raw(200, '{"ok":true,"payslip":{"id":1,"marker":"m","owner_label":"owner"}}')
    actor = _raw(403, '{"error":"forbidden","ok":false}')
    out = assess_pair_authorization(owner, actor)
    assert out.outcome == "cross_account_denied"
    assert out.annotation is not None
    assert out.annotation["annotation_version"] == ANNOTATION_VERSION
    assert out.annotation["role"] == "negative_control"
    assert out.annotation["contradicts_hypothesis"] is True


def test_pair_both_success_is_possible_access_not_confirmed() -> None:
    owner = _raw(200, '{"ok":true,"statement":{"id":1,"marker":"m","owner_label":"owner"}}')
    actor = _raw(200, '{"ok":true,"statement":{"id":1,"marker":"m","owner_label":"owner"}}')
    out = assess_pair_authorization(owner, actor)
    assert out.outcome == "possible_access"
    assert out.annotation is not None
    assert out.annotation.get("access_confirmed") is False
    assert out.annotation.get("contradicts_hypothesis") is not True


def test_ambiguous_500_stays_inconclusive() -> None:
    owner = _raw(200, '{"ok":true,"statement":{"id":1,"marker":"m","owner_label":"owner"}}')
    actor = _raw(500, '{"error":"internal"}')
    out = assess_pair_authorization(owner, actor)
    assert out.outcome == "inconclusive"


def test_assess_raw_response_parses_status_and_body() -> None:
    raw = b'HTTP/1.1 401 Unauthorized\r\nContent-Type: application/json\r\n\r\n{"error":"unauthenticated","ok":false}'
    a = assess_raw_response(raw)
    assert a.status_code == 401
    assert a.denial_demonstrated is True


def _load_corpus(split: str) -> list[dict]:
    path = LAB / split / "cases.json"
    return json.loads(path.read_text(encoding="utf-8"))


@pytest.mark.parametrize("split", ["dev", "final"])
def test_synthetic_corpus_labels(split: str) -> None:
    cases = _load_corpus(split)
    assert cases, f"{split} corpus must not be empty"
    for case in cases:
        out = assess_pair_authorization(case["owner_raw"], case["actor_raw"])
        assert out.outcome == case["expected_outcome"], f"{split}/{case['id']}: got {out.outcome} reasons={out.reasons}"
        if case.get("expect_negative_control"):
            assert out.annotation and out.annotation.get("role") == "negative_control"
            assert out.annotation.get("contradicts_hypothesis") is True
        if case.get("expect_not_reviewable_signal"):
            assert out.outcome == "cross_account_denied" or (out.annotation or {}).get("resource_visibility") in {
                "public",
                "shared",
            }


@pytest.mark.parametrize(
    "scenario,expect_reviewable,expect_stop",
    [
        ("A01", True, False),
        ("A02", False, True),
        ("A05", False, True),
        ("A06", True, False),
        ("A08", False, True),
        ("A09", False, True),
        ("C05", False, True),
    ],
)
def test_e2e_irb_scenarios_denial_aware(
    tmp_path: Path, scenario: str, expect_reviewable: bool, expect_stop: bool
) -> None:
    """Re-run selected IRB FINAL scenarios without touching frozen ground truth."""
    cap = IRB_FINAL / f"{scenario}.har"
    if not cap.is_file():
        pytest.skip("independent research FINAL capture missing")
    work = tmp_path / scenario
    program = f"denial-{scenario.lower()}"
    run_e2e_research(program, [cap], work, key=KEY, limit=20)
    ledger = json.loads(next(work.rglob("evidence-ledger.json")).read_text(encoding="utf-8"))
    reviewable = any(c.get("state") == "requires_validation" for c in ledger.get("candidates") or [])
    assert reviewable is expect_reviewable
    plan = build_plan(ProgramPaths(work, program), ledger_file=next(work.rglob("evidence-ledger.json")))
    statuses = [
        c.get("status") for c in plan.get("candidates") or [] if not str(c.get("status", "")).startswith("closed")
    ]
    if expect_stop:
        assert "stop_recommended" in statuses
    else:
        assert "open" in statuses or "ready_for_manual_review" in statuses
