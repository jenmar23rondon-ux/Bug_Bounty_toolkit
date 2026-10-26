"""Deterministic generators for handoff→case conversion corpora.

* ``adv-handoff-case-1.0`` (``frozen/``): FINAL evaluation only. Authored and hash-frozen
  BEFORE the case-reliability classification/evaluator fix. Never tune on it.
* ``adv-handoff-case-dev`` (``dev/``): separate DEV fixtures (different origin/nouns) for
  unit tests covering origin compatibility, formats, and rejection classes.

Ground truth labels conversion *eligibility class* expected after a provenance-correct
``discover_idor`` call — not confirmed vulnerabilities. Synthetic, loopback-only,
no real secrets. Regeneration must be byte-identical (test-enforced).
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent


def _har(entries: list[dict]) -> dict:
    return {
        "log": {
            "version": "1.2",
            "creator": {"name": "bbtk-idor-handoff-case-eval", "version": "1"},
            "entries": entries,
        }
    }


def _entry(
    origin: str,
    method: str,
    path: str,
    session: str | None,
    *,
    tok: str,
    body: dict | None = None,
    resp: dict | None = None,
    raw_resp: str | None = None,
    no_response: bool = False,
    status: int = 200,
    extra_headers: list[dict] | None = None,
) -> dict:
    hdr: list[dict] = list(extra_headers or [])
    if session is not None:
        hdr = [{"name": "Authorization", "value": f"Bearer {tok}-{session}"}] + hdr
    req: dict = {"method": method, "url": origin + path, "headers": hdr}
    if body is not None:
        req["headers"] = hdr + [{"name": "Content-Type", "value": "application/json"}]
        req["postData"] = {"mimeType": "application/json", "text": json.dumps(body, sort_keys=True)}
    entry: dict = {"request": req}
    if not no_response:
        text = raw_resp if raw_resp is not None else (json.dumps(resp, sort_keys=True) if resp is not None else "{}")
        entry["response"] = {
            "status": status,
            "headers": [{"name": "Content-Type", "value": "application/json"}],
            "content": {"mimeType": "application/json", "text": text},
        }
    return entry


def build_frozen() -> tuple[dict, dict]:
    """FINAL corpus: conversion eligibility under a correct provenance origin."""
    origin = "http://127.0.0.1:8141"
    prefix = "/hc"
    tok = "hc10"
    entries: list[dict] = []
    scenarios: list[dict] = []

    def add(method: str, path: str, session: str | None, **kw) -> int:
        entries.append(_entry(origin, method, prefix + path, session, tok=tok, **kw))
        return len(entries) - 1

    def scen(sid: str, tag: str, desc: str, idxs: list[int], **expect) -> None:
        scenarios.append(
            {
                "id": sid,
                "tag": tag,
                "description": desc,
                "entries": idxs,
                "expected_pair_types": list(expect.get("pair_types", ())),
                "forbidden_pair_types": list(expect.get("forbidden", ())),
                "ambiguous_types": list(expect.get("ambiguous", ())),
                "conversion_class": expect.get("conversion_class", "n/a"),
                "conversion_code": expect.get("conversion_code", "n/a"),
                "vulnerability_truth": expect.get("vuln", "n/a"),
            }
        )

    # H01 — valid GET path single-diff (parcel) → case_eligible
    a = add(
        "GET",
        "/parcels/50101",
        "owner",
        resp={"success": True, "data": {"id": 50101, "marker": "hc10-parcel-owner-aaa"}},
    )
    b = add(
        "GET",
        "/parcels/50102",
        "actor",
        resp={"success": True, "data": {"id": 50102, "marker": "hc10-parcel-actor-bbb"}},
    )
    scen(
        "H01",
        "valid-get-path",
        "Single path-segment GET resource diff",
        [a, b],
        pair_types=("parcel",),
        conversion_class="case_eligible",
        conversion_code="CASE_ELIGIBLE",
        vuln="vulnerable",
    )

    # H02 — valid GET query single-diff (roster)
    a = add(
        "GET",
        "/rosters?roster_id=50201",
        "owner",
        resp={"success": True, "data": {"id": 50201, "marker": "hc10-roster-owner-ccc"}},
    )
    b = add(
        "GET",
        "/rosters?roster_id=50202",
        "actor",
        resp={"success": True, "data": {"id": 50202, "marker": "hc10-roster-actor-ddd"}},
    )
    scen(
        "H02",
        "valid-get-query",
        "Single query-parameter GET resource diff",
        [a, b],
        pair_types=("roster",),
        conversion_class="case_eligible",
        conversion_code="CASE_ELIGIBLE",
        vuln="vulnerable",
    )

    # H03 — UUID path
    a = add(
        "GET",
        "/ledgers/0a1b2c3d-4e5f-6789-abcd-000000000301",
        "owner",
        resp={
            "success": True,
            "data": {"id": "0a1b2c3d-4e5f-6789-abcd-000000000301", "marker": "hc10-ledger-owner-eee"},
        },
    )
    b = add(
        "GET",
        "/ledgers/0a1b2c3d-4e5f-6789-abcd-000000000302",
        "actor",
        resp={
            "success": True,
            "data": {"id": "0a1b2c3d-4e5f-6789-abcd-000000000302", "marker": "hc10-ledger-actor-fff"},
        },
    )
    scen(
        "H03",
        "uuid-path",
        "UUID path identifiers",
        [a, b],
        pair_types=("ledger",),
        conversion_class="case_eligible",
        conversion_code="CASE_ELIGIBLE",
        vuln="vulnerable",
    )

    # H04 — nested JSON response (still single path diff)
    a = add(
        "GET",
        "/dockets/50301",
        "owner",
        resp={"success": True, "data": {"docket": {"id": 50301, "meta": {"marker": "hc10-docket-owner-ggg"}}}},
    )
    b = add(
        "GET",
        "/dockets/50302",
        "actor",
        resp={"success": True, "data": {"docket": {"id": 50302, "meta": {"marker": "hc10-docket-actor-hhh"}}}},
    )
    scen(
        "H04",
        "nested-json",
        "Nested JSON control bodies with single path diff",
        [a, b],
        pair_types=("docket",),
        conversion_class="case_eligible",
        conversion_code="CASE_ELIGIBLE",
        vuln="vulnerable",
    )

    # H05 — multi-diff parent+child path segments → REJECT_MULTI_RESOURCE_DIFF
    a = add(
        "GET",
        "/workspaces/50401/boards/50411",
        "owner",
        resp={"success": True, "data": {"board_id": 50411, "marker": "hc10-board-owner-iii"}},
    )
    b = add(
        "GET",
        "/workspaces/50402/boards/50412",
        "actor",
        resp={"success": True, "data": {"board_id": 50412, "marker": "hc10-board-actor-jjj"}},
    )
    scen(
        "H05",
        "multi-diff",
        "Two path segments differ (parent and child)",
        [a, b],
        pair_types=("board", "workspace"),
        conversion_class="needs_more_evidence",
        conversion_code="REJECT_MULTI_RESOURCE_DIFF",
        vuln="vulnerable",
    )

    # H06 — non-GET POST same shape → REJECT_NON_GET (session-only URL)
    a = add(
        "POST",
        "/shipments/lookup",
        "owner",
        body={"shipment_id": 50501},
        resp={"success": True, "data": {"id": 50501, "marker": "hc10-ship-owner-kkk"}},
    )
    b = add(
        "POST",
        "/shipments/lookup",
        "actor",
        body={"shipment_id": 50502},
        resp={"success": True, "data": {"id": 50502, "marker": "hc10-ship-actor-lll"}},
    )
    scen(
        "H06",
        "non-get",
        "POST body resource; read-case generator rejects",
        [a, b],
        pair_types=("shipment",),
        conversion_class="security_rejected",
        conversion_code="REJECT_NON_GET",
        vuln="n/a",
    )

    # H07 — session-only GET identical URL → REJECT_SESSION_ONLY
    a = add("GET", "/profile", "owner", resp={"success": True, "data": {"marker": "hc10-profile-owner-mmm"}})
    b = add("GET", "/profile", "actor", resp={"success": True, "data": {"marker": "hc10-profile-actor-nnn"}})
    scen(
        "H07",
        "session-only",
        "Identical URL; only session header differs",
        [a, b],
        pair_types=(),
        forbidden=("profile",),
        conversion_class="needs_more_evidence",
        conversion_code="REJECT_SESSION_ONLY",
        vuln="n/a",
    )

    # H08 — missing actor response → needs_more_evidence (structure may still propose)
    a = add(
        "GET",
        "/vouchers/50601",
        "owner",
        resp={"success": True, "data": {"id": 50601, "marker": "hc10-voucher-owner-ooo"}},
    )
    b = add("GET", "/vouchers/50602", "actor", no_response=True)
    scen(
        "H08",
        "missing-response",
        "Actor response absent",
        [a, b],
        pair_types=("voucher",),
        conversion_class="needs_more_evidence",
        conversion_code="NEEDS_RESPONSE",
        vuln="n/a",
    )

    # H09 — single session only (insufficient) → insufficient evidence at handoff
    a = add(
        "GET", "/coupons/50701", "solo", resp={"success": True, "data": {"id": 50701, "marker": "hc10-coupon-solo-ppp"}}
    )
    b = add(
        "GET", "/coupons/50702", "solo", resp={"success": True, "data": {"id": 50702, "marker": "hc10-coupon-solo-qqq"}}
    )
    scen(
        "H09",
        "insufficient-sessions",
        "One session reads two own coupons",
        [a, b],
        pair_types=(),
        forbidden=("coupon",),
        conversion_class="needs_more_evidence",
        conversion_code="NEEDS_SECOND_SESSION",
        vuln="n/a",
    )

    # H10 — shared identical id (not a cross-account resource diff)
    a = add(
        "GET",
        "/channels/50800",
        "owner",
        resp={"success": True, "data": {"id": 50800, "marker": "hc10-channel-shared-rrr"}},
    )
    b = add(
        "GET",
        "/channels/50800",
        "actor",
        resp={"success": True, "data": {"id": 50800, "marker": "hc10-channel-shared-rrr"}},
    )
    scen(
        "H10",
        "shared-id",
        "Same object id for both sessions",
        [a, b],
        pair_types=(),
        forbidden=("channel",),
        conversion_class="needs_more_evidence",
        conversion_code="REJECT_SESSION_ONLY",
        vuln="n/a",
    )

    # H11 — numeric + UUID mixed kinds on related endpoint (still single-diff each)
    a = add(
        "GET",
        "/filings/50901",
        "owner",
        resp={"success": True, "data": {"id": 50901, "marker": "hc10-filing-owner-sss"}},
    )
    b = add(
        "GET",
        "/filings/50902",
        "actor",
        resp={"success": True, "data": {"id": 50902, "marker": "hc10-filing-actor-ttt"}},
    )
    scen(
        "H11",
        "numeric-id",
        "Numeric path ids",
        [a, b],
        pair_types=("filing",),
        conversion_class="case_eligible",
        conversion_code="CASE_ELIGIBLE",
        vuln="vulnerable",
    )

    # H12 — duplicate exchanges (deterministic; still one eligible pair type)
    a = add(
        "GET",
        "/parcels/50101",
        "owner",
        resp={"success": True, "data": {"id": 50101, "marker": "hc10-parcel-owner-aaa"}},
    )
    b = add(
        "GET",
        "/parcels/50102",
        "actor",
        resp={"success": True, "data": {"id": 50102, "marker": "hc10-parcel-actor-bbb"}},
    )
    scen(
        "H12",
        "duplicate",
        "Duplicate of H01 exchanges (determinism / dedup pressure)",
        [a, b],
        pair_types=("parcel",),
        conversion_class="case_eligible",
        conversion_code="CASE_ELIGIBLE",
        vuln="vulnerable",
    )

    # H13 — incomplete truncated JSON response (still request-side ids)
    a = add("GET", "/contracts/51001", "owner", raw_resp='{"success":true,"data":{"id":51001')
    b = add("GET", "/contracts/51002", "actor", raw_resp='{"success":true,"data":{"id":51002')
    scen(
        "H13",
        "truncated-json",
        "Truncated JSON responses",
        [a, b],
        pair_types=("contract",),
        conversion_class="needs_more_evidence",
        conversion_code="NEEDS_RESPONSE",
        vuln="n/a",
    )

    # H14 — public unauthenticated catalogue (negative)
    a = add("GET", "/articles/51101", None, resp={"success": True, "data": {"id": 51101}})
    b = add("GET", "/articles/51102", None, resp={"success": True, "data": {"id": 51102}})
    scen(
        "H14",
        "public",
        "Unauthenticated public articles",
        [a, b],
        pair_types=(),
        forbidden=("article",),
        conversion_class="needs_more_evidence",
        conversion_code="NEEDS_SECOND_SESSION",
        vuln="n/a",
    )

    gt = {
        "corpus_version": "adv-handoff-case-1.0",
        "independent_of": ["adv-1.0", "adv-1.1", "adv-ranking-1.0"],
        "origin": origin,
        "path_prefix": prefix,
        "tuning_policy": "FINAL-evaluation-only; never tune on this corpus",
        "split": "frozen",
        "scenarios": scenarios,
        "conversion_classes": [
            "structural_valid",
            "case_eligible",
            "needs_more_evidence",
            "security_rejected",
            "technical_error",
        ],
    }
    return _har(entries), gt


def build_dev() -> tuple[dict, dict]:
    """DEV fixtures: broader format/origin edge coverage; may be used in unit tests."""
    origin = "http://127.0.0.1:8142"
    alt_origin = "http://127.0.0.1:8143"  # incompatible port peer
    prefix = "/hd"
    tok = "hcdev"
    entries: list[dict] = []
    scenarios: list[dict] = []

    def add(method: str, path: str, session: str | None, *, use_origin: str | None = None, **kw) -> int:
        entries.append(_entry(use_origin or origin, method, prefix + path, session, tok=tok, **kw))
        return len(entries) - 1

    def scen(sid: str, tag: str, desc: str, idxs: list[int], **expect) -> None:
        scenarios.append(
            {
                "id": sid,
                "tag": tag,
                "description": desc,
                "entries": idxs,
                "conversion_class": expect.get("conversion_class", "n/a"),
                "conversion_code": expect.get("conversion_code", "n/a"),
                "notes": expect.get("notes", ""),
            }
        )

    # D01 compatible origins valid GET
    a = add(
        "GET",
        "/widgets/60101",
        "owner",
        resp={"success": True, "data": {"id": 60101, "marker": "hcdev-widget-owner-aaa"}},
    )
    b = add(
        "GET",
        "/widgets/60102",
        "actor",
        resp={"success": True, "data": {"id": 60102, "marker": "hcdev-widget-actor-bbb"}},
    )
    scen(
        "D01",
        "compatible-origin",
        "Matching http origin both sides",
        [a, b],
        conversion_class="case_eligible",
        conversion_code="CASE_ELIGIBLE",
    )

    # D02 incompatible ports across sides
    a = add(
        "GET",
        "/widgets/60201",
        "owner",
        resp={"success": True, "data": {"id": 60201, "marker": "hcdev-widget-owner-ccc"}},
    )
    b = add(
        "GET",
        "/widgets/60202",
        "actor",
        use_origin=alt_origin,
        resp={"success": True, "data": {"id": 60202, "marker": "hcdev-widget-actor-ddd"}},
    )
    scen(
        "D02",
        "incompatible-ports",
        "Owner 8142 vs actor 8143",
        [a, b],
        conversion_class="technical_error",
        conversion_code="REJECT_ORIGIN_MISMATCH_SIDES",
        notes="Sides disagree; never rewrite",
    )

    # D03 multi-diff
    a = add(
        "GET",
        "/tenants/60301/sites/60311",
        "owner",
        resp={"success": True, "data": {"id": 60311, "marker": "hcdev-site-owner-eee"}},
    )
    b = add(
        "GET",
        "/tenants/60302/sites/60312",
        "actor",
        resp={"success": True, "data": {"id": 60312, "marker": "hcdev-site-actor-fff"}},
    )
    scen(
        "D03",
        "multiple-diffs",
        "Parent+child path diffs",
        [a, b],
        conversion_class="needs_more_evidence",
        conversion_code="REJECT_MULTI_RESOURCE_DIFF",
    )

    # D04 unsupported PUT
    a = add("PUT", "/settings", "owner", body={"theme": "dark"}, resp={"success": True})
    b = add("PUT", "/settings", "actor", body={"theme": "light"}, resp={"success": True})
    scen(
        "D04",
        "unsupported-method",
        "PUT write captures",
        [a, b],
        conversion_class="security_rejected",
        conversion_code="REJECT_NON_GET",
    )

    # D05 missing responses both sides
    a = add("GET", "/notes/60401", "owner", no_response=True)
    b = add("GET", "/notes/60402", "actor", no_response=True)
    scen(
        "D05",
        "missing-responses",
        "No responses",
        [a, b],
        conversion_class="needs_more_evidence",
        conversion_code="NEEDS_RESPONSE",
    )

    # D06 insufficient sessions
    a = add(
        "GET", "/memos/60501", "solo", resp={"success": True, "data": {"id": 60501, "marker": "hcdev-memo-solo-ggg"}}
    )
    b = add(
        "GET", "/memos/60502", "solo", resp={"success": True, "data": {"id": 60502, "marker": "hcdev-memo-solo-hhh"}}
    )
    scen(
        "D06",
        "insufficient-sessions",
        "Single session",
        [a, b],
        conversion_class="needs_more_evidence",
        conversion_code="NEEDS_SECOND_SESSION",
    )

    # D07 nested JSON + UUID
    uid_o = "bbbbbbbb-cccc-4ddd-8eee-ffffffffffff"
    uid_a = "cccccccc-dddd-4eee-8fff-000000000001"
    a = add(
        "GET",
        f"/artifacts/{uid_o}",
        "owner",
        resp={"success": True, "payload": {"artifact": {"uuid": uid_o, "marker": "hcdev-artifact-owner-iii"}}},
    )
    b = add(
        "GET",
        f"/artifacts/{uid_a}",
        "actor",
        resp={"success": True, "payload": {"artifact": {"uuid": uid_a, "marker": "hcdev-artifact-actor-jjj"}}},
    )
    scen(
        "D07",
        "nested-uuid",
        "Nested JSON with UUID path",
        [a, b],
        conversion_class="case_eligible",
        conversion_code="CASE_ELIGIBLE",
    )

    # D08 synthetic secret-looking values (must not appear in summaries)
    a = add(
        "GET",
        "/secrets/60601",
        "owner",
        resp={
            "success": True,
            "data": {"id": 60601, "token": "sk_live_SYNTHETIC_NOT_REAL_001", "marker": "hcdev-secret-owner-kkk"},
        },
        extra_headers=[{"name": "X-Api-Key", "value": "SYNTHETIC_API_KEY_DO_NOT_LEAK"}],
    )
    b = add(
        "GET",
        "/secrets/60602",
        "actor",
        resp={
            "success": True,
            "data": {"id": 60602, "token": "sk_live_SYNTHETIC_NOT_REAL_002", "marker": "hcdev-secret-actor-lll"},
        },
        extra_headers=[{"name": "X-Api-Key", "value": "SYNTHETIC_API_KEY_DO_NOT_LEAK_B"}],
    )
    scen(
        "D08",
        "synthetic-secrets",
        "Synthetic secrets must stay out of summaries",
        [a, b],
        conversion_class="case_eligible",
        conversion_code="CASE_ELIGIBLE",
        notes="Count-only summary / redaction surfaces must not echo sk_live_ or API keys",
    )

    # D09 incomplete request-like entry (empty headers path still has URL)
    a = add("GET", "/drafts/60701", "owner", resp={"success": True, "data": {"id": 60701}})
    b = add("GET", "/drafts/60702", "actor", no_response=True)
    scen(
        "D09",
        "incomplete",
        "Incomplete actor capture",
        [a, b],
        conversion_class="needs_more_evidence",
        conversion_code="NEEDS_RESPONSE",
    )

    # D10 duplicates
    a = add(
        "GET",
        "/widgets/60101",
        "owner",
        resp={"success": True, "data": {"id": 60101, "marker": "hcdev-widget-owner-aaa"}},
    )
    b = add(
        "GET",
        "/widgets/60102",
        "actor",
        resp={"success": True, "data": {"id": 60102, "marker": "hcdev-widget-actor-bbb"}},
    )
    scen(
        "D10",
        "duplicates",
        "Duplicate widget pair",
        [a, b],
        conversion_class="case_eligible",
        conversion_code="CASE_ELIGIBLE",
    )

    gt = {
        "corpus_version": "adv-handoff-case-dev",
        "independent_of": ["adv-handoff-case-1.0", "adv-1.0", "adv-1.1"],
        "origin": origin,
        "alt_origin": alt_origin,
        "path_prefix": prefix,
        "tuning_policy": "DEV fixtures for unit tests; not FINAL metrics",
        "split": "dev",
        "scenarios": scenarios,
        "format_notes": {
            "har": "primary frozen/dev HAR",
            "burp_xml": "generated beside DEV by tests from raw snapshots",
            "raw": "materialized by object_handoff / tests",
            "relative": "raw requests without absolute URL use Host + optional --base-url",
        },
    }
    return _har(entries), gt


def _write(dir_name: str, har: dict, gt: dict) -> Path:
    out = HERE / dir_name
    out.mkdir(parents=True, exist_ok=True)
    (out / "captures.har").write_text(json.dumps(har, indent=1, sort_keys=True) + "\n", encoding="utf-8")
    (out / "ground_truth.json").write_text(json.dumps(gt, indent=1, sort_keys=True) + "\n", encoding="utf-8")
    lines = []
    for name in ("captures.har", "ground_truth.json"):
        digest = hashlib.sha256((out / name).read_bytes()).hexdigest()
        lines.append(f"{digest}  {name}")
    (out / "MANIFEST.sha256").write_text("\n".join(lines) + "\n", encoding="utf-8")
    return out


def main(argv: list[str] | None = None) -> int:
    which = argv or sys.argv[1:]
    targets = which or ["frozen", "dev"]
    if targets == ["all"]:
        targets = ["frozen", "dev"]
    for name in targets:
        if name == "frozen":
            har, gt = build_frozen()
            path = _write("frozen", har, gt)
        elif name == "dev":
            har, gt = build_dev()
            path = _write("dev", har, gt)
        else:
            raise SystemExit(f"unknown target {name!r}")
        print(f"wrote {path} ({gt['corpus_version']}, {len(gt['scenarios'])} scenarios)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
