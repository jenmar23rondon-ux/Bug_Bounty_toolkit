"""Deterministic synthetic corpus for IDOR/BOLA E2E research quality.

Corpus ``idor-e2e-research-1.0`` (``frozen/``): independent of historical adv-* /
handoff-case / ranking corpora. Authored for measurement of the full research
contract with real eligibility codes. Never edit historical corpora to retarget metrics.

Origin: http://127.0.0.1:8155  path prefix: /er
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
ORIGIN = "http://127.0.0.1:8155"
ALT_ORIGIN = "http://127.0.0.1:8156"
PREFIX = "/er"
VERSION = "idor-e2e-research-1.0"
TOK = "er10"


def _har(entries: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "log": {
            "version": "1.2",
            "creator": {"name": "bbtk-idor-e2e-research", "version": "1"},
            "entries": entries,
        }
    }


def _entry(
    origin: str,
    method: str,
    path: str,
    session: str | None,
    *,
    tok: str = TOK,
    body: dict[str, Any] | None = None,
    resp: Any | None = None,
    raw_resp: str | None = None,
    no_response: bool = False,
    status: int = 200,
    extra_headers: list[dict[str, str]] | None = None,
) -> dict[str, Any]:
    hdr: list[dict[str, str]] = list(extra_headers or [])
    if session is not None:
        hdr = [{"name": "Authorization", "value": f"Bearer {tok}-{session}"}] + hdr
    req: dict[str, Any] = {"method": method, "url": origin + path, "headers": hdr}
    if body is not None:
        req["headers"] = hdr + [{"name": "Content-Type", "value": "application/json"}]
        req["postData"] = {"mimeType": "application/json", "text": json.dumps(body, sort_keys=True)}
    entry: dict[str, Any] = {"request": req}
    if not no_response:
        text = raw_resp if raw_resp is not None else (json.dumps(resp, sort_keys=True) if resp is not None else "{}")
        entry["response"] = {
            "status": status,
            "headers": [{"name": "Content-Type", "value": "application/json"}],
            "content": {"mimeType": "application/json", "text": text},
        }
    return entry


def build() -> tuple[dict[str, Any], dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    scenarios: list[dict[str, Any]] = []

    def add(method: str, path: str, session: str | None, **kw: Any) -> int:
        origin = kw.pop("origin", ORIGIN)
        entries.append(_entry(origin, method, PREFIX + path, session, **kw))
        return len(entries) - 1

    def scen(sid: str, tag: str, desc: str, idxs: list[int], **expect: Any) -> None:
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
                "pipeline_focus": expect.get("focus", "eligibility"),
                "expected_confirmed": False,
            }
        )

    # R01 — read IDOR (eligible)
    a = add(
        "GET",
        "/memos/61001",
        "owner",
        resp={"success": True, "data": {"id": 61001, "marker": "er10-memo-owner-aaaa"}},
    )
    b = add(
        "GET",
        "/memos/61002",
        "actor",
        resp={"success": True, "data": {"id": 61002, "marker": "er10-memo-actor-bbbb"}},
    )
    scen(
        "R01",
        "read-idor",
        "Classic GET path single-diff read IDOR candidate",
        [a, b],
        pair_types=("memo",),
        conversion_class="case_eligible",
        conversion_code="CASE_ELIGIBLE",
        vuln="vulnerable",
    )

    # R02 — access correctly denied (actor 403); still structurally proposable, never auto-confirm
    a = add(
        "GET",
        "/briefs/61101",
        "owner",
        resp={"success": True, "data": {"id": 61101, "marker": "er10-brief-owner-cccc"}},
    )
    b = add(
        "GET",
        "/briefs/61102",
        "actor",
        status=403,
        resp={"success": False, "error": "forbidden", "marker": "er10-brief-denied-dddd"},
    )
    scen(
        "R02",
        "access-denied",
        "Actor control returns 403; denial is not a confirmed finding",
        [a, b],
        pair_types=("brief",),
        conversion_class="case_eligible",
        conversion_code="CASE_ELIGIBLE",
        vuln="not_vulnerable",
        focus="control_review",
    )

    # R03 — public resource (same public id, no private marker semantics)
    a = add(
        "GET",
        "/notices/public",
        "owner",
        resp={"success": True, "data": {"id": "public", "marker": "er10-notice-public-eeee"}},
    )
    b = add(
        "GET",
        "/notices/public",
        "actor",
        resp={"success": True, "data": {"id": "public", "marker": "er10-notice-public-eeee"}},
    )
    scen(
        "R03",
        "public-resource",
        "Identical public URL; session-only difference",
        [a, b],
        pair_types=(),
        forbidden=("notice",),
        conversion_class="needs_more_evidence",
        conversion_code="REJECT_SESSION_ONLY",
        vuln="not_vulnerable",
    )

    # R04 — multi-diff parent+child
    a = add(
        "GET",
        "/tenants/61201/folders/61211",
        "owner",
        resp={"success": True, "data": {"folder_id": 61211, "marker": "er10-folder-owner-ffff"}},
    )
    b = add(
        "GET",
        "/tenants/61202/folders/61212",
        "actor",
        resp={"success": True, "data": {"folder_id": 61212, "marker": "er10-folder-actor-gggg"}},
    )
    scen(
        "R04",
        "multi-diff",
        "Two path segments differ",
        [a, b],
        pair_types=("folder", "tenant"),
        conversion_class="needs_more_evidence",
        conversion_code="REJECT_MULTI_RESOURCE_DIFF",
        vuln="vulnerable",
    )

    # R05 — insufficient session (same session two ids)
    a = add(
        "GET",
        "/tickets/61301",
        "solo",
        resp={"success": True, "data": {"id": 61301, "marker": "er10-ticket-solo-hhhh"}},
    )
    b = add(
        "GET",
        "/tickets/61302",
        "solo",
        resp={"success": True, "data": {"id": 61302, "marker": "er10-ticket-solo-iiii"}},
    )
    scen(
        "R05",
        "insufficient-session",
        "One session reads two own tickets",
        [a, b],
        pair_types=(),
        forbidden=("ticket",),
        conversion_class="needs_more_evidence",
        conversion_code="NEEDS_SECOND_SESSION",
        vuln="n/a",
    )

    # R06 — different roles (non-session header differs → REJECT_HEADER_DIFF)
    a = add(
        "GET",
        "/cases/61401",
        "owner",
        extra_headers=[{"name": "X-Role", "value": "analyst"}],
        resp={"success": True, "data": {"id": 61401, "marker": "er10-case-owner-jjjj"}},
    )
    b = add(
        "GET",
        "/cases/61402",
        "actor",
        extra_headers=[{"name": "X-Role", "value": "viewer"}],
        resp={"success": True, "data": {"id": 61402, "marker": "er10-case-actor-kkkk"}},
    )
    scen(
        "R06",
        "different-roles",
        "Resource id differs and non-session role header differs",
        [a, b],
        pair_types=("case",),
        conversion_class="needs_more_evidence",
        conversion_code="REJECT_HEADER_DIFF",
        vuln="n/a",
    )

    # R07 — legitimately shared object (same id both sessions)
    a = add(
        "GET",
        "/spaces/61500",
        "owner",
        resp={"success": True, "data": {"id": 61500, "marker": "er10-space-shared-llll"}},
    )
    b = add(
        "GET",
        "/spaces/61500",
        "actor",
        resp={"success": True, "data": {"id": 61500, "marker": "er10-space-shared-llll"}},
    )
    scen(
        "R07",
        "shared-legit",
        "Same object id for both sessions (shared workspace)",
        [a, b],
        pair_types=(),
        forbidden=("space",),
        conversion_class="needs_more_evidence",
        conversion_code="REJECT_SESSION_ONLY",
        vuln="not_vulnerable",
    )

    # R08 — repeated IDs across namespaces (invoice vs order same numeric)
    a = add(
        "GET",
        "/invoices/61600",
        "owner",
        resp={"success": True, "data": {"invoice_id": 61600, "marker": "er10-invoice-owner-mmmm"}},
    )
    b = add(
        "GET",
        "/orders/61600",
        "actor",
        resp={"success": True, "data": {"order_id": 61600, "marker": "er10-order-actor-nnnn"}},
    )
    scen(
        "R08",
        "ids-namespaces",
        "Same numeric id under different resource nouns must not cross-pair as one kind",
        [a, b],
        pair_types=(),
        forbidden=(),
        ambiguous=("invoice", "order"),
        conversion_class="needs_more_evidence",
        conversion_code="NEEDS_MORE_EVIDENCE",
        vuln="n/a",
        focus="pairing",
    )

    # R09 — arrays / nested resources
    a = add(
        "GET",
        "/bundles/61701",
        "owner",
        resp={
            "success": True,
            "data": {
                "bundle": {"id": 61701, "items": [{"sku": "A"}, {"sku": "B"}], "marker": "er10-bundle-owner-oooo"}
            },
        },
    )
    b = add(
        "GET",
        "/bundles/61702",
        "actor",
        resp={
            "success": True,
            "data": {"bundle": {"id": 61702, "items": [{"sku": "C"}], "marker": "er10-bundle-actor-pppp"}},
        },
    )
    scen(
        "R09",
        "arrays-nested",
        "Nested JSON with arrays; single path diff still eligible",
        [a, b],
        pair_types=("bundle",),
        conversion_class="case_eligible",
        conversion_code="CASE_ELIGIBLE",
        vuln="vulnerable",
    )

    # R10 — incomplete responses
    a = add(
        "GET",
        "/vouchers/61801",
        "owner",
        resp={"success": True, "data": {"id": 61801, "marker": "er10-voucher-owner-qqqq"}},
    )
    b = add("GET", "/vouchers/61802", "actor", no_response=True)
    scen(
        "R10",
        "incomplete-responses",
        "Actor response absent",
        [a, b],
        pair_types=("voucher",),
        conversion_class="needs_more_evidence",
        conversion_code="NEEDS_RESPONSE",
        vuln="n/a",
    )

    # R11 — inconsistent origin (owner on :8155, actor on :8156)
    a = add(
        "GET",
        "/claims/61901",
        "owner",
        origin=ORIGIN,
        resp={"success": True, "data": {"id": 61901, "marker": "er10-claim-owner-rrrr"}},
    )
    b = add(
        "GET",
        "/claims/61902",
        "actor",
        origin=ALT_ORIGIN,
        resp={"success": True, "data": {"id": 61902, "marker": "er10-claim-actor-ssss"}},
    )
    scen(
        "R11",
        "inconsistent-origin",
        "Owner/actor origins disagree; must fail closed without rewriting",
        [a, b],
        pair_types=("claim",),
        conversion_class="technical_error",
        conversion_code="REJECT_ORIGIN_MISMATCH_SIDES",
        vuln="n/a",
        focus="provenance",
    )

    # R12 — discarded candidate (single session noise endpoint)
    a = add(
        "GET",
        "/healthz",
        None,
        resp={"ok": True, "marker": "er10-health-tttt"},
    )
    scen(
        "R12",
        "discarded-candidate",
        "Unauthenticated health endpoint; not an IDOR pair",
        [a],
        pair_types=(),
        forbidden=("healthz",),
        conversion_class="needs_more_evidence",
        conversion_code="NEEDS_SECOND_SESSION",
        vuln="n/a",
        focus="ranking",
    )

    # R13 — false positive bait: HTTP 200 on both sides without private markers of ownership
    a = add(
        "GET",
        "/pages/62001",
        "owner",
        resp={"success": True, "data": {"id": 62001, "public": True, "marker": "er10-page-owner-uuuu"}},
    )
    b = add(
        "GET",
        "/pages/62002",
        "actor",
        resp={"success": True, "data": {"id": 62002, "public": True, "marker": "er10-page-actor-vvvv"}},
    )
    scen(
        "R13",
        "fp-http-200",
        "Both 200; HTTP status alone must not confirm ownership/IDOR",
        [a, b],
        pair_types=("page",),
        conversion_class="case_eligible",
        conversion_code="CASE_ELIGIBLE",
        vuln="false_positive_risk",
        focus="control_review",
    )

    # R14 — altered evidence probe: eligible pair whose post-run mutation must be detected
    a = add(
        "GET",
        "/archives/62101",
        "owner",
        resp={"success": True, "data": {"id": 62101, "marker": "er10-archive-owner-wwww"}},
    )
    b = add(
        "GET",
        "/archives/62102",
        "actor",
        resp={"success": True, "data": {"id": 62102, "marker": "er10-archive-actor-xxxx"}},
    )
    scen(
        "R14",
        "altered-evidence",
        "Eligible pair used to verify ARTIFACT_MODIFIED / stale ledger detection",
        [a, b],
        pair_types=("archive",),
        conversion_class="case_eligible",
        conversion_code="CASE_ELIGIBLE",
        vuln="n/a",
        focus="integrity",
    )

    # R15 — expired synthetic token marker in response body
    a = add(
        "GET",
        "/tokens/62201",
        "owner",
        resp={
            "success": True,
            "data": {"id": 62201, "marker": "er10-token-owner-yyyy", "token": "EXPIRED-SYNTH-TOKEN-owner"},
        },
    )
    b = add(
        "GET",
        "/tokens/62202",
        "actor",
        resp={
            "success": True,
            "data": {"id": 62202, "marker": "er10-token-actor-zzzz", "token": "EXPIRED-SYNTH-TOKEN-actor"},
        },
    )
    scen(
        "R15",
        "expired-token",
        "Synthetic expired token marker must surface as EVIDENCE_EXPIRED on integrity check",
        [a, b],
        pair_types=("token",),
        conversion_class="case_eligible",
        conversion_code="CASE_ELIGIBLE",
        vuln="n/a",
        focus="integrity",
    )

    gt = {
        "corpus_version": VERSION,
        "origin": ORIGIN,
        "alt_origin": ALT_ORIGIN,
        "path_prefix": PREFIX,
        "split": "frozen",
        "tuning_policy": "independent-measurement; do not retarget historical corpora",
        "independent_of": [
            "adv-1.0",
            "adv-1.1",
            "adv-ranking-1.0",
            "adv-handoff-case-1.0",
            "e2e-contract-1.0",
        ],
        "conversion_classes": [
            "structural_valid",
            "case_eligible",
            "needs_more_evidence",
            "security_rejected",
            "technical_error",
        ],
        "scenarios": scenarios,
    }
    return _har(entries), gt


def write(out: Path) -> None:
    out.mkdir(parents=True, exist_ok=True)
    har, gt = build()
    files = {
        "captures.har": json.dumps(har, indent=1, sort_keys=True) + "\n",
        "ground_truth.json": json.dumps(gt, indent=1, sort_keys=True) + "\n",
    }
    for name, text in files.items():
        (out / name).write_text(text, encoding="utf-8")
    manifest = "".join(f"{hashlib.sha256(t.encode()).hexdigest()}  {n}\n" for n, t in sorted(files.items()))
    (out / "MANIFEST.sha256").write_text(manifest, encoding="utf-8")


def main() -> None:
    target = HERE / "frozen" if len(sys.argv) < 2 or sys.argv[1] in {"frozen", "all"} else Path(sys.argv[1])
    write(target)
    print(f"wrote {target}")


if __name__ == "__main__":
    main()
