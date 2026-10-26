"""Synthetic, offline lab for the read-only triage dashboard.

Builds eight synthetic investigations under a temporary records root, drives the
dashboard through FastAPI's in-process TestClient (no sockets, no network) and
reports automated navigation steps, latency, response sizes, state
interpretation errors, broken-reference visibility and UI security checks.
No human-productivity figures are produced: steps are scripted API calls.
"""

from __future__ import annotations

import hashlib
import json
import statistics
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

from bugbounty_toolkit.core.records import ProgramPaths

JWT_CANARY = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJkYXNoLWNhbmFyeSJ9.ZGFzaGJvYXJkLWNhbmFyeS1zaWc"
TOKEN_CANARY = "DASHCANARYTOKEN7f3a91"
COOKIE_CANARY = "DASHCANARYCOOKIE5521"
BODY_CANARY = "DASHCANARYBODY0042"
PATH_CANARY = "private-dir-DASHCANARYPATH"
CANARIES = (JWT_CANARY, TOKEN_CANARY, COOKIE_CANARY, BODY_CANARY, PATH_CANARY)
XSS_PAYLOAD = "<img src=x onerror=alert(1)><script>alert(2)</script>"
NOW = "2026-10-26T00:00:00Z"

# scenario -> expected outcomes used for scoring the dashboard's interpretation
EXPECTED: dict[str, dict[str, Any]] = {
    "no-candidates": {"top": None, "states": {}, "broken": 0},
    "multi-candidates": {
        "top": "c-idor-orders",
        "states": {
            "c-idor-orders": "requires_validation",
            "c-xss-search": "candidate",
            "c-redirect": "candidate",
            "c-cors-confirmed": "confirmed",
        },
        "broken": 0,
    },
    "incomplete-evidence": {
        "top": "c-no-evidence",
        "states": {"c-no-evidence": "requires_validation"},
        "missing_evidence": "c-no-evidence",
        "broken": 0,
    },
    "false-positive": {"top": "c-fp-200", "states": {"c-fp-200": "rejected"}, "broken": 0},
    "rejected": {"top": "c-rejected", "states": {"c-rejected": "rejected"}, "broken": 0},
    "ai-discrepancy": {"top": "c-ai", "states": {"c-ai": "requires_validation"}, "broken": 0, "ai": True},
    "invalid-references": {
        "top": "c-fake-confirmed",
        "states": {"c-fake-confirmed": "requires_validation", "c-tampered": "requires_validation"},
        "broken": 2,
    },
    "reviewable-reports": {
        "top": "c-report",
        "states": {"c-report": "requires_validation"},
        "broken": 0,
        "reports": True,
    },
}


def _evidence(paths: ProgramPaths, eid: str, content: str, *, tamper: bool = False) -> dict[str, Any]:
    rel = f"evidence/{PATH_CANARY}/{eid}.json"
    target = paths.program_dir / rel
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content, encoding="utf-8")
    digest = hashlib.sha256(content.encode()).hexdigest()
    if tamper:
        target.write_text(content + "tampered", encoding="utf-8")
    return {
        "evidence_id": eid,
        "path": rel,
        "sha256": digest,
        "provenance": {"tool": f"synthetic-lab Authorization: Bearer {TOKEN_CANARY}", "captured_at": NOW},
    }


def _surface(sid: str, ref: str, status: str = "investigated", **extra: str) -> dict[str, Any]:
    return {"surface_id": sid, "kind": "endpoint", "ref": ref, "status": status, **extra}


def _cand(cid: str, sid: str, category: str, state: str, refs: list[str], **extra: Any) -> dict[str, Any]:
    return {
        "candidate_id": cid,
        "surface_id": sid,
        "category": category,
        "state": state,
        "evidence_refs": refs,
        "raised_by": "lab-raiser",
        **extra,
    }


def _write(paths: ProgramPaths, surfaces: list[Any], evidence: list[Any], candidates: list[Any]) -> None:
    ledger = {
        "schema_version": "bbtk-evidence-ledger/1",
        "program": paths.program,
        "updated_at": NOW,
        "surfaces": surfaces,
        "evidence": evidence,
        "candidates": candidates,
    }
    target = paths.program_dir / "ledger" / "evidence-ledger.json"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(ledger), encoding="utf-8")


def build_lab(root: Path) -> dict[str, ProgramPaths]:
    programs = {name: ProgramPaths(root, name) for name in EXPECTED}
    for p in programs.values():
        p.ensure()
    body = json.dumps({"response_body": BODY_CANARY, "cookie": f"session={COOKIE_CANARY}", "jwt": JWT_CANARY})
    review = {
        "reviewer": "lab-human-b",
        "method": "human_lab_reproduction",
        "basis": "Reproduced with two synthetic accounts in the local lab.",
        "reviewed_at": NOW,
    }

    # multi-candidates
    p = programs["multi-candidates"]
    ev = [_evidence(p, f"e{i}", body) for i in range(1, 5)]
    _write(
        p,
        [
            _surface("s-orders", "/api/orders/{id}"),
            _surface("s-search", "/search"),
            _surface("s-login", "/login"),
            _surface("s-api", "/api/profile"),
            _surface("s-admin", "/admin", "blocked", blocker="Needs a second synthetic role."),
        ],
        ev,
        [
            _cand(
                "c-idor-orders",
                "s-orders",
                "access_control",
                "requires_validation",
                ["e1"],
                title=f"Order read across accounts {XSS_PAYLOAD}",
                blockers=["Owner control for account B"],
            ),
            _cand("c-xss-search", "s-search", "xss", "candidate", ["e2"], title="Reflected search term"),
            _cand(
                "c-redirect",
                "s-login",
                "open_redirect",
                "candidate",
                ["e3"],
                title=f"Redirect with token={TOKEN_CANARY}",
            ),
            _cand("c-cors-confirmed", "s-api", "cors", "confirmed", ["e4"], review=review),
        ],
    )
    # incomplete evidence
    p = programs["incomplete-evidence"]
    _write(
        p,
        [_surface("s1", "/api/invoices/{id}", "pending", blocker="No control response captured")],
        [],
        [
            _cand(
                "c-no-evidence",
                "s1",
                "access_control",
                "requires_validation",
                [],
                blockers=["Missing control request from the resource owner"],
            )
        ],
    )
    # false positive
    p = programs["false-positive"]
    _write(
        p,
        [_surface("s1", "/api/status")],
        [_evidence(p, "e1", body)],
        [
            _cand(
                "c-fp-200",
                "s1",
                "access_control",
                "rejected",
                ["e1"],
                rejection={"reason": "false_positive", "detail": "HTTP 200 returned a public status page."},
            )
        ],
    )
    # rejected
    p = programs["rejected"]
    _write(
        p,
        [_surface("s1", "/api/files/{id}")],
        [_evidence(p, "e1", body)],
        [
            _cand(
                "c-rejected",
                "s1",
                "access_control",
                "rejected",
                ["e1"],
                rejection={"reason": "not_reproducible", "detail": "Access correctly denied (403)."},
            )
        ],
    )
    # AI discrepancy
    p = programs["ai-discrepancy"]
    _write(
        p,
        [_surface("s1", "/api/users/{id}")],
        [_evidence(p, "e1", body), _evidence(p, "e2", body)],
        [
            _cand(
                "c-ai",
                "s1",
                "access_control",
                "requires_validation",
                ["e1", "e2"],
                blockers=["Reviewers disagree on e2"],
            )
        ],
    )
    comparison = {
        "type": "ai-evidence-review-comparison",
        "finding_confirmed": False,
        "reviews": [
            {"provider": "mock", "model": "model-a", "decision": "likely", "validation_status": "valid"},
            {"provider": "mock", "model": "model-b", "decision": "unlikely", "validation_status": "valid"},
        ],
        "comparison": {
            "decision_agreement": False,
            "both_reviews_valid": True,
            "disputed_evidence": ["e2"],
            "cited_by_first_only": ["e1"],
            "cited_by_second_only": [],
            "missing_controls_union": ["owner control"],
            "independence": {"independent": True},
            "consensus_weight": "advisory_only",
        },
    }
    (p.reports_dir / "ai-compare.json").write_text(json.dumps(comparison), encoding="utf-8")
    # invalid references: model "confirmation", broken ref, tampered evidence
    p = programs["invalid-references"]
    _write(
        p,
        [_surface("s1", "/api/carts/{id}"), _surface("s2", "/api/notes/{id}")],
        [_evidence(p, "e1", body), _evidence(p, "e-tampered", body, tamper=True)],
        [
            _cand(
                "c-fake-confirmed",
                "s1",
                "access_control",
                "confirmed",
                ["e1", "e-ghost"],
                review={"reviewer": "ollama", "method": "model", "basis": "model", "reviewed_at": NOW},
            ),
            _cand(
                "c-tampered",
                "s2",
                "access_control",
                "requires_validation",
                ["e-tampered"],
                blockers=["Re-capture needed"],
            ),
        ],
    )
    # reviewable reports
    p = programs["reviewable-reports"]
    _write(
        p,
        [_surface("s1", "/api/docs/{id}")],
        [_evidence(p, "e1", body)],
        [
            _cand(
                "c-report",
                "s1",
                "access_control",
                "requires_validation",
                ["e1"],
                blockers=["Awaiting independent human review"],
            )
        ],
    )
    (p.reports_dir / "c-report-draft.md").write_text("# Draft\nSynthetic report for review.\n", encoding="utf-8")
    prio = {
        "type": "investigation-prioritization",
        "status": "review_required",
        "items": [{"group_id": "c-report", "priority_score": 40, "research_priority": "P2"}],
    }
    (p.reports_dir / "prio-1.json").write_text(json.dumps(prio), encoding="utf-8")
    prio["items"] = [
        {"group_id": "c-report", "priority_score": 55, "research_priority": "P2"},
        {"group_id": "g-new", "priority_score": 20, "research_priority": "P3"},
    ]
    later = p.reports_dir / "prio-2.json"
    later.write_text(json.dumps(prio), encoding="utf-8")
    import os

    os.utime(later, (time.time() + 5, time.time() + 5))
    return programs


def _client(root: Path, program: str) -> Any:
    from fastapi.testclient import TestClient

    from bugbounty_toolkit.dashboard import create_app

    return TestClient(create_app(root, program), base_url="http://127.0.0.1:8765", client=("127.0.0.1", 50000))


def _security_checks(root: Path) -> dict[str, bool]:
    c = _client(root, "multi-candidates")
    html = c.get("/").text
    checks = {
        "foreign_host_rejected": c.get("/api/triage", headers={"host": "rebind.example"}).status_code == 403,
        "foreign_origin_rejected": c.get("/api/triage", headers={"origin": "http://evil.example"}).status_code == 403,
        "cross_site_fetch_rejected": c.get("/api/triage", headers={"sec-fetch-site": "cross-site"}).status_code == 403,
        "non_loopback_client_rejected": _remote_client(root).get("/api/triage").status_code == 403,
        "write_methods_rejected": c.post("/api/triage").status_code == 405
        and c.delete("/api/reports/x.md").status_code == 405,
        "traversal_blocked": c.get("/api/reports/..%2F..%2Fledger%2Fevidence-ledger.json/content").status_code == 404
        and c.get("/api/triage/candidates/..%2Fx").status_code in {400, 404},
        "bad_filter_rejected": c.get("/api/triage", params={"state": "pwned"}).status_code == 400,
        "no_innerhtml_in_ui": "innerHTML" not in html and "insertAdjacentHTML" not in html and "eval(" not in html,
        "csp_present": "frame-ancestors 'none'" in c.get("/").headers.get("content-security-policy", ""),
        "no_action_buttons": not any(
            word in html.lower() for word in ("approve", "run scan", "aprobar", "ejecutar escáner")
        ),
    }
    c.close()
    return checks


def _remote_client(root: Path) -> Any:
    from fastapi.testclient import TestClient

    from bugbounty_toolkit.dashboard import create_app

    return TestClient(create_app(root, "multi-candidates"), base_url="http://127.0.0.1:8765", client=("203.0.113.9", 1))


def run(root: Path, repetitions: int = 20) -> dict[str, Any]:
    build_lab(root)
    scenarios: dict[str, Any] = {}
    leaked: set[str] = set()
    xss_raw = 0
    interp_errors = 0
    states_checked = 0
    broken_expected = broken_shown = 0
    all_latencies: list[float] = []
    for name, exp in EXPECTED.items():
        c = _client(root, name)
        latencies: list[float] = []
        sizes: dict[str, int] = {}
        for url in ("/api/triage", "/api/triage/ai-reviews", "/api/triage/runs", "/api/triage/review-queue"):
            for _ in range(repetitions):
                t0 = time.perf_counter()
                r = c.get(url)
                latencies.append((time.perf_counter() - t0) * 1000)
            assert r.status_code == 200, (name, url, r.status_code)
            sizes[url] = len(r.content)
            leaked |= {k for k in CANARIES if k in r.text}
            xss_raw += r.text.count("<script>")
        triage = c.get("/api/triage").json()
        # automated navigation: step 1 = open queue; the top candidate is rank 1 of that single response
        steps_top = 1
        top = triage["candidates"][0]["candidate_id"] if triage["candidates"] else None
        detail_steps = None
        if exp.get("missing_evidence"):
            detail = c.get(f"/api/triage/candidates/{exp['missing_evidence']}").json()
            leaked |= {k for k in CANARIES if k in json.dumps(detail)}
            detail_steps = 2 if any("evidence" in m.lower() for m in detail["candidate"]["missing_controls"]) else None
        for cand in triage["candidates"]:
            d = c.get(f"/api/triage/candidates/{cand['candidate_id']}")
            leaked |= {k for k in CANARIES if k in d.text}
            xss_raw += d.text.count("<script>")
        for cid, expected_state in exp["states"].items():
            states_checked += 1
            row = next((r for r in triage["candidates"] if r["candidate_id"] == cid), None)
            if (
                row is None
                or row["displayed_state"] != expected_state
                or row["confirmed"] != (expected_state == "confirmed")
            ):
                interp_errors += 1
        broken_expected += exp["broken"]
        broken_shown += min(exp["broken"], len({i["ref"] for i in triage["issues"] if i["broken_reference"]}))
        all_latencies += latencies
        scenarios[name] = {
            "top_candidate": top,
            "top_candidate_correct": top == exp["top"],
            "steps_to_top_candidate": steps_top if top else 1,
            "steps_to_missing_evidence": detail_steps,
            "broken_references_reported": triage.get("broken_references", 0),
            "response_bytes": sizes,
            "latency_ms_median": round(statistics.median(latencies), 3),
            "latency_ms_p95": round(sorted(latencies)[int(len(latencies) * 0.95) - 1], 3),
        }
        c.close()
    security = _security_checks(root)
    return {
        "type": "dashboard-triage-lab",
        "synthetic_only": True,
        "network_requests_sent": 0,
        "ollama_calls": 0,
        "human_participants": 0,
        "note": "Steps are scripted API calls and times are in-process TestClient timings, not human productivity.",
        "scenarios": scenarios,
        "metrics": {
            "scenarios": len(scenarios),
            "top_candidate_correct": sum(1 for s in scenarios.values() if s["top_candidate_correct"]),
            "state_interpretation_errors": interp_errors,
            "states_checked": states_checked,
            "broken_references_expected": broken_expected,
            "broken_references_shown": broken_shown,
            "canaries_leaked": sorted(leaked),
            "inert_xss_payloads_in_json_data": xss_raw,
            "security_checks_passed": sum(security.values()),
            "security_checks_total": len(security),
            "latency_ms_median_all": round(statistics.median(all_latencies), 3),
            "max_response_bytes": max(max(s["response_bytes"].values()) for s in scenarios.values()),
        },
        "security_checks": security,
    }


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="bbtk-dashboard-lab-") as tmp:
        result = run(Path(tmp))
    print(json.dumps(result, indent=2, sort_keys=True))
    m = result["metrics"]
    ok = (
        not m["canaries_leaked"]
        and m["state_interpretation_errors"] == 0
        and m["security_checks_passed"] == m["security_checks_total"]
        and m["broken_references_shown"] == m["broken_references_expected"]
    )
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
