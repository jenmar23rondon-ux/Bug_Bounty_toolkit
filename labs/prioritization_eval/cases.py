"""Human-style reference queue for the review prioritizer.

Hosts are loopback or RFC 5737 documentation addresses. Nothing here is a live
target, and the rows are not the frozen DEV, FINAL, or STRESS labels.

Reference policy, applied in this order:

1. Abstain when scope, origin, location, vulnerability class, session, evidence,
   or corroboration is missing, ambiguous, or contradictory.
2. Ignore tool severity. A Nuclei ``critical`` label adds no points.
3. Among rows that can be compared, order by the existing evidence and impact
   score, then one corroboration bonus, then one clear-session bonus, then item id.

The expected order below is that policy written out, not a fit to a later run.
"""

from __future__ import annotations

from typing import Any

SCOPE = ["127.0.0.1", "!127.0.0.1/admin"]
PROGRAM = "review-lab"

# Evidence, known controls, impact, corroboration (+6), clear session (+4).
# External rows have no attested control list, so their control term is 0.
GOLD_RANK = (
    "hyp-sqli-strong",  # 3 evidence, high, corroborated: 66
    "hyp-idor-session",  # 2 evidence, high, clear session: 54
    "hyp-xss-two",  # 2 evidence, medium, corroborated: 48
    "cand-jwt",  # 2 ledger refs, high, no attested controls: 40
    "ext-zap-sqli",  # 1 observed, high, corroborated: 36
    "hyp-info",  # 1 evidence, medium: 32
    "ext-xss-low",  # 1 observed, medium, corroborated, severity low: 28
    "hyp-redirect",  # 1 evidence, low: 25
    "hyp-redirect-b",  # same score; item id decides
    "ext-nuclei-critical-observed",  # 1 observed, medium, severity critical: 22
)

GOLD_ABSTAIN = {
    "ext-nuclei-critical-bare": "severity_without_supporting_evidence",
    "ext-out-of-scope": "out_of_scope",
    "ext-excluded-admin": "out_of_scope",
    "hyp-no-location": "missing_location",
    "ext-rce": "ambiguous_vulnerability_class",
    "ext-ffuf": "missing_vulnerability_class",
    "ext-contradictory-url": "contradictory_evidence",
    "ext-split-location": "contradictory_location",
    "hyp-contradicted": "contradictory_evidence",
    "ext-clash-xss": "contradictory_vulnerability_class",
    "ext-clash-sqli": "contradictory_vulnerability_class",
    "hyp-expired-session": "ambiguous_session",
    "hyp-two-actors": "contradictory_session",
    "ext-partial": "ambiguous_evidence",
    "ext-no-tool": "missing_origin",
    "ext-dup-a": "ambiguous_corroboration",
    "ext-dup-b": "ambiguous_corroboration",
    "cand-confirmed": "closed_review",
    "cand-rejected": "contradictory_evidence",
    "hyp-two-methods": "ambiguous_location",
}


def _gid(number: int) -> str:
    return f"{number:024x}"


def _evidence(number: int) -> dict[str, str]:
    return {"record_id": f"{number:024x}", "why": "Observed response differs from the same-user control."}


def _hypothesis(
    review_id: str,
    number: int,
    category: str,
    support: int,
    *,
    against: int = 0,
    host: str | None = "127.0.0.1",
    path: str | None = None,
    method: str | None = "GET",
    methods: list[str] | None = None,
    session: list[dict[str, Any]] | None = None,
    summary: str = "Compare the cited records before any further check.",
) -> dict[str, Any]:
    group: dict[str, Any] = {
        "review_id": review_id,
        "group_id": _gid(number),
        "status": "reviewed",
        "hypothesis": {
            "category": category,
            "summary": summary,
            "evidence_for": [_evidence(1000 + number * 10 + offset) for offset in range(support)],
            "evidence_against": [_evidence(5000 + number * 10 + offset) for offset in range(against)],
            "missing_controls": [],
            "confidence": "low",
            "next_check": {
                "kind": "offline",
                "suggestion": "Read the cited records side by side.",
                "why": "The citation is not a confirmed result.",
            },
            "status": "hypothesis",
        },
    }
    if host is not None and path is not None:
        endpoint: dict[str, Any] = {"host": host, "path_template": path}
        if methods is not None:
            endpoint["methods"] = methods
        elif method is not None:
            endpoint["method"] = method
        group["endpoint"] = endpoint
    if session is not None:
        group["session_observations"] = session
    return group


def _external(
    review_id: str,
    *,
    tool: str | None,
    source: str,
    index: int | None,
    host: str | None,
    endpoint: str | None,
    method: str | None,
    url: str | None,
    confidence: str | None,
    response: bool,
    status_code: int | None,
    diagnostics: list[str],
    vulnerability_class: str | None,
    claimed: bool,
    severity: str | None,
    status: str,
    access_confirmed: bool = False,
    vulnerabilities_confirmed: int = 0,
) -> dict[str, Any]:
    origin: dict[str, Any] = {"source_file": source}
    if tool is not None:
        origin["tool"] = tool
    if index is not None:
        origin["record_index"] = index
    return {
        "review_id": review_id,
        "schema": "bbtk.external-finding/1",
        "origin": origin,
        "evidence": {
            "url": url,
            "host": host,
            "endpoint": endpoint,
            "method": method,
            "status_code": status_code,
            "request_present": response,
            "response_present": response,
            "ingestion_confidence": confidence,
            "ingestion_diagnostics": diagnostics,
        },
        "hypothesis": {
            "vulnerability_class": vulnerability_class,
            "vulnerability_claimed": claimed,
            "claim": vulnerability_class,
            "severity_claimed": severity,
        },
        "status": status,
        "access_confirmed": access_confirmed,
        "vulnerabilities_confirmed": vulnerabilities_confirmed,
    }


def _owner(proofs: list[str]) -> list[dict[str, Any]]:
    return [
        {
            "session_ref": "owner-1",
            "label": "owner",
            "account_attested": True,
            "target_label": "owner",
            "access_proof": proof,
        }
        for proof in proofs
    ]


def build_queue() -> dict[str, Any]:
    """Return the main synthetic queue, its scope, and the ledger."""
    hypotheses = [
        _hypothesis("hyp-sqli-strong", 1, "sqli", 3, path="/api/invoices/{id}"),
        _hypothesis(
            "hyp-idor-session",
            2,
            "access_control",
            2,
            path="/api/orders/{id}",
            session=_owner(["private_resource_200"]),
        ),
        _hypothesis("hyp-xss-two", 3, "xss", 2, path="/api/comments"),
        _hypothesis("hyp-info", 4, "info_disclosure", 1, path="/api/profile"),
        _hypothesis("hyp-redirect", 5, "open_redirect", 1, path="/redirect"),
        _hypothesis("hyp-redirect-b", 6, "open_redirect", 1, path="/go"),
        _hypothesis("hyp-no-location", 7, "sqli", 2, host=None, path=None),
        _hypothesis("hyp-contradicted", 8, "sqli", 2, against=1, path="/api/contradiction"),
        _hypothesis(
            "hyp-expired-session",
            9,
            "xss",
            2,
            path="/api/expired",
            session=_owner(["private_resource_200", "http_401", "http_401"]),
        ),
        _hypothesis(
            "hyp-two-actors",
            10,
            "access_control",
            2,
            path="/api/shared-session",
            session=[
                {
                    "session_ref": "shared",
                    "label": "owner",
                    "account_attested": True,
                    "target_label": "owner",
                    "access_proof": "private_resource_200",
                },
                {
                    "session_ref": "shared",
                    "label": "actor",
                    "account_attested": True,
                    "target_label": "actor",
                    "access_proof": "private_resource_200",
                },
            ],
        ),
        _hypothesis("hyp-two-methods", 11, "sqli", 3, path="/api/either", methods=["GET", "POST"]),
    ]
    external = [
        _external(
            "ext-zap-sqli",
            tool="zap",
            source="zap.json",
            index=1,
            host="127.0.0.1",
            endpoint="/api/invoices/{id}",
            method="GET",
            url="http://127.0.0.1/api/invoices/{id}",
            confidence="observed",
            response=True,
            status_code=200,
            diagnostics=[],
            vulnerability_class="sql_injection",
            claimed=True,
            severity="medium",
            status="candidate",
        ),
        _external(
            "ext-xss-low",
            tool="nuclei",
            source="xss-low.json",
            index=1,
            host="127.0.0.1",
            endpoint="/api/comments",
            method="GET",
            url="http://127.0.0.1/api/comments",
            confidence="observed",
            response=True,
            status_code=200,
            diagnostics=[],
            vulnerability_class="cross_site_scripting",
            claimed=True,
            severity="low",
            status="candidate",
        ),
        _external(
            "ext-nuclei-critical-observed",
            tool="nuclei",
            source="critical-observed.json",
            index=1,
            host="127.0.0.1",
            endpoint="/api/search",
            method="GET",
            url="http://127.0.0.1/api/search",
            confidence="observed",
            response=True,
            status_code=200,
            diagnostics=[],
            vulnerability_class="cross_site_scripting",
            claimed=True,
            severity="critical",
            status="candidate",
            access_confirmed=True,
            vulnerabilities_confirmed=3,
        ),
        _external(
            "ext-nuclei-critical-bare",
            tool="nuclei",
            source="critical-bare.json",
            index=1,
            host="127.0.0.1",
            endpoint="/api/bare",
            method="GET",
            url="http://127.0.0.1/api/bare",
            confidence=None,
            response=False,
            status_code=None,
            diagnostics=[],
            vulnerability_class="cross_site_scripting",
            claimed=True,
            severity="critical",
            status="needs_review",
        ),
        _external(
            "ext-out-of-scope",
            tool="nuclei",
            source="outside.json",
            index=1,
            host="192.0.2.1",
            endpoint="/api/search",
            method="GET",
            url="http://192.0.2.1/api/search",
            confidence="observed",
            response=True,
            status_code=200,
            diagnostics=[],
            vulnerability_class="xss",
            claimed=True,
            severity="high",
            status="candidate",
        ),
        _external(
            "ext-excluded-admin",
            tool="nuclei",
            source="admin.json",
            index=1,
            host="127.0.0.1",
            endpoint="/admin/panel",
            method="GET",
            url="http://127.0.0.1/admin/panel",
            confidence="observed",
            response=True,
            status_code=200,
            diagnostics=[],
            vulnerability_class="xss",
            claimed=True,
            severity="high",
            status="candidate",
        ),
        _external(
            "ext-rce",
            tool="nuclei",
            source="rce.json",
            index=1,
            host="127.0.0.1",
            endpoint="/api/rce",
            method="GET",
            url="http://127.0.0.1/api/rce",
            confidence="observed",
            response=True,
            status_code=200,
            diagnostics=[],
            vulnerability_class="remote_code_execution",
            claimed=True,
            severity="critical",
            status="candidate",
        ),
        _external(
            "ext-ffuf",
            tool="ffuf",
            source="ffuf.json",
            index=1,
            host="127.0.0.1",
            endpoint="/api/hidden",
            method="GET",
            url="http://127.0.0.1/api/hidden",
            confidence=None,
            response=False,
            status_code=200,
            diagnostics=[],
            vulnerability_class="content_discovery",
            claimed=False,
            severity=None,
            status="candidate",
        ),
        _external(
            "ext-contradictory-url",
            tool="zap",
            source="conflict.json",
            index=1,
            host="127.0.0.1",
            endpoint="/api/conflict",
            method="GET",
            url="http://127.0.0.1/api/conflict",
            confidence="observed",
            response=True,
            status_code=200,
            diagnostics=["contradictory_url"],
            vulnerability_class="xss",
            claimed=True,
            severity="high",
            status="abstain",
        ),
        _external(
            "ext-split-location",
            tool="zap",
            source="split.json",
            index=1,
            host="127.0.0.1",
            endpoint="/api/a",
            method="GET",
            url="http://127.0.0.1/api/b",
            confidence="observed",
            response=True,
            status_code=200,
            diagnostics=[],
            vulnerability_class="xss",
            claimed=True,
            severity="medium",
            status="candidate",
        ),
        _external(
            "ext-clash-xss",
            tool="nuclei",
            source="clash-xss.json",
            index=1,
            host="127.0.0.1",
            endpoint="/api/notes",
            method="GET",
            url="http://127.0.0.1/api/notes",
            confidence="observed",
            response=True,
            status_code=200,
            diagnostics=[],
            vulnerability_class="xss",
            claimed=True,
            severity="medium",
            status="candidate",
        ),
        _external(
            "ext-clash-sqli",
            tool="sqlmap",
            source="clash-sqli.log",
            index=1,
            host="127.0.0.1",
            endpoint="/api/notes",
            method="GET",
            url="http://127.0.0.1/api/notes",
            confidence="observed",
            response=True,
            status_code=200,
            diagnostics=[],
            vulnerability_class="sql_injection",
            claimed=True,
            severity="high",
            status="candidate",
        ),
        _external(
            "ext-partial",
            tool="nuclei",
            source="partial.json",
            index=1,
            host="127.0.0.1",
            endpoint="/api/partial",
            method="GET",
            url="http://127.0.0.1/api/partial",
            confidence="partial",
            response=True,
            status_code=200,
            diagnostics=[],
            vulnerability_class="sqli",
            claimed=True,
            severity="high",
            status="needs_review",
        ),
        _external(
            "ext-no-tool",
            tool=None,
            source="anonymous.json",
            index=1,
            host="127.0.0.1",
            endpoint="/api/anon",
            method="GET",
            url="http://127.0.0.1/api/anon",
            confidence="observed",
            response=True,
            status_code=200,
            diagnostics=[],
            vulnerability_class="xss",
            claimed=True,
            severity="critical",
            status="candidate",
        ),
        _external(
            "ext-dup-a",
            tool="nuclei",
            source="dup.json",
            index=1,
            host="127.0.0.1",
            endpoint="/api/dup",
            method="GET",
            url="http://127.0.0.1/api/dup",
            confidence="observed",
            response=True,
            status_code=200,
            diagnostics=[],
            vulnerability_class="xss",
            claimed=True,
            severity="info",
            status="candidate",
        ),
        _external(
            "ext-dup-b",
            tool="nuclei",
            source="dup.json",
            index=1,
            host="127.0.0.1",
            endpoint="/api/dup",
            method="GET",
            url="http://127.0.0.1/api/dup",
            confidence="observed",
            response=True,
            status_code=200,
            diagnostics=[],
            vulnerability_class="xss",
            claimed=True,
            severity="critical",
            status="candidate",
        ),
    ]
    ledger = {
        "schema_version": "bbtk-evidence-ledger/1",
        "program": PROGRAM,
        "surfaces": [
            {
                "surface_id": "surf-jwt",
                "kind": "endpoint",
                "ref": "http://127.0.0.1/api/session",
                "status": "investigated",
            },
            {
                "surface_id": "surf-closed",
                "kind": "endpoint",
                "ref": "http://127.0.0.1/api/closed",
                "status": "reviewed",
            },
            {
                "surface_id": "surf-rejected",
                "kind": "endpoint",
                "ref": "http://127.0.0.1/api/rejected",
                "status": "investigated",
            },
        ],
        "evidence": [],
        "candidates": [
            {
                "review_id": "cand-jwt",
                "candidate_id": "cand-jwt",
                "surface_id": "surf-jwt",
                "category": "jwt",
                "state": "candidate",
                "evidence_refs": ["evidence-jwt-1", "evidence-jwt-2"],
                "raised_by": "bbtk",
                "title": "Local token structure still needs a human pass.",
            },
            {
                "review_id": "cand-confirmed",
                "candidate_id": "cand-confirmed",
                "surface_id": "surf-closed",
                "category": "sqli",
                "state": "confirmed",
                "evidence_refs": ["evidence-closed-1", "evidence-closed-2", "evidence-closed-3"],
                "raised_by": "bbtk",
                "title": "Already closed by a human reviewer.",
            },
            {
                "review_id": "cand-rejected",
                "candidate_id": "cand-rejected",
                "surface_id": "surf-rejected",
                "category": "xss",
                "state": "rejected",
                "evidence_refs": ["evidence-rejected-1"],
                "raised_by": "bbtk",
                "rejection": {"reason": "false_positive", "detail": "The marker was not the claimed sink."},
                "title": "Rejected false positive.",
            },
        ],
    }
    return {
        "program": PROGRAM,
        "scope": list(SCOPE),
        "hypotheses": {"type": "ai-hypotheses", "notice": "second opinion", "groups": hypotheses},
        "external": external,
        "ledger": ledger,
        "group_ids": {group["review_id"]: group["group_id"] for group in hypotheses},
    }


def severity_of(queue: dict[str, Any]) -> dict[str, int]:
    """Tool-severity weights used only by the before arm. Missing severity is 0."""
    weights = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
    found = {review_id: 0 for review_id in (*GOLD_RANK, *GOLD_ABSTAIN)}
    for finding in queue["external"]:
        severity = finding["hypothesis"].get("severity_claimed")
        found[finding["review_id"]] = weights.get(severity, 0) if isinstance(severity, str) else 0
    return found
