"""Pre-declared disposable-lab cases.

Labels describe the lab behavior. They were not copied from detector output.
DEV may be used to fix the harness. FINAL and STRESS labels are frozen with the
hash manifest before the first FINAL/STRESS measurement.
"""

from __future__ import annotations

from typing import Any

TRUTHS = ("review", "reject", "abstain")
WORKFLOWS = ("A", "B", "C")


def _case(
    case_id: str,
    split: str,
    workflow: str,
    truth: str,
    reason: str,
    behavior: dict[str, Any],
) -> dict[str, Any]:
    if truth not in TRUTHS:
        raise ValueError(truth)
    if workflow not in WORKFLOWS:
        raise ValueError(workflow)
    return {
        "id": case_id,
        "split": split,
        "workflow": workflow,
        "truth": truth,
        "truth_reason": reason,
        "behavior": behavior,
    }


def _idor(
    case_id: str,
    split: str,
    truth: str,
    reason: str,
    *,
    kind: str,
    resource_id: str,
    visibility: str,
    owner_status: int = 200,
    actor_status: int = 200,
    cross_account: bool = False,
    contradiction: bool = False,
) -> dict[str, Any]:
    return _case(
        case_id,
        split,
        "A",
        truth,
        reason,
        {
            "type": "idor_pair",
            "resource_kind": kind,
            "resource_id": resource_id,
            "visibility": visibility,
            "owner_status": owner_status,
            "actor_status": actor_status,
            "cross_account": cross_account,
            "contradiction": contradiction,
        },
    )


def _xss(
    case_id: str,
    split: str,
    truth: str,
    reason: str,
    *,
    marker: str,
    escape: bool,
    truncated: bool = False,
    injection: bool = False,
) -> dict[str, Any]:
    return _case(
        case_id,
        split,
        "B",
        truth,
        reason,
        {
            "type": "reflected",
            "marker": marker,
            "escape": escape,
            "truncated": truncated,
            "injection": injection,
        },
    )


def _dom(case_id: str, split: str, truth: str, reason: str, *, sink: str) -> dict[str, Any]:
    return _case(
        case_id,
        split,
        "B",
        truth,
        reason,
        {"type": "dom", "sink": sink, "truncated": False},
    )


def _disc(
    case_id: str,
    split: str,
    truth: str,
    reason: str,
    *,
    shape: str,
    audience: str,
    path: str,
    status: int = 200,
    truncated: bool = False,
) -> dict[str, Any]:
    return _case(
        case_id,
        split,
        "C",
        truth,
        reason,
        {
            "type": "disclosure",
            "shape": shape,
            "audience": audience,
            "path": path,
            "status": status,
            "truncated": truncated,
        },
    )


def cases_for(split: str) -> list[dict[str, Any]]:
    """Return the cases for one split. Order is the triage order."""
    if split == "dev":
        return [
            _idor(
                "A-dev-vuln-order",
                "dev",
                "review",
                "Actor token receives the owner private marker for order 1001.",
                kind="order",
                resource_id="1001",
                visibility="private",
                cross_account=True,
            ),
            _idor(
                "A-dev-safe-deny",
                "dev",
                "reject",
                "Protected order route returns 403 to the other account.",
                kind="order",
                resource_id="1002",
                visibility="private",
                actor_status=403,
            ),
            _idor(
                "A-dev-shared",
                "dev",
                "reject",
                "Both accounts receive the same shared handbook.",
                kind="document",
                resource_id="handbook",
                visibility="shared",
                cross_account=True,
            ),
            _xss(
                "B-dev-reflect",
                "dev",
                "review",
                "HTML text reflects the marker with live angle brackets.",
                marker="bbtkmdev1",
                escape=False,
            ),
            _xss(
                "B-dev-escaped",
                "dev",
                "reject",
                "The same marker is HTML-escaped.",
                marker="bbtkmdev2",
                escape=True,
            ),
            _dom(
                "B-dev-dom-sink",
                "dev",
                "review",
                "Page assigns location.hash to innerHTML. Browser execution is not claimed.",
                sink="innerHTML",
            ),
            _disc(
                "C-dev-public-secret",
                "dev",
                "review",
                "Public response carries a password field.",
                shape="password",
                audience="public",
                path="/api/export",
            ),
            _disc(
                "C-dev-docs",
                "dev",
                "reject",
                "Documentation path serves an example placeholder.",
                shape="example",
                audience="public",
                path="/docs/api",
            ),
            _disc(
                "C-dev-truncated",
                "dev",
                "abstain",
                "Response is marked truncated before a disposition is reliable.",
                shape="password",
                audience="public",
                path="/api/export-partial",
                truncated=True,
            ),
        ]
    if split == "final":
        return [
            _idor(
                "A-final-vuln-invoice",
                "final",
                "review",
                "Actor token receives the owner private marker for invoice 4402.",
                kind="invoice",
                resource_id="4402",
                visibility="private",
                cross_account=True,
            ),
            _idor(
                "A-final-safe-deny",
                "final",
                "reject",
                "Invoice route returns 403 to the other account.",
                kind="invoice",
                resource_id="4403",
                visibility="private",
                actor_status=403,
            ),
            _idor(
                "A-final-public-catalog",
                "final",
                "reject",
                "Catalog object is marked public for every caller.",
                kind="catalog",
                resource_id="sku-9",
                visibility="public",
                cross_account=True,
            ),
            _idor(
                "A-final-error-500",
                "final",
                "abstain",
                "Cross-account read returns HTTP 500 without a private marker.",
                kind="invoice",
                resource_id="4404",
                visibility="private",
                actor_status=500,
            ),
            _xss(
                "B-final-reflect",
                "final",
                "review",
                "Held-out HTML reflection with live angle brackets.",
                marker="bbtkmfin1",
                escape=False,
            ),
            _xss(
                "B-final-escaped",
                "final",
                "reject",
                "Held-out reflection is HTML-escaped.",
                marker="bbtkmfin2",
                escape=True,
            ),
            _dom(
                "B-final-dom-safe",
                "final",
                "reject",
                "Page reads location.hash into textContent and has no innerHTML sink.",
                sink="textContent",
            ),
            _xss(
                "B-final-truncated-reflect",
                "final",
                "abstain",
                "Reflection response is explicitly truncated.",
                marker="bbtkmfin3",
                escape=False,
                truncated=True,
            ),
            _disc(
                "C-final-public-token",
                "final",
                "review",
                "Unauthenticated export carries a password field.",
                shape="password",
                audience="public",
                path="/api/status-export",
            ),
            _disc(
                "C-final-self-profile",
                "final",
                "reject",
                "Authenticated caller sees their own password field.",
                shape="password",
                audience="authenticated_self",
                path="/api/me",
            ),
            _disc(
                "C-final-truncated",
                "final",
                "abstain",
                "Held-out disclosure body is truncated.",
                shape="password",
                audience="public",
                path="/api/me-partial",
                truncated=True,
            ),
            _disc(
                "C-final-empty",
                "final",
                "abstain",
                "HTTP 204 with an empty body is technically inconclusive.",
                shape="empty",
                audience="public",
                path="/api/empty",
                status=204,
            ),
        ]
    if split == "stress":
        rows = [
            _xss(
                "S-xss-primary",
                "stress",
                "review",
                "Unescaped reflection used as the dedup original.",
                marker="bbtkmstr1",
                escape=False,
            ),
            _case(
                "S-xss-duplicate",
                "stress",
                "B",
                "reject",
                "Same response body as S-xss-primary; a second candidate is duplicate paperwork.",
                {"type": "mirror", "of": "S-xss-primary"},
            ),
            _xss(
                "S-xss-injection",
                "stress",
                "review",
                "Unescaped reflection plus an instruction string in an HTML comment.",
                marker="bbtkmstr2",
                escape=False,
                injection=True,
            ),
            _idor(
                "S-idor-contradiction",
                "stress",
                "abstain",
                "Actor body contains the owner marker and a denial contradiction.",
                kind="order",
                resource_id="9001",
                visibility="private",
                cross_account=True,
                contradiction=True,
            ),
            _disc(
                "S-canary-public",
                "stress",
                "review",
                "Public body contains the lab canary. Shareable output must omit the value.",
                shape="canary",
                audience="public",
                path="/api/canary",
            ),
        ]
        for index in range(1, 6):
            rows.append(
                _disc(
                    f"S-noise-{index}",
                    "stress",
                    "reject",
                    "Public status object with no secret-shaped field.",
                    shape="status",
                    audience="public",
                    path=f"/api/health-noise-{index}",
                )
            )
        return rows
    raise ValueError(f"unknown split: {split}")


def document(split: str) -> dict[str, Any]:
    rows = cases_for(split)
    if any(row["split"] != split for row in rows):
        raise ValueError("split mismatch")
    ids = [row["id"] for row in rows]
    if len(ids) != len(set(ids)):
        raise ValueError("duplicate case id")
    return {
        "schema": "bbtk-investigator-workflow-efficacy-cases/1",
        "split": split,
        "finding_confirmed": False,
        "note": (
            "Labels describe this disposable lab only. They were declared from the "
            "server behavior before the bbtk arm was scored. Not field bug-bounty efficacy."
        ),
        "cases": rows,
    }
