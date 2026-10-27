"""Vulnerability review checklist and shared confirmation-bar helpers.

confirmed requires a second independent proof defined per check. A single signal
is candidate. Rejected checks must record why. No new bug classes live here.
"""

from __future__ import annotations

from typing import Any

CHECKLIST = [
    {
        "category": "IDOR / Object Authorization",
        "items": [
            "Compare two authorized test accounts and verify object identifiers cannot be swapped.",
            "Review numeric IDs, UUIDs, slugs, invoice IDs, file IDs, organization IDs, and user IDs.",
            "Check read, update, delete, export, and download actions separately.",
        ],
    },
    {
        "category": "Authorization Bypass",
        "items": [
            "Compare normal user, manager, and admin routes when program scope allows role testing.",
            "Verify hidden UI actions are also blocked server-side.",
            "Review direct API calls for role-only functions.",
        ],
    },
    {
        "category": "Injection",
        "items": [
            "Review parameters that reach search, filters, sorting, login, reports, exports, and admin tools.",
            "Use safe, non-destructive SQLi validation patterns and stop before data access beyond authorization.",
            "Review reflected, stored, and DOM XSS surfaces with benign proof-of-execution evidence.",
            "Check command execution risk only where application features legitimately call system tooling.",
        ],
    },
    {
        "category": "Security Misconfiguration",
        "items": [
            "Look for exposed admin panels, default pages, debug endpoints, verbose errors, and unsafe headers.",
            "Review subdomain takeover indicators for dangling third-party service records.",
            "Validate CORS only with authorized origins and evidence of readable sensitive responses.",
        ],
    },
    {
        "category": "Business Logic",
        "items": [
            "Review price, quantity, coupon, refund, and subscription transitions.",
            "Test rate limits, replay behavior, workflow skipping, and one-time token reuse.",
            "Document business impact clearly; scanner output alone is not enough.",
        ],
    },
    {
        "category": "Sensitive Information Exposure",
        "items": [
            "Review public JavaScript, source maps, repositories, error pages, headers, and logs exposed by the app.",
            "Classify tokens and API keys by service, permissions, environment, and exploitability.",
            "Avoid using secrets beyond minimal validation allowed by the program policy.",
        ],
    },
]

FINDING_STATES = ("candidate", "confirmed", "not_observed", "inconclusive", "rejected")
REJECTION_REASONS = frozenset({"false_positive", "out_of_scope", "no_second_proof"})
# Checks that can reach confirmed under the confirmation bar (used by hunt).
CONFIRMABLE_MODULES = (
    "cors-check",
    "ssrf-check",
    "open-redirect",
    "xss",
    "sqli",
    "access-check",
)


def render_checklist() -> str:
    lines = ["# Vulnerability Review Checklist", ""]
    for group in CHECKLIST:
        lines.append(f"## {group['category']}")
        for item in group["items"]:
            lines.append(f"- [ ] {item}")
        lines.append("")
    return "\n".join(lines)


def validate_rejection_reason(reason: str | None) -> str | None:
    if reason is None:
        return None
    if reason not in REJECTION_REASONS:
        raise ValueError(f"Unsupported rejection reason: {reason}")
    return reason


def aggregate_finding_state(states: list[str], *, stop_reason: str | None = None) -> str:
    """Aggregate per-probe states: confirmed > candidate > inconclusive > not_observed."""
    unique = {state for state in states if state}
    if "confirmed" in unique:
        return "confirmed"
    if "candidate" in unique:
        return "candidate"
    if stop_reason or "inconclusive" in unique or "rejected" in unique:
        return "inconclusive" if "inconclusive" in unique or stop_reason else "rejected"
    return "not_observed"


def candidates_per_confirmed(candidate_count: int, confirmed_count: int) -> float | None:
    """Lab metric: candidates observed per confirmed finding. None if no confirmations."""
    if confirmed_count <= 0:
        return None
    if candidate_count < 0 or confirmed_count < 0:
        raise ValueError("Counts must be non-negative.")
    return candidate_count / confirmed_count


def apply_rejection(row: dict[str, Any], reason: str) -> dict[str, Any]:
    """Mark a check result rejected with a required reason; never confirms."""
    validate_rejection_reason(reason)
    updated = dict(row)
    updated["finding_state"] = "rejected"
    updated["confirmed"] = False
    updated["rejection_reason"] = reason
    updated["confirmation_gap"] = None
    return updated
