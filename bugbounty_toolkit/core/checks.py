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


def render_checklist() -> str:
    lines = ["# Vulnerability Review Checklist", ""]
    for group in CHECKLIST:
        lines.append(f"## {group['category']}")
        for item in group["items"]:
            lines.append(f"- [ ] {item}")
        lines.append("")
    return "\n".join(lines)
