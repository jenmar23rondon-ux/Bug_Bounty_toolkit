---
name: bugbounty-open-redirect
description: Check a supplied authorized in-scope URL parameter for redirects to an external host without following the redirect. Use for open-redirect testing, not route discovery.
---

# Open Redirect

Handle only the open-redirect topic. Require the existing program authorization, scope, automation setting and configured limits before live traffic. Read the shared [command reference](../bugbounty-executor/references/commands.md) for setup and CLI mechanics.

Use `bbtk open-redirect <program> --url <supplied-url> --param <name> --dry-run` first. The URL must already contain that query parameter exactly once. The bounded runner replaces only its value with five reviewed external redirect forms, sends GET requests through the native in-scope client, and never follows `Location`. Remove `--dry-run` only for the already authorized run. Scope, timeout, rate limit, credential redaction and stop-on-401/403/429 are shared with the toolkit.

An absolute or protocol-relative Location resolving to `evil.com` or its subdomains is a candidate vulnerable redirect; a relative internal path or missing Location is not vulnerable in this test. A matching Location alone does not prove parameter causality: a fixed redirect can ignore the parameter entirely. Native results remain candidates with missing baseline and independent destination controls. The toolkit does not visit the destination. An absent finding is not proof that other parameters or browser-specific parsing are safe. Do not add paths, parameters or payloads beyond the supplied case without a separately reviewed scope and budget.

Report each test value, status, redacted Location and verdict, then the local evidence path. Never open the external Location, expose credentials, or copy private tokens from a redirect URL into a shared report.
