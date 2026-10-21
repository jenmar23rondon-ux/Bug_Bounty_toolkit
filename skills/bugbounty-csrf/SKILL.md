---
name: bugbounty-csrf
description: Heuristically inspect one authorized HTML response for CSRF-related form tokens and SameSite cookie attributes. Does not submit forms or confirm exploitability.
---

# CSRF Audit

Handle only the CSRF topic. Use the shared [command reference](../bugbounty-executor/references/commands.md) for program setup, scope, limits and evidence.

Use only the exact supplied URL. Run `bbtk csrf-audit <program> --url <supplied-url> --dry-run` first, then execute only within the program's existing authorization and automation policy. The command sends one GET through the native scope-, rate-, timeout- and budget-aware HTTP client. It does not follow redirects, submit forms, change state or probe alternate routes.

The audit parses HTML with the existing Beautiful Soup parser. It records form methods, whether POST forms contain a hidden field whose name or id resembles a CSRF token, and SameSite/Secure/HttpOnly attributes from response cookies. Cookie values, form values and response HTML are not written to evidence. Multiple `Set-Cookie` headers are inspected separately.

Interpret `protected`, `weak` and `possible_csrf` as heuristic labels only. A single GET cannot establish browser behavior or exploitability. `inconclusive` means the response could not be assessed, for example because it was non-HTML, truncated, redirected, denied or unavailable. `SameSite=None` without `Secure` is called out, but this does not by itself prove CSRF. Never submit a cross-origin form or claim a confirmed finding from this command.

Install the parser with `python -m pip install -e ".[csrf]"` or use the broader `xss` extra. The skill itself does not install dependencies or initiate network traffic.
