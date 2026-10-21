---
name: bugbounty-ssrf
description: Run a bounded, heuristic SSRF comparison on a supplied authorized in-scope URL parameter. Use for SSRF checks, not URL discovery, internal-network enumeration or metadata extraction.
---

# SSRF

Handle only the SSRF topic. Require the existing program authorization, scope, automation setting and configured limits before live traffic. Read the shared [command reference](../bugbounty-executor/references/commands.md) for setup and CLI mechanics.

Use only the exact URL and parameter supplied by the user. Dry-run first with `bbtk ssrf-check <program> --url <supplied-url> --param <name> --dry-run`. The fixed runner sends the supplied URL once as a baseline, then tests five fixed URL values in that parameter. It enforces target scope, configured rate, timeout and the shared request budget. Redirects are not followed; response bodies and request credentials are never saved.

Interpret `possible` as a status/body difference from baseline and `reflected` as the injected URL appearing in the response. Timing deltas are supporting context, not standalone proof. Every result is heuristic and unconfirmed; no OOB callback or impact validation is implemented. A metadata-path response can contain sensitive information, so the tool discards response bodies and the skill must not request, reproduce or extract metadata values or credentials.

Stop on 401/403/429, rate limits, transport errors, truncation or program restrictions. Do not add ports, paths, hosts, redirects, OOB destinations or follow-up probes. Summarize the baseline status, per-probe status and timing delta, classifications, stop reason and local evidence path without including secrets or response content.
