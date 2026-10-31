---
name: bugbounty-cors
description: Check CORS policy on a supplied authorized in-scope URL by comparing attacker Origin values with ACAO and ACAC response headers. Use for CORS, not general HTTP or access-control testing.
---

# CORS

Handle only the CORS topic. Require the existing program authorization, scope, automation setting and configured limits before live traffic. Read the shared [command reference](../bugbounty-executor/references/commands.md) for setup and CLI mechanics.

Use `bbtk cors-check <program> --url <supplied-url> --dry-run` first. The executor tests four Origins (`https://evil.com`, `null`, `https://evil.<target-host>`, and `https://<target-host>.evil.com`) with GET and compares only `Access-Control-Allow-Origin` and `Access-Control-Allow-Credentials`. Remove `--dry-run` only for the already authorized run. The native client enforces scope, configured rate and timeout and does not follow redirects. Optional user-provided headers/cookies are never written to this evidence type.

Exact Origin reflection plus case-sensitive `ACAC: true` is a candidate policy signal. A Cookie or Authorization header plus a non-empty 2xx body does not prove that the content is private or browser-readable by an attacker: cookies can be analytics and the resource can be public. Native probes therefore never confirm CORS or set `private_body_readable` from body presence. Independent private-resource controls and a real authorized browser-read proof are still needed. Wildcard/no reflection means no credentialed-reflection signal in this test, not proof that the endpoint is safe.

Use `finding_state`, `confirmed` and `confirmation_gap` as the evidence verdict; legacy `classification: VULNERABLE` describes only the headers. Rejected checks record a reason (`false_positive`, `out_of_scope`, `no_second_proof`). Truncation/server failures are inconclusive. Evidence omits cookies, tokens and bodies. Stop on 401/403/429, transport errors or program restrictions; do not bypass a stop with different origins or paths.

Report the four sent Origins, returned ACAO/ACAC, statuses, verdict counts and local evidence path. Do not reproduce cookies, tokens, response bodies or private data in the summary.
