---
name: bugbounty-cors
description: Check CORS policy on a supplied authorized in-scope URL by comparing attacker Origin values with ACAO and ACAC response headers. Use for CORS, not general HTTP or access-control testing.
---

# CORS

Handle only the CORS topic. Require the existing program authorization, scope, automation setting and configured limits before live traffic. Read the shared [command reference](../bugbounty-executor/references/commands.md) for setup and CLI mechanics.

Use `bbtk cors-check <program> --url <supplied-url> --dry-run` first. The executor tests four Origins (`https://evil.com`, `null`, `https://evil.<target-host>`, and `https://<target-host>.evil.com`) with GET and compares only `Access-Control-Allow-Origin` and `Access-Control-Allow-Credentials`. Remove `--dry-run` only for the already authorized run. The native client enforces scope, configured rate and timeout and does not follow redirects. Optional user-provided headers/cookies are never written to this evidence type.

Interpret exact reflection plus `ACAC: true` as a vulnerable CORS configuration; reflection without true credentials is weak; wildcard or no attacker-origin reflection is safe under this tool's classification. This is a header-policy result, not proof that sensitive data is accessible or that a browser can exploit the policy. Check the program's policy for authenticated testing and use only the necessary test account. Stop on 401/403/429, transport errors or program restrictions; do not try additional origins or paths to bypass a stop.

Report the four sent Origins, returned ACAO/ACAC, statuses, verdict counts and local evidence path. Do not reproduce cookies, tokens, response bodies or private data in the summary.
