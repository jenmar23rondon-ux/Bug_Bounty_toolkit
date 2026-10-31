# Hunt (confirmation bar)

One-page workflow for authorized programs. Pick a program yourself; this doc never names one. No real-domain traffic from the toolkit docs or labs.

## 1. Scope first

1. Obtain written program scope and authorization.
2. Put in-scope hosts in `inputs/scope.yaml` (or `scope.txt`) under your program folder.
3. Keep routes and parameters you already have in `inputs/routes.txt` and `inputs/parameters.txt`.

## 2. Command

`bbtk hunt` coordinates the following checks, preserving each check's evidence threshold:

`cors-check`, `ssrf-check`, `open-redirect`, `xss`, `sqli`, `access-check`

Standalone (never auto-confirmed by hunt): `csrf-audit`, `takeover-check`.

Example (dry-run, offline planning):

```bash
bbtk hunt my-program \
  --base-url "https://authorized.example" \
  --routes inputs/routes.txt \
  --params inputs/parameters.txt \
  --max-tests 30 \
  --dry-run
```

Use `--only` / `--exclude` to bound modules. SSRF needs `--ssrf-url` and `--ssrf-param`. Access-check needs a case file.

## 3. Candidate → confirmed

| Check | Confirmed only when | Otherwise |
| --- | --- | --- |
| CORS | Independent private-data and attacker-browser read proof, not supplied by native probes | reflected policy = candidate |
| Open redirect | Independent parameter-causality controls, not supplied by native probes | matching external Location = candidate; never followed |
| SSRF | Lab loopback canary received the request | candidate |
| XSS | `--confirm-exec`/Playwright or DOM loopback execution | reflection = candidate |
| SQLi | Independent execution proof with repeated stable controls, not supplied by native probes | error/timing/boolean/UNION indicators = candidate |
| IDOR/BOLA | Session B reads/writes A’s resource, controls proven, both responses in evidence | candidate |
| CNAME takeover | Never confirmed | candidate (dangling+known+unclaimed) or inconclusive |

Rejected rows record `false_positive`, `out_of_scope`, or `no_second_proof`.

## 4. When NOT to report

- State is `candidate`, `not_observed`, `inconclusive`, or `rejected`.
- Second proof missing (canary, execution, cross-session evidence, controlled redirect causality).
- Asset or behavior is out of written scope.
- You only saw a fingerprint, reflection, or error signature.
- You have not reproduced on the authorized asset with your own accounts.

## 5. Report shape

Confirmed lab evidence → HackerOne-shaped Markdown via the reporting helpers (title, asset, type, state, request, truncated response, numbered steps, one-sentence impact, what was not done). Use `reports/template.md`. Close and submit the hunt yourself; the toolkit does not send reports.

## Pre-submit checklist

1. Written scope and authorization cover the asset and method.
2. Finding state is `confirmed` (not candidate).
3. Second proof for that check type is in evidence.
4. Request/response snippets are redacted; no secrets in the draft.
5. Steps reproduce with your own test accounts only.
6. Impact is one factual sentence; no adjectives.
7. “What was not done” lists limits (no redirect follow, no out-of-scope hosts).
8. You will submit manually; nothing was auto-sent.


## Business-logic planner

`bbtk analyze business-logic` builds an offline candidate test plan from HAR/captures. See docs/business-logic-planner.md.
