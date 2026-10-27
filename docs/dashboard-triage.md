# Investigation triage dashboard

`bbtk dashboard <program>` serves a loopback-only, read-only triage view. All data is
derived from artifacts that other commands already write; the dashboard stores nothing
and cannot change authorization, scope or candidate state.

## Data sources (no duplicated storage)

| View | Source artifact | Logic reused |
|---|---|---|
| Overview, coverage, candidate queue, broken refs | `ledger/evidence-ledger.json` | `analysis.evidence_ledger.validate_ledger` / `summarize_ledger` |
| Impact band in ranking | category table | `analysis.prioritization._POTENTIAL_IMPACT` |
| Priority score, run comparison | `reports/*.json` with `type: investigation-prioritization` | saved by `bbtk prioritize` |
| AI reviewer differences | `reports/*.json` with `type: ai-evidence-review-comparison` | `analysis.multi_review.compare_reviews` output |
| Progress / technical errors | `runs` table in `toolkit.sqlite3` | counts only, no command lines |
| Legacy views | unchanged `/api/overview`, `/api/hypotheses`, `/api/graph/search`, … | unchanged |

## New read-only endpoints

* `GET /api/triage?category=&state=&evidence=` — prioritized queue, coverage, issues, ranking explanation.
* `GET /api/triage/candidates/{id}` — missing controls, IDOR/BOLA flow stage, minimized provenance (evidence ID, digest prefix, tool, capture time; never paths, bodies, headers or cookies).
* `GET /api/triage/ai-reviews` — disputed / one-sided citations; `consensus_is_proof` is always `false`.
* `GET /api/triage/runs` — run progress and diff of the two latest prioritization reports.
* `GET /api/triage/review-queue` — saved reports alongside candidates awaiting human review.

## State rules

A candidate is displayed as `confirmed` only when the ledger says `confirmed` **and**
the ledger validator raised no error for it **and** it has current evidence and a review
record. Otherwise it is shown as `requires_validation` with a warning. The ranking is a
reading order (state → usable evidence → heuristic impact band → saved score → ID), not
severity or proof.

## Security

* Loopback bind and loopback client only; `Host` must be `localhost`/loopback (DNS-rebinding guard).
* Any request carrying a non-loopback `Origin` or `Sec-Fetch-Site: cross-site` is rejected.
* All non-GET methods are rejected except the pre-existing offline evidence import.
* UI renders every value with `textContent` (no `innerHTML`); CSP `frame-ancestors 'none'`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`.
* Display text is length-bounded and passes `redact_jwts` plus display-only masking of bearer/basic credentials and `token=`/`cookie:`-style pairs. `/api/overview` now withholds directories from `output_path` / `evidence_path` and masks secrets in run commands.
* No buttons to run scanners, approve tests, confirm findings, change scope, run commands or upload evidence.

## Lab and metrics

`python -m labs.dashboard_triage_lab.run_lab` builds eight synthetic investigations
(no candidates, multiple candidates, incomplete evidence, false positive, rejected,
AI discrepancy, invalid references, reviewable reports) with JWT/token/cookie/body/path
canaries and an XSS payload, then drives the app in-process. Steps are scripted API
calls and times are TestClient timings — no human productivity is claimed.

Residual risks: display masking is pattern-based and can miss novel secret formats in
free-text ledger fields; the impact band is a category heuristic; the dashboard trusts the
ledger file on disk as the source of review state.

## Unified security-research view

`GET /api/triage/security-research` (see `docs/unified-security-research-triage.md`)
aggregates IDOR/XSS/disclosure candidates with gaps, blockers, duplicates,
pos/neg controls, inconclusive and review-ready dossiers. Read-only; AI cannot
approve; no exploit buttons; ranking is not invented severity.
