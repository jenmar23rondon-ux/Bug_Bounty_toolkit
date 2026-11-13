# Explainable review prioritization

`bugbounty_toolkit/analysis/review_prioritization.py` (`bbtk.review-prioritization/1`)
orders three local inputs for a human reviewer:

- `bbtk.external-finding/1` rows from `bbtk evidence external`
- reviewed groups from `bbtk ai hypotheses`
- open candidates in a `bbtk-evidence-ledger/1` document

The order is advisory. `access_confirmed` stays false, `vulnerabilities_confirmed`
stays 0, and `confirmations_created` stays 0. A row that already claims
confirmation, including a ledger candidate in `confirmed`, is not turned into a
new confirmation. Tool severity is stored on the explanation and is not a score
term.

This command does not run Nuclei, ZAP, FFUF, or SQLMap, and it does not send a
request. `--requests-per-second` and `--max-tests` are recorded. The test budget
is only a deferral flag on a later check; it is not spent. `--dry-run` prints
the order and does not write a file. Scope matching uses the existing scope
rules and still leaves `scope_validated` false, because a local rule is not an
authorization decision.

## What is reused

| Piece | Role in this order |
|---|---|
| `prioritization._score` | Evidence count (capped at 3) and the existing impact points. Execution cost and operational risk are passed as 0 so a cheaper check is not reviewed first. |
| `prioritization._POTENTIAL_IMPACT` and `_IMPACT_POINTS` | The only impact bands. Unmapped classes abstain. |
| `prioritization._priority` | P1, P2, P3, or hold from the final score. |
| `skill_router.SKILL_REGISTRY` | The suggested dry-run command template and the budget used for deferral. |
| `actor_provenance.classify_session_controls` | Session and actor clarity. `confirmed` from that helper is ignored. |
| `external_importers._CONTRADICTIONS` | Capture contradictions such as `contradictory_url` and `ambiguous_session`. |
| `core.scope.ScopeRule` | In-scope and excluded locations. |

`bbtk ai prioritize` is unchanged. It still ranks hypothesis checks by evidence,
impact, cost, and operational risk. This command answers a different question:
which item a person should open first.

## Score

Only a row with no abstain reason is scored.

| Term | Points | Source |
|---|---:|---|
| Observed supporting records | 10 each, cap 3 | `_score` |
| Attested missing controls | 10 minus 2 per listed control, floor 0 | `_score`, only when the hypothesis supplied the list |
| Controls not attested | 0 | The empty-list bonus inside `_score` is removed. An external row does not get credit for controls nobody listed. |
| Vulnerability-class band | high 20, medium 12, low 5 | `_IMPACT_POINTS` |
| Corroboration | 6 once | At least one other origin (different tool or source file) agrees on host, endpoint, method, and class |
| Clear session or actor | 4 once | `classify_session_controls` returns only clear classes |
| Tool severity | 0 | Never |
| Execution cost | 0 in the review score | Reported on `suggested_check` and used only for `budget_status` |

Ties break by `item_id` ascending. The same inputs produce the same order.

Class aliases that already exist as bands: `sql_injection` → `sqli`,
`cross_site_scripting` and `xss` → `xss`, `idor` and `bola` → `access_control`,
`information_exposure` and `information_disclosure` → `info_disclosure`.
`remote_code_execution`, `server_side_request_forgery`, `path_traversal`,
`csrf`, `subdomain_takeover`, and `content_discovery` do not get a new band.

## Factors

Every ranked and abstained row has these seven factors and a paragraph that
names each one:

| Factor | Compared when |
|---|---|
| Origin | One known tool (`nuclei`, `zap`, `ffuf`, `sqlmap`, or `bbtk`) and one source file. |
| Location | One host and one endpoint, then the explicit scope rules. A URL path that disagrees with the endpoint is a contradiction. |
| Evidence strength | `ingestion_confidence: observed` with a response or status, hypothesis citations, or ledger evidence refs. Partial and ambiguous ingestion are not treated as full strength. |
| Session/actor | Clear, unknown, ambiguous, or contradictory. Unknown adds nothing and invents no actor. |
| Corroboration | Independent origins on the same location and class. Two rows with the same tool, source, and record index are not independent. |
| Vulnerability class impact | The existing band only. |
| Contradictions | Any contradictory origin, location, class, session, evidence, or corroboration. |

## Abstain reasons

The first matching reason in this list is `reason`. Every match is kept in
`reasons`. The engine does not pick a rank in order to fill a gap.

| Reason | When |
|---|---|
| `missing_scope` | The scope file has no rules. |
| `out_of_scope` | The location misses the allow rules or hits an exclusion. |
| `closed_review` | A ledger candidate is already `confirmed`, or a human rejection is not a comparison contradiction (`expected_behavior`, `insufficient_impact`, `other`). |
| `missing_origin` | Tool, source, or record index is absent. |
| `ambiguous_origin` | The tool name is not one of the known sources. |
| `contradictory_origin` | The row names more than one tool. |
| `missing_location` | Host or endpoint is absent. |
| `ambiguous_location` | More than one method, or the path is not a single usable endpoint. |
| `contradictory_location` | URL and endpoint name different paths. |
| `missing_vulnerability_class` | No class, the class is `unknown`, or an external row does not claim a vulnerability (FFUF content discovery). |
| `ambiguous_vulnerability_class` | The class has no existing impact band. |
| `contradictory_vulnerability_class` | Two otherwise comparable rows put different classes on one location. Both abstain. |
| `contradictory_session` | One session ref is attested to two actors, or the capture says `ambiguous_session`. |
| `ambiguous_session` | The session control is invalid, possibly expired, or mixes a clear control with an unproven actor. |
| `contradictory_evidence` | Evidence for and against, an importer `abstain`, a capture contradiction, or a rejection for a false positive, invalid evidence, invalid control, or a result that was not reproduced. |
| `ambiguous_evidence` | Ingestion confidence is `partial` or `ambiguous`, or the evidence list is not usable. |
| `severity_without_supporting_evidence` | A tool severity is present and there is no observed support. The severity does not create a rank. |
| `missing_evidence` | There is no observed support and no severity label to ignore. |
| `contradictory_corroboration` | A comparable row shares a location and class with a row that has contradictory evidence. |
| `ambiguous_corroboration` | Two comparable rows share one origin identity, or a candidate was rejected as a duplicate. |

## Example

Scope file:

```text
127.0.0.1
!127.0.0.1/admin
```

```sh
bbtk evidence prioritize review-lab \
  --scope-file registros/review-lab/scope.txt \
  --external registros/review-lab/evidence/imports/external-findings.json \
  --hypotheses registros/review-lab/evidence/ai-hypotheses.json \
  --ledger registros/review-lab/ledger/evidence-ledger.json \
  --max-tests 100 \
  --requests-per-second 1 \
  --attest-local-review \
  --dry-run
```

A hypothesis with three cited records, class `sqli`, and a second origin on the
same loopback path is rank 1 at score 66 (30 evidence + 10 attested controls +
20 high band + 6 corroboration). A Nuclei row labeled `critical` with an
observed XSS response and no second source scores 22 and is not first. The same
label with no observed response abstains:

```text
Abstain (severity_without_supporting_evidence). Origin: nuclei record 1 in critical-bare.json. Location: GET 127.0.0.1/api/bare; scope check in_scope. Evidence strength: No observed supporting evidence was available. Tool severity 'critical' was not used. ...
```

`--dry-run` does not write `review-prioritization.json`.

## Evaluation

`labs/prioritization_eval` is a 30-row synthetic queue with a reference order
and 20 rows that should abstain. It is not DEV (6), FINAL (45), or STRESS (6).
Those frozen captures, labels, and `MANIFEST.sha256` files are not inputs and
are not edited from this score.

The severity arm sorts on the tool label and never abstains. The existing arm
is `prioritize_hypotheses` on the hypothesis groups only. Review-time proxy is
unitless: 30 false confirmation, 25 wrong confident rank, 15 dropped gold row,
8 inverted gold pair, 5 wrong abstain reason, 2 incomplete explanation, 1
correctly handled row. Lower is better.

| Metric | Severity sort | Existing hypothesis prioritizer | Review prioritizer |
|---|---:|---:|---:|
| Precision@1 | 0.0 | 1.0 | 1.0 |
| Precision@3 | 0.0 | 0.3333 | 1.0 |
| Precision@5 | 0.0 | 0.4 | 1.0 |
| NDCG@10 | 0.0144 | 0.6312 | 1.0 |
| Abstention precision | n/a | n/a | 1.0 |
| Abstention recall | 0.0 | 0.0 | 1.0 |
| Abstention reason accuracy | 0.0 | 0.0 | 1.0 |
| Wrong confident ranks | 20 | 5 | 0 |
| False confirmations | 0 | 0 | 0 |
| Explanation completeness | 0.0 | 0.0 | 1.0 |
| Review-time proxy | 794 | 438 | 30 |

The severity sort places `ext-dup-b` first because its label is `critical`.
That row shares an origin identity with another row, so the new engine abstains
with `ambiguous_corroboration` instead of treating the duplicate as support.
`ext-nuclei-critical-bare` is also near the front of the severity sort and has
no observed response; the new engine abstains with
`severity_without_supporting_evidence`. The new order places
`hyp-sqli-strong` first. A forged `access_confirmed: true` and
`vulnerabilities_confirmed: 3` on the observed critical row are ignored
(`confirmation_claims_ignored` is 2, together with one ledger row already
marked confirmed). An empty scope abstains with `missing_scope` and ranks
nothing.

These figures measure agreement with the reference policy on this synthetic
queue. They are not a real-world detection rate.

## Limitations

- The score is not a probability and not a severity. Impact bands are the
  existing category heuristic. Nothing is demonstrated by a high score.
- A hypothesis evidence id is a citation. This command does not reopen the
  capture and check that the id still matches the bytes.
- One external finding counts as one observation, even when the embedded
  response is long.
- Duplicate origin identity abstains both rows instead of collapsing them.
- Two classes on one location abstain both rows. A contradictory sibling
  suppresses other comparable rows at that location and class.
- Unknown session is not a penalty. A clear session adds four points, which is
  less than one supporting record.
- Review order does not apply the execution-cost penalty from
  `bbtk ai prioritize`. That penalty still applies to that older command.
  `--max-tests` only marks later checks `deferred_over_budget`.
- Matching a scope rule does not validate authorization.
- Unmapped classes abstain. This command does not invent a band for RCE, SSRF,
  path traversal, CSRF, or takeover.
- Explanations name the factors. They do not contain request bodies, and they
  are not reproduction steps.
- The synthetic queue was not used to change frozen DEV, FINAL, or STRESS
  labels.
