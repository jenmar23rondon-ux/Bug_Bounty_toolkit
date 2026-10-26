# Object Discovery Efficacy Lab

Versioned, labeled, **synthetic** corpus for measuring offline object-candidate →
capture-pair handoff ranking. All hosts are loopback. No fixture contacts the network.

## Splits

| Split | Purpose |
| --- | --- |
| `dev/` | Development fixtures. May be inspected while iterating on rules. |
| `eval/` | Holdout evaluation. **Do not tune ranking rules against this split.** |

Each split contains:

- `captures.har` — authorized synthetic HAR (multiple sessions, nested paths, query/JSON IDs)
- `labels.json` — ground truth categories: vulnerable, protected, cross-tenant, nested-json, query, public, single-session, ambiguous, session-only, plus (corpus 1.1) response-observed, response-nested, response-collision, ambiguous-shared, incomplete-capture

### Corpus 1.1 (response-observed identifiers)

| Scenario | Expected | DEV shape | EVAL shape (holdout, different structure) |
| --- | --- | --- | --- |
| response-observed (`project`) | proposal | typed `project_id` in POST response vs `project_id` in another session's POST body | `projects[*].project_id` in a listing vs `/projects/{id}` path |
| response-nested (`address`) | proposal | `addresses[*].id` array vs `/addresses/{id}` path | nested `shipping.address_id` vs `?address_id=` query |
| response-collision (`team`) | no proposal | bare `data.id` in response vs typed `team_id` request | bare ids in a keyless array vs typed `team_id` |
| response-shared (`tenant`) | no proposal | same `tenant_id` in both sessions' responses | same nested `tenant_id` in both sessions |
| incomplete-capture (`customer`) | no proposal | `customer_id` only in responses; request capture without session/body | same, different nesting |

EVAL fixtures were authored from the scenario spec at the same time as DEV and before the rule ran on them; the rule was developed and checked on DEV only.

## Run

```bash
bbtk lab object-discover --dry-run
bbtk lab object-discover --split eval --metrics-json /tmp/object-metrics.json
```

## Metrics semantics

Each split reports `request_only_comparison` (response identifiers disabled) next to the default metrics.


Precision@k / recall / FP / FN measure **candidate-pair ranking efficacy** on
synthetic labels. They do **not** claim real bug-bounty vulnerability
confirmation. `vulnerabilities_confirmed` is always `0`. Protected cases may
produce handoff *proposals* but never confirmed findings.
