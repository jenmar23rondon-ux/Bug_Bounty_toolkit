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
- `labels.json` — ground truth categories: vulnerable, protected, cross-tenant, nested-json, query, public, single-session, ambiguous, session-only

## Run

```bash
bbtk lab object-discover --dry-run
bbtk lab object-discover --split eval --metrics-json /tmp/object-metrics.json
```

## Metrics semantics

Precision@k / recall / FP / FN measure **candidate-pair ranking efficacy** on
synthetic labels. They do **not** claim real bug-bounty vulnerability
confirmation. `vulnerabilities_confirmed` is always `0`. Protected cases may
produce handoff *proposals* but never confirmed findings.
