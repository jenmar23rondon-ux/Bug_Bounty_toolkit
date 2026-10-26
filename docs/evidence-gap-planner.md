# Evidence-gap guided investigation planner

Opt-in, offline, deterministic planner that answers *what evidence is missing*
and *which human review step would resolve the most uncertainty* for open
candidates in the Evidence Ledger.

It is **not** a scanner, an autonomous agent or a generic re-ranker. Ranking
weights are fixed in `STEP_CATALOG`; AI never decides steps. The planner works
with zero Ollama / LM Studio calls.

## Command

```bash
bbtk investigation next-steps PROGRAM --dry-run
bbtk investigation next-steps PROGRAM --minimize --output plan.json
bbtk investigation next-steps PROGRAM --schema
bbtk lab evidence-gap --split final
```

Default behaviour of every other command is unchanged. The planner is opt-in.

## Contract

Schema version: `bbtk-evidence-gap-plan/1` (`docs/schemas/evidence-gap-plan-v1.schema.json`).

Every recommendation includes:

| field | rule |
|---|---|
| `execution_allowed` | always `false` |
| `finding_confirmed` | always `false` |
| `requires_human_review` | always `true` |
| `evidence_refs` | only digest-verified ledger refs |
| `step_id` | stable across regenerations for equivalent steps |

## What it reads (never writes)

- Evidence Ledger (`bbtk ledger validate` digests / references / fingerprints)
- Local evidence JSON carrying `bbtk-control-annotation/1` or an IDOR E2E
  `classification` block
- Investigation Memory (read-only SQLite) for closed-investigation provenance

It does **not** duplicate dashboard triage ranking, Evidence Ledger mutation,
eligibility classification or prioritization. Those systems remain authoritative.

## What it will not infer

Ownership, distinct accounts, privacy or authorization are **never** inferred
from path names, HTTP 200, different cookies or response similarity. Those
facts count only when an annotated evidence file attests them, or when an IDOR
E2E eligibility code already states them. Otherwise the planner returns
`unknown` / `requires_validation` and recommends an attestation or abstains.

## Safety

- No HTTP to third parties; synthetic labs only
- No auto-confirm; no auto-execution; PR #43 tool-policy gate and PR #45
  redaction are untouched
- Ledger is never modified by planning
- Historical evaluation corpora are not rewritten to chase metrics

## Lab

`labs/evidence_gap_planner_eval/` — DEV + FINAL, 20 scenarios. Metrics are
labelled `synthetic: true` and must not be quoted as human-productivity claims.
