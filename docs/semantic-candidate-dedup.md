# Semantic candidate correlation (duplicate detection, read-only)

`bugbounty_toolkit/analysis/candidate_similarity.py` finds Evidence Ledger
candidates that **probably describe the same issue** and separates them from
candidates that merely share an endpoint, an object or a category. It is
offline, deterministic, explainable and never writes anything.

```
python -m bugbounty_toolkit.analysis.candidate_similarity registros/<program> [--now ISO8601]
python -m labs.semantic_candidate_eval.run_lab [--split dev|final|both] [--output F]
```

No `cli.py` subcommand was added in this PR (to avoid conflicts with parallel work).

## Why

The ledger deduplicates by exact key (`dedup_key`, default `surface|category`).
On the synthetic FINAL corpus this either misses every duplicate whose analyst
supplied distinct keys (recall 0.00) or, with the default key, wrongly groups
candidates on the same endpoint that affect different objects/roles/causes
(false-merge rate 0.36).

## Guarantees

- Ledger is the only state source; validated with `validate_ledger`, never saved.
  `dedup_key`, `state`, `duplicate_of`, confirmations unchanged. Every pair has
  `merge_performed: false`, `finding_confirmed: false`, `human_review_required: true`.
- Only digest-verified, non-stale, non-expired evidence contributes facts. Broken,
  tampered or stale refs appear in `missing_information` and are never in
  `supporting_evidence_refs`. Without a program directory nothing is trusted.
- Facts come from explicit annotations only (below) and ledger surface refs. Raw
  bodies, headers and cookies are never read; session data never supports "same
  account"; ownership is never inferred.
- Object IDs, paths, surface refs, investigation IDs and graph nodes are
  HMAC-SHA256 pseudonymised in memory (same construction as
  `object_relationships`) with a per-run random key unless one is supplied. Only
  ledger candidate/evidence IDs, counts and reason codes are exported.
- Different programs are never compared by default (`cross_program_pairs_skipped`);
  with `include_cross_program=True` they are reported only as
  `not_comparable_cross_program`.
- No AI provider, no network, fixed weights (`WEIGHTS`, `CONFLICT_PENALTY`).
- More than `MAX_CANDIDATES` (1000) → `status: too_many_candidates`, never silent truncation.

## Annotation `bbtk-candidate-correlation/1` (optional, inside an evidence JSON file)

```json
{"correlation": {"annotation_version": "bbtk-candidate-correlation/1",
  "method": "GET", "path_template": "/api/orders/{id}",
  "objects": [{"namespace": "order", "id": "123"}],
  "operation": "read", "actor_role": "customer", "required_permission": "orders:read",
  "control_type": "tenant_scope", "root_cause": "missing_owner_check",
  "session_ambiguous": false}}
```

All fields are analyst/lab declarations. The planner's `bbtk-control-annotation/1`
(`role`, `ownership`, `distinct_accounts`, `resource_visibility`,
`contradicts_hypothesis`, `expires_at`) is also read.

## Bands

| band | rule (all evidence must be usable) |
|---|---|
| `strong` | same category family (idor≡bola), same method+path template, identical object set, same operation, a discriminator (same root cause, same control type or identical evidence digest), no conflicts, no ambiguous session, no contradicting negative control; neither candidate rejected; no public/shared resource |
| `possible` | same category + endpoint, objects equal/overlapping or undeclared, no hard conflict (also: strong-like pairs capped because one side is `rejected` → `may_repeat_rejected_candidate`) |
| `weak` | some shared context only (or capped by documented public/shared resource) |
| `unrelated` | nothing but maybe the category |
| `distinct` | explicit conflict: category, endpoint, disjoint objects (incl. `same_literal_id_different_namespace`), operation, role, permission, control type or root cause |
| `insufficient_evidence` | a side has no usable evidence |

Only `strong` is a duplicate hypothesis. Groups are formed only from components
where **every** pair is strong; transitive-only chains go to
`groups_requiring_review`.

## Reuse recommendations and planner contract

`reuse_recommendations` (strong/possible pairs on the same endpoint) point at
existing ledger evidence IDs: `reuse_negative_control` (non-contradicting only),
`reuse_ownership_attestation` / `reuse_distinct_accounts_attestation` /
`consult_prior_investigation` (strong only), `reuse_object_relation` (shared graph
nodes). Nothing is copied (`copy_performed: false`).
`planner_context(plan, report)` returns a separate side-car
(`bbtk-candidate-correlation-planner-context/1`) keyed by candidate; the plan and
its scores are not modified.

## Limitations

- Quality depends on structured annotations; candidates with no annotation stay
  `possible`/`weak` at best (by design: no inference from free text).
- Slug-like IDs (e.g. `rx-1`) are not recognised as dynamic path segments; a
  candidate whose surface template and annotation path disagree gets an
  "endpoint conflicting" state and cannot be strong (the one FINAL miss).
- Graph node IDs are merged into the object set, so a candidate with extra graph
  nodes has a different object set than an otherwise identical one (→ `possible`).
- O(n²) pairs per program; measured only on small synthetic corpora.
- Metrics are synthetic; they do not prove real-world reduction of work.
