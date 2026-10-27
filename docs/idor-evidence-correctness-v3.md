# IDOR/BOLA evidence correctness v3

Offline, deterministic, synthetic-only. Nothing here sends HTTP, executes cases, consults AI
or confirms a vulnerability. Redaction, scope, tool-policy gate, human approval and budgets
are unchanged: every output is a human-review hint (`confirmed: false`).

## A. Integrity-aware reviewability (`evidence_gap_planner`, `evidence_ledger`)

`build_plan` adds `effective_eligibility` (one row per ledger candidate: `ledger_state`,
`effective_state`, `effective_reviewable`, `blockers`, `ledger_modified: false`). A recorded
`requires_validation` is reviewable *now* only without blockers:

| blocker | source |
|---|---|
| `invalid_evidence` | digest mismatch / missing file / unrecorded ref / evidence annotated for another program |
| `stale_evidence` | fingerprint change or `expires_at` ≤ now |
| `insufficient_capture` | `capture_complete: false` or `TECH_INCOMPLETE_CAPTURE` |
| `contradictory_observation` | origin mismatch, content denial, public/shared, contradicting control |
| `session_control` | owner positive control broken (`owner_control: broken`) |
| `access_proof` | actor body only echoes the identifier |
| `status:*` | `integrity_blocked`, `blocked`, `duplicate`, `stop_recommended`, `abstain` |

Any failed required evidence now yields `integrity_blocked` even when other refs are usable.
Integrity, contradiction and duplicate blockers propagate to siblings on the same surface that
share an owner/actor object (or the whole surface when the compromised file's objects can no
longer be trusted — conservative; see tradeoff V3-A11). Missing human attestations are **not**
blockers: `requires_validation` already means a human decides.

## B. Session control (`actor_provenance.classify_session_controls`)

Classes: `owner_control_valid`, `second_account_control_valid`, `cross_control_observed`,
`anonymous_control`, `invalid_session`, `possibly_expired_session`, `identity_unproven`.
Cookies alone never prove identity (needs a human account declaration). A single trailing 401
is `identity_unproven` + `isolated_401_not_expiry`; ≥2 trailing auth failures or a login
redirect after success is only *possibly* expired (`expiry_proven` is always false). Actor
results that depend on the owner and come before any owner success or after the owner control
is lost are `inconclusive`.

## C. Access proof (`authorization_denial`)

`ResponseAssessment.access_proof`: `private_resource_200`, `public_200`, `denial_in_200`,
`http_401`, `http_403`, `http_404`, `login_redirect`, `id_echo_without_resource`, `ambiguous`.
Pair annotations carry `owner_access_proof`, `actor_access_proof`, `owner_control`. Owner
401/login redirect → `inconclusive` (`owner_control_broken`); actor id echo → `inconclusive`.
`idor_e2e_research` does not promote either to `requires_validation`.

## D. Encoded identifiers (`object_handoff.normalize_captured_identifier`, opt-in)

Disabled by default. Only values present in `captured_values` (from authorized captures) are
processed; others are `refused_not_in_capture`. Shapes: numeric, UUID, Base64, Base64URL,
JSON-then-encoded (`id`/`uuid`/`object_id`/`resource_id`). Every transform is listed;
`namespace_key = <kind>:<shape>:<canonical>` so kinds never collide. No ranges, increments or
guesses (`generated_values: 0`). `undecodable` is never denial evidence.

## E. Resource correlation (`resource_kind_lineage.correlate_resources`)

`relation`: `same_object` / `different_object` / `different_kind` / `unknown`; `accounts`:
`distinct_attested` / `same_account` / `unknown`; `legitimate_shared` for public, shared or
identical non-private responses; `idor_review_signal` only for same object + attested distinct
accounts + not legitimate. Kind is preserved; ambiguous kinds stay `unknown`.

## Benchmarks

- IRB FINAL (45, labels frozen, MANIFEST verified): false reviewable 6→0 (D11–D16),
  accuracy 0.756→0.800, missed eligible 2→2, pairing P/R 0.65/0.963 unchanged.
  Scoring now reads the effective view; raw ledger state is kept per scenario.
- `labs/idor_evidence_v3_eval` FINAL (48, frozen): see
  `labs/idor_evidence_v3_eval/results/metrics_before_after.json`.
