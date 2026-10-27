# AI evidence contract v2 — audit

Audit of the production path local models see today. The deterministic engine
(`analysis/evidence_review.review_evidence`) was not modified. This note records
why dual review abstains and which facts minimization drops.

## Production dual-review rule

`review_evidence` always sets `decision` to `review_required`. That string is not
in `multi_review.DECISIONS` (`candidate`, `not_observed`, `inconclusive`).

`dual_review.compare` keeps the deterministic decision only when it is one of
those three values. Any other value, including `review_required`, becomes
`inconclusive`. The advisory then stays `inconclusive` unless both model reviews
are valid, agree with that reference, and raise no contradiction or unsupported
claim. Models are not allowed to promote the reference.

Consequence: on current bundles the production advisory cannot be `candidate` or
`not_observed`. Agreement between models is still not confirmation
(`consensus_is_proof` is false, `finding_confirmed` is false).

## Facts lost when the bundle is minimized

`build_evidence_bundle` flattens the `review_evidence` packet into `field` /
`value` observations. Keys the engine does not copy never become observations.

| Fact | What the engine keeps | What disappears |
| --- | --- | --- |
| Visibility | No visibility field | `public` / `private` / `shared` / `unknown`. A shared object with a private marker looks like the same booleans as a cross-read of a private object. |
| Contradictions | Counts and a single `private_evidence_observed` boolean | Two cross-reads that disagree (status family, marker, denial, visibility) are not paired. There is no `contradicting_refs` list. |
| Unknown | Missing `controls_valid` becomes false (`is True`) | A missing tri-state is not stored as null. Consumers cannot tell "observed false" from "not declared". |
| Session continuity | Not present | Same / distinct / broken / unknown is dropped. |
| Distinct accounts | Raw account ids are correctly omitted | The boolean "two synthetic actors" is omitted with them. |
| Explicit denial | Status codes are counted | 401/403/404 is not a structured negative. A 200 soft failure is not distinct from success beyond the code histogram. |
| Truncation and integrity | `truncated_rows` and `transport_error_rows` counts | Partial vs complete loss vs unknown, and intact vs suspect, are not enums. Zero looks like "none". |
| Valid negatives | Not present | A denied cross-read or a public non-disclosure is not a `{ref, kind}` fact. |
| Tool execution and auth context | Not present | Prose that says "run a tool" is dropped (good) and so is a boolean declaration that a tool was or was not observed. |
| Secrets and instructions | Bodies, cookies, headers, notes are omitted | Privacy holds. The semantic flags above are omitted with the prose. |

`local_ai_evidence_assistant.deterministic_assist` reads `private_evidence_observed`,
`controls_valid`, and `cross_read_observed` from that flattened view. It cannot
see a share, a contradiction pair, or an explicit unknown.

## What this change does not do

- It does not change `review_evidence` or `dual_review.compare`.
- It does not rewrite Evidence Ledger history. The new advisory does not call
  `save_ledger`, `add_candidate`, or `review_candidate`.
- It does not edit `labs/local_llm_quality_eval` or any frozen FINAL labels.
- It does not give the model tools or a path that sets `finding_confirmed`.
