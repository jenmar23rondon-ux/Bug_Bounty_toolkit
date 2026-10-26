# P1 — Open-Vocabulary Resource Kind Inference: measured results

Branch `feature/open-vocab-resource-kind`. Version 0.2.2. Measurement only on frozen corpora;
candidates/proposals are review leads, never confirmed findings.

## Commit order (anti-tuning evidence)
1. `ff54513` — adv-1.1 corpus frozen (`frozen_adv11/`, hash-pinned) + its **baseline** on main@11df465.
   No open-vocabulary code existed at this commit.
2. `58451df` — open-vocabulary logic. Developed against unit fixtures and the already-observed
   adv-1.0 diagnostic corpus only.
3. Next commit — adv-1.1 measured **once** with the committed logic; no rule changed afterwards.

Pre-freeze authoring corrections to adv-1.1 (before the commit in step 1, run only with the OLD
main logic): `shelves`→`bins` (evaluator singularizer would label it `shelve`), `author_id`→`editor_id`
(collides with the existing credential-name filter `auth*`, which would make the scenario measure
the secret filter, not pairing). Both documented; neither involved the new logic.

## Pairing (handoff) — baseline vs after

| Corpus | Build | Proposals | TP | FP | Ambiguous | Precision | Recall | P@1 | P@3 | P@5 | P@10 | FN |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| adv-1.0 (diagnostic, 24 sc.) | main 47c8a30 | 23 | 13 | 6 | 4 | 0.68 | 0.83 | 1.0 | 0.67 | 0.6 | 0.5 | S04, S11 |
| adv-1.0 | feature | 19 | 16 | **0** | 3 | **1.00** | **1.00** | 1.0 | 0.67 | 0.8 | 0.8 | — |
| adv-1.1 (final, 24 sc.) | main 11df465 | 29 | 15 | 9 | 5 | 0.63 | 0.86 | 1.0 | 0.33 | 0.4 | 0.4 | T04, T05 |
| adv-1.1 | feature | 20 | 16 | **0** | 4 | **1.00** | **1.00** | 1.0 | 0.67 | 0.6 | 0.8 | — |

Ambiguous kinds still surfaced for human review (not suppressed): adv-1.0 S22 member, S23 folder;
adv-1.1 T22 entity, T23 tag, T24 patient. (Ambiguous count on adv-1.0 drops 4→3 only because one
duplicate S23 proposal disappeared; no ambiguous *kind* was dropped.)

Unchanged stages: discovery recall 1.0 on both; discovery P@k unchanged (C2 ranking out of scope);
case discovery on adv-1.1 yields 0 cases on TP pairs both before and after (`discover_idor`
JSON-body/uuid limits, C4, out of scope). Existing dev/eval labs: identical metrics
(P@1 1.0, P@3 1.0, P@5 0.8, recall 1.0, FP 0, FN 0).

## Remaining limitations
- Small synthetic corpora (≈14 expected pairs each); 95% CIs are wide.
- Generic-name list is closed (`ref`, `key`, `data`, wrappers…). Unlisted generic nouns (adv-1.1 T22
  `entity_id`) still become a kind and reach review as ambiguous proposals.
- English-centric singularizer (`-ies/-es/-s`); irregular plurals (`people`, `data`, `indices`) do not
  normalize and may miss cross-reference pairs (FN risk, not FP: kinds must match exactly).
- Same-noun, different-semantics ids (`source_wallet_id` vs `target_wallet_id` are distinct kinds;
  but `parent/child` both under one noun are not distinguished in asymmetric pairs).
- Discovery ranking (C2), importer whole-file rejection (C3), `discover_idor` coverage (C4) untouched.
