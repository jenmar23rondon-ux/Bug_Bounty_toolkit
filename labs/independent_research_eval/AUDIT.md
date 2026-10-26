# Phase 0 audit — prior corpora and HEAD baseline

Base: `main` @ `40a28b4c904c841c4af1f957894e5ec287307f9a` (PR #46 merged, no open PRs at start).
Audited modules (read-only): `analysis/object_relationships.py`, `object_handoff.py`,
`handoff_case_eligibility.py`, `idor_e2e_research.py`, `evidence_gap_planner.py`,
`prioritization.py`, `evidence_ledger.py`. No production code was modified by this PR.

## Corpora previously used while developing rules

| Lab | Version | Size | Families / focus | Limitations for generalization |
|---|---|---|---|---|
| `adversarial_idor_eval/frozen` | adv-1.0 | 24 scenarios, 48 entries | discovery + pairing (member/folder ambiguity, negatives) | Rules (open-vocab kind, ranking v2, resilient HAR) were iterated against it; origin :8137-8143 |
| `adversarial_idor_eval/frozen_adv11` | adv-1.1 | 24 scenarios, 49 entries | same families, new nouns | Built as a hold-out but subsequently used for several PR before/after runs |
| `object_ranking_eval/frozen` (+dev 5) | adv-ranking-1.0 | 12 | ranking order, shared parents | Reports P@k=1.0 / MRR=1.0; exported types are `unknown` |
| `idor_handoff_case_eval` | adv-handoff-case-* | — | handoff→case conversion | pair-level only |
| `idor_e2e_research/frozen` | idor-e2e-research-1.0 | 15 scenarios in one HAR | full contract, real eligibility codes | One shared HAR → per-scenario attribution is approximate; 1 origin pair |
| `eval_integrity/frozen_e2e` | e2e-contract-1.0 | 4 | integrity / mutation harness | small |
| `evidence_gap_planner_eval` dev/final | (20 + 20) | 40 | planner on **hand-annotated ledgers** | Never fed by the real capture pipeline; annotations given directly |

Common limitation: labels and rules were co-developed; responses were mostly 200 with
owner-like bodies; status/denial semantics, entry-count limits and noise volume were barely
exercised; the planner benchmark bypasses the capture pipeline entirely.

## HEAD baseline on historical labs (re-run, results not rewritten)

* idor-e2e-research-1.0: 15 scenarios, codes `CASE_ELIGIBLE×6, REJECT_MULTI_RESOURCE_DIFF×4, REJECT_HEADER_DIFF×1`, false cases 0, reviewable 6, network 0, confirmations 0.
* evidence-gap planner FINAL: P@1 1.0, P@3 1.0, MRR 1.0, NDCG@5 1.0, missing-control recall 1.0, incompatible recommendations 0.
* adv-ranking-1.0: P@k 1.0, MRR 1.0, recall 1.0 (CI95 0.772–1.0).
* adv-1.0 / adv-1.1: all expected objects found (12/12, 14/14), pairing FP 0, network 0.

These near-perfect numbers are the reason for an independent benchmark: irb-1.0 shows where they do not transfer.
