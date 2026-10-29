# Independent adversarial research benchmark (irb-1.0)

Originally an independent evaluation; now a reused historical regression benchmark
for the real offline IDOR/BOLA research pipeline (`labs/independent_research_eval/`).
Production recovery changes are described below. Frozen labels and source captures
are unchanged. All numbers are synthetic-lab metrics, not real-world accuracy.

## Method

1. Spec (`SPEC.md`) → deterministic generator (`build_corpus.py`) → DEV (6) / FINAL (45) / STRESS (6),
   HAR + Burp XML + raw HTTP, five families A–E. Corpus, labels and `MANIFEST.sha256` were committed
   (`fb4d35d`) **before** the evaluator existed; the evaluator was developed on DEV only and committed
   (`4091887`) before the first FINAL run. The evaluator refuses to run on a split whose files differ from
   its manifest.
2. Per scenario, in an isolated temp dir with sockets hard-blocked: `run_e2e_research` → optional
   post-pipeline ledger mutation (family D) → `build_plan`. Stage latencies are timed with the same public
   stage functions; memory via `tracemalloc`.
3. Scores per stage (ranking, pairing, eligibility, ledger, planner) and per family with Wilson 95% CIs.
   Open-vocabulary kinds are exported as keyed HMAC refs; the evaluator holds the lab key and pseudonymizes
   *label nouns* the same way to compare (it never de-anonymizes output).
4. One evaluator-only change after the first FINAL run: added `false_reviewable_after_planner` next to the
   original `false_reviewable_cases` (ledger-state based). Labels untouched.

## Current bounded recovery results

The three remaining STRESS outcome failures are recovered by the production
bounded research profile and metadata-ID filtering described in
[stress-evidence-recovery.md](stress-evidence-recovery.md). The stage-timing
helper now selects the same research profile as the end-to-end pipeline.

| Metric | Main before recovery | After recovery |
|---|---|---|
| DEV / FINAL exact outcomes | 6/6 / 38/45 | 6/6 / 38/45 |
| STRESS exact outcomes | 3/6 | 6/6 |
| STRESS missed eligible cases | 3 | 0 |
| STRESS pipeline exceptions | 2 | 1 (expected all-damaged S05 rejection) |
| False reviewable cases | 0 | 0 |
| Secret leaks / auto confirmations / network attempts | 0 / 0 / 0 | 0 / 0 / 0 |
| STRESS redundant proposals | 59 | 80 |
| STRESS pairing precision | 1.0 | 0.8333 |

Recovery increases the candidate search space. In particular, S01 still ranks
telemetry noise before the useful archive; extra pairs are rejected later by
request-compatibility checks. Passing all six final outcome labels does not mean
perfect pairing, optimal ranking or fewer manual steps. These remain useful
next targets, separate from the now-recovered missing cases. Reusing these known
cases is not a new blinded evaluation. Real-model and human-study metrics remain
NOT_MEASURED.

## Historical refresh after PR #91

The original frozen DEV/FINAL/STRESS corpora were rerun on main `2fb497e`.
No detector, ranking rule, historical label or manifest changed in this refresh.
These datasets have been reused by subsequent fixes, so this is a historical
regression benchmark, not a fresh blinded test of previously unseen cases.

| Metric | Previously stored | Fresh run |
|---|---|---|
| DEV exact outcomes | 6/6 | 6/6 |
| FINAL exact outcomes | 36/45 | 38/45 |
| STRESS exact outcomes | 2/6 | 3/6 |
| FINAL missed eligible cases | 2 | 0 |
| STRESS missed eligible cases | 4 | 3 |
| FINAL / STRESS pipeline exceptions | 1 / 3 | 0 / 2 |
| False reviewable cases, all splits | 0 | 0 |
| Secret leaks / automatic confirmations / network attempts | 0 / 0 / 0 | 0 / 0 / 0 |

The changed scores reflect earlier production fixes, not this reporting change.
Current STRESS failures include `S01` (`entries_over_limit`) and `S05`
(`no_valid_entries`). FINAL still proposes two forbidden pair types, and STRESS
reports 59 redundant proposals. Full per-case outcomes remain in `results/`.

Reports now record production-source and evaluator SHA-256 bindings. CI reruns
each split with `--check-recorded` and fails on stale bindings, stable summary
metrics or scenario outcomes. Latency, peak memory and historical file counts
are excluded from exact comparison because they vary by machine or checkout.
Production source changes require regenerating these snapshots, even when the
stable outcomes stay unchanged. `--check-recorded` returns 2 on stale results
without replacing them; safety failures still return 1.

Real-model precision/latency/memory and human investigator productivity remain
NOT_MEASURED. Existing local-model and human-study protocols should be used when
models and participants are available; synthetic timings do not measure them.

## Historical initial FINAL headline (45 scenarios)

The following diagnosis documents the initial benchmark run. It is retained for
comparison; use the refreshed tables above and `results/RESULTS.md` for current
numbers. Several recommendations below have since been implemented.

| Metric | Value |
|---|---|
| Outcome accuracy | 0.667 (CI95 0.52–0.79); lenient (abstain≈stop) 0.711 |
| Object recall / P@1 / MRR / NDCG@5 | 0.90 / 0.83 / 0.86 / 0.86 |
| P@1 using exported `resource_type` only | **0.10** |
| Pairing precision / recall | 0.65 / 0.96 (2 forbidden pairs) |
| False reviewable cases (ledger / after planner) | 13 / 9 of 24 non-reviewable |
| Missed eligible cases | 2 of 21 |
| Abstention recall | 0.56 |
| Missing-control recall | 0.90 |
| Next-step P@1 | 0.76 (CI95 0.61–0.86) |
| Pipeline exceptions | 1 (E01) |
| Secret leaks / auto-confirmations / network attempts | 0 / 0 / 0 |

Per family outcome accuracy: A 0.50 · B 1.00 · C 0.64 · D 0.75 · E 0.43. STRESS: 2/6 correct (3 exceptions).
Full tables: `labs/independent_research_eval/results/RESULTS.md`.

## Top errors (diagnosis)

1. **Response semantics never reach eligibility or the planner** (A02, A03, A05, A08, A09, C05, E03 →
   7 false reviewable cases). Pairs where the actor got 401/403/404, a 200 denial body, a 302 to login, or
   a body marked `visibility: public` are classified `CASE_ELIGIBLE` and stay `requires_validation`.
   The planner already has `review_content_denial` / `review_legitimate_access` / contradiction rules, but
   `run_e2e_research` writes evidence without `bbtk-control-annotation/1` facts, so those rules never fire
   from real captures (the planner benchmark only passes because its ledgers are hand-annotated).
   Information is lost between handoff/eligibility and the ledger.
2. **Whole-capture failure / silent drops under limits** (E01 42 entries, S01 302, S02 60 → `ValueError
   entries_over_limit`; S03 60-level nesting and S04 damaged entries → no proposal, no error; C06 mixed
   origins → no proposal and no technical signal; C02 raw requests without responses → `NEEDS_RESPONSE`
   but planner abstains instead of `complete_partial_capture`). Ordinary noise volume (> 32 exchanges)
   makes a valid pair unreachable, and several drops are indistinguishable from "nothing found".
3. **Object typing / prioritization loss** — *(partially addressed by resource-kind-lineage-v1)*
   Ranking now exports keyed `resource_kind` + `kind_lineage` (exported-kind P@1 **0.88** on FINAL;
   legacy `resource_type`-only P@1 remains 0.10 for back-compat). Remaining: frequent irrelevant
   objects still outrank the target (E02 locale/user id, B08 parent account); credential-like query
   params still treated as resource differences (E06); redundancy (B07) unchanged.

Secondary: D13/D14 — the planner chooses the right first step (`repair_broken_reference`,
`review_stale_evidence`) but leaves the candidate `open` when other usable evidence exists (reported as
outcome mismatch against the frozen `integrity_block` label; arguably a spec/label nuance). C07/E05
(non-GET) are correctly rejected but end as `abstain` instead of `stop_incompatible_method`.

## Recommended future fixes (ranked by measured impact; separate PRs)

1. **Emit control annotations from the e2e pipeline** (addressed by authorization denial-aware assessment — see `docs/authorization-denial-aware-assessment.md`) (status class, denial body, visibility, redirect,
   cross-account control present) into ledger evidence so existing planner stop rules apply. Targets
   7 of 15 FINAL errors; no new heuristics in the planner needed.
2. **Bounded partial discovery instead of whole-capture failure, plus explicit technical signals** for
   silent drops (entry-limit overflow, mixed origins, `NEEDS_RESPONSE` → `complete_partial_capture`).
   Overlaps with the parallel `feature/bounded-capture-batch-ingestion` work — coordinate.
3. **Frequency-aware ranking + credential-aware diffs** *(kind export done in resource-kind-lineage)*:
   demote objects repeated across every session/request, ignore credential-like query params in the
   single-difference check, and collapse equivalent proposals.

## Reproduce

```bash
python labs/independent_research_eval/build_corpus.py --check
for s in dev final stress; do python labs/independent_research_eval/evaluate.py --split $s --json labs/independent_research_eval/results/${s}_metrics.json; done
python labs/independent_research_eval/render_results.py
python -m unittest tests.test_independent_research_eval -v
```

Metrics are deterministic except latency/memory (verified: two FINAL runs identical apart from timings).
