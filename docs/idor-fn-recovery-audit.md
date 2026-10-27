# IDOR false-negative recovery audit

Base `bbd0068f90b0f411360519434008ccdcfcbaaae0`. Version stays `0.2.2`.
This note is the FASE 1 module audit and the FASE 2 writeups for E01, E06, and V3-A11.
Ground truth files were not edited. Ledger history is not rewritten. Effective states are an overlay.

## FASE 1 — how a candidate becomes blocked

### `evidence_ledger`

Schema `bbtk-evidence-ledger/1` (`additionalProperties: false`). `add_evidence` appends a row and stores a SHA-256 of the file bytes. It does not store a mutable "reviewable" flag that later code is allowed to flip. Candidate `state` values already on disk stay as written.

`effective_eligibility` is a read-only view: `requires_validation` is reviewable only when no effective blocking gap applies. `finding_confirmed` is not set by this path.

Over-broad spot: the ledger row itself does not know which object identities were in the file at registration time. After a byte change, re-reading the file is not a safe way to learn those identities. The additive provenance keys `registered_object_refs` and `depends_on` are snapshotted while the digest still matches. An empty list means the file named no objects. A missing key means the row predates the snapshot (unknown). Tampered bytes are never parsed for object identity.

### `evidence_gap_planner`

`build_plan` is read-only (`ledger_modified: false`, `network_requests_sent: 0`, `auto_confirmations: 0`). Per candidate it records gaps and a status: `open`, `ready_for_manual_review`, `integrity_blocked`, `stop_recommended`, `duplicate`, `abstain`, `blocked`.

Historical `_propagate_integrity_blocks` copied `integrity_blocked`, `stop_recommended`, and `duplicate` onto same-surface siblings unless both object sets were nonempty and disjoint. An unreadable tampered file has an empty live object set, so the whole surface was blocked. That is the V3-A11 miss.

The planner now builds `blocker_dependency_graph` and applies integrity propagation only when the overlay state is `blocked_invalid_evidence`, `blocked_stale_evidence`, or `requires_manual_independence_review`. `reviewable` and `safely_independent` are not propagated. Stop and duplicate propagation still use the live object intersection. Propagated steps cite ledger evidence ids only; blocker labels such as `invalid:<id>` are not stored as evidence refs.

### `blocker_dependency_graph`

Schema `bbtk-blocker-dependency-graph/1`. Computed at plan time. Inputs are not mutated. `finding_confirmed` stays false.

Effective states: `reviewable`, `blocked_invalid_evidence`, `blocked_stale_evidence`, `blocked_missing_control`, `inconclusive`, `safely_independent`, `requires_manual_independence_review`.

Per candidate: `original_state`, `effective_state`, `blockers`, `dependent_refs`, `independent_refs`, `independence_basis`, `evidence_integrity`, `decision_reason`.

Priority: own or verifiably associated invalid objects, then stale, then a bad artifact whose object set is missing or empty (`requires_manual_independence_review`, fail closed), then missing mandatory controls, conflict, semantic duplicate, proven nonempty disjoint objects (`safely_independent`), intact shared bundle, otherwise `reviewable`. A whole-surface block remains when any candidate needs manual independence review, or when every candidate on a multi-candidate surface depends on the same bad ref. `expires_at <= now` marks digest-ok evidence stale in the overlay.

### `object_handoff` and `handoff_case_eligibility`

Handoff proposes request/request pairs only when both sides share one inferred kind and one identifier position, and the sessions and object refs differ. Bare, generic, conflicting, or untyped ids are not paired. Asymmetric response/request pairs use the same kind rule and never claim ownership. `confirmed` and `case_executable` stay false.

Eligibility (`handoff_case_eligibility`) labels a materialized GET pair. It does not confirm a finding. `CASE_ELIGIBLE` means the pair is structurally ready for human review. `REJECT_MULTI_RESOURCE_DIFF` fires when the read-pair diff is not a single resource difference. That check used to treat an `api_key` query as a second resource (E06).

### `idor_e2e_research`

The offline pipeline imports a capture, ranks objects, proposes handoffs, classifies pairs, and writes unconfirmed ledger candidates. It now opts into independent windows so one HAR over the 32-entry window, but within the 256-observation budget, is not rejected as a whole file. Default `build_object_graph` is unchanged. `finding_confirmed` is not set.

### `authorization_denial`

Separates structural eligibility from evidence of cross-account access. A denied actor response must not become a reviewable IDOR claim. Status alone is not conclusive. This recovery does not weaken that rule and does not auto-confirm.

### `case_generator` resource diff

`SESSION_HEADER` names in the query string (`api_key` matches `api[-_]?key`) are a session channel. They are removed from the resource diff when exactly one other path or query difference remains. A session-query-only pair is still rejected. Identical `Authorization` values are still rejected before the resource selector runs.

## FASE 2 — case writeups

Historical IRB after-v3 row (frozen `labs/idor_evidence_v3_eval/results/metrics_before_after.json` and `labs/independent_research_eval/results/final_metrics.json`): missed eligible ids E01 and E06; false reviewable after planner 0, including D11–D16; outcome accuracy 0.8; pairing precision/recall 0.65/0.963; secret leaks, network attempts, and auto-confirmations 0.

Historical V3 FINAL: 48 scenarios, accuracy 0.9792, missed V3-A11 only, false reviewable 0, ledger history unmodified.

### E01 — heavy noise, 42 HAR entries

Observed before this change: `ValueError` `entries_over_limit`. No proposals. Outcome `technical_error`. Not reviewable.

Root cause, two checks:

1. `MAX_EXCHANGES` is 32. `build_object_graph` rejected the whole HAR. The estimates pair is the last two entries, after 40 static asset requests.
2. After the file is accepted, `/estimates2/{id}` still produced no proposal. `resource_kind_noun` required a letter-only token (`[a-z][a-z_]*[a-z]`). `estimates2` was insufficient kind evidence, so handoff refused to pair it. The response container `quotation` is a different kind and does not form a same-kind request pair by itself.

Classification: detector false negative. Not a label error. The ideal outcome `reviewable` and pair nouns `estimates2` / `quotation` match the capture. Pairing counts those nouns as alternatives (at most one true positive).

Recovery: `run_e2e_research` opts into independent windows, raising the per-file cap to the entry count when `32 < n <= 256`. Files above 256 still fail. A trailing numeric suffix is part of the collection token when the alphabetic stem passes the existing generic, sensitive, version, and length checks (`estimates2` stays the kind name so the label HMAC matches). `v2`, `id2`, `data2`, and pure numbers stay insufficient.

Measured after: outcome `reviewable`, one proposal, type `estimates2`, `CASE_ELIGIBLE`, effective reviewable, leaks 0, confirmed 0, network 0, pairing true positive. `quotation` is not a second proposal; the alternative-noun rule still scores a true positive. Stage timings still call `build_object_graph` without the window flag, so `stage_ms` can record `ValueError` while the research path succeeds. That timing error is not a pipeline exception (`pipeline_exceptions` is 0).

### E06 — secret canaries, `api_key` query

Observed before: `REJECT_MULTI_RESOURCE_DIFF` because the query `api_key` counted as a second resource. Outcome abstain. Not reviewable. Canaries did not leak into shareable artifacts.

Root cause: `inspect_read_pair` treated a credential query as an object-id difference.

Classification: detector false negative. Not a label error. The path difference is one resource. The query is a session channel. Uncertainty about ownership stays in the human-review controls (`distinct_accounts`, `ownership`, `negative_control`). Nothing is confirmed.

Recovery: session-header query names are not resource diffs when one other difference remains. A pair that differs only by that query is still rejected.

Measured after: outcome `reviewable`, `CASE_ELIGIBLE`, proposal type `export`, pairing true positive, leaks 0, confirmed 0. Three proposals share that one type (the set metric does not add a false pair). `max_reasonable_proposals` is not exceeded as a forbidden pair.

### V3-A11 — same surface, disjoint objects, tampered sibling

Observed before: effective reviewable false. The tampered sibling's objects could not be read, so the whole surface was `integrity_blocked`. V3-A10 (shared object `o2`) correctly stayed blocked.

Root cause: propagation used the live file. A tampered file is not a trustworthy object list. Empty meant "block everyone".

Classification: detector false negative from over-broad propagation. Not a label error. The registration snapshot for the intact candidate is `o5,o6`, disjoint from the tampered candidate's snapshotted `o1,o2`.

Recovery: the overlay reads `registered_object_refs` captured at `add_evidence` time. Nonempty disjoint objects on the same surface are `safely_independent` and stay `open`. Shared objects stay `blocked_invalid_evidence`. A bad artifact with no registered objects is `requires_manual_independence_review` and the planner fail-closes that surface (this is what keeps D14 blocked: the expired annotation has no object list).

Measured after: V3 FINAL 48/48, missed eligible 0, false reviewable 0, ledger history unmodified, network 0, auto-confirmations 0. Family A is 13/13, which includes A10 still blocked and A11 recovered. `invalid_evidence_blockers` moved from 7 to 6 because A11 is no longer counted as an invalid-evidence block.

### Six prior false reviewables

| id | ideal | after outcome | predicted reviewable |
| --- | --- | --- | --- |
| D11 | integrity_block | integrity_block | false |
| D12 | integrity_block | integrity_block | false |
| D13 | integrity_block | integrity_block | false |
| D14 | integrity_block | integrity_block | false |
| D15 | stop | stop | false |
| D16 | duplicate | duplicate | false |

Ledger raw state for these rows can still be `requires_validation`. The effective view blocks them. History was not rewritten.

## FASE 4–6 — what was measured

New lab `labs/idor_false_negative_recovery/`. DEV 6 and FINAL 15 families. FINAL manifest SHA-256 `25d7a1c79fabbbe9266346c8f173d4925305fd71eb4236286d67bf28eb1a3590`. DEV manifest `9ee8c8e6eb921766b1d2c673b97b0979407846c6bfb3b6f1b30b537044679e34`. Cases were not edited after those hashes were written.

| set | before (frozen historical) | after (this branch) |
| --- | --- | --- |
| IRB FINAL 45 outcome accuracy | 0.8 | 0.8444 |
| IRB missed eligible | 2 (E01, E06) | 0 |
| IRB false reviewable after planner | 0 | 0 |
| IRB pairing precision / recall | 0.65 / 0.963 | 0.6585 / 1.0 |
| IRB reference-correct rate | 0.9565 | 0.9655 |
| IRB secret leaks / network / auto-confirm | 0 / 0 / 0 | 0 / 0 / 0 |
| IRB synthetic manual steps | 240 | 264 |
| V3 FINAL 48 accuracy | 0.9792 | 1.0 |
| V3 missed eligible | 1 (V3-A11) | 0 |
| V3 false reviewable | 0 | 0 |
| V3 ledger history unmodified | true | true |
| FN-recovery FINAL 15 eligible recall | n/a (new lab) | 1.0 |
| FN-recovery FINAL false reviewable | n/a | 0 |
| FN-recovery FINAL fn count | n/a | 0 |
| FN-recovery invalid-evidence detection | n/a | 1.0 |
| FN-recovery abstention rate | n/a | 1.0 |
| FN-recovery provenance completeness | n/a | 1.0 |
| FN-recovery integrity-propagation precision | n/a | 1.0 |
| FN-recovery manual-effort proxy | n/a | 0 on FINAL, 1 on DEV |
| FN-recovery secret leaks / network / auto-confirm | n/a | 0 / 0 / 0 |

Manual steps rose by 24 because E01 and E06 are now human-review cases (+10 each) and D11–D14 each gained one sibling integrity step (+1). Those four stay non-reviewable. Forbidden pairs proposed stay 2, the same historical count.

## Limitations

- Independence is proven only from registration snapshots and declared `depends_on` edges. Unknown or empty object sets on a bad artifact stay fail-closed.
- Default HAR import remains 32 entries. Only the e2e research path opts into independent windows, and only up to 256 entries.
- `quotation` on E01 is response-only and is not emitted as its own proposal. The frozen pairing rule treats `estimates2` and `quotation` as alternative names for one target.
- Numbered collection tokens whose alphabetic stem matches the sensitive-field pattern (stress `tokens2`) stay untyped. Stress was not re-scored.
- IRB stage timings for E01 still exercise the historical 32-entry cap.

## NOT_MEASURED

- IRB STRESS (6). Not required by the brief. S01 (302 entries) is still over `MAX_CAPTURES` (256) and would still fail closed. S02 (60) would now import on the e2e path. S04 `tokens2` is still an untyped sensitive stem.
- Playwright browser tests. 41 tests were skipped in the full discovery run. Chromium was not required for this change.

The full `unittest` discovery (`python3 -m unittest discover -s tests -q`) ran 1188 tests in 103.9s with HTML extras installed (`beautifulsoup4`, `lxml`, `html5lib`). One failure was `test_no_overlap_with_historical_corpora` while a results file under `labs/` contained the substring `irb-` (the independent-research corpus version). That file is not kept. One error, `test_excluded_tests_are_reported_as_skips_not_dropped`, raises `ImportError: Start directory is not importable` from `unittest` discovery on a bare temp directory. This branch does not change `scripts/offline_lab/run_suite.py`.
