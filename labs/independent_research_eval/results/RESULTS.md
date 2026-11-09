# irb-1.0 results (synthetic loopback lab — not real-world performance)


## FINAL (manifest sha256 `097ec726a02c22fa…`)

| metric | overall | A | B | C | D | E |
|---|---|---|---|---|---|---|
| scenarios | 45 | 10 | 9 | 11 | 8 | 7 |
| outcome_accuracy | 0.9111 | 1.0 | 1.0 | 0.7273 | 1.0 | 0.8571 |
| outcome_accuracy_ci95 | [0.7927, 0.9649] | [0.7225, 1.0] | [0.7009, 1.0] | [0.4344, 0.9025] | [0.6756, 1.0] | [0.4869, 0.9743] |
| object_recall | 0.7317 | 0.375 | 0.75 | 0.6364 | 1.0 | 1.0 |
| precision_at_1 | 0.6829 | 0.375 | 0.75 | 0.6364 | 1.0 | 0.6667 |
| precision_at_3 | 0.6585 | 0.375 | 0.6667 | 0.5758 | 1.0 | 0.7222 |
| precision_at_5 | 0.5073 | 0.275 | 0.525 | 0.4364 | 0.8 | 0.5333 |
| mrr | 0.7033 | 0.375 | 0.75 | 0.6364 | 1.0 | 0.8056 |
| ndcg_at_5 | 0.6988 | 0.375 | 0.7046 | 0.6364 | 1.0 | 0.8354 |
| precision_at_1_strict_resource_type | 0.0976 | 0.0 | 0.125 | 0.1818 | 0.0 | 0.1667 |
| pairing_precision | 1.0 | 1.0 | 1.0 | 1.0 | 1.0 | 1.0 |
| pairing_recall | 1.0 | 1.0 | 1.0 | 1.0 | 1.0 | 1.0 |
| forbidden_pairs_proposed | 0 | 0 | 0 | 0 | 0 | 0 |
| eligibility_correct | 0.8 | 0.8 | 1.0 | 0.9091 | 0.25 | 1.0 |
| false_reviewable_cases | 0 | 0 | 0 | 0 | 0 | 0 |
| false_reviewable_after_planner | 0 | 0 | 0 | 0 | 0 | 0 |
| missed_eligible_cases | 0 | 0 | 0 | 0 | 0 | 0 |
| pipeline_exceptions | 0 | 0 | 0 | 0 | 0 | 0 |
| technical_errors_predicted | 1 | 0 | 0 | 1 | 0 | 0 |
| correct_abstentions | 16 | 7 | 3 | 3 | 1 | 2 |
| abstention_recall | 1.0 | 1.0 | 1.0 | 1.0 | 1.0 | 1.0 |
| missing_control_recall | 1.0 | 1.0 | 1.0 | 1.0 | 1.0 | 1.0 |
| next_step_precision_at_1 | 0.9556 | 1.0 | 1.0 | 1.0 | 0.75 | 1.0 |
| next_step_precision_at_1_ci95 | [0.8517, 0.9877] | [0.7225, 1.0] | [0.7009, 1.0] | [0.7412, 1.0] | [0.4093, 0.9285] | [0.6457, 1.0] |
| redundant_proposals | 3 | 0 | 0 | 2 | 0 | 1 |
| synthetic_manual_steps | 259 | 37 | 60 | 52 | 60 | 50 |
| reference_correct_rate | 0.9583 | 1.0 | — | 1.0 | 0.9333 | — |
| secret_leaks | 0 | 0 | 0 | 0 | 0 | 0 |
| auto_confirmations | 0 | 0 | 0 | 0 | 0 | 0 |
| network_attempts | 0 | 0 | 0 | 0 | 0 | 0 |

Latency (ms, median/max): `{"e2e_total_ms": {"max": 148.76, "median": 49.17}, "handoff_ms": {"max": 22.86, "median": 10.8}, "import_discovery_ms": {"max": 34.33, "median": 4.29}, "planner_ms": {"max": 10.58, "median": 3.27}, "ranking_ms": {"max": 4.05, "median": 1.56}}`  
Peak traced memory: 33012.2 KiB  
Historical overlap: `{"historical_files_scanned": 216, "identical_files": 0, "needle_hits": {}, "our_bytes": 92054, "overlap_free": true}`

| id | fam | tag | ideal | predicted | ok | codes | first step | top-1 type | proposals | notes |
|---|---|---|---|---|---|---|---|---|---|---|
| A01 | A | read-idor-proven | reviewable | reviewable | ✓ | CASE_ELIGIBLE | attest_distinct_accounts | statement | 2 |  |
| A02 | A | idor-absent-denied | stop | stop | ✓ | REJECT_SESSION_ONLY | stop_contradicted_hypothesis | unknown | 0 |  |
| A03 | A | public-resource-id | abstain | abstain | ✓ |  | none | — | 0 |  |
| A04 | A | shared-legit | abstain | abstain | ✓ |  | none | — | 0 |  |
| A05 | A | denied-http-200 | stop | stop | ✓ | CASE_ELIGIBLE | stop_contradicted_hypothesis | unknown | 0 |  |
| A06 | A | success-with-403 | reviewable | reviewable | ✓ | CASE_ELIGIBLE | attest_distinct_accounts | claim | 3 |  |
| A07 | A | authorized-admin-role | abstain | abstain | ✓ |  | none | unknown | 0 |  |
| A08 | A | insufficient-permission | stop | stop | ✓ | CASE_ELIGIBLE | stop_contradicted_hypothesis | unknown | 0 |  |
| A09 | A | negative-control-correct | stop | stop | ✓ | REJECT_SESSION_ONLY | stop_contradicted_hypothesis | unknown | 0 |  |
| A10 | A | ownership-not-shown | reviewable | reviewable | ✓ | CASE_ELIGIBLE | attest_distinct_accounts | ticket | 3 |  |
| B01 | B | cross-reference | reviewable | reviewable | ✓ | CASE_ELIGIBLE | attest_distinct_accounts | invoice | 1 |  |
| B02 | B | uuid-ids | reviewable | reviewable | ✓ | CASE_ELIGIBLE | attest_distinct_accounts | vault | 3 |  |
| B03 | B | same-id-diff-namespace | abstain | abstain | ✓ |  | none | — | 0 |  |
| B04 | B | nested-resource | reviewable | reviewable | ✓ | CASE_ELIGIBLE | attest_distinct_accounts | comment | 3 |  |
| B05 | B | array-members | reviewable | reviewable | ✓ | CASE_ELIGIBLE | attest_distinct_accounts | group | 3 |  |
| B06 | B | duplicate-fields | abstain | abstain | ✓ |  | none | unknown | 0 |  |
| B07 | B | shared-object-across | reviewable | reviewable | ✓ | CASE_ELIGIBLE | attest_distinct_accounts | report | 12 |  |
| B08 | B | parent-frequency-trap | abstain | abstain | ✓ |  | none | account | 0 |  |
| B09 | B | ownership-looking-field | reviewable | reviewable | ✓ | CASE_ELIGIBLE | attest_distinct_accounts | note | 3 |  |
| C01 | C | burp-xml | reviewable | reviewable | ✓ | CASE_ELIGIBLE | attest_distinct_accounts | shipment | 3 |  |
| C02 | C | raw-http | technical_error | abstain | ✗ |  | none | unknown | 0 |  |
| C03 | C | reordered | reviewable | reviewable | ✓ | CASE_ELIGIBLE | attest_distinct_accounts | license | 3 |  |
| C04 | C | missing-response | technical_error | technical_error | ✓ |  | none | unknown | 0 |  |
| C05 | C | redirect | stop | stop | ✓ | CASE_ELIGIBLE | stop_contradicted_hypothesis | unknown | 0 |  |
| C06 | C | mixed-origins | technical_error | abstain | ✗ |  | none | unknown | 0 |  |
| C07 | C | write-method | stop | abstain | ✗ |  | none | address | 0 |  |
| C08 | C | duplicate-captures | reviewable | reviewable | ✓ | CASE_ELIGIBLE | attest_distinct_accounts | booking | 3 |  |
| C09 | C | ambiguous-session | abstain | abstain | ✓ |  | none | cart | 0 |  |
| C10 | C | deep-json | reviewable | reviewable | ✓ | CASE_ELIGIBLE | attest_distinct_accounts | subscription | 3 |  |
| C11 | C | partially-damaged | reviewable | reviewable | ✓ | CASE_ELIGIBLE | attest_distinct_accounts | estimate | 3 |  |
| D11 | D | evidence-altered | integrity_block | integrity_block | ✓ | CASE_ELIGIBLE | verify_evidence_digest | manifest | 3 |  |
| D12 | D | evidence-deleted | integrity_block | integrity_block | ✓ | CASE_ELIGIBLE | verify_evidence_digest | dossier | 3 |  |
| D13 | D | broken-reference | integrity_block | integrity_block | ✓ | CASE_ELIGIBLE | repair_broken_reference | transcript | 3 |  |
| D14 | D | expired-evidence | integrity_block | integrity_block | ✓ | CASE_ELIGIBLE | review_stale_evidence | certificate | 3 |  |
| D15 | D | contradiction | stop | stop | ✓ | CASE_ELIGIBLE | stop_contradicted_hypothesis | agreement | 3 |  |
| D16 | D | repeated-candidate | duplicate | duplicate | ✓ | CASE_ELIGIBLE | review_duplicate | voucherbook | 3 |  |
| D17 | D | controls-complete | reviewable | reviewable | ✓ | CASE_ELIGIBLE | reuse_existing_control | deposit | 3 |  |
| D18 | D | missing-negative | reviewable | reviewable | ✓ | CASE_ELIGIBLE | attest_distinct_accounts | transfer | 3 |  |
| E01 | E | heavy-noise | reviewable | reviewable | ✓ | CASE_ELIGIBLE | attest_distinct_accounts | estimates2 | 1 |  |
| E02 | E | frequent-irrelevant | reviewable | reviewable | ✓ | CASE_ELIGIBLE | attest_distinct_accounts | unknown | 3 |  |
| E03 | E | misleading-labels | abstain | abstain | ✓ |  | none | — | 0 |  |
| E04 | E | similar-routes | reviewable | reviewable | ✓ | CASE_ELIGIBLE | attest_distinct_accounts | user | 1 |  |
| E05 | E | unseen-shape-graphql | stop | abstain | ✗ |  | none | unknown | 0 |  |
| E06 | E | secret-canaries | reviewable | reviewable | ✓ | CASE_ELIGIBLE | attest_distinct_accounts | export | 3 |  |
| E07 | E | prompt-injection | reviewable | reviewable | ✓ | CASE_ELIGIBLE | attest_distinct_accounts | message | 3 |  |

## STRESS (manifest sha256 `4dd82cac98084f0a…`)

| metric | overall | C | E |
|---|---|---|---|
| scenarios | 6 | 5 | 1 |
| outcome_accuracy | 1.0 | 1.0 | 1.0 |
| outcome_accuracy_ci95 | [0.6097, 1.0] | [0.5655, 1.0] | [0.2065, 1.0] |
| object_recall | 1.0 | 1.0 | 1.0 |
| precision_at_1 | 0.8 | 1.0 | 0.0 |
| precision_at_3 | 0.7333 | 0.9167 | 0.0 |
| precision_at_5 | 0.6 | 0.75 | 0.0 |
| mrr | 0.825 | 1.0 | 0.125 |
| ndcg_at_5 | 0.8 | 1.0 | 0.0 |
| precision_at_1_strict_resource_type | 0.0 | 0.0 | 0.0 |
| pairing_precision | 1.0 | 1.0 | 1.0 |
| pairing_recall | 1.0 | 1.0 | 1.0 |
| forbidden_pairs_proposed | 0 | 0 | 0 |
| eligibility_correct | 1.0 | 1.0 | 1.0 |
| false_reviewable_cases | 0 | 0 | 0 |
| false_reviewable_after_planner | 0 | 0 | 0 |
| missed_eligible_cases | 0 | 0 | 0 |
| pipeline_exceptions | 1 | 1 | 0 |
| technical_errors_predicted | 1 | 1 | 0 |
| correct_abstentions | 0 | 0 | 0 |
| abstention_recall | — | — | — |
| missing_control_recall | 1.0 | 1.0 | 1.0 |
| next_step_precision_at_1 | 1.0 | 1.0 | 1.0 |
| next_step_precision_at_1_ci95 | [0.6097, 1.0] | [0.5655, 1.0] | [0.2065, 1.0] |
| redundant_proposals | 59 | 59 | 0 |
| synthetic_manual_steps | 50 | 40 | 10 |
| reference_correct_rate | — | — | — |
| secret_leaks | 0 | 0 | 0 |
| auto_confirmations | 0 | 0 | 0 |
| network_attempts | 0 | 0 | 0 |

Latency (ms, median/max): `{"e2e_total_ms": {"max": 1384.03, "median": 91.94}, "handoff_ms": {"max": 268.98, "median": 29.06}, "import_discovery_ms": {"max": 1021.72, "median": 23.55}, "planner_ms": {"max": 66.0, "median": 3.43}, "ranking_ms": {"max": 67.59, "median": 1.62}}`  
Peak traced memory: 33950.8 KiB  
Historical overlap: `{"historical_files_scanned": 216, "identical_files": 0, "needle_hits": {}, "our_bytes": 309172, "overlap_free": true}`

| id | fam | tag | ideal | predicted | ok | codes | first step | top-1 type | proposals | notes |
|---|---|---|---|---|---|---|---|---|---|---|
| S01 | E | noise-300 | reviewable | reviewable | ✓ | CASE_ELIGIBLE | attest_distinct_accounts | unknown | 3 |  |
| S02 | C | many-objects | reviewable | reviewable | ✓ | CASE_ELIGIBLE | attest_distinct_accounts | row | 64 |  |
| S03 | C | deep-nesting-60 | reviewable | reviewable | ✓ | CASE_ELIGIBLE | attest_distinct_accounts | slot | 3 |  |
| S04 | C | mostly-damaged | reviewable | reviewable | ✓ | CASE_ELIGIBLE | attest_distinct_accounts | tokens2 | 1 |  |
| S05 | C | all-damaged | technical_error | technical_error | ✓ |  | none | — | 0 | ValueError: Offline captures are invalid, incomplete or exce |
| S06 | C | large-body | reviewable | reviewable | ✓ | CASE_ELIGIBLE | attest_distinct_accounts | blob | 3 |  |

## DEV (manifest sha256 `5294f1efc5a7105f…`)

| metric | overall | A | C | D | E |
|---|---|---|---|---|---|
| scenarios | 6 | 2 | 2 | 1 | 1 |
| outcome_accuracy | 1.0 | 1.0 | 1.0 | 1.0 | 1.0 |
| outcome_accuracy_ci95 | [0.6097, 1.0] | [0.3424, 1.0] | [0.3424, 1.0] | [0.2065, 1.0] | [0.2065, 1.0] |
| object_recall | 0.8 | 1.0 | 0.5 | 1.0 | 1.0 |
| precision_at_1 | 0.8 | 1.0 | 0.5 | 1.0 | 1.0 |
| precision_at_3 | 0.8 | 1.0 | 0.5 | 1.0 | 1.0 |
| precision_at_5 | 0.64 | 0.8 | 0.4 | 0.8 | 0.8 |
| mrr | 0.8 | 1.0 | 0.5 | 1.0 | 1.0 |
| ndcg_at_5 | 0.8 | 1.0 | 0.5 | 1.0 | 1.0 |
| precision_at_1_strict_resource_type | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| pairing_precision | 1.0 | 1.0 | 1.0 | 1.0 | 1.0 |
| pairing_recall | 1.0 | 1.0 | 1.0 | 1.0 | 1.0 |
| forbidden_pairs_proposed | 0 | 0 | 0 | 0 | 0 |
| eligibility_correct | 0.8333 | 1.0 | 1.0 | 0.0 | 1.0 |
| false_reviewable_cases | 0 | 0 | 0 | 0 | 0 |
| false_reviewable_after_planner | 0 | 0 | 0 | 0 | 0 |
| missed_eligible_cases | 0 | 0 | 0 | 0 | 0 |
| pipeline_exceptions | 0 | 0 | 0 | 0 | 0 |
| technical_errors_predicted | 1 | 0 | 1 | 0 | 0 |
| correct_abstentions | 1 | 1 | 0 | 0 | 0 |
| abstention_recall | 1.0 | 1.0 | — | — | — |
| missing_control_recall | 1.0 | 1.0 | 1.0 | — | 1.0 |
| next_step_precision_at_1 | 1.0 | 1.0 | 1.0 | 1.0 | 1.0 |
| next_step_precision_at_1_ci95 | [0.6097, 1.0] | [0.3424, 1.0] | [0.3424, 1.0] | [0.2065, 1.0] | [0.2065, 1.0] |
| redundant_proposals | 0 | 0 | 0 | 0 | 0 |
| synthetic_manual_steps | 37 | 10 | 10 | 7 | 10 |
| reference_correct_rate | 1.0 | — | — | 1.0 | — |
| secret_leaks | 0 | 0 | 0 | 0 | 0 |
| auto_confirmations | 0 | 0 | 0 | 0 | 0 |
| network_attempts | 0 | 0 | 0 | 0 | 0 |

Latency (ms, median/max): `{"e2e_total_ms": {"max": 66.38, "median": 52.63}, "handoff_ms": {"max": 14.77, "median": 11.86}, "import_discovery_ms": {"max": 6.18, "median": 4.2}, "planner_ms": {"max": 3.49, "median": 3.45}, "ranking_ms": {"max": 1.69, "median": 1.56}}`  
Peak traced memory: 33017.9 KiB  
Historical overlap: `{"historical_files_scanned": 216, "identical_files": 0, "needle_hits": {}, "our_bytes": 6924, "overlap_free": true}`

| id | fam | tag | ideal | predicted | ok | codes | first step | top-1 type | proposals | notes |
|---|---|---|---|---|---|---|---|---|---|---|
| D01 | A | read-idor-basic | reviewable | reviewable | ✓ | CASE_ELIGIBLE | attest_distinct_accounts | receipt | 3 |  |
| D02 | A | public-same-url | abstain | abstain | ✓ |  | none | — | 0 |  |
| D03 | C | missing-response | technical_error | technical_error | ✓ |  | none | unknown | 0 |  |
| D04 | D | tampered-evidence | integrity_block | integrity_block | ✓ | CASE_ELIGIBLE | verify_evidence_digest | parcel | 3 |  |
| D05 | E | canary-header | reviewable | reviewable | ✓ | CASE_ELIGIBLE | attest_distinct_accounts | badge | 3 |  |
| D06 | C | burp-xml-pair | reviewable | reviewable | ✓ | CASE_ELIGIBLE | attest_distinct_accounts | coupon | 3 |  |
