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
| redundant_proposals | 1 | 0 | 0 | 1 | 0 | 0 |
| synthetic_manual_steps | 255 | 37 | 60 | 52 | 56 | 50 |
| reference_correct_rate | 0.9524 | 1.0 | — | 1.0 | 0.9167 | — |
| secret_leaks | 0 | 0 | 0 | 0 | 0 | 0 |
| auto_confirmations | 0 | 0 | 0 | 0 | 0 | 0 |
| network_attempts | 0 | 0 | 0 | 0 | 0 | 0 |

Latency (ms, median/max): `{"e2e_total_ms": {"max": 87.9, "median": 39.46}, "handoff_ms": {"max": 22.86, "median": 8.36}, "import_discovery_ms": {"max": 35.01, "median": 4.4}, "planner_ms": {"max": 3.28, "median": 2.55}, "ranking_ms": {"max": 4.31, "median": 1.67}}`  
Peak traced memory: 33020.4 KiB  
Historical overlap: `{"historical_files_scanned": 216, "identical_files": 0, "needle_hits": {}, "our_bytes": 92054, "overlap_free": true}`

| id | fam | tag | ideal | predicted | ok | codes | first step | top-1 type | proposals | notes |
|---|---|---|---|---|---|---|---|---|---|---|
| A01 | A | read-idor-proven | reviewable | reviewable | ✓ | CASE_ELIGIBLE | attest_distinct_accounts | statement | 2 |  |
| A02 | A | idor-absent-denied | stop | stop | ✓ | REJECT_SESSION_ONLY | stop_contradicted_hypothesis | unknown | 0 |  |
| A03 | A | public-resource-id | abstain | abstain | ✓ |  | none | — | 0 |  |
| A04 | A | shared-legit | abstain | abstain | ✓ |  | none | — | 0 |  |
| A05 | A | denied-http-200 | stop | stop | ✓ | CASE_ELIGIBLE | stop_contradicted_hypothesis | unknown | 0 |  |
| A06 | A | success-with-403 | reviewable | reviewable | ✓ | CASE_ELIGIBLE | attest_distinct_accounts | claim | 2 |  |
| A07 | A | authorized-admin-role | abstain | abstain | ✓ |  | none | unknown | 0 |  |
| A08 | A | insufficient-permission | stop | stop | ✓ | CASE_ELIGIBLE | stop_contradicted_hypothesis | unknown | 0 |  |
| A09 | A | negative-control-correct | stop | stop | ✓ | REJECT_SESSION_ONLY | stop_contradicted_hypothesis | unknown | 0 |  |
| A10 | A | ownership-not-shown | reviewable | reviewable | ✓ | CASE_ELIGIBLE | attest_distinct_accounts | ticket | 2 |  |
| B01 | B | cross-reference | reviewable | reviewable | ✓ | CASE_ELIGIBLE | attest_distinct_accounts | invoice | 1 |  |
| B02 | B | uuid-ids | reviewable | reviewable | ✓ | CASE_ELIGIBLE | attest_distinct_accounts | vault | 2 |  |
| B03 | B | same-id-diff-namespace | abstain | abstain | ✓ |  | none | — | 0 |  |
| B04 | B | nested-resource | reviewable | reviewable | ✓ | CASE_ELIGIBLE | attest_distinct_accounts | comment | 2 |  |
| B05 | B | array-members | reviewable | reviewable | ✓ | CASE_ELIGIBLE | attest_distinct_accounts | group | 2 |  |
| B06 | B | duplicate-fields | abstain | abstain | ✓ |  | none | unknown | 0 |  |
| B07 | B | shared-object-across | reviewable | reviewable | ✓ | CASE_ELIGIBLE | attest_distinct_accounts | report | 2 |  |
| B08 | B | parent-frequency-trap | abstain | abstain | ✓ |  | none | account | 0 |  |
| B09 | B | ownership-looking-field | reviewable | reviewable | ✓ | CASE_ELIGIBLE | attest_distinct_accounts | note | 2 |  |
| C01 | C | burp-xml | reviewable | reviewable | ✓ | CASE_ELIGIBLE | attest_distinct_accounts | shipment | 2 |  |
| C02 | C | raw-http | technical_error | abstain | ✗ |  | none | unknown | 0 |  |
| C03 | C | reordered | reviewable | reviewable | ✓ | CASE_ELIGIBLE | attest_distinct_accounts | license | 2 |  |
| C04 | C | missing-response | technical_error | technical_error | ✓ |  | none | unknown | 0 |  |
| C05 | C | redirect | stop | stop | ✓ | CASE_ELIGIBLE | stop_contradicted_hypothesis | unknown | 0 |  |
| C06 | C | mixed-origins | technical_error | abstain | ✗ |  | none | unknown | 0 |  |
| C07 | C | write-method | stop | abstain | ✗ |  | none | address | 0 |  |
| C08 | C | duplicate-captures | reviewable | reviewable | ✓ | CASE_ELIGIBLE | attest_distinct_accounts | booking | 2 |  |
| C09 | C | ambiguous-session | abstain | abstain | ✓ |  | none | cart | 0 |  |
| C10 | C | deep-json | reviewable | reviewable | ✓ | CASE_ELIGIBLE | attest_distinct_accounts | subscription | 2 |  |
| C11 | C | partially-damaged | reviewable | reviewable | ✓ | CASE_ELIGIBLE | attest_distinct_accounts | estimate | 2 |  |
| D11 | D | evidence-altered | integrity_block | integrity_block | ✓ | CASE_ELIGIBLE | verify_evidence_digest | manifest | 2 |  |
| D12 | D | evidence-deleted | integrity_block | integrity_block | ✓ | CASE_ELIGIBLE | verify_evidence_digest | dossier | 2 |  |
| D13 | D | broken-reference | integrity_block | integrity_block | ✓ | CASE_ELIGIBLE | repair_broken_reference | transcript | 2 |  |
| D14 | D | expired-evidence | integrity_block | integrity_block | ✓ | CASE_ELIGIBLE | review_stale_evidence | certificate | 2 |  |
| D15 | D | contradiction | stop | stop | ✓ | CASE_ELIGIBLE | stop_contradicted_hypothesis | agreement | 2 |  |
| D16 | D | repeated-candidate | duplicate | duplicate | ✓ | CASE_ELIGIBLE | review_duplicate | voucherbook | 2 |  |
| D17 | D | controls-complete | reviewable | reviewable | ✓ | CASE_ELIGIBLE | reuse_existing_control | deposit | 2 |  |
| D18 | D | missing-negative | reviewable | reviewable | ✓ | CASE_ELIGIBLE | attest_distinct_accounts | transfer | 2 |  |
| E01 | E | heavy-noise | reviewable | reviewable | ✓ | CASE_ELIGIBLE | attest_distinct_accounts | estimates2 | 1 |  |
| E02 | E | frequent-irrelevant | reviewable | reviewable | ✓ | CASE_ELIGIBLE | attest_distinct_accounts | unknown | 2 |  |
| E03 | E | misleading-labels | abstain | abstain | ✓ |  | none | — | 0 |  |
| E04 | E | similar-routes | reviewable | reviewable | ✓ | CASE_ELIGIBLE | attest_distinct_accounts | user | 1 |  |
| E05 | E | unseen-shape-graphql | stop | abstain | ✗ |  | none | unknown | 0 |  |
| E06 | E | secret-canaries | reviewable | reviewable | ✓ | CASE_ELIGIBLE | attest_distinct_accounts | export | 2 |  |
| E07 | E | prompt-injection | reviewable | reviewable | ✓ | CASE_ELIGIBLE | attest_distinct_accounts | message | 2 |  |

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
| redundant_proposals | 0 | 0 | 0 |
| synthetic_manual_steps | 50 | 40 | 10 |
| reference_correct_rate | — | — | — |
| secret_leaks | 0 | 0 | 0 |
| auto_confirmations | 0 | 0 | 0 |
| network_attempts | 0 | 0 | 0 |

Latency (ms, median/max): `{"e2e_total_ms": {"max": 1687.33, "median": 87.69}, "handoff_ms": {"max": 499.83, "median": 29.93}, "import_discovery_ms": {"max": 1067.29, "median": 25.84}, "planner_ms": {"max": 4.4, "median": 2.86}, "ranking_ms": {"max": 77.09, "median": 1.66}}`  
Peak traced memory: 33633.3 KiB  
Historical overlap: `{"historical_files_scanned": 216, "identical_files": 0, "needle_hits": {}, "our_bytes": 309172, "overlap_free": true}`

| id | fam | tag | ideal | predicted | ok | codes | first step | top-1 type | proposals | notes |
|---|---|---|---|---|---|---|---|---|---|---|
| S01 | E | noise-300 | reviewable | reviewable | ✓ | CASE_ELIGIBLE | attest_distinct_accounts | unknown | 2 |  |
| S02 | C | many-objects | reviewable | reviewable | ✓ | CASE_ELIGIBLE | attest_distinct_accounts | row | 1 |  |
| S03 | C | deep-nesting-60 | reviewable | reviewable | ✓ | CASE_ELIGIBLE | attest_distinct_accounts | slot | 2 |  |
| S04 | C | mostly-damaged | reviewable | reviewable | ✓ | CASE_ELIGIBLE | attest_distinct_accounts | tokens2 | 1 |  |
| S05 | C | all-damaged | technical_error | technical_error | ✓ |  | none | — | 0 | ValueError: Offline captures are invalid, incomplete or exce |
| S06 | C | large-body | reviewable | reviewable | ✓ | CASE_ELIGIBLE | attest_distinct_accounts | blob | 2 |  |

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
| synthetic_manual_steps | 36 | 10 | 10 | 6 | 10 |
| reference_correct_rate | 1.0 | — | — | 1.0 | — |
| secret_leaks | 0 | 0 | 0 | 0 | 0 |
| auto_confirmations | 0 | 0 | 0 | 0 | 0 |
| network_attempts | 0 | 0 | 0 | 0 | 0 |

Latency (ms, median/max): `{"e2e_total_ms": {"max": 52.19, "median": 44.83}, "handoff_ms": {"max": 12.85, "median": 8.67}, "import_discovery_ms": {"max": 8.06, "median": 4.37}, "planner_ms": {"max": 3.01, "median": 2.58}, "ranking_ms": {"max": 2.03, "median": 1.57}}`  
Peak traced memory: 32999.9 KiB  
Historical overlap: `{"historical_files_scanned": 216, "identical_files": 0, "needle_hits": {}, "our_bytes": 6924, "overlap_free": true}`

| id | fam | tag | ideal | predicted | ok | codes | first step | top-1 type | proposals | notes |
|---|---|---|---|---|---|---|---|---|---|---|
| D01 | A | read-idor-basic | reviewable | reviewable | ✓ | CASE_ELIGIBLE | attest_distinct_accounts | receipt | 2 |  |
| D02 | A | public-same-url | abstain | abstain | ✓ |  | none | — | 0 |  |
| D03 | C | missing-response | technical_error | technical_error | ✓ |  | none | unknown | 0 |  |
| D04 | D | tampered-evidence | integrity_block | integrity_block | ✓ | CASE_ELIGIBLE | verify_evidence_digest | parcel | 2 |  |
| D05 | E | canary-header | reviewable | reviewable | ✓ | CASE_ELIGIBLE | attest_distinct_accounts | badge | 2 |  |
| D06 | C | burp-xml-pair | reviewable | reviewable | ✓ | CASE_ELIGIBLE | attest_distinct_accounts | coupon | 2 |  |
