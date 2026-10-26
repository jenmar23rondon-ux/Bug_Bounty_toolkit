# irb-1.0 results (synthetic loopback lab — not real-world performance)


## FINAL (manifest sha256 `097ec726a02c22fa…`)

| metric | overall | A | B | C | D | E |
|---|---|---|---|---|---|---|
| scenarios | 45 | 10 | 9 | 11 | 8 | 7 |
| outcome_accuracy | 0.6667 | 0.5 | 1.0 | 0.6364 | 0.75 | 0.4286 |
| outcome_accuracy_ci95 | [0.5207, 0.7864] | [0.2366, 0.7634] | [0.7009, 1.0] | [0.3538, 0.8483] | [0.4093, 0.9285] | [0.1582, 0.7495] |
| object_recall | 0.9024 | 1.0 | 1.0 | 0.7273 | 1.0 | 0.8333 |
| precision_at_1 | 0.8293 | 1.0 | 0.875 | 0.7273 | 1.0 | 0.5 |
| precision_at_3 | 0.8211 | 1.0 | 0.8333 | 0.6667 | 1.0 | 0.6111 |
| precision_at_5 | 0.6341 | 0.725 | 0.7 | 0.4909 | 0.8 | 0.4667 |
| mrr | 0.8577 | 1.0 | 0.9167 | 0.7273 | 1.0 | 0.6389 |
| ndcg_at_5 | 0.859 | 1.0 | 0.9009 | 0.7273 | 1.0 | 0.6687 |
| precision_at_1_strict_resource_type | 0.0976 | 0.0 | 0.125 | 0.1818 | 0.0 | 0.1667 |
| pairing_precision | 0.65 | 0.3333 | 0.6667 | 0.625 | 1.0 | 0.6667 |
| pairing_recall | 0.963 | 1.0 | 1.0 | 1.0 | 1.0 | 0.8 |
| forbidden_pairs_proposed | 2 | 1 | 0 | 0 | 0 | 1 |
| eligibility_correct | 0.6667 | 0.5 | 1.0 | 0.9091 | 0.25 | 0.5714 |
| false_reviewable_cases | 13 | 5 | 0 | 1 | 6 | 1 |
| false_reviewable_after_planner | 9 | 5 | 0 | 1 | 2 | 1 |
| missed_eligible_cases | 2 | 0 | 0 | 0 | 0 | 2 |
| pipeline_exceptions | 1 | 0 | 0 | 0 | 0 | 1 |
| technical_errors_predicted | 2 | 0 | 0 | 1 | 0 | 1 |
| correct_abstentions | 9 | 2 | 3 | 2 | 1 | 1 |
| abstention_recall | 0.5625 | 0.2857 | 1.0 | 0.6667 | 1.0 | 0.5 |
| missing_control_recall | 0.8983 | 1.0 | 1.0 | 1.0 | 1.0 | 0.6 |
| next_step_precision_at_1 | 0.7556 | 0.5 | 1.0 | 0.9091 | 0.75 | 0.5714 |
| next_step_precision_at_1_ci95 | [0.6133, 0.8576] | [0.2366, 0.7634] | [0.7009, 1.0] | [0.6226, 0.9838] | [0.4093, 0.9285] | [0.2505, 0.8418] |
| redundant_proposals | 3 | 0 | 0 | 2 | 0 | 1 |
| synthetic_manual_steps | 326 | 80 | 60 | 60 | 86 | 40 |
| reference_correct_rate | 0.8889 | — | — | — | 0.8889 | — |
| secret_leaks | 0 | 0 | 0 | 0 | 0 | 0 |
| auto_confirmations | 0 | 0 | 0 | 0 | 0 | 0 |
| network_attempts | 0 | 0 | 0 | 0 | 0 | 0 |

Latency (ms, median/max): `{"e2e_total_ms": {"max": 133.01, "median": 43.54}, "handoff_ms": {"max": 27.04, "median": 10.4}, "import_discovery_ms": {"max": 29.38, "median": 4.2}, "planner_ms": {"max": 10.4, "median": 2.74}, "ranking_ms": {"max": 3.34, "median": 1.31}}`  
Peak traced memory: 33950.7 KiB  
Historical overlap: `{"historical_files_scanned": 71, "identical_files": 0, "needle_hits": {}, "our_bytes": 92054, "overlap_free": true}`

| id | fam | tag | ideal | predicted | ok | codes | first step | top-1 type | proposals | notes |
|---|---|---|---|---|---|---|---|---|---|---|
| A01 | A | read-idor-proven | reviewable | reviewable | ✓ | CASE_ELIGIBLE | attest_distinct_accounts | statement | 2 |  |
| A02 | A | idor-absent-denied | stop | reviewable | ✗ | CASE_ELIGIBLE, REJECT_SESSION_ONLY | attest_distinct_accounts | payslip | 4 |  |
| A03 | A | public-resource-id | abstain | reviewable | ✗ | CASE_ELIGIBLE | attest_distinct_accounts | — | 1 |  |
| A04 | A | shared-legit | abstain | abstain | ✓ |  | none | — | 0 |  |
| A05 | A | denied-http-200 | stop | reviewable | ✗ | CASE_ELIGIBLE | attest_distinct_accounts | contract | 2 |  |
| A06 | A | success-with-403 | reviewable | reviewable | ✓ | CASE_ELIGIBLE | attest_distinct_accounts | claim | 3 |  |
| A07 | A | authorized-admin-role | abstain | abstain | ✓ | REJECT_HEADER_DIFF | none | profile | 3 |  |
| A08 | A | insufficient-permission | stop | reviewable | ✗ | CASE_ELIGIBLE | attest_distinct_accounts | ledger | 2 |  |
| A09 | A | negative-control-correct | stop | reviewable | ✗ | CASE_ELIGIBLE, REJECT_SESSION_ONLY | attest_distinct_accounts | prescription | 4 |  |
| A10 | A | ownership-not-shown | reviewable | reviewable | ✓ | CASE_ELIGIBLE | attest_distinct_accounts | ticket | 3 |  |
| B01 | B | cross-reference | reviewable | reviewable | ✓ | CASE_ELIGIBLE, REJECT_MULTI_RESOURCE_DIFF | attest_distinct_accounts | invoice | 2 |  |
| B02 | B | uuid-ids | reviewable | reviewable | ✓ | CASE_ELIGIBLE | attest_distinct_accounts | vault | 3 |  |
| B03 | B | same-id-diff-namespace | abstain | abstain | ✓ |  | none | — | 0 |  |
| B04 | B | nested-resource | reviewable | reviewable | ✓ | CASE_ELIGIBLE | attest_distinct_accounts | comment | 3 |  |
| B05 | B | array-members | reviewable | reviewable | ✓ | CASE_ELIGIBLE | attest_distinct_accounts | group | 3 |  |
| B06 | B | duplicate-fields | abstain | abstain | ✓ | REJECT_MULTI_RESOURCE_DIFF | none | wallet | 6 |  |
| B07 | B | shared-object-across | reviewable | reviewable | ✓ | CASE_ELIGIBLE | attest_distinct_accounts | report | 12 |  |
| B08 | B | parent-frequency-trap | abstain | abstain | ✓ | REJECT_MULTI_RESOURCE_DIFF | none | account | 4 |  |
| B09 | B | ownership-looking-field | reviewable | reviewable | ✓ | CASE_ELIGIBLE | attest_distinct_accounts | note | 3 |  |
| C01 | C | burp-xml | reviewable | reviewable | ✓ | CASE_ELIGIBLE | attest_distinct_accounts | shipment | 3 |  |
| C02 | C | raw-http | technical_error | abstain | ✗ | NEEDS_RESPONSE | none | kind-370923e21ed2d0804e880898f849f570 | 1 |  |
| C03 | C | reordered | reviewable | reviewable | ✓ | CASE_ELIGIBLE | attest_distinct_accounts | license | 3 |  |
| C04 | C | missing-response | technical_error | technical_error | ✓ |  | none | unknown | 0 |  |
| C05 | C | redirect | stop | reviewable | ✗ | CASE_ELIGIBLE | attest_distinct_accounts | quote | 2 |  |
| C06 | C | mixed-origins | technical_error | abstain | ✗ |  | none | unknown | 0 |  |
| C07 | C | write-method | stop | abstain | ✗ | REJECT_NON_GET | none | address | 1 |  |
| C08 | C | duplicate-captures | reviewable | reviewable | ✓ | CASE_ELIGIBLE | attest_distinct_accounts | booking | 3 |  |
| C09 | C | ambiguous-session | abstain | abstain | ✓ |  | none | cart | 0 |  |
| C10 | C | deep-json | reviewable | reviewable | ✓ | CASE_ELIGIBLE | attest_distinct_accounts | subscription | 3 |  |
| C11 | C | partially-damaged | reviewable | reviewable | ✓ | CASE_ELIGIBLE | attest_distinct_accounts | estimate | 3 |  |
| D11 | D | evidence-altered | integrity_block | integrity_block | ✓ | CASE_ELIGIBLE | verify_evidence_digest | manifest | 3 |  |
| D12 | D | evidence-deleted | integrity_block | integrity_block | ✓ | CASE_ELIGIBLE | verify_evidence_digest | dossier | 3 |  |
| D13 | D | broken-reference | integrity_block | reviewable | ✗ | CASE_ELIGIBLE | repair_broken_reference | transcript | 3 |  |
| D14 | D | expired-evidence | integrity_block | reviewable | ✗ | CASE_ELIGIBLE | review_stale_evidence | certificate | 3 |  |
| D15 | D | contradiction | stop | stop | ✓ | CASE_ELIGIBLE | stop_contradicted_hypothesis | agreement | 3 |  |
| D16 | D | repeated-candidate | duplicate | duplicate | ✓ | CASE_ELIGIBLE | review_duplicate | voucherbook | 3 |  |
| D17 | D | controls-complete | reviewable | reviewable | ✓ | CASE_ELIGIBLE | reuse_existing_control | deposit | 3 |  |
| D18 | D | missing-negative | reviewable | reviewable | ✓ | CASE_ELIGIBLE | attest_distinct_accounts | transfer | 3 |  |
| E01 | E | heavy-noise | reviewable | technical_error | ✗ |  | none | — | 0 | ValueError: Offline captures are invalid, incomplete or exce |
| E02 | E | frequent-irrelevant | reviewable | reviewable | ✓ | CASE_ELIGIBLE | attest_distinct_accounts | unknown | 3 |  |
| E03 | E | misleading-labels | abstain | reviewable | ✗ | CASE_ELIGIBLE | attest_distinct_accounts | — | 3 |  |
| E04 | E | similar-routes | reviewable | reviewable | ✓ | CASE_ELIGIBLE | attest_distinct_accounts | user | 2 |  |
| E05 | E | unseen-shape-graphql | stop | abstain | ✗ | REJECT_NON_GET | none | kind-75c55565937017fc6e4899ab98f8b87b | 1 |  |
| E06 | E | secret-canaries | reviewable | abstain | ✗ | REJECT_MULTI_RESOURCE_DIFF | none | export | 3 | paired_but_no_reviewable_case |
| E07 | E | prompt-injection | reviewable | reviewable | ✓ | CASE_ELIGIBLE | attest_distinct_accounts | message | 3 |  |

## STRESS (manifest sha256 `4dd82cac98084f0a…`)

| metric | overall | C | E |
|---|---|---|---|
| scenarios | 6 | 5 | 1 |
| outcome_accuracy | 0.3333 | 0.4 | 0.0 |
| outcome_accuracy_ci95 | [0.0968, 0.7] | [0.1176, 0.7693] | [0.0, 0.7935] |
| object_recall | 0.2 | 0.25 | 0.0 |
| precision_at_1 | 0.2 | 0.25 | 0.0 |
| precision_at_3 | 0.2 | 0.25 | 0.0 |
| precision_at_5 | 0.16 | 0.2 | 0.0 |
| mrr | 0.2 | 0.25 | 0.0 |
| ndcg_at_5 | 0.2 | 0.25 | 0.0 |
| precision_at_1_strict_resource_type | 0.0 | 0.0 | 0.0 |
| pairing_precision | 1.0 | 1.0 | — |
| pairing_recall | 0.2 | 0.25 | 0.0 |
| forbidden_pairs_proposed | 0 | 0 | 0 |
| eligibility_correct | 0.3333 | 0.4 | 0.0 |
| false_reviewable_cases | 0 | 0 | 0 |
| false_reviewable_after_planner | 0 | 0 | 0 |
| missed_eligible_cases | 4 | 3 | 1 |
| pipeline_exceptions | 3 | 2 | 1 |
| technical_errors_predicted | 5 | 4 | 1 |
| correct_abstentions | 0 | 0 | 0 |
| abstention_recall | — | — | — |
| missing_control_recall | 0.2 | 0.25 | 0.0 |
| next_step_precision_at_1 | 0.3333 | 0.4 | 0.0 |
| next_step_precision_at_1_ci95 | [0.0968, 0.7] | [0.1176, 0.7693] | [0.0, 0.7935] |
| redundant_proposals | 0 | 0 | 0 |
| synthetic_manual_steps | 10 | 10 | 0 |
| reference_correct_rate | — | — | — |
| secret_leaks | 0 | 0 | 0 |
| auto_confirmations | 0 | 0 | 0 |
| network_attempts | 0 | 0 | 0 |

Latency (ms, median/max): `{"e2e_total_ms": {"max": 84.41, "median": 13.91}, "handoff_ms": {"max": 26.06, "median": 2.08}, "import_discovery_ms": {"max": 22.44, "median": 3.91}, "planner_ms": {"max": 3.0, "median": 1.18}, "ranking_ms": {"max": 1.4, "median": 0.92}}`  
Peak traced memory: 34814.2 KiB  
Historical overlap: `{"historical_files_scanned": 71, "identical_files": 0, "needle_hits": {}, "our_bytes": 309172, "overlap_free": true}`

| id | fam | tag | ideal | predicted | ok | codes | first step | top-1 type | proposals | notes |
|---|---|---|---|---|---|---|---|---|---|---|
| S01 | E | noise-300 | reviewable | technical_error | ✗ |  | none | — | 0 | ValueError: Offline captures are invalid, incomplete or exce |
| S02 | C | many-objects | reviewable | technical_error | ✗ |  | none | — | 0 | ValueError: Offline captures are invalid, incomplete or exce |
| S03 | C | deep-nesting-60 | reviewable | technical_error | ✗ |  | none | unknown | 0 |  |
| S04 | C | mostly-damaged | reviewable | technical_error | ✗ |  | none | — | 0 |  |
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
| false_reviewable_cases | 1 | 0 | 0 | 1 | 0 |
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
| synthetic_manual_steps | 41 | 10 | 10 | 11 | 10 |
| reference_correct_rate | 1.0 | — | — | 1.0 | — |
| secret_leaks | 0 | 0 | 0 | 0 | 0 |
| auto_confirmations | 0 | 0 | 0 | 0 | 0 |
| network_attempts | 0 | 0 | 0 | 0 | 0 |

Latency (ms, median/max): `{"e2e_total_ms": {"max": 66.58, "median": 45.15}, "handoff_ms": {"max": 12.39, "median": 11.15}, "import_discovery_ms": {"max": 5.49, "median": 4.45}, "planner_ms": {"max": 2.78, "median": 2.65}, "ranking_ms": {"max": 1.58, "median": 1.22}}`  
Peak traced memory: 33005.5 KiB  
Historical overlap: `{"historical_files_scanned": 71, "identical_files": 0, "needle_hits": {}, "our_bytes": 6924, "overlap_free": true}`

| id | fam | tag | ideal | predicted | ok | codes | first step | top-1 type | proposals | notes |
|---|---|---|---|---|---|---|---|---|---|---|
| D01 | A | read-idor-basic | reviewable | reviewable | ✓ | CASE_ELIGIBLE | attest_distinct_accounts | receipt | 3 |  |
| D02 | A | public-same-url | abstain | abstain | ✓ |  | none | — | 0 |  |
| D03 | C | missing-response | technical_error | technical_error | ✓ |  | none | unknown | 0 |  |
| D04 | D | tampered-evidence | integrity_block | integrity_block | ✓ | CASE_ELIGIBLE | verify_evidence_digest | parcel | 3 |  |
| D05 | E | canary-header | reviewable | reviewable | ✓ | CASE_ELIGIBLE | attest_distinct_accounts | badge | 3 |  |
| D06 | C | burp-xml-pair | reviewable | reviewable | ✓ | CASE_ELIGIBLE | attest_distinct_accounts | coupon | 3 |  |
