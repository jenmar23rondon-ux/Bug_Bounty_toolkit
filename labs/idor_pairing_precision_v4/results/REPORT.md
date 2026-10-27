# IDOR pairing precision v4

Split `final` manifest `3756b547c4d378b1eaa2761b515173f03d55317f409743ff8ce10d54024a881f`.
Version `0.2.2`. finding_confirmed `False`.

## Lab before (naive equal path id) / after (compatibility v4)

| metric | before | after |
|---|---:|---:|
| precision | 0.375 | 1.0 |
| recall | 0.75 | 1.0 |
| f1 | 0.5 | 1.0 |
| false_pairs | 5 | 0 |
| missed_valid_pairs | 1 | 0 |
| abstentions | 0 | 6 |
| cross_kind_collisions | 1 | 0 |
| cross_program_contamination | 0 | 0 |
| cross_origin_contamination | 0 | 0 |

Mismatches vs frozen expectations: none.
Provenance completeness 1.0.
Wall time 3.1533s. Peak memory 851.1 KiB.
secret_leaks 0. network_attempts 0. external_requests 0.

## IRB FINAL 45 re-eval (labels not modified)

| metric | frozen reference | compatibility v4 |
|---|---:|---:|
| precision | 0.65 | 0.931 |
| recall | 0.963 | 1.0 |
| f1 | 0.7761 | 0.9643 |
| false pairs (fp) | 14 | 2 |
| missed valid (fn) | 1 | 0 |

The reference counts legacy handoff proposal types. The v4 column counts kinds admitted by `evaluate_compatibility` on the same frozen captures. Legacy handoff defaults were not changed.

