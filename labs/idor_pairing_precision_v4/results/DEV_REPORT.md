# IDOR pairing precision v4

Split `dev` manifest `4dde2a9725eb7d3accd4bcc2ad665bc4952bd0ad318732f31ffe1c3979b07047`.
Version `0.2.2`. finding_confirmed `False`.

## Lab before (naive equal path id) / after (compatibility v4)

| metric | before | after |
|---|---:|---:|
| precision | 0.5 | 1.0 |
| recall | 0.6667 | 1.0 |
| f1 | 0.5714 | 1.0 |
| false_pairs | 2 | 0 |
| missed_valid_pairs | 1 | 0 |
| abstentions | 0 | 1 |
| cross_kind_collisions | 1 | 0 |
| cross_program_contamination | 0 | 0 |
| cross_origin_contamination | 0 | 0 |

Mismatches vs frozen expectations: none.
Provenance completeness 1.0.
Wall time 0.007s. Peak memory 40.3 KiB.
secret_leaks 0. network_attempts 0. external_requests 0.

