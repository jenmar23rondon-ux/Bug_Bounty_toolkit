# Independent response-control evaluation

This new corpus was frozen before changing the production classifier. SHA-256:
`5b866136b436bc6101088b36d5614e6815363d04c9a096b8bc16171e07e5e65e`.
No historical FINAL/STRESS files or labels were edited. Cases call production
`assess_pair_authorization` directly and run without network connections.

```bash
python -m labs.authorization_controls_independent.evaluate
python -m unittest tests.test_independent_authorization_controls tests.test_authorization_denial tests.test_authorization_control_matrix -v
```

| Synthetic response metric | Baseline main `545a1e9` | Corrected |
| --- | --- | --- |
| Exact outcome matches | 12/17 | 17/17 |
| Incorrect possible-access signals | 4 | 0 |
| Missed expected possible-access signals | 0 | 0 |
| Possible-access precision | 2/6 | 2/2 |
| Possible-access recall | 2/2 | 2/2 |
| Inconclusive outcomes | 7 | 12 |

The five mismatches were errors-array contradictions, owner/actor HTTP 500 with
resource bodies, a resource body on HTTP 302, and denial inferred from a generic
owner greeting. Conventional `errors` arrays now participate in contradiction
assessment. Pair outcomes require a valid owner resource proof; possible access
requires resource proofs on HTTP 200 for both responses. A resource note that
mentions a historical denied event remains a valid negative control for the
error-envelope heuristic.

This tests response evidence, not end-to-end ownership, session identity or
resource-type compatibility. Those remain separate gates in existing IDOR
pairing/control-matrix tests. Possible access never confirms an IDOR. The cases
were authored by the implementer, so this is an independent regression corpus
relative to earlier datasets, not a blinded external validation or real bounty
performance measurement.
