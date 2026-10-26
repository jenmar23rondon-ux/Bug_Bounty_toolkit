# Semantic candidate correlation lab (synthetic only)

- `corpus.py` — DEV (8) and FINAL (16) scenario builders; labels come from the scenario spec.
- `freeze.py` — writes `dev|final/ground_truth.json` + `MANIFEST.sha256`. FINAL was frozen
  (commit "labs: freeze semantic candidate DEV/FINAL corpus…") **before** the first FINAL run
  and was not re-frozen afterwards.
- `metrics.py` — verifies the manifest + regenerated ledgers, then scores semantic `strong`
  pairs vs. two baselines: ledger rule (`dedup_key` or `surface|category`) and the default
  `surface|category` key alone. Also: adversarial false merges, neighbour P@1, reuse
  precision/recall, invalid refs accepted, canary leaks, socket connect attempts, ledger
  file hashes before/after, latency, tracemalloc peak.
- `run_lab.py` — exits 1 on any network attempt, leak, accepted invalid ref, ledger change,
  auto-merge/confirmation, or adversarial false merge.
- `results/metrics.json` — HEAD results (latency/memory vary per machine).

Reuse precision counts only labelled reuse; unlabelled but plausible recommendations
(e.g. `reuse_object_relation`) count as misses, so it is a lower bound.
