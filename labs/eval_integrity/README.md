# Evaluation integrity lab (measurement quality only)

This lab checks that bbtk's **evaluation** can fail. It adds no detection rules, does not
change ranking, and never rewrites a frozen corpus.

## What it verifies

* `corpus_integrity.py` — read-only checks for every registered frozen corpus
  (`registry.py`): manifest vs bytes, a **pinned digest of the manifest itself**
  (so a coordinated capture+manifest edit is still caught), exact file set (added /
  removed files), ground-truth structure (missing entry refs, entries shared by two
  scenarios, orphan entries, contradictory labels, any `expected_confirmed != false`),
  independence between sets (shared origin, scenario IDs or identical exchanges) and
  **regeneration into a disposable temp dir**, byte-compared against the originals.
* `pipeline.py` — an offline end-to-end contract over public interfaces on `main`:
  synthetic capture → import → object discovery → ranking → handoff → eligibility
  (real `handoff_case_eligibility` codes from PR #34) → reviewable proposal → Evidence
  Ledger → structured program report. Sockets are hard blocked; checks cover req/resp
  correspondence (entry digests), origin preservation, provenance
  (source/observation/locator), cross-scenario pairing, no confirmation, ledger validity,
  report references and determinism (two runs, canonical digest).
  `pending_contracts` is empty: PR #34 is on main and origins are never rewritten.
* `mutations.py` — seeded, reversible mutations on temp copies / in-memory reports.
  Every one must make a validator fail. It also replays the **pre-fix test logic** on the
  same mutations for a before/after comparison.

## Fixed bug

`tests/test_object_ranking_eval.py::test_regeneration_is_byte_identical` used to rebuild
inside `frozen/` and `dev/` and then compare against the manifest it had just rewritten,
so a drifting generator always passed (and the test wrote into the corpus). It now
regenerates into a temp dir, byte-compares against the originals and verifies the pinned
original manifests.

## Run

```bash
python -m labs.eval_integrity.mutations --json /tmp/integrity-metrics.json
python -m unittest tests.test_eval_integrity tests.test_object_ranking_eval
```

`results/integrity-metrics.json` is a recorded run (timing/memory vary by machine).
Metrics are about the *test harness*, on synthetic data; they are not a validation of
detection quality on real targets.
