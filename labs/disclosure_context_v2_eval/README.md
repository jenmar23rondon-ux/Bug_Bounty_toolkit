# Disclosure context quality v2 lab

Synthetic DEV / FINAL / STRESS corpora for
`bugbounty_toolkit.analysis.disclosure_context`. Offline only: the evaluator
blocks socket creation and counts any attempt. Fixtures use `SYNTH` /
`BBTK_CANARY_` / `BBTK_PRIVATE_MARKER_` prefixes. The evaluator prints
aggregate metrics and mismatch ids. It does not print response bodies.

```bash
python -m labs.disclosure_context_v2_eval.evaluate --split dev
python -m labs.disclosure_context_v2_eval.evaluate --split all
```

- `dev/cases.json` is the tuning corpus. Rules were adjusted only against DEV.
- `final/cases.json` is the held-out FINAL corpus. `final/FROZEN.sha256` was
  written before the first FINAL run. The evaluator refuses to score a thawed
  FINAL. Labels are not edited to match the model.
- `stress/cases.json` is frozen the same way (`stress/FROZEN.sha256`).
- `prior` re-scores `labs/information_disclosure_eval/final` (18 cases). That
  file and its hash are not modified. F16's label stays `indicator_detected`.

Labels follow `docs/disclosure-context-v2-audit.md`.

Positive class for precision/recall: `expected_disposition == reviewable`.
High confidence is scored separately. A hard negative that becomes reviewable
or high confidence fails the run.

Metrics from the frozen run are recorded in the PR after that run. Until then
they are not implied by this file.
