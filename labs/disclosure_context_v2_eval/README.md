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

## First frozen run

| Split | Cases | Reviewable P/R | High-confidence P/R | Inconclusive rate | FP reduction vs v1 candidates | Provenance | Leaks | External requests |
|---|---|---|---|---|---|---|---|---|
| DEV | 39 | 1.0 / 1.0 | 1.0 / 1.0 | 1.0 (9/9) | 1.0 (8 → 0) | 1.0 | 0 | 0 |
| FINAL | 18 | 1.0 / 0.9 | 1.0 / 0.875 | 1.0 (1/1) | 1.0 (3 → 0) | 1.0 | 0 | 0 |
| STRESS | 8 | 1.0 / 1.0 | 1.0 / 1.0 | 1.0 (3/3) | 1.0 (2 → 0) | 1.0 | 0 | 0 |

`finding_confirmed` true was 0 on every split. Hard negatives promoted: 0.

FINAL miss, label left as frozen: **C17**. The URL is `https://final.invalid/api/docs/9`.
The rubric treats `/docs/` as public documentation, so the model returns
`not_a_disclosure` / `documentation`. The label says `reviewable` (correlated
national-id read). That is a suspected fixture/label tension, not a reason to
edit the case.

Prior 18 (`labs/information_disclosure_eval/final`, hash unchanged): v1 state
accuracy 0.944, only mismatch F16 (`indicator_detected` vs
`ready_for_manual_review`). v2 disposition for F16 is `inconclusive`, high
confidence false.
