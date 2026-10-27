# Information disclosure lab

Synthetic DEV/FINAL corpora for `bugbounty_toolkit.analysis.information_disclosure`.
Offline only: the evaluator blocks socket creation and counts any attempt.

```bash
python -m labs.information_disclosure_eval.evaluate            # dev + final
python -m labs.information_disclosure_eval.evaluate --split final
```

- `final/cases.json` is the **independent held-out FINAL** corpus. It was written and
  committed (with `final/FROZEN.sha256`) *before* any detection rule existed; the
  evaluator refuses to report success if the hash changes. Labels are never edited to
  match the detector.
- `dev/cases.json` is the tuning corpus. Rules were adjusted only against DEV.
- Every value is synthetic (`*.invalid` hosts, `BBTK_CANARY_*`, `bbtk-synth-*`, `000-xx-xxxx`).
  No real credentials. `canaries` per case are checked to never appear in output.

FINAL covers: synthetic JWT, synthetic API key, public certificate, private PEM,
placeholders, `.env`, stack trace, synthetic PII, public docs, generic error,
malformed JSON, unsupported compressed response, truncated response,
request-reflected data, secret canaries, prompt injection in body, public
server/version metadata, internal config / private file refs.

## Results (current)

| Split | Cases | State acc. | FP | Correct abstentions | % incomplete | Secret leaks | External requests |
|---|---|---|---|---|---|---|---|
| DEV | 12 | 1.0 | 0 | 2/2 | 25.0% | 0 | 0 |
| FINAL | 18 | 0.944 | 0 | 2/2 | 11.1% | 0 | 0 |

FINAL first run (rules written, before any DEV tuning): state accuracy 0.889 (16/18).
After DEV-only tuning: 0.944 (17/18). The remaining FINAL mismatch (F16: canary token
inside a prompt-injection comment served publicly, labelled `indicator_detected`, got
`ready_for_manual_review`) is kept as is, not fixed by editing labels.
Per-category precision/recall/F1, peak memory and time are printed by the evaluator.
