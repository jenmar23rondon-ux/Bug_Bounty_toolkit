# IDOR pairing precision v4

Offline, synthetic, loopback fixtures only (`http://127.0.0.1:8194`, alt
`http://127.0.0.1:8195`). The scorer is
`evaluate_compatibility` (`bbtk.idor-compatibility/1`). It does not call the
network, does not confirm findings, and does not replace `propose_object_handoff`.

## Splits

`dev/cases.json` and `final/cases.json` are the authored cases. Each split has
a `MANIFEST.sha256` that must match before a run. FINAL was frozen before the
first FINAL measurement. Do not edit case labels to chase a score.

## Run

```bash
python labs/idor_pairing_precision_v4/build_cases.py --check
python labs/idor_pairing_precision_v4/evaluate.py --split dev --json labs/idor_pairing_precision_v4/results/dev_metrics.json --report labs/idor_pairing_precision_v4/results/dev_report.md
python labs/idor_pairing_precision_v4/evaluate.py --split final --json labs/idor_pairing_precision_v4/results/final_metrics.json --report labs/idor_pairing_precision_v4/results/final_report.md
python labs/idor_pairing_precision_v4/reeval_irb.py labs/idor_pairing_precision_v4/results/irb45_reeval.json
python -m unittest tests.test_idor_pairing_compatibility tests.test_idor_pairing_precision_v4_lab -q
```

`reeval_irb.py` reads `labs/independent_research_eval/final` and does not write
there. IRB labels stay frozen.
