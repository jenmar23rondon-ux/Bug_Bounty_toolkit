# IDOR pairing precision v4

Offline synthetic lab for `bugbounty_toolkit.analysis.idor_pairing_precision.evaluate_compatibility`.
No HTTP. `finding_confirmed` stays false. Legacy `propose_object_handoff` is not called.

DEV is the tuning split. FINAL is frozen by `final/MANIFEST.sha256` and must not be edited to
move a score. The runner checks the manifest before it scores.

```bash
python labs/idor_pairing_precision_v4/freeze.py
python labs/idor_pairing_precision_v4/evaluate.py --split dev --json labs/idor_pairing_precision_v4/results/dev_metrics.json
python labs/idor_pairing_precision_v4/evaluate.py --split final --irb \
  --json labs/idor_pairing_precision_v4/results/final_metrics.json \
  --report labs/idor_pairing_precision_v4/results/REPORT.md
python -m unittest tests.test_idor_pairing_precision_v4 -q
```

`--irb` re-reads `labs/independent_research_eval/final` and does not write those labels.
The naive "equal final path segment" column is a baseline only; it is not a product decision.
