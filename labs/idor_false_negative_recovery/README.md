# IDOR false-negative recovery lab

Offline synthetic cases for the blocker dependency graph. DEV is for development.
FINAL (15 families) is frozen by `final/MANIFEST.sha256` before the first FINAL run.
The evaluator refuses a split whose `cases.json` hash differs.

```bash
python labs/idor_false_negative_recovery/freeze.py
python labs/idor_false_negative_recovery/evaluate.py --split dev
python labs/idor_false_negative_recovery/evaluate.py --split final --json labs/idor_false_negative_recovery/results/final_metrics.json
python -m unittest tests.test_blocker_dependency_graph -v
```

Nothing is confirmed. No HTTP. Labels are not taken from IRB or V3 ground truth.
