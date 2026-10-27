# IDOR evidence correctness v3 lab

48 independent synthetic FINAL scenarios (families A integrity, B session control, C access
proof, D encoded identifiers, E resource correlation). Labels in `final/scenarios.json` are
frozen by `final/MANIFEST.sha256`; the evaluator refuses to run if they change.

```bash
python labs/idor_evidence_v3_eval/evaluate.py --json labs/idor_evidence_v3_eval/results/final_metrics.json
python -m unittest tests.test_idor_evidence_v3
```

`results/metrics_before_after.json` compares base `09e345f` with this change on both this lab
and the historical IRB FINAL 45 (labels untouched). Network is hard-blocked; nothing is confirmed.
Known tradeoff: V3-A11 (sibling with disjoint objects next to a *tampered* file) is blocked,
because objects named inside an altered file are not trusted.
