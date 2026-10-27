# Disclosure ↔ access correlation lab

Synthetic DEV/FINAL corpora for `bugbounty_toolkit.analysis.disclosure_access_correlation`.
Offline only: the evaluator blocks socket creation and counts any attempt.

```bash
python -m labs.disclosure_access_correlation_eval.evaluate
python -m labs.disclosure_access_correlation_eval.evaluate --split final
```

Scenarios covered: denied access, shared resource, public resource, cross-actor
private marker, reflected/example bodies, fake JWT shape, altered evidence,
expired evidence, cross-program evidence, undeclared auth context, missing sides.

`final/cases.json` is frozen (`final/FROZEN.sha256`); labels are never retuned to
match the correlator. Every canary/marker/JWT is synthetic and must never appear
in correlator output (`secret_leaks=0`). `finding_confirmed` is always false.
