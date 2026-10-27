# AI evidence contract v2 lab

Offline structural eval. No model host, no third-party HTTP, no real credentials.

```bash
python -m labs.ai_evidence_contract_v2_eval.evaluate --split dev
python -m labs.ai_evidence_contract_v2_eval.evaluate --split final
```

DEV cases and held-out FINAL cases live in `corpus.py`. `MANIFEST.sha256` is
the freeze. `evaluate` refuses to score when the manifest or generated files
drift. Results under `results/` are in-process measurements, not model scores.

`finding_confirmed` stays false. Synthetic canaries in the corpus are the
privacy traps; they must not appear in packets or result files.
