# local_ai_evidence_assistant_eval

Offline evaluation of the local AI evidence assistant vs the deterministic baseline.

- Mock profiles (`faithful`, `enricher`, `inventor`) on loopback — not real model scores.
- FINAL is frozen; do not retune labels to chase the mock.
- If AI does not improve advisory quality, deterministic stays primary.

```bash
python -m labs.local_ai_evidence_assistant_eval.evaluate --split all
```
