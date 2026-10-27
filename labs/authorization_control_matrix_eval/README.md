# Authorization control matrix lab

Synthetic, offline DEV and FINAL splits for `authorization_control_matrix`.
No sockets. Identifiers use the `SYNTH_` prefix. `finding_confirmed` stays false.

FINAL `scenarios.json` is hashed in `final/MANIFEST.sha256`. Freeze that file
before scoring FINAL. Do not edit FINAL labels to match a score.

```bash
python -m labs.authorization_control_matrix_eval.evaluate --split dev
python -m labs.authorization_control_matrix_eval.evaluate --split final --write
```

The naive baseline in `baseline.py` is a before-column only. It is not the product.
