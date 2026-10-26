# Authorization denial-aware assessment lab

Synthetic DEV/FINAL cases for the deterministic denial classifier
(`bugbounty_toolkit.analysis.authorization_denial`). Offline only; no network.

```bash
python -m pytest tests/test_authorization_denial.py -q
```

DEV (8) trains the decision surface; FINAL (12) is held-out. Labels are authored
from the SPEC in `docs/authorization-denial-aware-assessment.md` and are not
derived from IRB ground truth. The independent IRB FINAL 45-scenario bench is
re-run separately without modifying its labels.
