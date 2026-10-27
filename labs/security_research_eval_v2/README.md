# security_research_eval_v2

Offline meta-benchmark for IDOR, reflected XSS, DOM XSS, information disclosure,
IDOR↔disclosure correlation, and capture→dossier flow.

- **DEV** — tunable development cases.
- **FINAL** — frozen labels (`FROZEN.sha256`); do not retune to chase score.
- **STRESS** — volume + prompt-injection noise; regressions reported honestly.

Synthetic only. No network. `finding_confirmed` must stay false. Secret canaries
must never appear in serialized outputs.

```bash
python -m labs.security_research_eval_v2.evaluate --split all
```
