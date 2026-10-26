# Verified research dossier evaluation

Offline, synthetic lab for `reporting/dossier_verifier.py`.

## What it measures

Documentary claim-to-evidence verification quality — **not** vulnerability-detection accuracy.

Metrics include verifiable-claim ratio, unsupported-claim recall, invalid/stale reference detection, false confirmations accepted (target 0), redaction of shareable views, wall time, and peak memory.

## Splits

| Split | Purpose |
|---|---|
| DEV | Harness validation (subset) |
| FINAL | Frozen adversarial scenarios |

Ground truth is authored in `corpus.py` before scoring. Manifest SHA-256 is written per split build.

## Run

```bash
python -m labs.verified_dossier_eval.run_lab --split both
```

## Safety

- Synthetic data only
- Zero network
- Zero ledger mutations
- Zero auto-confirmations
- No payload generation / HTTP replay
