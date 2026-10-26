# Evidence-gap planner evaluation lab

Synthetic, offline corpus for the deterministic next-step planner
(`bugbounty_toolkit.analysis.evidence_gap_planner`).

## Splits

| Split | Purpose |
|---|---|
| `dev` | Development / diagnosis |
| `final` | Frozen independent evaluation (do not retune against it) |

Both contain the same 20 scenario shapes listed in the P1 brief (ready controls,
missing owner, cookies≠accounts, content denial, public/shared, multi-diff,
non-GET, tampered, expired, broken ref, duplicate, contradicted, eligible
pending review, partial capture, origin difference, reuse of an existing
control, out-of-scope/blocked, blocked authorization, insufficient info).

## Run

```bash
python -m labs.evidence_gap_planner_eval.run_lab
python -m labs.evidence_gap_planner_eval.run_lab --split final --output /tmp/egp.json
```

No network traffic is emitted. Metrics are labelled `synthetic: true` and must
not be quoted as human-productivity claims.

## Ground truth

Each scenario records expected top step, missing/present controls, allowed and
forbidden steps, and estimated manual-step baselines used for the before/after
table.
