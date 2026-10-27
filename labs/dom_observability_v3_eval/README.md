# DOM observability v3 evaluation

Offline comparison of the v3 observer with DOM local v2 on synthetic traces.
No browser and no network are required for the score. Live Chrome checks live
in `tests/test_dom_observability_v3_browser.py` and skip when Chrome is absent.

## Layout

- `dev/cases.json` — 27 hand-labeled scenarios used while building the observer.
- `final/cases.json` — the same scenario types with different ids and timings.
- `final/MANIFEST.sha256` — SHA-256 of `final/cases.json`, written before the
  first FINAL run. The evaluator refuses a thawed FINAL.

## Run

```bash
python -m labs.dom_observability_v3_eval.evaluate --split all
```

`finding_confirmed` stays false. `external_requests` must stay 0.
Negatives must stay negative, and `innerHTML` alone must not be reported as
execution.
