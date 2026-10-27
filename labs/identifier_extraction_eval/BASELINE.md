# FASE 0 baseline and FASE 1 after metrics

Measured offline with `python -m labs.identifier_extraction_eval.run_lab` (see `METRICS.json`).
No network traffic. Version remains **0.2.2**. PR #52 denial assessment is untouched.
Object Discovery ranking is unchanged; the adapter is opt-in only.

## Before (legacy path/query/JSON heuristics)

| Metric | Value |
|--------|-------|
| Precision | 0.364 |
| Recall | 0.235 |
| F1 | 0.286 |
| True positives | 4 / 17 |

Uncovered formats (recall 0): matrix, XML, form, declared references.
Legacy always stringifies values (types not preserved). Secrets occasionally leak into
name-based matches when field naming is ambiguous.

## After (structured extractor)

| Metric | Value |
|--------|-------|
| Precision | 1.000 |
| Recall | 1.000 |
| F1 | 1.000 |
| True positives | 17 / 17 |
| Secret leaks | 0 |
| Types preserved | yes |
| Locators valid | yes |
| Hostile inputs rejected | yes |
| Elapsed | ~0.6 ms on the corpus |

### Recall by format (after)

path, query, matrix, json, json_array, xml, xml_attr, form, declared — all 1.0

### Deltas

- Δ recall ≈ **+0.765**
- Δ precision ≈ **+0.636**
- Δ F1 ≈ **+0.714**

## Limitations

- Heuristic field-name matching can miss unconventional keys that are neither UUID-shaped
  nor explicitly declared; callers should pass `declared_references` when the schema is known.
- XML support is bounded (no DTDs/entities, depth/byte/element caps) and uses the stdlib
  parser only after a DOCTYPE/ENTITY pre-check.
- The extractor never determines ownership, visibility or authorization and never
  auto-confirms findings.
