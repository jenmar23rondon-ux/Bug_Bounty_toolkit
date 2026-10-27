# Security research benchmark v2

Offline meta-evaluation over existing deterministic pipelines:

| Category | Engine |
|---|---|
| IDOR | `resource_kind_lineage.correlate_resources` |
| Reflected XSS | `xss.context_classifier.classify_reflected_context` |
| DOM XSS | `xss.evidence_record.classify_dom_state` |
| Information disclosure | `analysis.information_disclosure.assess_disclosure` |
| IDOR↔disclosure | `analysis.disclosure_access_correlation.correlate_disclosure_access` |
| Capture→dossier | `reporting.dossier_verifier.verify_research_dossier` |

## Corpora

- `labs/security_research_eval_v2/dev/` — development cases (may change).
- `labs/security_research_eval_v2/final/` — frozen FINAL; do not retune labels.
- `labs/security_research_eval_v2/stress/` — volume + prompt-injection noise.

## Safety invariants

- Offline / synthetic only (socket creation blocked during evaluation).
- `finding_confirmed` stays false.
- Secret canaries never appear in serialized outputs.
- FINAL/STRESS digests verified via `FROZEN.sha256`.

## Run

```bash
python -m labs.security_research_eval_v2.evaluate --split all
```

Version stays **0.2.2**. No tags/releases for this change.
