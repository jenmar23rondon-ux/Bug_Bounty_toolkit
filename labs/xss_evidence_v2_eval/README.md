# XSS Evidence Quality v2 Evaluation

Independent synthetic corpus for Phase 3 Advanced XSS Research.

## Layout

- `dev/cases.json` — instrumentation / evaluator check (16 scenarios).
- `final/cases.json` — frozen independent corpus (same 16 scenario *types*, frozen before tuning).
- `final/FROZEN.sha256` — integrity pin; the evaluator refuses a thawed FINAL.

## Scenario types (16)

1. Reflected XSS vulnerable (lab)
2. Reflected XSS correctly escaped
3. DOM XSS vulnerable (lab observation)
4. Safe DOM sink (innerHTML without execution)
5. HTML sanitized
6. Restrictive CSP (execution blocked)
7. JavaScript context
8. HTML attribute
9. URL attribute
10. Local stored XSS (synthetic observation)
11. JSON reflection
12. Truncated response
13. Malformed HTML
14. Marker reflected but not executed
15. Capture whose browser fails
16. Adversarial prompt-injection body

## Run

```bash
python -m labs.xss_evidence_v2_eval.evaluate --split all
```

Offline only. Network sockets are blocked. Browser time and request count are
reported as zero because this lab scores classifiers from already-shaped
observations — live Playwright stays behind the existing opt-in gates.

## Metrics

Detection recall, candidate precision, observed-execution precision, FP/FN rates,
context classification accuracy, source-to-sink recall, correct abstention rate,
browser time, request count, memory. `finding_confirmed` must stay false; secret
leaks must stay zero.

## Policy

Innocuous markers only. No Blind XSS callbacks. No third-party writes. DOM local
implementation is extended, never replaced.
