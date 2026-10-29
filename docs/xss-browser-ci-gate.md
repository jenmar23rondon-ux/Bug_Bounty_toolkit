# Required live XSS evaluation

The XSS CLI previously returned success for explicit `--mode live` when
Chromium was unavailable. Unit tests could also skip a missing browser, and
the live CLI only failed on safety counters, not wrong browser states.

Explicit live evaluation now fails for NOT_MEASURED, missing runs, state
mismatches, incomplete evidence, or disagreement between repeated runs.
Mock mode remains available for parser-only environments and never claims
live measurements. Existing network, secret and automatic-confirmation gates
remain mandatory. Static parser accuracy stays separate from browser accuracy.

CI and the network-disabled Playwright container run:

```bash
python -m labs.xss_real_browser_eval.evaluate --split final --mode live --repeat 2
```

Acceptance criteria: missing Chromium must fail instead of skip; the unchanged
16-case FINAL must run twice with matching expected browser states, complete
evidence, no external requests or observed external sockets, no secret leaks
and no automatic vulnerability confirmation. Regression tests also reject
wrong/incomplete observations and absent reproducibility measurements.

This integrates the existing browser pipeline rather than adding another
detector. FINAL inputs and labels, version 0.2.2 and human-review requirements
are unchanged. Passing a local browser matrix does not measure real-world XSS
detection rates.
