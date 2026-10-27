# XSS Evidence Quality v2

Phase 3 Advanced XSS Research. Improves reflected/DOM/stored evidence quality
without auto-confirming vulnerabilities and without replacing the merged
`--dom-local` implementation (PR #63).

## What changed

### A. Reflected context analysis (`xss/context_classifier.py`)

Offline classification of where an innocuous marker is reflected:

- HTML text / comment / attribute / template
- URL attributes and event attributes
- JavaScript string vs code
- JSON / non-HTML
- Escaping, transforms, truncation, malformed HTML
- Parse vs render note (static analysis never claims execution)
- Adversarial prompt-injection bodies are ignored (`prompt_injection_ignored`)

Wired into `XssParameterTester` as additive `reflected_assessment` (default on;
disable with `--no-enrich-context`). Existing classifications stay intact;
`finding_confirmed` / `confirmed` remain false unless the separate opt-in
Playwright path marks a laboratory execution.

### B. DOM state machine (`xss/evidence_record.py`)

Extends merged `dom_local.py` results with a precise `dom_state`:

| State | Meaning |
|---|---|
| `execution_observed` | Innocuous marker / alert observed |
| `execution_blocked_csp` | CSP error prevented execution |
| `interaction_required` | Further user interaction needed |
| `sanitization_applied` | Marker removed/neutralized |
| `sink_reached` | Sink hit (e.g. innerHTML) **without** execution |
| `source_observed` | Source present only |
| `inconclusive` / `inconclusive_browser_error` | Abstain |

**Never** infer execution from `innerHTML` alone.

### C. Stored XSS local lab (`xss/stored_local.py`)

`bbtk xss … --stored-local --stored-write-url … --stored-render-url …`

Write → store → render → browser marker check. Literal loopback only. No
third-party writes. No Blind XSS callbacks.

### D. Offline capture review (`xss/capture_review.py`)

`bbtk xss … --capture-review captures.json`

Recommends human review from already-captured exchanges. Issues **zero** new
HTTP requests. Isolated reflection is never a vulnerability verdict.

### E. Minimized browser evidence

`build_browser_evidence` keeps case id, context, source, sink, execution
result, relevant CSP directives, technical errors, capture refs, and SHA-256
hashes. Cookies, tokens, private HTML, localStorage, and session data are
forbidden (`assert_minimized`).

## Lab evaluation

```bash
python -m labs.xss_evidence_v2_eval.evaluate --split all
```

See `labs/xss_evidence_v2_eval/README.md`. FINAL is frozen before tuning.

## Policy

- Version stays `0.2.2`
- Innocuous markers only
- Playwright restrictions unchanged
- Scope / redaction / budgets / tool-policy / human approval preserved
- `finding_confirmed=false` always for these additive paths
