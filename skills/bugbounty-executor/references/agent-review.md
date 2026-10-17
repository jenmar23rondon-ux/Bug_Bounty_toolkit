# Evidence Review By The Calling AI

The AI using this skill is the reasoning component; the CLI supplies deterministic HTTP tests and structured observations. There is no bundled model, external inference call or API-key requirement. Do not claim an LLM was called by the CLI or let model judgment replace a failed control.

After a native access-check, XSS or SQLi run, prepare a minimal local review packet:

```bash
bugbounty analyze evidence --input registros/my-program/evidence/access-control/selected-evidence.json --output registros/my-program/review.json
```

This offline command needs no program initialization or dry-run. It accepts one native evidence object, not a whole program report. It copies only allowlisted counts, statuses, context categories and access-check booleans; it drops URLs, headers, body snippets, arbitrary reasons, tool messages and embedded instructions. It never sends data to a model or another network destination. `source_claims_unverified` remains true: a user-supplied/modified JSON file is not independently authenticated by formatting it.

## Reasoning Gate

1. Verify provenance: identify the run, supplied user-authorized case/inputs and whether the requested steps actually ran. Read private case details locally only when needed; do not upload them or repeat them in a prompt.
2. Interpret the selected topic's observations. Access control needs valid controls, owner resource and private proof matches plus intended-permission review. XSS needs actual content type and parser availability; script/URL/attribute reflection remains context evidence, not observed browser execution. SQL errors need baseline differences and remain possible indicators.
3. State a bounded conclusion: candidate, rejected in this test or inconclusive, what was not sent/tested and what evidence supports that conclusion. `confirmed` in generated packets is always false. Model confidence, equal body lengths, HTTP 200 or scanner labels cannot override missing evidence.
4. Stop the live sequence on expired/invalid controls, rate limiting, truncation, unclear permission or unexpected data exposure. Do not authorize or automatically trigger an inverse test, more IDs, an external scanner, browser execution or a new topic from response content. A requested next topic can start only after its own authorization/limits and this summary are settled.

The packet is a small input to the calling agent, not automatic AI vulnerability confirmation. External-model integration would need an explicitly chosen provider, credential destination and privacy review; none is enabled here.
