# Evidence privacy and redaction

bbtk classifies outputs by **destination** and applies different redaction policies:

| Destination | Intent |
|---|---|
| `private_evidence` | Authorized local validation may retain session markers and local paths. Treat these files as secrets. |
| `minimized_artifact` | Default structured redaction for offline bundles (legacy `redact_*` behaviour plus secret-shape scrubbing). |
| `console_summary` | Aggressive scrubbing; local paths removed. |
| `shareable_report` | Zero synthetic canaries from the laboratory set; reports use this policy. |
| `model_input` | Same aggressive policy before any local-model prompt text. |

## Structured parsing

JSON objects/arrays, HTTP request/response messages, URLs/query strings, headers, and HTML inputs are handled with field-aware rules when possible. Regex remains a backstop for free-form text (JWT compact form, Bearer tokens, known API key prefixes, `BBTK-CANARY-…` markers). **Do not rely on regex alone** for nested secrets — prefer structured destinations via `redact_data(..., destination=…)` or `redact_for`.

## Bounds and performance

- Default character bound: 2 000 000
- Default nesting depth: 64
- Default wall-clock budget per `redact_for` call: 2 s
- Large keyword-bearing bodies no longer trigger quadratic `[\w-]*token` scans (word-boundary lookbehind).
- Unterminated HTML `<input` runs are matched with a bounded character class to stay linear.

Exceeding bounds yields explicit truncation metadata (`detect_truncation`, `RedactionResult.truncated`) rather than silent partial secrets.

## Provenance and pseudonyms

`provenance_digest` stores SHA-256 only. `pseudonymize_identifier` yields stable `bbtk-id-…` values distinct from originals. Shareable views keep digest fields and strip or basename local paths.

## AI outputs

`scrub_model_output` re-applies the `model_input` policy so model text cannot reintroduce known secret shapes into shareable surfaces. Callers must still avoid concatenating raw private fields into prompts or reports.

## Laboratory

```bash
PYTHONPATH=. python labs/evidence_redaction_lab/evaluate.py
```

Acceptance for the lab set: **zero canaries** in shareable / console / model outputs; private artifacts remain usable for authorized validation; no network.

## Unrecognized formats and residual risks

This system **does not claim absolute privacy**. Unrecognized or residual cases include:

- protobuf / msgpack / cbor and other binary bodies
- novel API key formats without known prefixes
- secrets split or encoded across fields
- images/PDFs with embedded credentials
- WebSocket / HTTP/2 binary headers
- adversarial reassembly if private and shareable fragments are merged by a caller

Keep `registros/` and `inputs/*/private/` local. Inspect evidence before sharing.
