# Offline information disclosure indicators

`bugbounty_toolkit/analysis/information_disclosure.py` (`information-disclosure-v1`)
scans **already stored** HTTP responses for sensitive-information indicators. It sends
no requests, calls no AI provider, and never sets `finding_confirmed` to anything but
`false`.

```bash
bbtk analyze disclosure --input private/responses.json [--output summary.json]
```

Input: `{"responses": [record, ...]}` (or a list / single record). A record:

```json
{"id": "r1", "url": "https://target/api/x", "audience": "public|authenticated_self|cross_actor|unknown",
 "request": {"body": "...", "query": "..."},
 "response": {"status": 200, "headers": {"Content-Type": "application/json"}, "body": "...", "truncated": false}}
```

Bodies with `Content-Encoding: gzip|deflate` are expected base64-encoded; any other
encoding is `invalid_evidence`.

## Three separate questions

| Dimension | Decided here? |
|---|---|
| Secret/sensitive **shape** detected | Yes, heuristic indicator only. Validity/activity is never asserted |
| **Audience exposure** (who got the response) | Taken from the record's `audience` |
| **Unauthorized access** | Never. `access_control_validation_required` hands it to manual authz validation |

## Categories

`credentials`, `token`, `private_key`, `env_vars`, `internal_config`, `stack_trace`,
`pii`, `private_file_ref`, `debug_info`.

**Not findings by default:** `Server`/`X-Powered-By` headers, public versions, support
emails, generic paths, placeholders (`YOUR_API_KEY_HERE`, `changeme`, `<token>`,
`xxxx`), documentation pages/examples, public certificates/keys, `password` fields
holding validation text, values reflected from the request.

## States (all `finding_confirmed: false`)

| State | Meaning |
|---|---|
| `not_observed` | No unsuppressed indicator |
| `indicator_detected` | Indicator present; context (audience/status/completeness) insufficient to prioritize |
| `insufficient_context` | Truncated/partial body without indicators — abstain |
| `access_control_validation_required` | Sensitive indicator in a response to another actor |
| `public_or_intended_information` | Public key material, docs, or the owner's own non-secret data |
| `invalid_evidence` | Missing status/body, unsupported or undecodable encoding |
| `ready_for_manual_review` | Secret-shaped indicator in a complete 200 response to a public audience |

## Data minimization

- Output carries only category, rule, location (JSON path), value length and a salted
  12-hex fingerprint — never the value, an excerpt, or the body. `suppressed`
  indicators carry a reason.
- The body's SHA-256 (`body_sha256`, via `core.redaction.provenance_digest`) preserves
  provenance; the original stays in your private storage.
- Shape rules reuse `core.redaction` (`JWT_TOKEN`, `SENSITIVE_KEY`,
  `provenance_digest`) rather than duplicating its secret redactor. Redaction answers
  "what to hide before sharing"; this module answers "what may be exposed, to whom".
- Body text, including prompt-injection attempts, is inert data.

Lab: `labs/information_disclosure_eval/` (DEV + frozen FINAL, see its README).
