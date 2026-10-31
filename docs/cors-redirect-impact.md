# CORS / open-redirect impact (offline)

`analysis/cors_redirect_impact.py` and `bbtk analyze cors-redirect-impact` assess
**impact** of CORS and open-redirect signals already present in a local HAR or
capture JSON. They do not replace `cors-check` / `open-redirect` (presence +
candidate-vs-confirmed bar). Every item is a **CANDIDATE**;
`finding_confirmed` stays false. No HTTP requests are sent. Version stays 0.2.2.

## Usage

```bash
bbtk analyze cors-redirect-impact \
  --input path/to/capture.har \
  --output reports/cors-redirect-impact.json \
  --markdown reports/cors-redirect-impact.md
```

## CORS impact classes

| Impact | Meaning |
| --- | --- |
| `exploitable-credentialed-read` | Reflected arbitrary / `null` origin **with** `ACAC: true` (browsers allow credentialed cross-origin reads). Body sensitivity uses the disclosure classifiers when present. |
| `info-only` | Reflection without ACAC, or wildcard ACAO with a sensitive-looking body (browsers block credentials with `*`). |
| `not-exploitable` | No attacker-origin reflection, or wildcard without a sensitive body. |

Confirmation still requires an independent browser credentialed-read proof in scope.

## Open-redirect chainability

Flags redirect-like parameters (`redirect_uri`, `return_to`, `next`, `callback`, …)
on OAuth/SSO/login-like paths or alongside OAuth query params (`client_id`,
`response_type`, …). Emits a **candidate chain description** toward code/token
theft. Manual in-scope OAuth testing is required to confirm.

## Safety contract

- Offline only (`requests_sent` is always false)
- `finding_confirmed` stays false
- Secrets and cookies are redacted; disclosure scan fingerprints only
- Synthetic fixtures under `tests/fixtures/cors_redirect_impact.har`
