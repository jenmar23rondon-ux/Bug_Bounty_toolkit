# Disclosure ↔ access correlation

`bugbounty_toolkit/analysis/disclosure_access_correlation.py`
(`disclosure-access-correlation-v1`) correlates **already stored** Information
Disclosure indicators with IDOR/access evidence for one resource.

```bash
bbtk analyze disclosure-access --input private/correlation-cases.json [--output summary.json]
```

## Required evidence (all offline)

| Side | Meaning |
|---|---|
| Actor A (owner) | Declared auth context + capture showing private marker on the resource |
| Actor B (second) | Declared distinct account + capture when B requests the object |
| Cross | B→A-object response that may carry the private marker / disclosure indicator |

Declared `auth_context` with `attested: true` and distinct `account_ref` values is
mandatory. Integrity must be `valid` on every side; `altered`, `expired`,
`missing_ref`, `out_of_program` / cross-program, or `incomplete_capture` yields
`integrity_blocked`.

## Visibility

`resource.visibility_declared` ∈ {`private`, `shared`, `public`}. Public and
legitimately shared resources are never treated as unauthorized exposure.

## States (all `finding_confirmed: false`)

`insufficient_evidence` · `auth_context_undeclared` · `integrity_blocked` ·
`public_resource` · `shared_resource` · `denied_correctly` ·
`reflected_or_example` · `fake_or_invalid_credential_shape` · `contradiction` ·
`correlation_candidate` · `ready_for_manual_review` · `invalid_evidence`

`ready_for_manual_review` means A shows a private marker, the cross capture shows
the same marker fingerprint, and disclosure indicators are present — **not** that
a vulnerability is confirmed.

## Minimization

- Private markers and secret values never appear in output (salted 12-hex
  fingerprints only).
- Reuses `assess_disclosure`, `correlate_resources`, and `provenance_digest`.
- No network I/O; no AI; no ledger mutation.

Lab: `labs/disclosure_access_correlation_eval/` (DEV + frozen FINAL).
