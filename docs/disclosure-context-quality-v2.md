# Disclosure context quality v2

`bugbounty_toolkit/analysis/disclosure_context.py`
(`disclosure-context-quality-v2`) scores **already stored** HTTP responses.
It reuses `assess_disclosure` for sensitive-shape detection and, when the
record includes an `access_case`, `correlate_disclosure_access` for access
context. Session observations, when present, go through
`classify_session_controls`. There is no second IDOR engine, no network I/O,
and no credential validation.

```bash
bbtk analyze disclosure-context --input private/responses.json [--output summary.json]
```

## Exposure dimensions (every candidate)

| Dimension | Question |
|---|---|
| `sensitive_shape` | `none`, `secret`, `sensitive_context`, `public_material`, or `suppressed_only` |
| `content_origin` | Where the text appears to come from (server body, comment, docs, echo, example, …) |
| `observed_audience` | Who received the stored response |
| `intended_audience` | Who the evidence says should have received it, or `unknown` |
| `access_auth_state` | Public / owner / cross-actor, plus correlation or session classification when supplied |
| `integrity` | `valid`, `truncated`, `invalid_evidence`, or `integrity_blocked` |
| `completeness` | `complete`, `partial`, or `missing` |
| `confidence_basis` | Deterministic rule ids for the decision |
| `human_verification_required` | True for `reviewable` and `inconclusive` |

## Dispositions

All of them keep `finding_confirmed: false`.

| Disposition | Meaning |
|---|---|
| `reviewable` | Evidence says this data should not have been available to that audience. A human still has to review it. |
| `inconclusive` | An indicator or a partial context exists, but audience mismatch is not shown. |
| `not_a_disclosure` | Hard negative or no active sensitive indicator. |
| `invalid_evidence` | The stored response cannot be decoded or has no status. |

`high_confidence` is true only for a reviewable strong secret shape (private
key, env secret, vendor or JWT or server-field canary, sensitive JSON field,
embedded URL password, or government-id / payment-id style PII) with a public
audience, or a cross-actor audience whose correlation state is
`ready_for_manual_review`. Stack traces and debug banners can be reviewable
at medium confidence. They are not high confidence.

Hard negatives (public docs, public certificates, own-user profile fields,
request echoes, author-intended public HTML comments, version banners,
example credentials) are never high confidence.

Optional record fields:

- `access_case`: the disclosure↔access correlation case schema
- `session_observations`: already-redacted rows for `classify_session_controls`

v1 states are still produced by `assess_disclosure` and are not retuned.
The historical F16 label stays `indicator_detected`. See
`docs/disclosure-context-v2-audit.md`.

Lab: `labs/disclosure_context_v2_eval/`.
