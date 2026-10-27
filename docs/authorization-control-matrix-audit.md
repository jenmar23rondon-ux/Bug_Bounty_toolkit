# Authorization control matrix — audit (FASE 1)

Read-only audit of the controls that already exist before this brief. No module listed
here is modified by the matrix. The matrix emits an opt-in annotation
(`bbtk.authorization-control-matrix-annotation/1`) that existing consumers can ignore.

Base verified: `origin/main` = `bbd0068f90b0f411360519434008ccdcfcbaaae0`. Version `0.2.2`.

## What is required vs optional today

### `analysis/actor_provenance.classify_session_controls`

Required on each observation: `session_ref` (else an anonymous bucket), `label`,
`account_attested`, `target_label`, `access_proof` from `authorization_denial.assess_response`.
Order is list order, treated as capture order.

Session class is inferred only from own-object proofs plus the human attestation flag.
Cookies are not an input. `expiry_proven` is hard-coded false. A dependent request for
the owner's object is `inconclusive` when it lands before the first owner
`private_resource_200` or after the first later owner auth failure.

Not represented: the seven-cell matrix, a public/shared cell, a negative-control cell,
a subsequent owner recheck, deleted resources, token rotation versus identity, or
timestamp reliability. There is no token field, so this function cannot (and does not)
treat a different token as a different identity.

### `analysis/access_assessment`

BOLA path requires `accounts_authorized is True`, every check pointer, `resource_private
is True`, `expected_cross_access == "deny"`, native `type=access-control` / `mode=read`
evidence, `controls_valid is True`, and both `owner_control` and `actor_control` steps
with `application_success`, `resource_match` and `private_match` true. The crossed step
`cross_read` is required before any access or denial classification. Anything missing
returns `insufficient_evidence` with `confirmed: false`. Status codes are not read
(`status_code_used: false`).

Optional in the sense that the function accepts partial JSON, but every missing
predicate is fail-closed. There is no session-continuity timeline and no 401/redirect
classifier here. A 401 cannot be called expiration because status is ignored.

### `analysis/authorization_denial`

A pair is two raw responses. Owner `http_401` or `login_redirect` forces outcome
`inconclusive` and reason `owner_control_broken`. `owner_control_state` maps one such
response to `broken` and documents that this is not proven expiry. Actor
`id_echo_without_resource` is `inconclusive`. Public/shared visibility is
`inconclusive` with `public_or_shared_resource`. Actor denial plus an owner
positive-looking response is `cross_account_denied` and writes
`bbtk-control-annotation/1` with `role=negative_control`.

That pair decision does **not** require a second-actor own-resource capture, an
anonymous cell, or a capture-order proof. A missing second-actor control can still
become `cross_account_denied` at this layer. This brief does not change that function.
The matrix's own disposition stays `blocked` / `inconclusive` when a mandatory cell is
missing, and it never sets a negative finding. Consumers opt in.

### `access_control/comparison`

Required case fields: `owner_request`, `actor_request`, `base_url`, `session_headers`,
`resource`, `checks`, `accounts_authorized`, `resource_private`, `expected_cross_access`.
Optional: `identity_check`, `additional_accounts`, persistence/cleanup blocks,
`expected_anonymous`. `load_owner_get` requires the captured session headers to match
that account's captured context. It does not infer expiry from a later 401. This
module executes authorized comparisons; the matrix does not call it and does not take
its place.

### `authorization_workbench`

Columns A and B are required together. C is optional and is never synthesized, including
for anonymous. A saved per-capture assessment is shown, not recomputed. HTTP status,
including 401/403/404 and 200, does not become `denied_saved` unless that capture's
saved assessment already says `denied`. The payload says HTTP 200 and body differences
do not establish unauthorized access, and `finding_confirmed` is false. No session-expiry
or identity inference.

### `analysis/semantic_response_diff`

Compares two stored responses. Denial labels stay with `authorization_denial.assess_response`.
Header names such as `session` and `expires` are volatility hints for the diff, not a
decision that a session expired or that an identity changed. Ranking is untouched.

## Where 401s and redirects are misread

| Location | What it does with an isolated 401 / login redirect | Gap |
| --- | --- | --- |
| `classify_session_controls` | One trailing 401 after success becomes `identity_unproven` plus `isolated_401_not_expiry`, not expiry. Two trailing auth failures, or a login redirect after success, become `possibly_expired_session` with `expiry_proven` false. The same single trailing 401 also drops `owner_control_valid`. | Correct that it is not expiry. Over-blocks a session that still has an earlier positive control. Cannot see token rotation, deleted resources, or timestamp order. |
| `owner_control_state` / pair assessment | One owner 401 or login redirect on that pair is `broken` and the pair is `inconclusive`. Comment states this is not proven expiry. | Pair scope cannot tell an isolated 401 from a repeated one, and does not look at a later owner recheck. |
| `access_assessment` | Status is unused. | Safe against status-to-expiry, and also blind to it. Predicate writers upstream could still collapse a 401 into `application_success: false`. |
| Workbench | Status is not denial. | No continuity timeline at all. |
| `semantic_response_diff` | `expires` is a volatile header name. | Must not be read as session expiry. This audit records that it is not. |

No audited module treats a different token as a different identity. None of them states
the negative rule either, so a later consumer could invent it. The matrix states the
rule: a different token is not a different identity without provenance proof, and it
does not create actors.

## Baseline

Full `python3 -m unittest discover -s tests -q` on this base after
`pip install -e ".[dashboard,xss,sqli,jwt,http,dev]"`: **1176 tests, 103.5s, 1 error,
4 skipped**. The error is pre-existing and out of scope:
`test_offline_lab.SuiteRunnerExclusionTests.test_excluded_tests_are_reported_as_skips_not_dropped`
(`unittest` discovery on a temp directory that is not a package under Python 3.12).
It does not involve authorization comparison. An earlier run before those extras
installed also failed CSRF HTML tests (`bs4` missing) and Ruff discovery; those cleared
once the documented extras were installed.
