# Authorization control matrix

Offline annotation for owner / second-actor / anonymous comparisons when the
captures already exist. It is not a scanner, it does not send HTTP, and it does
not change session identity. Ranking and pairing engines are not used.

```python
from bugbounty_toolkit.analysis.authorization_control_matrix import evaluate_control_matrix

matrix = evaluate_control_matrix(observations, comparison_scope="owner_second")
```

Schema `bbtk.authorization-control-matrix/1`. The `annotation` object uses
`bbtk.authorization-control-matrix-annotation/1` with `safe_to_ignore: true`.
Existing consumers that do not know the schema can skip it. `finding_confirmed`
and `negative_finding` are always false.

## Cells

| Cell | Required for `owner_second` |
| --- | --- |
| `owner_own_resource` | yes |
| `second_own_resource` | yes |
| `second_owner_resource` (cross-access) | yes |
| `anonymous` | only when `comparison_scope` is `owner_second_anonymous` |
| `public_shared_control` | no; a public or shared body explains the private cell instead of a missing-control code |
| `negative_control` | no |
| `owner_recheck` | no; a later owner capture counts only after the cross |

`second_account` and `actor` are accepted as aliases of the second-actor role and
emitted as `second`. No new actor is created.

A missing mandatory cell is `blocked`. That path never sets `denial_consistent`
or `negative_finding`.

## Reason codes

| Code | When | Existing alias |
| --- | --- | --- |
| `OWNER_CONTROL_MISSING` | No usable owner own-resource control | — |
| `ACTOR_CONTROL_MISSING` | No usable second-actor own-resource control | — |
| `CROSS_CAPTURE_MISSING` | No cross-access capture | — |
| `SESSION_POSSIBLY_EXPIRED` | Repeated 401 or a login redirect after a success | — |
| `PUBLIC_RESOURCE_CONTROL` | Public visibility | `public_or_shared_resource` |
| `SHARED_RESOURCE_CONTROL` | Shared visibility | `public_or_shared_resource` |
| `ID_ECHO_ONLY` | Body only echoes the identifier | `id_echo_without_resource`, `actor_id_echo_without_resource` |
| `OWNER_CONTROL_BROKEN` | Owner session is invalid (auth failure, no prior success) | `owner_control_broken` |
| `CAPTURE_ORDER_AMBIGUOUS` | Missing, duplicate, or timestamp-contradicted order, or a recheck that does not follow the cross | — |
| `COMPLETE_CONTROL_SET` | Every mandatory cell is usable and continuity holds | — |

`expiry_proven` is always false. One isolated 401 after a success keeps the
session `valid` and does not emit `SESSION_POSSIBLY_EXPIRED`. A different token
sets `rotated_token` and does not set `identity_changed` unless provenance says
the declared account changed. Token material is withheld unless it matches
`SYNTH_` / `CANARY_` and is not copied into the result.

## Lab

`labs/authorization_control_matrix_eval/` holds DEV and FINAL. FINAL is frozen
in `final/MANIFEST.sha256` before it is scored.

```bash
python -m labs.authorization_control_matrix_eval.evaluate --split dev
python -m labs.authorization_control_matrix_eval.evaluate --split final
```
