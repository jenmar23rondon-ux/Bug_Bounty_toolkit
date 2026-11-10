# IDOR/BOLA object recall recovery

`propose_object_handoff` still withholds incompatible pairs when
`compatibility_gate=True`. Those withheld rows are not proposals, so they no
longer supply a kind for handoff-backfilled object recall. This recovery names
the object from its own capture evidence and does not put the pair back.

`recovered_objects` is not a proposal, does not confirm a finding, and does not
send a request. Admitted proposals keep priority when both name the same object
ref. Version stays 0.2.2.

## Why FINAL recall was 0.7317

Handoff-backfilled recall reads `resource_type` on the ranked row, then a kind
carried by an admitted proposal for that `object_ref`. After PR #108 the gate
removed the proposal, and the ranked row's open-vocabulary kind was ignored by
that backfill. Exported-kind recall stayed 0.9756 because the ranking row already
had the kind. Before the gate, recall was 0.9268 (38/41). The three that were
already missed had no admitted proposal even with the gate off.

| Id | Gold object | Why it was dropped | Evidence that names it now |
|---|---|---|---|
| A02 | payslip | Sibling denial and the 403 cross-read are withheld | Route `/payslips/{id}` and the `payslip` container |
| A05 | contract | Denial-shaped HTTP 200 withheld both proposals | Route `/contracts/{id}` and the `contract` container |
| A07 | profile | `X-Role: admin` withheld the pair | Route `/profiles/{id}` |
| A08 | ledger | 401 withheld both proposals | Route `/ledgers/{id}` |
| A09 | prescription | Sibling 404 and that denial are withheld | Route `/prescriptions/{id}` |
| B06 | wallet | Path and query both change, so the pair is request-incompatible | Route, `wallet_id`, and the `wallet` container |
| B08 | card | Account id and card id both change, so the pair is withheld | Route `/cards/{id}` and the `card` container. The account parent is not linked to the card |
| C02 | permit | No response, so no pair. Raw HTTP is stored as `https`, so the kind did not match the lab's `http` origin | Route `/permits/{id}`. The scorer resolves label nouns on both schemes of the frozen hosts |
| C04 | refund | Owner response is missing, so there was never a pair | Route `/refunds/{id}` on the capture that remains |
| C05 | quote | Login redirect withheld both proposals | Route `/quotes/{id}` |
| C06 | policy | The two captures are different origins, so there is no pair | Each origin's route `/policies/{id}`. The two objects are not linked |

DEV D03 (`voucher`, missing response) was the same gap and is named the same way.

## What is not linked

- A value with no kind (bare `id`, generic containers such as `data`).
- The same value on two origins.
- A path parent and the nested path child in that request, including when the raw values collide.

Same-origin echoes of one value and one kind may be linked (path id and response id). Different payslip ids are not.

## What stayed put

Frozen labels, captures, and `MANIFEST.sha256` were not edited. The confirmation
bar was not lowered. FINAL redundant proposals stay 1 (C08's path pair and
response-body pair). STRESS and DEV redundant proposals stay 0. Correct outcomes
stay 41/45, 6/6, and 6/6. Pairing precision and recall stay 1.0. Forbidden pairs,
false reviewable cases, automatic confirmations, and network attempts stay 0.

`implementation_sha256` and `evaluator_sha256` changed because the recovery code
and the lab origin map changed. That is a source binding, not a corpus change.

## Limitations

- B08 recalls `card`, but the shared account parent still ranks first
  (`wrong_object_top1` 2 → 3). The multi-resource pair stays withheld.
- Raw HTTP still defaults to `https`. C02 is recognized because the scorer maps
  both schemes. The parser default was not changed.
- Recovery does not merge object identities and does not turn a named object
  into an IDOR proposal.
- Strict `resource_type` recall is unchanged (0.122 on FINAL). Open-vocabulary
  nouns stay keyed; only known collections export a plain `resource_type`.
