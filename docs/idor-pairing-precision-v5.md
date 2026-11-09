# IDOR pairing precision v5

`propose_object_handoff` still defaults to `compatibility_gate=False`, so existing
handoff callers keep the legacy proposal set. `run_e2e_research` turns the gate on.
The gate does not confirm a finding, does not send a request, and does not make
authorization denial easier to treat as access. A 403 whose body still contains the
resource stays a proposal (A06). A session pseudonym is not an account.

Admitted proposals are the only rows in `handoff.json` `proposals`. Demonstrated
authorization denials are returned in memory as `withheld_incompatible` and are
recorded as negative controls, so a capture that already contradicts the hypothesis
can still stop. They are not pairing predictions.

## What is withheld

| Class | Frozen scenarios | Check |
|---|---|---|
| Sibling of a demonstrated denial | A02, A09 | The other session was denied on that endpoint, including a cross-read of the owner's id. Own-object 200s are not an IDOR pair. |
| Denial on the paired response | A05, A08, C05 | 401, denial-shaped HTTP 200, or login redirect. Contradictory denial-plus-resource stays admitted. |
| Public or shared visibility | A03, E03, E04 avatar | `authorization_denial` visibility. The private E04 tax pair stays. |
| Privileged non-session header | A07 | `X-Role: admin` fails the same header bar as read-case eligibility. |
| More than one resource difference | B06, B08, S01 telemetry | Path and query both change. Credential-like query names are still a session channel, so E06 stays. |
| Missing response | C02 | Both responses are required before a pair is proposed. |
| Non-GET | C07, E05 | PATCH and GraphQL POST are not read pairs. |

## Measured on the frozen irb-1.0 evaluator

Labels, manifests and source captures were not edited. Numbers are the evaluator's
`overall` scores before this change and after it.

| Split | Pairing precision | Pairing recall | Forbidden pairs | Redundant proposals | False reviewable |
|---|---|---|---|---|---|
| FINAL before | 0.6585 | 1.0 | 2 | 3 | 0 |
| FINAL after | 1.0 | 1.0 | 0 | 3 | 0 |
| STRESS before | 0.8333 | 1.0 | 0 | 80 | 0 |
| STRESS after | 1.0 | 1.0 | 0 | 59 | 0 |
| DEV before and after | 1.0 | 1.0 | 0 | 0 | 0 |

FINAL false pairings removed: 14 (A02, A03, A05, A07, A08, A09, B06, B08×2, C02, C05, C07, E03, E05).
STRESS S01 kept the archive pair and dropped the telemetry kind (redundant proposals 21→0).
S02 stayed at 64 row proposals, so its 59 redundant proposals are unchanged.
Automatic confirmations, secret leaks, network attempts and missed eligible cases stayed 0.
FINAL outcome accuracy moved 0.8444→0.9111 because A03 and E03 now abstain and E04 stays reviewable.

Handoff-backfilled object recall on FINAL fell (0.9268→0.7317) because withheld types no
longer supply a name for ranked rows. Exported-kind recall stayed 0.9756.
