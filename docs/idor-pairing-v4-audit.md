# IDOR/BOLA pairing precision v4 — audit (FASE 1)

Read-only. No code in the modules below was changed for this note. Line numbers refer to
`origin/main` `bbd0068f90b0f411360519434008ccdcfcbaaae0`. Frozen IRB FINAL 45 reference
(unchanged labels): pairing precision **0.65**, recall **0.963** (26 TP, 14 FP, 1 FN).
Those 14 false types are the historical false pairs this mission has to stop admitting
without rewriting the labels.

`finding_confirmed` is not set by any of these pairing paths. Nothing here sends HTTP.

## Where pairs are created

| Module | Pair creation | Signals actually used | Identity assumed without proof |
|---|---|---|---|
| `object_handoff` | `_build_proposals` (`object_handoff.py:512-641`) and `_asymmetric_proposals` (`object_handoff.py:401-509`) | Same `kind_ref`, same identifier position or same origin, distinct `session_ref`, distinct `object_ref`, endpoint template | Same kind + two sessions is treated as an owner/actor pair. Account, response access, visibility, integrity, time and batch are not required. `insufficient_evidence` is hard-coded `False` (`object_handoff.py:609`). |
| `object_relationships` | No owner/actor pair. `object_candidates` (`object_relationships.py:794-987`) ranks objects. `_identity_namespace` (`object_relationships.py:401-414`) only *splits* equal raw ids when kinds differ. | Locations, typed fields, path parent/leaf, session count, kind refs | `ownership` stays `unknown`, but a single kind ref is still enough for a peer signal (`object_relationships.py:879-886`). |
| `resource_kind_lineage` | `correlate_resources` (`resource_kind_lineage.py:115-172`) relates two already-built sides. `check_kind_coherence` (`resource_kind_lineage.py:43-107`) only *reports* `handoff_cross_kind_pair`. | Kind status, `namespace_key`, attested account refs, visibility, body digest | It does **not** gate `propose_object_handoff`. Unknown kind becomes `unknown` (good) but denial, id-echo, time, integrity and batch never enter. |
| `actor_provenance` | `associate_actors` (`actor_provenance.py:128-240`) builds a sidecar. It does not emit IDOR pairs. | Human account alias + distinct-account list. Session HMAC is not an account (`actor_provenance.py:172-173`, `identity_basis`). | Callers that skip the manifest still pair on cookies. `classify_session_controls` (`actor_provenance.py:278`) keeps `identity_unproven` when no human account exists; handoff does not read it. |
| `handoff_case_eligibility` | `classify_capture_pair` (`handoff_case_eligibility.py:178-305`) labels one materialized pair. | Method GET, one structural diff, same origin, both response files present, session header diff | Both responses present ⇒ `CASE_ELIGIBLE` (`handoff_case_eligibility.py:296-304`) with **no** read of the body. Denial, public ACL, id-echo and kind are invisible here. |
| `authorization_denial` | `assess_pair_authorization` (`authorization_denial.py:566`) classifies an existing pair. It does not create one. | Status, denial tokens, visibility, id-echo (`authorization_denial.py:311-351`, `353-381`) | A clean denial is not access. Handoff never calls this before appending a proposal, so denied pairs still count as pairing types. |
| `evidence_engine` | No pairing. `EvidenceRecord` (`evidence_engine.py:77-95`) stores fingerprints and provenance. | Host, endpoint, method, session fingerprint, resource fingerprint | `resource_path_segments` (`evidence_engine.py:174`) is a hint. It does not decide that two captures are the same object. |
| `semantic_response_diff` | No pairing. `diff_responses` (`semantic_response_diff.py:768`) compares two stored bodies. | Status, content type, JSON/HTML structure, volatile rules (`semantic_response_diff.py:734-765`) | Key order and spacing are not authorization. The diff can still *look* like a conflict if a caller treats raw text inequality as contradictory evidence. Pairing does not consult it. |

## IRB FINAL 45 false pairs, by originating module

Scoring is type-level (`labs/independent_research_eval/metrics.py:51-62`): any proposed
type outside `ideal_pair_types` is an FP. Legacy handoff proposed these types anyway.

| Scenario | Proposed type | Why it is a false pair | Module that admitted it |
|---|---|---|---|
| A02 idor-absent-denied | `payslip` | Actor cross-read is HTTP 403. Own-id rows still share a kind and two sessions. | `object_handoff._build_proposals` (no denial check). Eligibility later sees the pair; pairing metric uses the proposal. |
| A03 public-resource-id | `catalog` | Body `visibility: public`. | Handoff ignores visibility. `correlate_resources` would say `legitimate_shared` but is not on the proposal path. |
| A05 denied-http-200 | `contract` | Actor body is `not_authorized` with HTTP 200. | Handoff ignores body. `authorization_denial` would be `denial_in_200`. |
| A07 authorized-admin-role | `profile` | Extra `X-Role: admin`, not a second account. | Handoff treats the role header as just another session-shaped capture. Eligibility returns `REJECT_HEADER_DIFF`; the proposal still exists. |
| A08 insufficient-permission | `ledger` | Actor HTTP 401. | Same as A02: kind + two sessions. |
| A09 negative-control-correct | `prescription` | Same id from the actor is HTTP 404. | Handoff still pairs the two own-id rows. |
| B06 duplicate-fields | `wallet` | Same id in path, query and body. | Handoff pairs on kind. Eligibility `REJECT_MULTI_RESOURCE_DIFF` does not remove the proposal. |
| B08 parent-frequency-trap | `account`, `card` | Parent account id is the frequent object; card parents differ (`/accounts/75700` vs `/accounts/75701`). | Handoff pairs each kind across sessions. `forbidden` does not include `account` or `card`; ideal pairs are empty (`abstain`). |
| C02 raw-http | open kind ref | No response bytes. | Handoff emits a request-side pair (`insufficient_evidence: False`). Eligibility is `NEEDS_RESPONSE` only afterwards. |
| C05 redirect | `quote` | Actor 302 to login. | Handoff does not read `Location`. |
| C07 write-method | `address` | PATCH, not a read pair. | Handoff has no method gate. Eligibility `REJECT_NON_GET` is later. |
| E03 misleading-labels | `category` | `visibility: public` plus a field named `private_owner_id`. | Handoff trusts the kind token, not visibility. |
| E05 unseen-shape-graphql | open kind ref | POST GraphQL. | Same missing method gate as C07. |
| E01 heavy-noise | *(none)* | FN, not FP. Import raises `entries_over_limit` (`object_relationships.py` capture cap). | Whole-capture failure, not an over-pair. |

B03 (`/teams/900` vs `/projects/900`) is already dropped (0 proposals). Kind split in
`_identity_namespace` works for that shape. The remaining false pairs are same-kind
comparisons that are not evidence of one resource: denial, public/shared, missing
body, non-GET, duplicate slots, and parent/leaf mixes.

## Failure modes the v4 gate has to cover

1. Same digits, different kind or namespace, must not match (`/users/42` vs `/orders/42`).
2. Canonical JSON equality must not be reported as a conflict.
3. Declared route aliases (`/api/v1/orders/7` vs `/orders/7`) are one endpoint.
4. Same attested account in two sessions is not a second actor (`actor_provenance` already says this; handoff does not).
5. Public/shared ACL is not an IDOR candidate (`correlate_resources` / `authorization_denial` already know; handoff does not).
6. Missing response artifact is insufficient, not a pair (eligibility knows; handoff still proposes).
7. HTTP 200 denial body is not access.
8. Id echo is not a resource (`authorization_denial._id_echo_only`).
9. Disjoint temporal windows and stale artifacts are not current evidence.
10. Unknown or multi-kind objects stay unproven (`check_kind_coherence` `handoff_ambiguous_side`).
11. Declared integrity hash mismatch is a conflict, not a pair.
12. Different program or origin is not one resource (eligibility flags origin; handoff pairs inside one endpoint ref only, so mixed files often yield nothing — C06 — but a caller can still submit the two sides).
13. A partial overlap inside an object array is not the resource id.
14. Two batches without declared continuity are insufficient.
15. One side a clean denial and the other private access of the **same** id is conflicting evidence, not a compatible pair.

## What v4 will not do

- It will not change `propose_object_handoff` or Evidence Ledger schemas or historical ledger states.
- It will not edit IRB / v3 labels or `MANIFEST.sha256` files.
- It will not auto-confirm. `finding_confirmed` stays false.
- Distinct-instance handoff (owner `/receipts/40101` vs actor `/receipts/40102`) is what IRB calls an ideal *type*. That is not proof the captures refer to the same resource. The new API abstains unless the canonical identity matches. Applying it on top of IRB 45 will drop those type-level true positives. That recall gap is real and has to be reported; it is not a reason to relabel IRB 45 or to flip the legacy default.
