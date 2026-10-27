# IDOR/BOLA pairing audit (v4, read-only)

Audit of owner↔actor pair creation on `bbd0068f90b0f411360519434008ccdcfcbaaae0` before any
compatibility-evaluator change. No code in this note is a behavior change. IRB FINAL 45 labels
were not edited. Frozen pairing reference from
`labs/independent_research_eval/results/final_metrics.json`: **precision 0.65, recall 0.963**
(tp 26, fp 14, fn 1, forbidden hits 2).

Pairing precision counts **handoff proposal resource types**, not the later authorization
outcome. A proposal that authorization later refuses is still a predicted pair.

## Where pairs are created

| Module | Pair creation | Signals used | Identity assumed without proof |
|---|---|---|---|
| `object_relationships` | `build_object_graph` (`object_relationships.py:453`) links objects to `SessionContext` nodes. `object_candidates` (`object_relationships.py:795`) scores `cross_session_kind_peers` (+20, line 101) and `multiple_session_contexts_leaf` (+15). | Path/query/JSON locations, kind ref, session HMAC, origin. Parent paths are demoted (`shared_path_parent_across_sessions`, line 108) but not removed. | `account_identity` is hardcoded `"unknown"` (`object_relationships.py:580`) while the session edge is still enough for a peer score. A session fingerprint is not an account. |
| `object_handoff` | `_build_proposals` (`object_handoff.py:512`) emits a pair when two sides share `kind_ref` and identifier position, differ in `session_ref`, and differ in `object_ref` (lines 538–552). | Kind, position, session ref, object ref, endpoint template. Score is an integer priority (`object_handoff.py:564`), not a probability. | Distinct session refs are treated as two parties (`basis` `same_endpoint_template_distinct_sessions`, line 585) with `ownership: unknown`. No account attestation is required. Same-object exchanges are skipped (line 552), so a negative control that re-reads the owner's id never becomes a proposal. |
| `resource_kind_lineage` | `correlate_resources` (`resource_kind_lineage.py:115`) can say `different_kind`, `same_object`, `legitimate_shared`, or `idor_review_signal`. `check_kind_coherence` (`resource_kind_lineage.py:43`) flags cross-kind handoff pairs. | Kind status, namespace key, attested account refs, visibility, body digest. | Not on the default proposal path. Handoff never calls it, so same-kind over-pairing is not blocked here. Cookies/sessions alone do not prove distinct accounts (lines 145–153) — but that rule is unused at pair emission. |
| `actor_provenance` | `associate_actors` (`actor_provenance.py:128`) is an opt-in sidecar. `classify_session_controls` (`actor_provenance.py:278`) refuses to infer identity from cookies. | Human manifest selectors, opaque session refs, access-proof labels. | Not consulted by `propose_object_handoff`. Unattested sessions stay `identity_unproven`. |
| `handoff_case_eligibility` | `classify_capture_pair` (`handoff_case_eligibility.py:178`) labels an already materialized pair. | Method, origin, session header, response presence. | Runs **after** proposals exist. `REJECT_NON_GET` / `NEEDS_RESPONSE` do not remove the proposal type from the pairing metric. |
| `authorization_denial` | `assess_response` (`authorization_denial.py:353`) and `assess_pair_authorization` (`authorization_denial.py:566`). | Status, denial tokens, visibility, id-echo, login redirect. | `idor_e2e_research.py:445` assesses materialized proposals only. It can suppress `requires_validation`, but the IRB scorer still reads `handoff.json` proposal types (`labs/independent_research_eval/evaluate.py:321`). A 403 on the owner's id is often the same object and was never proposed (`object_handoff.py:552`), so it never suppresses the sibling cross-id pair. |
| `evidence_engine` | `correlate_evidence` (`evidence_engine.py:1112`) groups captures by host, method, endpoint template, and parameter names. `import_evidence` (`evidence_engine.py:1191`) packages records. | Endpoint template, session fingerprint, parameter names. | Groups are descriptive. They do not decide resource identity, and they do not drop a handoff pair. |
| `semantic_response_diff` | `diff_responses` (`semantic_response_diff.py:768`) compares two stored responses. | Canonical JSON structure, headers, volatile fields. | Not imported by `object_handoff`. Key-order differences never reach pairing, and real body conflicts never block a proposal either. |

`object_handoff.py` does not import `authorization_denial`, `actor_provenance`, `semantic_response_diff`, or `correlate_resources`.

## IRB FINAL 45 false pairs (labels frozen)

Predicted type is outside `ideal_pair_types`. Source: committed `final_metrics.json` on this base.

| Id | Predicted | Why it is a false pair | Module that emits it | Signal ignored |
|---|---|---|---|---|
| A02 | payslip | Actor's read of the owner's id is HTTP 403. The scored pair is the two successful own-object reads. | `object_handoff._build_proposals` | Denial exchange dropped as same `object_ref` (line 552); denial classifier never sees it. |
| A03 | catalog | Body `visibility: public`. | `object_handoff` | `authorization_denial` public class; `correlate_resources` `legitimate_shared`. |
| A05 | contract | Actor HTTP 200 body is `not_authorized`. | `object_handoff` | `denial_in_200` (`authorization_denial.py:450`). |
| A07 | profile | Actor request carries `X-Role: admin`. | `object_handoff` | Role header is not an account proof; `actor_provenance` not applied. |
| A08 | ledger | Actor HTTP 401. | `object_handoff` | `http_401`. |
| A09 | prescription | Actor HTTP 404 on the owner's id, plus two own-object 200s. | `object_handoff` | Negative control not attached to the sibling pair. |
| B06 | wallet | Same id repeated in path, query, and body. Label withholds `ideal_pair_types` (abstain). | `object_handoff` | Duplicate locations still one kind and one position, so a pair is emitted. Suspected label tension: structurally a private cross-session read. **Not edited.** |
| B08 | account, card | Parent account is frequent; child card is a private cross-session read. Label abstains (no ideal pair). | `object_handoff` plus ranking demotion only | Frequency penalty does not delete the handoff row. Card remains a suspected label tension. **Not edited.** |
| C02 | keyed kind | Raw requests, no response bodies. | `object_handoff` | `NEEDS_RESPONSE` is an eligibility code after the proposal exists. |
| C05 | quote | Actor 302 to `/login`. | `object_handoff` | `login_redirect`. |
| C07 | address | PATCH only. | `object_handoff` | `REJECT_NON_GET` is post-proposal. |
| E03 | category | `visibility: public` plus a misleading `private_owner_id` field. | `object_handoff` | Visibility and field name are not kind proof. |
| E05 | keyed kind | GraphQL POST. | `object_handoff` | Non-GET still paired. |

False negatives: **E01** (heavy noise) produces no proposal because discovery limits drop the capture before pairing. That miss is not a compatibility bug inside `_build_proposals`; the exchanges never arrive.

Forbidden hits in the frozen score are A03 (`catalog`) and E03 (`category`), both public resources the handoff still proposes.

## Failure modes this v4 evaluator must not repeat

1. Same digits under different kinds (`/users/42` vs `/orders/42`) are not the same resource.
2. Session difference is not a second account.
3. Public/shared ACL is not an IDOR candidate.
4. Denial (401/403/404, denial-shaped HTTP 200, login redirect) is not access. A denial of the other side's id blocks the sibling pair.
5. Missing response, id-echo, ambiguous kind, stale time, or undeclared batch break is insufficient evidence, not a guess.
6. Integrity hash mismatch and denial-versus-access on the same id are conflicts, not a compatible pair.
7. JSON key order is not a conflict.
8. Declared route aliases may collapse `/api/v1/orders/7` and `/orders/7`. Undeclared prefix differences must not be invented into a match.
9. A partial overlap inside an array is not the resource.
10. Nothing in this path may set `finding_confirmed`.

Legacy `propose_object_handoff` behavior stays as documented above until a later gated change. v4 adds `evaluate_compatibility` and does not rewrite Evidence Ledger states.
