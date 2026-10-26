# SPEC (implemented in feature/open-vocab-resource-kind, see OPEN_VOCAB_KIND_RESULTS.md): position-qualified object kinds for out-of-vocabulary identifiers

**Motivation (from adv-1.0):** cause C1/C1b explains 6/6 pairing FPs and 2/2 pairing FNs.
Identifiers whose collection/field noun is outside the 19 built-in nouns are all exported as
`unknown`; handoff then pairs ids from different path positions / pointers of the same endpoint
(e.g. shared `org` id of A vs `pipeline` id of B), and the asymmetric response rule drops them.

## Proposed behaviour
1. Derive an internal *kind* for every identifier occurrence from its own evidence: the preceding
   collection path segment (singularized) or the typed field name (`*_id|_ids|_uuid`). Keep it
   keyed-hashed in exports (no new names leak); keep `resource_type: "unknown"` for display.
2. Handoff may pair owner/actor only when their kinds match **and** their field pointer templates
   (path position / JSON pointer) match. Never pair across positions.
3. `response-identifier-v1` accepts a derived kind as type evidence under the same existing guards
   (distinct sessions, same origin, single-session observation, ids differ). Bare `id` stays excluded.
4. No change to scoring weights, confirmation, gates, or network behaviour.

## Acceptance (measured, not tuned)
- adv-1.0: FP-type-mismatch 6 → 0; S04/S11 recovered; forbidden-kind proposals stay 0; ambiguous not reduced silently.
- A NEW frozen corpus `adv-1.1` authored before implementation must show the same direction.
- Existing dev/eval lab metrics and the full suite must not regress; determinism and 0 network preserved.

## Out of scope
Discovery ranking (C2), importer whole-file rejection (C3), `discover_idor` JSON-body support (C4).
