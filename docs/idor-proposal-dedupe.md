# IDOR/BOLA equivalent-proposal dedupe

`propose_object_handoff` still ranks capture pairs and, when asked, withholds
incompatible ones before anything is collapsed. Collapse does not confirm a
finding, does not send a request, and does not put a withheld denial back into
`proposals`.

## Relationship key

One canonical proposal per:

- HTTP method
- route template with trailing slashes removed (`{id}` stays a placeholder)
- identifier location and position (path index, query pointer, request JSON, or response JSON)
- resource kind
- account pair (the two session refs, order ignored)

Concrete identifier values are not part of the key. These therefore collapse:

- distinct ids of that same parameter, including equivalent encodings
- query-parameter order
- a trailing slash on the same template
- repeated captures of the same pair

These do not collapse:

- a different route template or resource kind (a different object parameter)
- a different identifier location, such as the path parameter versus a response-body id
- a different account pair
- a different HTTP method

The surviving row is the first admitted proposal in the existing rank order.
`supporting_evidence` is the union of the folded pairs' object refs, sessions,
sources, and locators. `equivalent_proposal_count` is how many pairs were folded.
`confirmed` stays false.

## What remains redundant

On the frozen irb-1.0 benchmark, STRESS redundant proposals went from 59 to 0.
S02 was 64 proposals for one `GET` list route, one path parameter, one kind, and
one account pair; it is now one proposal.

FINAL redundant proposals went from 3 to 1. E02's second response-side direction
folded into the response relationship (3 proposals, cap 2 → 2 proposals, cap 2).
C08 still has two proposals against a cap of 1: the path/path pair and the
response/path pair. Those locations are different, so the cap still counts one
as redundant. `tests/test_idor_proposal_dedupe.py` covers that split.

Handoff-backfilled object recall stays 0.7317 on FINAL because the kind backfill
reads every object ref in `supporting_evidence`, not only the canonical pair.
Pairing precision and recall stay 1.0. Forbidden pairs stay 0. Correct outcomes
stay 41/45 on FINAL and 6/6 on DEV and STRESS.

FINAL `synthetic_manual_steps` moved 259 → 255 and `reference_correct_rate`
0.9583 → 0.9524 because family D plans cite fewer evidence rows after duplicate
candidates are removed. The invalid D13 reference is unchanged. DEV manual steps
moved 37 → 36. No confirmation bar was lowered.
