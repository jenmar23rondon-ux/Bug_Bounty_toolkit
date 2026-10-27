# Resource Kind Lineage (`resource-kind-lineage-v1`)

Preserves the inferred resource type / namespace of an object reference from capture
through Object Discovery, ranking and Object Handoff.

## What changed

1. **Stable identity namespace** — bare JSON `id` values typed by a collection container
   (`tickets[*].id`) are namespaced by their inferred kind, so equal raw IDs of different
   kinds never collapse into one object (`tickets[*].id=7` ≠ `claims[*].id=7`). Path and
   typed-field identities are unchanged (byte-compatible with prior graphs).
2. **Ranking export** — each candidate carries `resource_kind` (keyed id), `kind_lineage`
   (`status` ∈ {`explicit`, `derived`, `unknown`, `ambiguous`}, bases, evidence refs,
   namespace refs). Conflicting kinds yield `ambiguous` and suppress kind-peer signals.
3. **Coherence check** — `resource_kind_lineage.check_kind_coherence` validates that
   ranking and handoff kinds match graph facts (no silent renames, no invented kinds,
   no ownership claims).
4. **E2E report** — ranking rows expose `resource_kind` / `kind_status`; the report includes
   a `kind_coherence` block.

## Non-goals / limits

- A kind is a **structural inference**, never ownership, privacy or authorization.
- The open vocabulary from P1 is reused; no closed noun list is introduced.
- Authorization denial assessment (PR #52) is untouched.
- The parallel advanced identifier extractor and batch ingestion are untouched.
- Historical `resource_type` for known vocabulary is unchanged; open nouns still export
  `resource_type: unknown` (use `resource_kind` / `kind_lineage` instead).

## Lab

`labs/resource_kind_lineage_eval/` (`rkl-1.0`, origin `http://127.0.0.1:8191/rk`).
See its README for scenarios and how to reproduce metrics.
