# Resource Kind Lineage Evaluation (`rkl-1.0`)

Offline lab measuring whether resource type / namespace is preserved from capture through
Object Discovery, ranking and Object Handoff (`resource-kind-lineage-v1`).

Kinds are structural inferences only. Ownership, privacy and authorization are **never**
claimed from a kind. The open vocabulary already integrated by P1 is reused; no closed list
of resource nouns is introduced.

## Corpus (`corpus/`)

| ID | Tag | What it checks |
|---|---|---|
| K01 | users-vs-orders-same-id | `/users/7` vs `/orders/7` stay distinct |
| K02 | identical-id-different-collections | tickets vs claims with id 42 |
| K03 | uuid-different-namespace | same UUID under dossiers vs shipments |
| K04 | singular-plural | invoices ↔ invoice |
| K05 | unconventional-noun | open-vocabulary `crates` |
| K06 | nested-resources | `/users/1/orders/7` |
| K07 | arrays | `tickets[*].id` |
| K08 | schema-change-same-kind | `/orders` vs `/v2/orders` |
| K09 | unknown-generic-id | bare `?id=` → unknown |
| K10 | bare-id-field | top-level `{id}` → unknown |
| K11 | foreign-id-fields | `order_id` + `user_id` same value |
| K12 | out-of-order-captures | session order does not change kinds |
| K13 | contradictory-kind-evidence | `ticket_id` + `claim_id` same value → ambiguous |

All captures are loopback-only (`http://127.0.0.1:8191/rk/...`). Network is hard-blocked
during evaluation. Nothing is confirmed or executed.

## Run

```bash
python labs/resource_kind_lineage_eval/build_corpus.py --check
python -m labs.resource_kind_lineage_eval.evaluate
python -m pytest tests/test_resource_kind_lineage.py -q
```

## Metrics

- Kind accuracy / recall by scenario tag
- Kind preservation rate (graph ↔ ranking ↔ handoff)
- Cross-kind collisions and false namespace unions (target: **0**)
- Ownership claims from kind (target: **0**)
- Correct abstentions on unknown / ambiguous evidence
- Handoff coherence rate
- Effects on IRB Precision@1 are reported alongside the independent-research lab
  (`precision_at_1_exported_kind` vs legacy `precision_at_1_strict_resource_type`)
