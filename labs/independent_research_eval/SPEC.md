# irb-1.0 — Independent behavioural specification

Labels in `*/ground_truth.json` encode what an **ideal, conservative offline researcher**
should conclude from the captures alone. They were written from this specification and
the scenario descriptions, *before* running bbtk on FINAL, and are never derived from bbtk
output or from any model. bbtk's internal rule names (eligibility codes, ranking weights,
kind heuristics) were deliberately not used to decide labels; the planner step vocabulary is
only used to express *which output would be acceptable*.

## Outcomes (`ideal_outcome`)

| Outcome | Meaning (independent of bbtk) |
|---|---|
| `reviewable` | Two distinct sessions each read a private object of the same type through an endpoint that differs only in the object id → a human-review case should be opened (never confirmed). |
| `stop` | The capture *already* contains evidence against the hypothesis (correct 401/403/404 for the cross-account read, a denial body with 200, a redirect to login, a write-only method, a contradicting stored control). |
| `abstain` | Not enough information for a case: public/shared resources, same token on both sides, same id in different namespaces, authorized privileged role, ambiguous duplicates of the id. |
| `technical_error` | Input broken or incomplete (missing responses, raw requests without responses, mixed origins, all entries damaged). |
| `integrity_block` | Stored evidence altered, deleted, expired or referenced but not recorded. |
| `duplicate` | A second ledger candidate for the same issue. |

`ideal_reviewable` ⇔ `ideal_outcome == reviewable`. `vulnerability_truth` records the
synthetic app's ground truth where the scenario defines it (`unknown` otherwise); it is
**not** used to demand detection — captures never prove access control.

## Other labels

* `target_types` — the object type(s) a researcher should rank first (empty = no target).
* `ideal_pair_types` / `forbidden_pair_types` — owner/actor pair types that should / must not be proposed.
* `acceptable_first_steps` — planner step types acceptable as the top-ranked next step (`none` = empty plan acceptable).
* `expected_missing_controls` — human controls still missing for reviewable cases (default: distinct accounts, ownership, negative control).
* `canaries` — fake secrets that must never appear in shareable artifacts.
* `max_reasonable_proposals` — bound above which proposals are counted as redundant work.

## Families

A access control (10) · B object relations (9) · C HTTP captures HAR/Burp/raw (11) ·
D investigation state via post-pipeline ledger mutation (8) · E adversarial (7). DEV has 6
harness scenarios; STRESS has 6 robustness scenarios. Mutations (D) are applied by the
evaluator to the ledger/evidence the real pipeline produced, simulating later edits.

## Independence from historical corpora

New origin (`127.0.0.1:8177/8178`), new prefix `/ib`, new token prefix `ib30`, new resource
nouns and id ranges (40101–85002). The evaluator re-checks overlap against every historical
lab capture at run time and reports it.
