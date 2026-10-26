# Object Discovery Ranking Evaluation (`adv-ranking-1.0`)

Measurement lab for **human-review prioritization** of offline object-discovery
candidates. Ground truth is **review relevance**, not confirmed vulnerabilities.

## Corpora

| Corpus | Role | Origin |
|---|---|---|
| `frozen/` (`adv-ranking-1.0`) | FINAL evaluation only — never tune on it | `http://127.0.0.1:8139/rk` |
| `dev/` (`adv-ranking-dev`) | Tuning / development only | `http://127.0.0.1:8140/rd` |

Both are synthetic, loopback-only, hash-pinned in `MANIFEST.sha256`, and were
committed **before** ranking v2.0 rules. Historical `adv-1.0` / `adv-1.1` ground
truths are never edited by this lab.

## Scenarios (eval)

Shared frequent parents vs rare private children, multi-role, ID collisions across
kinds, UUID+numeric, nested/arrays, relations, partial/duplicate captures,
ambiguous fields, public vs protected, misleading shared resources, unknown
endpoint nouns, cross-reference listings.

## Run

```bash
python -m labs.object_ranking_eval.evaluate --corpus adv-ranking-1.0
python -m labs.object_ranking_eval.build_corpus all   # must stay byte-identical
```

Network is hard-blocked. Candidates remain review leads — never auto-confirmed.
