# Independent Adversarial IDOR/BOLA Evaluation (corpus `adv-1.0`)

Measurement-only lab. **No detection rule is changed by this lab or the PR that adds it.**
Synthetic, loopback-only (`http://127.0.0.1:8137/adv/…`), offline, no secrets, no HTTP
validation, no auto-approve. Candidates and proposals are **not** confirmed findings.

Pipeline under test:

```
HAR → object_candidates (discovery) → propose_object_handoff (pairing)
    → discover_idor (IDOR case proposal, needs_review) → [human approve-idor + authorized access-check: NOT run]
```

## Independence and freezing

- Separate from `labs/object_discovery_lab/{dev,eval}`: different origin/port, no shared URL
  (test-enforced), and **resource nouns deliberately outside** the pipeline's built-in
  19-noun vocabulary (`order`, `invoice`, `project`, …) used by the existing splits.
- Authored from the scenario spec in `build_corpus.py` and committed (`frozen/`, hash-pinned in
  `MANIFEST.sha256`) **before the pipeline was ever run on it** (commit order on the branch shows
  this). Regeneration is byte-identical (test-enforced).
- `adv-1.0` has now been observed. It must not be used to tune rules; a future improvement
  must be validated on a newly authored frozen corpus (`adv-1.1`) as well.

## Ground truth (24 scenarios, 48 exchanges, 11 positive / 9 negative / 4 ambiguous)

Unit of truth = (scenario, object kind). "Must pair" = an owner/actor review proposal across two
distinct sessions for that kind is correct. "Must NOT pair" = any proposal is an error.
"Ambiguous" = a human must decide; excluded from precision/recall, reported as review load.
"Designed server truth" is informational: no offline stage can confirm it.

| ID | Class | Tag | Scenario | Must pair | Must NOT pair | Ambiguous (human) | Designed server truth |
|---|---|---|---|---|---|---|---|
| S01 | positive | uuid | UUID path ids, two sessions, distinct objects | receipt | — | — | vulnerable |
| S02 | positive | nested-objects | Child object under per-session parent | board, workspace | — | — | vulnerable |
| S03 | positive | arrays | Array of ids in JSON request body | shipment | — | — | vulnerable |
| S04 | positive | cross-reference | Id observed in session A listing response, requested by B | ticket | — | — | vulnerable |
| S05 | positive | multi-session | Three sessions on the same template | statement | — | — | vulnerable |
| S06 | positive | hierarchical-permissions | Manager and report both reach employee records; manager access is LEGITIMATE (hierarchy) | employee | department | — | protected-by-hierarchy |
| S07 | positive | uuid | UUID in query parameter | export | — | — | vulnerable |
| S08 | positive | nested-objects | Deeply nested typed id in JSON request body | preference | — | — | protected |
| S09 | positive | multi-session | Cookie-based sessions instead of bearer tokens | payslip | — | — | vulnerable |
| S10 | positive | shared-ids | Shared parent org, distinct child pipelines | pipeline | org | — | vulnerable |
| S11 | positive | cross-reference | Nested response object id vs query parameter in another session | subscription | — | — | vulnerable |
| S12 | negative | shared-ids | Same object id requested by both sessions (shared resource) | — | channel | — | n/a |
| S13 | negative | public-objects | Public catalogue, no credentials | — | article | — | n/a |
| S14 | negative | multi-session | Single session reads two own objects | — | coupon | — | n/a |
| S15 | negative | partial-responses | Truncated JSON responses only; ids never in requests | — | contract | — | n/a |
| S16 | negative | incomplete-captures | Second capture missing credentials and response | — | license | — | n/a |
| S17 | negative | public-objects | Pagination/limit numbers differ across sessions (not object ids) | — | report, page, limit | — | n/a |
| S18 | negative | partial-responses | Response echoes own id only; request has no id | — | locker | — | n/a |
| S19 | negative | public-objects | Public object accessed with and without auth, same id | — | banner | — | n/a |
| S20 | negative | incomplete-captures | Only one session captured at all for a resource | — | voucher | — | n/a |
| S21 | ambiguous | ambiguous | Opaque generic `ref` parameter, unclear if object id | — | — | ref, lookup | n/a |
| S22 | ambiguous | hierarchical-permissions | Admin vs member reading member records; policy unknown | — | — | member | unknown |
| S23 | ambiguous | shared-ids | Ids overlap partially in arrays across sessions | — | — | folder | n/a |
| S24 | ambiguous | cross-reference | Bare `id` in response vs typed id in other session path | — | — | message | n/a |

## Methodology

- `evaluate.py` imports the pipeline unchanged and scores each stage separately.
- **Importer bounds:** the HAR importer accepts ≤32 entries/file and rejects a *whole file* if any
  entry lacks a response or has unparsable JSON. The frozen HAR (48 entries) is therefore
  (a) probed as-is (rejected, recorded), and (b) deterministically sharded into 2 files of ≤25
  entries for the primary run, excluding only the 3 entries the importer cannot accept
  (S15 ×2 truncated JSON, S16b no response). These are measured as fail-closed probes.
- **Object typing for scoring:** the pipeline exports every out-of-vocabulary object as
  `resource_type: "unknown"`. To score independently of that, the evaluator resolves each
  object's captured location (path position / JSON or query pointer; keyed name hashes are
  inverted with the synthetic eval key) to the collection/field it came from. A pairing proposal
  is TP only if owner and actor are the **same kind**, in the same scenario, in distinct sessions.
- Precision excludes ambiguous proposals; precision@k counts ambiguous as non-relevant.
  95% CIs are Wilson intervals. Network is hard-blocked (socket connect/DNS raise) for the run.

## Results (measured, `results/*.json`)

| Stage | Metric | v0.2.1 | PR #26 (`4e59994`) | main after #27 (`47c8a30`) |
|---|---|---|---|---|
| Discovery | recall (12 expected kinds) | 1.00 [0.76–1.00] | 1.00 | 1.00 |
| Discovery | P@1 / P@3 / P@5 / P@10 | 0 / 0 / 0.2 / 0.4 | same | same |
| Discovery | negative kinds surfaced as candidates | 9 | 9 | 9 |
| Pairing | proposals | n/a | 23 | 23 |
| Pairing | TP / FP / ambiguous | n/a | 13 / 6 / 4 | 13 / 6 / 4 |
| Pairing | precision (excl. ambiguous) | n/a | 0.684 [0.46–0.85] | 0.684 [0.46–0.85] |
| Pairing | P@1 / P@3 / P@5 / P@10 | n/a | 1.0 / 0.67 / 0.6 / 0.5 | same |
| Pairing | recall (10/12 kinds) | n/a | 0.833 [0.55–0.95] | 0.833 [0.55–0.95] |
| Pairing | FN | n/a | S04 ticket, S11 subscription | same |
| Pairing | forbidden-kind proposals (shared/public/single-session/pagination) | n/a | 0 | 0 |
| Review | proposals requiring manual review | n/a | 100% | 100% |
| Review | proposals that are not TP (wasted review) | n/a | 43.5% (10/23) | 43.5% |
| Case | TP pairs yielding an `idor-case-proposal` candidate | n/a | 8/13 = 0.62 [0.36–0.82] | same |
| Case | non-TP pairs yielding a case candidate | n/a | 5 | 5 |
| Confirmation | confirmed by pipeline | 0 | 0 | 0 (not measurable offline, by design) |
| Safety | network connect attempts | 0 | 0 | 0 |

Every bounds probe failed closed: 49-entry HAR, 33 entries, 17 files (> `MAX_FILES`), truncated
HAR, one entry without response, one truncated-JSON response. Two runs are byte-identical.

## Error-cause matrix

| Cause | Stage | Scenarios | Errors | Effect |
|---|---|---|---|---|
| C1 closed resource vocabulary: unseen nouns collapse to `unknown`, so pairing ignores *which* id position is compared | Pairing | S02, S06, S10 | 6 FP (type-mismatch: shared `org` ↔ `pipeline`, `department` ↔ `employee`, `workspace` ↔ `board`) | 100% of FPs |
| C1b asymmetric `response-identifier-v1` requires a known resource_type (`excluded_untyped_resource: 8`) | Pairing | S04, S11 | 2 FN | 100% of FNs; #27 gives 0 gain here |
| C2 discovery score rewards shared parents (`multiple_session_contexts` + nested path) | Discovery ranking | S10, S06, S23 | top-3 = org(neg), department(neg), folder(amb) | P@1 = P@3 = 0 |
| C3 whole-file fail-closed on one bad entry / >32 entries | Import | S15, S16 | 3 entries unusable; real Burp exports usually need splitting | safe, but loses all evidence in that file |
| C4 `discover_idor` cannot build cases from JSON-body ids or multi-id paths | Case | S03, S08 (session_only), S02 (unsupported) | 5/13 TP pairs give no case | case yield 0.62 |
| C5 duplicate/permuted proposals for the same pair | Review | S02, S05, S06, S23 | 23 proposals for 10 TP kinds | review load |
| Ambiguous correctly left to humans | Pairing | S22 member, S23 folder proposed; S21, S24 not | 4 ambiguous proposals | expected review |

## Comparison and statistical caution

- PR #26 vs main-after-#27: **identical** on every stage here (Δ = 0). #27's asymmetric
  pairing helped only in-vocabulary on the old eval split (2/2 response scenarios, Wilson
  [0.34–1.00]) — that gain is **statistically inconclusive** and did not transfer.
- Old eval split reports recall 6/6 (Wilson [0.61–1.00]); here 10/12 ([0.55–0.95]). The
  intervals overlap, so the apparent drop is also not conclusive from recall alone; the
  type-mismatch FPs (6/19 scored proposals) are the clearer signal.
- v0.2.1 has no pairing stage; discovery is unchanged across all three versions.
- n = 24 scenarios / 12 positive kinds: any single-scenario change moves recall by ±8 pts.

## Limitations

- Synthetic corpus written by one author; designed "server truth" is never executed.
- Evaluator-side typing uses the synthetic key to invert name hashes (eval-only).
- Shards are needed because of the importer cap; cross-file session linking was exercised.
- Confirmation stage is intentionally not measured (requires human-gated authorized tests).

## Run

```bash
PYTHONPATH=. python labs/adversarial_idor_eval/evaluate.py --json /tmp/adv.json
python -m unittest tests.test_adversarial_idor_eval -v
# previous versions (read-only worktree): git worktree add /tmp/wt v0.2.1 && PYTHONPATH=/tmp/wt python labs/adversarial_idor_eval/evaluate.py
```

## Recommended next improvement (SPEC only, not implemented)

See `NEXT_IMPROVEMENT_SPEC.md` — position-qualified object kinds for out-of-vocabulary identifiers.
