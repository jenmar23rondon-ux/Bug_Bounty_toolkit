# IDOR Handoff → Case Conversion Reliability (`adv-handoff-case-1.0`)

Measurement lab for **offline conversion** of object-handoff owner/actor pairs into
`discover-idor` human-review case proposals. Ground truth is **conversion eligibility
class**, not confirmed vulnerabilities.

## Corpora

| Corpus | Role | Origin |
|---|---|---|
| `frozen/` (`adv-handoff-case-1.0`) | FINAL evaluation only — never tune on it | `http://127.0.0.1:8141/hc` |
| `dev/` (`adv-handoff-case-dev`) | DEV fixtures / unit tests only | `http://127.0.0.1:8142/hd` (+ alt `:8143`) |

Both are synthetic, loopback-only, hash-pinned in `MANIFEST.sha256`, and were committed
**before** the case-reliability classification / evaluator provenance fix. Historical
`adv-1.0` / `adv-1.1` ground truths are never edited by this lab.

## Conversion classes

`structural_valid` · `case_eligible` · `needs_more_evidence` · `security_rejected` · `technical_error`

Stable codes include `CASE_ELIGIBLE`, `REJECT_MULTI_RESOURCE_DIFF`, `REJECT_NON_GET`,
`REJECT_SESSION_ONLY`, `NEEDS_RESPONSE`, `NEEDS_SECOND_SESSION`,
`REJECT_ORIGIN_MISMATCH_SIDES`, `TECH_ORIGIN_OVERRIDE`.

## Run

```bash
python labs/idor_handoff_case_eval/build_corpus.py all   # must stay byte-identical
python labs/idor_handoff_case_eval/evaluate.py --corpus adv-handoff-case-1.0
```

Also re-measure historical corpora via `labs/adversarial_idor_eval/evaluate.py`
(`adv-1.0` / `adv-1.1`) — evaluator must use each corpus’s recorded origin, never a
hardcoded port. Network is hard-blocked. Proposals remain `needs_review`; nothing is
auto-approved or executed.
