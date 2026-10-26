# IDOR/BOLA End-to-End Research Quality (`idor-e2e-research-1.0`)

Independent synthetic lab for the **full offline research contract**:

capture → import → object discovery → ranking → object handoff → **real eligibility codes**
→ IDOR proposal → control review → evidence → Evidence Ledger → report.

PR #34 eligibility (`handoff_case_eligibility`) is on main and is used here — it is **not** a
pending contract. Historical corpora (`adv-1.0`, `adv-1.1`, `adv-ranking-*`,
`adv-handoff-case-*`, `e2e-contract-1.0`) are left intact; this lab does not retarget their metrics.

## Scenarios (frozen)

| ID | Tag | Focus |
|---|---|---|
| R01 | read-idor | Eligible GET read pair |
| R02 | access-denied | Actor 403; never auto-confirm |
| R03 | public-resource | Session-only public URL |
| R04 | multi-diff | `REJECT_MULTI_RESOURCE_DIFF` |
| R05 | insufficient-session | Same session, two ids |
| R06 | different-roles | Non-session header diff |
| R07 | shared-legit | Shared object id |
| R08 | ids-namespaces | Same numeric id, different nouns |
| R09 | arrays-nested | Nested JSON / arrays |
| R10 | incomplete-responses | `NEEDS_RESPONSE` |
| R11 | inconsistent-origin | Fail closed; no origin rewrite |
| R12 | discarded-candidate | Unauthenticated noise |
| R13 | fp-http-200 | 200 ≠ ownership |
| R14 | altered-evidence | Integrity / resume |
| R15 | expired-token | Synthetic expiry marker |

Origin: `http://127.0.0.1:8155` (alt `:8156` for R11). Loopback-only. No real secrets.

## Run

```bash
python labs/idor_e2e_research/build_corpus.py frozen   # must stay byte-identical
python labs/idor_e2e_research/evaluate.py --json labs/idor_e2e_research/results/metrics.json
python -m unittest tests.test_idor_e2e_research -v
```

Network is hard-blocked. Proposals remain `needs_review` / ledger `requires_validation`;
nothing is auto-approved, access-checked, or confirmed.
