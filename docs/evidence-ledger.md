# Evidence verification & coverage ledger

An offline, file-based ledger for **human review** of candidates. It answers:
which surfaces were investigated / reviewed / pending / blocked / out of scope,
which candidates exist, which local evidence files (SHA-256 + provenance) back
each one, and what a human reviewer decided.

Concepts were studied from Cloudflare's `security-audit-skill` (coverage
ledger, distinct verdicts, independent record verification, zero-dependency
validators). Nothing was copied; there is no multi-agent platform and no AI
agent is needed for review.

## Files

- Ledger: `registros/<program>/ledger/evidence-ledger.json` (override with `--ledger`).
- Schema: `docs/schemas/evidence-ledger-v1.schema.json` (`bbtk ledger schema`), version `bbtk-evidence-ledger/1`.
- Validator: `bugbounty_toolkit/analysis/evidence_ledger.py` (zero extra dependencies).

## States

| state | meaning | requirements |
|---|---|---|
| `candidate` | raised, not yet reviewed | surface exists; missing evidence is a warning |
| `requires_validation` | plausible, unresolved | ≥1 evidence ref, ≥1 `blockers` entry naming the unresolved fact |
| `rejected` | disproved / not applicable | `rejection.reason` (enum) + `detail`; `duplicate` needs `duplicate_of` |
| `confirmed` | human-confirmed | reached only from `requires_validation`; human method (`human_manual`, `human_lab_reproduction`, `human_code_review`); reviewer ≠ `raised_by`; reviewer not a tool name; `--i-reviewed-the-evidence`; ≥1 current, digest-verified evidence file; no blockers; surface not pending/out-of-scope |

Allowed transitions: candidate→requires_validation|rejected; requires_validation→confirmed|rejected|candidate;
rejected→candidate; confirmed→requires_validation|rejected.

No code path sets `confirmed` automatically. `bbtk ledger import` maps tool labels
such as `confirmed`/`VULNERABLE` to a plain `candidate`.

## Integrity checks (`bbtk ledger validate`, exit 1 on errors)

Schema/enum/unknown-field errors; duplicate IDs; broken surface/evidence/duplicate refs;
broken Evidence Graph node refs and Investigation Memory IDs and finding IDs (checked
read-only against the program SQLite DB when present); unsafe evidence paths; missing or
modified evidence files (digest mismatch); evidence captured against an older surface
`fingerprint` (code change → stale; error for confirmed, warning otherwise); incompatible
states; duplicate active candidates (same `dedup_key`, default `surface|category`).
Every write command validates first and refuses to save an invalid ledger.

## Commands

```
bbtk ledger init P
bbtk ledger surface P --id s1 --kind endpoint --ref "GET /api/orders/{id}" --status investigated [--fingerprint rev]
bbtk ledger surface P --id s2 ... --status blocked --blocker "no second account"
bbtk ledger evidence P --id e1 --path evidence/x.json --tool access-check [--graph-node N] [--investigation-id I]
bbtk ledger candidate P --id c1 --surface s1 --category idor --raised-by alice --evidence e1
bbtk ledger import P --evidence-path evidence/native.json --surface s1
bbtk ledger review P --id c1 --state requires_validation --reviewer bob --blocker "replay with fresh owner"
bbtk ledger review P --id c1 --state confirmed --reviewer bob --method human_lab_reproduction --basis "..." --i-reviewed-the-evidence
bbtk ledger review P --id c2 --state rejected --reviewer bob --reason false_positive --detail "..."
bbtk ledger validate P
bbtk ledger report P [--output ledger.md]
bbtk lab evidence-ledger
```

`bbtk report P --format json` gains an `evidence_ledger` block (validity + coverage summary)
when a ledger exists; otherwise output is unchanged.

## Limitations

- Digest verification proves the file is unchanged, not that its content is truthful.
- Surface fingerprints are user-supplied (e.g. a git revision); the ledger does not compute them.
- Reviewer identity is a free-text label, not authenticated; independence is a name check.
- Duplicate detection is key-based (`dedup_key` or `surface|category`), not semantic.
- Graph/memory/finding refs are only checked when the program SQLite DB exists.
- Existing `findings` table and tool `classification` values are unchanged for compatibility.

## Related: next-step planner

After the ledger is populated, `bbtk investigation next-steps PROGRAM --dry-run`
reads it (without writing) and returns a versioned plan of human review steps for
missing controls. See [evidence-gap-planner.md](evidence-gap-planner.md).

## Related: semantic correlation

`python -m bugbounty_toolkit.analysis.candidate_similarity registros/<program>` reports
probable duplicates beyond exact keys, read-only. See [semantic-candidate-dedup.md](semantic-candidate-dedup.md).
