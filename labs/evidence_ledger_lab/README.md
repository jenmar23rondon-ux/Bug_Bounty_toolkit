# Evidence ledger lab (synthetic, offline)

Run: `bbtk lab evidence-ledger [--metrics-json out.json]`

Each scenario builds a throwaway program directory in a temp folder (real
`RecordStore`, `EvidenceGraphStore` tables and `InvestigationMemory` entry),
writes synthetic evidence JSON, mutates a known-good ledger in one way, and
checks that `validate_ledger` reports the expected issue codes. Scenarios live
in `bugbounty_toolkit/analysis/evidence_ledger_lab.py` (`SCENARIOS`).

No network requests, no targets, no test execution. Metrics measure ledger
integrity checks, not vulnerability detection.
