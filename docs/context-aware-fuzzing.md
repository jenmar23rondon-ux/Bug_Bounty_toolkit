# Context-aware discovery planning

`bbtk fuzz-plan` turns a **local** HAR capture plus **registered local wordlists** into a bounded discovery plan. It improves the existing investigation flow; it does not replace `bbtk fuzz` or `ffuf_runner`.

## What already existed

| Piece | Role reused by the planner |
|---|---|
| `analysis/har_import.py` | Partial-recovery HAR parsing (from resilient HAR import) |
| `fuzzing/wordlist_manager.py` | Local SecLists/Assetnote/fuzzdb/custom registry, category classify/recommend/prepare |
| `fuzzing/ffuf_runner.py` | Scope-checked, capped, confirmed execution (unchanged) |
| `fuzzing/results_parser.py` | Baseline classification and authorization follow-ups |
| `analysis/object_relationships.py` / handoff | Structural object candidates; associations never confirm ownership |
| Evidence Graph + Investigation Memory | Plan snapshots and later fuzz evidence import |

## What was missing

Capture context (API prefixes, params, technologies) was not connected to wordlist recommendation or FUZZ URL construction. Operators selected lists manually or via category-only `wordlists recommend`.

## Command

```bash
bbtk wordlists register context-lab labs/context_fuzz_lab/wordlists
bbtk fuzz-plan my-program --har captures.har --dry-run
bbtk fuzz-plan my-program --har captures.har --category api --max-tests 40 --dry-run
bbtk fuzz-plan my-program --har captures.har --output plan.json
```

Planning:

- Queries **local** collections only (never downloads wordlists).
- Sends **zero** network requests (socket-blocked in tests).
- Does **not** start ffuf.
- Redacts tokens/cookies/secrets from the plan JSON.
- Validates every generated URL template against program scope when scope is configured.
- Drops password/credential and SQLi/XSS lists from generic discovery.
- Deduplicates recommendation paths and applies `--max-tests` / `--max-targets` budgets.

Execution of an approved target **reuses** the existing gate:

```bash
bbtk fuzz my-program \
  --url "http://127.0.0.1:8191/api/v1/FUZZ" \
  --wordlist /path/to/api-endpoints.txt \
  --max-tests 40 --dry-run
# after review:
bbtk fuzz my-program --url "..." --wordlist "..." --max-tests 40 --confirm
```

There is no alternate execution path that skips authorization or `--confirm`.

## Object Discovery association

Optional `--object-candidates` (and `--object-key`) attaches structural path matches from Object Discovery. Associations stay `confirmed=false` and never copy raw resource identifiers into ownership claims.

## Lab

See [labs/context_fuzz_lab](../labs/context_fuzz_lab/README.md) for a loopback API, synthetic HAR, tiny wordlist collection and ground truth used by the unit/integration tests.

## Security defaults

- Offline by default; zero network during planning.
- No automatic execution, redirects, recursion or retries.
- In-scope hosts only; stop on HTTP 429 at execution time (existing ffuf runner).
- No ID enumeration; no auto-confirmed findings.
- Execution tests only against synthetic loopback labs.
