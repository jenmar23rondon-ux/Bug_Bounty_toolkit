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

## Multi-format captures (HAR, Burp XML, raw HTTP)

`--har` keeps its historical behaviour and output. `--capture` accepts any supported local capture:

```bash
bbtk fuzz-plan my-program --capture history.xml --dry-run                 # Burp XML (auto-detected)
bbtk fuzz-plan my-program --capture history.xml --format burp-xml --strict
bbtk fuzz-plan my-program --capture req.http --origin http://127.0.0.1:8191 --dry-run
bbtk fuzz-plan my-program --capture req.http --response resp.http --origin http://127.0.0.1:8191
```

Contract (`bugbounty_toolkit/fuzzing/capture_adapter.py`):

- Reuses existing parsers: HAR → `import_har`; Burp/raw → `parse_captured_exchanges` and
  `captured_response`. No new HTTP parser.
- `--format auto` detects from leading syntax; an explicit `--format` that disagrees fails with
  `format_mismatch`.
- Burp items are validated independently. In the default `partial` mode bad items are isolated with
  a stable reason code; `--strict` rejects the file. Globally malformed XML, DTD/entity
  declarations, and empty exports are file-fatal and never repaired.
- A request is only paired with the response of the same item, or with a `--response` file given
  explicitly for one raw request. Missing responses are never invented (`requests_without_response`).
- Raw HTTP has no scheme, so `--origin` is required; the Host header must agree (`host_inconsistent`).
- The 32-entry limit and `--allow-truncate` semantics are the same as for HAR.
- Non-HAR plans add `capture_import.provenance` (adapter version, SHA-256 of input files, item
  locators, paired/unpaired counts). Summaries never contain URLs, headers, cookies, or bodies.

File-fatal codes: `format_unknown`, `format_mismatch`, `not_utf8`, `nul_bytes`, `xml_dtd_or_entity`,
`xml_malformed`, `xml_no_items`, `entries_over_limit`, `no_valid_entries`, `strict_entry_rejected`,
`response_without_raw_request`, `raw_origin_required`.

Per-item codes: `item_messages_ambiguous`, `request_missing`, `request_base64_invalid`,
`response_base64_invalid`, `request_incomplete`, `request_line_invalid`, `request_headers_ambiguous`,
`host_inconsistent`, `origin_inconsistent`, `item_url_invalid`, `message_too_large`,
`response_incomplete`, `response_headers_ambiguous`, `response_encoding_unsupported`,
`response_length_mismatch`, `request_invalid`, `over_entry_limit`.

Parity fixtures (`labs/context_fuzz_lab/fixtures/capture.burp.xml`, `fixtures/raw/`) are generated
deterministically from `capture.har` by `make_capture_fixtures.py`; `multi_capture_benchmark.py`
reports before/after metrics offline. Planning stays separate from execution: run `bbtk fuzz`
with `--dry-run`/`--confirm` as before.
