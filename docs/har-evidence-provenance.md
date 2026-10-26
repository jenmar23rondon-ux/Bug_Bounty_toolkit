# Structured HAR provenance in `bbtk evidence import`

`bbtk evidence import` now records, for every HAR input, a content-free account of what happened
to each original entry (`inputs[i].capture_import`) and a bundle-level `capture_origin` section.
There is still **one** HAR importer: per-entry decisions come from
`analysis/har_import.py` (`entry_reason`, `import_har`, `load_har_entries`), and records are still
decoded by `evidence_engine.har_entry_source`. `analysis/har_provenance.py` only accounts for
entries and validates that the account matches the produced records.

Processing is local only: no sockets, DNS, URL inputs or content execution.

## Audit: evidence import vs Object Discovery (before this change)

| Aspect | `evidence_engine._har` / `har_capture_sources` | `har_import.import_har` (Object Discovery) |
|---|---|---|
| File limit | 32 MiB | 32 MiB (`MAX_ITEM_BYTES`) |
| Entry limit | 10 000 (`MAX_RECORDS`), over → file error | 32 processed (`MAX_EXCHANGES`), 4096 hard; over → `entries_over_limit` unless `--allow-truncate` |
| Invalid entry | non-object / non-dict request or response silently skipped; **missing** request or response still produced a record (empty side) | isolated with an enumerated reason code |
| Duplicate JSON keys | last value wins silently | entry rejected `duplicate_json_keys`; container keys file-fatal |
| Exact duplicates | merged by semantic dedup, all locators kept; not counted | kept, counted in `duplicate_entries` |
| Locators | `/log/entries[<original index>]` | same |
| Summary | `records_parsed` only | `capture_import` (signed into the graph) |
| Message size | none below the file cap | 1 MB per message |

## Modes (`--har-mode`)

| Mode | Records produced | Use |
|---|---|---|
| `compat` (default) | **identical** to the historical importer (tested byte-for-byte with a fixed salt) | existing workflows; invalid entries are *reported*, and `emitted_as_record: true` flags legacy records the resilient validator would reject |
| `partial` | only entries accepted by `import_har`; rejected ones isolated | cleaner evidence; same codes as Object Discovery |
| `strict` | file rejected (`strict_entry_rejected`) on any invalid entry | fail-closed pipelines |

Limits in `partial`/`strict`: 32 MiB file, `max_entries = min(10 000, 4096)` (the importer's
existing hard memory ceiling), message cap = file cap. Object Discovery's 32-entry cap is **not**
applied to evidence import, so previously valid files keep working. No default limit was raised.
`compat` keeps the 10 000-entry limit; files with 4097–10 000 entries work in `compat` only.

## `capture_import` (schema `bbtk.har-capture-import/1`)

Counts: `entries_declared`, `entries_processed`, `entries_accepted`, `entries_rejected`,
`rejections_by_reason`, `rejected_entries[{index, reason, emitted_as_record}]`,
`duplicate_entries` (valid entries byte-identical to an earlier valid entry),
`omitted_by_limits` / `truncated` (always 0/false: evidence import never truncates; over-limit
stays file-fatal), `records_emitted`, `emitted_entry_indices`, `container_duplicate_keys`, `mode`,
`limits`.

Integrity: `source_sha256` (exact file bytes) and `entry_sha256[index]` (SHA-256 of the canonical
JSON of each emitted entry). They are reproducible only with the original file and contain no
capture content.

Separate concepts, never conflated:

* invalid entries → `rejected_entries`
* valid duplicates → `duplicate_entries`
* omitted by limits → `omitted_by_limits`
* accepted, then merged by semantic dedup → `capture_origin.records_merged_by_deduplication`
  (bundle-wide) vs `records_unique`. `entries_accepted` is **not** the number of unique evidence
  records.

## Validation

* `validate_capture_provenance(bundle)` checks count arithmetic, reason tallies, index ranges,
  `emitted_as_record` flags vs record locators, records per input, digest key sets, and the
  bundle `records_parsed` total. Any disagreement is an issue code (no paths or content).
* `verify_capture_sources(bundle, {source_path: Path})` recomputes the file and entry digests.
* `bbtk evidence correlate` includes `capture_provenance: {status, valid, issue_codes, capture_origin}`.

## Compatibility and migration

* Bundle `schema_version` stays `1.1`; the new keys are additive. No existing field changed meaning.
* Bundles without `capture_import` validate as `status: absent` and remain fully readable.
* Non-HAR inputs are unchanged and carry no `capture_import`.
* Evidence Ledger: unchanged schema; ledger evidence rows already reference `bundle_id` and the
  bundle file's SHA-256, which now covers `capture_origin`. Adding a dedicated ledger field is a
  follow-up (it would change the ledger's closed schema).

## Related fix

`core/redaction.redact_text` scanned keyword-free text with a quadratic regex; a 64 KiB HAR
body took ~17 s and a 2 MiB body did not finish in 700 s. An exact keyword pre-check
(the pattern cannot match without one of its literals) makes such bodies linear. Bodies that do
contain a keyword are still scanned by the original pattern (residual risk).
