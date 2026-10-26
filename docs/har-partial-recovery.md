# Resilient HAR import with partial recovery

`bbtk object-discover` (and every consumer of the same reader: `object-handoff`
materialization, `lab object-discover`, the adversarial evaluation harness) parses HAR files
with per-entry isolation. One malformed entry no longer discards every valid capture in the file.
Parsing is fully offline: no HTTP, DNS or socket use, and recovered entries never trigger any
network validation.

## Audit of consumers

| Consumer | Path | Behaviour now |
|---|---|---|
| `build_object_graph` / `object-discover` | `analysis/object_relationships._read_sources` | partial (default) or `--strict`; summary in `capture_import` |
| `indexed_capture_sources` / `object-handoff --materialize-dir` | same reader | re-reads in the mode recorded in the signed graph |
| `lab object-discover` | `build_object_graph` | clean synthetic corpus, identical results |
| `labs/adversarial_idor_eval/evaluate.py` | `build_object_graph` | bounds probes run `strict=True`; new `partial_recovery` section |
| `evidence_engine._har` (evidence import) | `har_capture_sources` | unchanged (already skipped non-object entries); shares `har_entry_source` |
| Burp XML / raw HTTP (`parse_captured_exchanges`) | `burp_import` | unchanged whole-file semantics; summary reports `format: burp`, `mode: strict` |

## Modes

| Option | Invalid entry | More than 32 entries |
|---|---|---|
| default (partial) | entry isolated with a reason code, rest processed | **file rejected** (`entries_over_limit`, unchanged) |
| `--strict` | **file rejected** (`strict_entry_rejected`) | file rejected |
| `--allow-truncate` | entry isolated | first 32 processed, the rest reported as `over_entry_limit`, `truncated: true` |

`--strict` and `--allow-truncate` are mutually exclusive.

Why partial is the default: an entry accepted in partial mode is exactly an entry the
previous importer accepted (each recovered entry also passes strict mode on its own; this is
tested), so no file that worked before changes output, and files that were rejected before now
yield their valid entries plus an explicit report. Why over-count stays fatal: silently analysing
a prefix could hide most of a capture, so truncation is opt-in and always flagged.

## Integrity rules

- A request is only decoded together with the `response` object of the **same** entry.
  Entries missing either side are rejected (`request_missing` / `response_missing`); neighbours
  are never combined. An entry with duplicate JSON keys (for example two `response` keys) is
  rejected as `duplicate_json_keys`; nothing is repaired or guessed.
- Order and original indices are preserved: locators stay `/log/entries[<original index>]`.
  Source commitments still hash the exact file bytes, so `--verify-input` keeps working.
- Duplicated entries are kept (as before) with their own locators and counted in
  `duplicate_entries`.
- The summary is part of the HMAC-signed graph (`capture_import`).
- Errors and summaries contain only counts, indices and enumerated codes; never headers, cookies,
  tokens, bodies, URLs or personal data.

## Limits

| Limit | Value | Scope |
|---|---|---|
| File size | 32 MiB (`MAX_ITEM_BYTES`) | file-fatal `file_too_large` |
| Declared entries | 4096 | file-fatal `entries_over_hard_limit` |
| Processed entries | 32 per file (`MAX_EXCHANGES`) | `entries_over_limit` / truncation |
| Document JSON depth | 256 (checked before decoding) | file-fatal `json_too_deep` |
| Entry JSON depth | 32 | `entry_too_deep` |
| Body JSON depth / structure | 16 levels, 4096 nodes, 128 fields | `body_json_too_deep` / `body_json_structure_limit` |
| Message body | 1 MB (`MAX_EXCHANGE_BYTES`) | `message_too_large` |
| Headers per message | 256 | `headers_limit` |
| Object references per message | 64 | `object_reference_limit` |
| Captures per run / total bytes | 256 / 64 MiB | file set fatal (unchanged) |

## Reason codes

File-fatal: `file_too_large`, `not_utf8`, `json_invalid`, `json_too_deep`,
`duplicate_json_keys`, `log_entries_missing`, `entries_empty`, `entries_over_hard_limit`,
`entries_over_limit`, `no_valid_entries`, `strict_entry_rejected`.

Per entry: `entry_not_object`, `duplicate_json_keys`, `entry_too_deep`, `request_missing`,
`response_missing`, `request_body_malformed`, `response_content_malformed`,
`unsupported_content_encoding`, `response_base64_invalid`, `method_invalid`, `url_invalid`,
`url_embedded_credentials`, `url_structural_limit`, `headers_limit`, `message_too_large`,
`body_json_too_deep`, `body_json_invalid`, `body_json_structure_limit`,
`object_reference_limit`, `over_entry_limit`.

## Summary shape

```json
"capture_import": {
  "mode": "partial", "truncate_allowed": false, "network_validation": "none",
  "entries_total": 5, "accepted": 4, "rejected": 1, "truncated": false, "duplicate_entries": 0,
  "reasons": {"entry_not_object": 1},
  "sources": [{"source_ref": "…", "format": "har", "mode": "partial", "entries_total": 5,
               "accepted": 4, "rejected": 1, "reasons": {"entry_not_object": 1},
               "rejected_entries": [{"index": 2, "reason": "entry_not_object"}],
               "truncated": false, "duplicate_entries": 0}]
}
```

The CLI prints the totals (without per-source rows) and a one-line notice when entries were isolated.

## Before / after on the synthetic fixtures (`examples/har-recovery`)

"Before" is main at d6b895b (after #29), "after" is this branch in the default mode.

| fixture | entries | before: accepted (observations) | after default: accepted (observations) | after: rejected | reason codes (per entry or file-fatal) |
|---|---|---|---|---|---|
| adversarial_mixing | 5 | 0 (0) | 1 (1) | 4 | duplicate_json_keys×1, request_missing×1, response_missing×2 |
| deep_json | 4 | 0 (0) | 2 (2) | 2 | body_json_too_deep×1, entry_too_deep×1 |
| duplicates | 4 | 4 (2) | 4 (2) | 0 | — |
| incomplete_requests | 6 | 0 (0) | 2 (2) | 4 | method_invalid×1, request_body_malformed×1, request_missing×1, url_invalid×1 |
| incomplete_responses | 7 | 0 (0) | 2 (2) | 5 | body_json_invalid×1, response_base64_invalid×1, response_content_malformed×1, response_missing×1, unsupported_content_encoding×1 |
| invalid_all_entries_bad | 3 | 0 (0) | 0 (0) | whole file | fatal: no_valid_entries |
| invalid_deep_document | 1 | 0 (0) | 0 (0) | whole file | fatal: json_too_deep |
| invalid_duplicate_log | 0 | 0 (0) | 0 (0) | whole file | fatal: duplicate_json_keys |
| invalid_empty_entries | 0 | 0 (0) | 0 (0) | whole file | fatal: entries_empty |
| invalid_no_entries | n/a | 0 (0) | 0 (0) | whole file | fatal: log_entries_missing |
| invalid_not_utf8 | n/a | 0 (0) | 0 (0) | whole file | fatal: not_utf8 |
| invalid_truncated_file | n/a | 0 (0) | 0 (0) | whole file | fatal: json_invalid |
| malformed_among_valid | 5 | 0 (0) | 4 (4) | 1 | entry_not_object×1 |
| over_count | 40 | 0 (0) | 0 (0) | whole file | fatal: entries_over_limit |
| synthetic_secrets | 4 | 0 (0) | 3 (3) | 1 | url_embedded_credentials×1 |
| valid | 5 | 5 (5) | 5 (5) | 0 | — |

`over_count` with `--allow-truncate`: 32 accepted (observations 32), 8 `over_entry_limit`, `truncated: true`.
With `--strict`, every fixture that has a rejected entry is rejected whole (`strict_entry_rejected`).

Valid entries recovered across the mixed fixtures: **9 before → 23 after** (+14). All 22 invalid
entries are isolated with a code, and the 8 globally invalid files stay rejected.

## Frozen adversarial corpora

Ground truth and manifests are untouched (SHA-256 manifests verify). Primary-run metrics for
adv-1.0 and adv-1.1 (discovery, pairing, case discovery) are identical. Bounds probes still fail
closed (they now run in strict mode, and their error text adds the reason code). A new
`partial_recovery` section imports **all** frozen entries in partial mode: adv-1.0 recovers 45/48
without the harness pre-filter; the 3 previously unreadable entries (29, 30, 32) stay
isolated as `body_json_invalid` ×2 and `response_missing` ×1. They are genuinely incomplete, so
recovering them would need repair, which this importer does not do. adv-1.1 recovers 49/49.
Snapshots: `labs/adversarial_idor_eval/results/adv1{0,1}-resilient-har.json`.

Regenerate fixtures with `python examples/har-recovery/build_fixtures.py` (deterministic; a test
checks that the committed files match).
