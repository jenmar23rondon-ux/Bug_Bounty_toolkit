# Bounded incremental capture ingestion (batch campaigns)

`bugbounty_toolkit/analysis/batch_capture_pipeline.py` processes many **pre-split** local capture
files (HAR, Burp XML, raw HTTP) as small, verifiable, resumable batches. It is offline, adds no
parser, and does not raise any existing limit.

## Problem (measured on `40a28b4`)

`evidence_engine.import_evidence` is monolithic: one call accepts at most 100 files, 10,000
records and 32 MiB per file. It is all-or-nothing:

* 200 files × 30 entries (6,000 valid entries) → whole import refused (`ValueError`), 0 entries
  preserved (benchmark row `files=200`).
* One truncated HAR among valid files → whole import refused; the valid entries in the other
  files are lost (`incomplete_file` scenario, DEV and FINAL).
* No resume, no input manifest, no campaign identity, no record of which file failed.

## Stage limits (unchanged)

| Stage | Limit | Source |
|---|---|---|
| Evidence import, per file | 32 MiB (`MAX_INPUT_BYTES`) | `analysis/evidence_engine.py` |
| Evidence import, per call | 100 files, 10,000 records, 2,000 correlation groups | `analysis/evidence_engine.py` |
| HAR, per file | 4,096 declared entries (hard), file depth 256, entry depth 32, body depth 16, 256 headers, 8,192-char URL | `analysis/har_import.py` |
| Burp import (CLI path) | 100 MiB sitemap, 8 MiB request, 32 MiB item, 32 exchanges | `burp_import.py` |
| Object discovery | 16 files, 64 MiB, 256 captures, 64 occurrences | `analysis/object_relationships.py` |

A batch is exactly **one ordinary `import_evidence` call**, so all import limits apply unchanged.
`CampaignLimits.validate()` refuses per-batch values above them (`max_files_per_batch ≤ 100`,
`max_records_per_batch ≤ 10,000`). Object discovery is **not** run by this module.

## New, explicit campaign budget

All six limits are required (no defaults). Campaign totals are capped by new hard ceilings
(`1,000` files, `1 GiB`, `100,000` records); values above are refused, never clamped.
Totals are enforced *before* a batch is committed:

* a batch whose records would exceed `max_total_records` → `blocked_by_campaign_limit`, its
  bundle is not stored, every later batch is blocked, campaign `partial_limit_reached`;
* a batch above `max_records_per_batch` → `failed` (`batch_record_limit`), never truncated;
* files above the 32 MiB file limit → `omitted_file_limit`; beyond `max_total_bytes` →
  `omitted_campaign_limit`. Either makes the campaign `partial_limit_reached`.

## Plan, manifest and identity

* Inputs are relative paths under one root; absolute, `..`, symlinked, non-regular or missing
  inputs are refused (`core.private_files.local_path` + `lstat`). Listing order is irrelevant
  (sorted).
* `campaign_id` = SHA-256 of schema, program, HAR mode, format, limits and file list.
* `manifest_sha256` adds every file's SHA-256 and size.
* `batch_id` = SHA-256 of campaign id + member `(relpath, sha256)` — content addressed.
* Byte-identical files are `duplicate_file` (`duplicate_of` keeps the canonical relpath).

## Execution and isolation

Inputs are re-hashed before and after the import (TOCTOU guard → `source_changed_*`, batch
`failed`). If the combined import is refused, each file is probed alone; only files that fail
alone are excluded (`rejected_file` with an enumerated code such as `har:json_invalid`) and
the batch is re-imported without them. Entry-level HAR rejections stay in the importer's
`capture_import` account. Burp `<item>` elements are counted and `burp_items_not_emitted`
warns when the importer skipped items.

## Resume

State (`campaign-state.json`) and batch bundles live in a private directory (0700, owner,
no symlinks), written atomically with mode 0600 after **every** batch. On re-run:

* different schema / program / limits / mode / file list → `campaign_mismatch`;
* changed file contents → `source_changed` unless `allow_source_changes=True`; then only batches
  whose content-addressed id still exists are reused; the rest run again;
* a completed batch is reused only if its stored output SHA-256 verifies; otherwise it is
  re-run (`reprocessed_output_altered`);
* failed / pending batches are re-run; the campaign is `complete` only when every batch is
  completed and nothing was omitted by limits.

## What is *not* done

* **No streaming.** HAR files are still decoded whole by the existing importer. Large captures
  must be split beforehand into files within the per-file limits.
* **No cross-batch merge.** Fingerprints are salted per import, so each batch bundle is an
  independent partial graph. Cross-batch / cross-file duplicate HAR entries are *reported*
  (entry SHA-256) but not deduplicated. Ranking or correlation over the union is not claimed to
  be equivalent to a single import.
* A duplicate file's provenance path is kept only in the manifest (`duplicate_of`), not as an
  extra provenance row in the bundle (the monolithic import merges both paths).
* No change to the Evidence Ledger, scoring, AI, redaction or tool gate.

## Evaluation (synthetic only)

`python -m labs.batch_capture_eval.evaluate --bench` verifies the frozen corpus
(`labs/batch_capture_eval/manifest.json`) before computing metrics; results in
`labs/batch_capture_eval/results.json`.
