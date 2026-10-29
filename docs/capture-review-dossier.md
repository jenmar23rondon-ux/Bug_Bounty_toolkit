# Capture intake dossier

Run one offline command over existing HAR, Burp XML or raw HTTP files:

```bash
bbtk evidence dossier --input capture.har burp.xml --output review.json
bbtk evidence dossier --input capture.har --output review.json --dry-run
```

The command reuses `import_evidence` with resilient HAR mode. Exact semantic
duplicates become one observation while every source locator and SHA-256 is
retained. Source paths become opaque references. Bodies, headers, filenames,
URLs and session values are absent from the output. Sources must remain intact
during import. The output is created atomically with mode 0600; existing files
are refused. Existing importer limits apply (100 files, 32 MiB per file,
10,000 observations). This command does not batch or merge independent graphs.

Every observation remains inconclusive and lists ownership/sharing, distinct
actor authorization and negative controls for human review. This intake artifact
is not a verified claim dossier. After reviewing controls, use the existing
Evidence Ledger and verified dossier API to support individual claims.

Acceptance evaluation is synthetic and offline:

| Check | Existing separate importer/API steps | Intake command |
| --- | --- | --- |
| Normalization and semantic deduplication | Existing importer | Same importer |
| Two identical files, one observation, two locators | Supported | Preserved |
| Source digest binding and source-change refusal | Caller-managed | Included |
| Content-free inventory and missing controls | Caller-managed | Included |
| Confirmed findings or network requests | 0 | 0 |

Reproduce with `python -m unittest tests.test_capture_dossier -v`.
This evaluation measures behavior, not investigator productivity or real-world
vulnerability detection. No human-time savings have been measured.
