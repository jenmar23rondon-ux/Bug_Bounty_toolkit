# Review a Burp/HAR intake dossier

The existing intake command now renders Markdown for human review as well as
JSON for automation, using the same importer, deduplication and evidence rows.

```bash
bbtk evidence dossier --input capture.har burp.xml --output review.md --output-format markdown --dry-run
bbtk evidence dossier --input capture.har burp.xml --output review.md --output-format markdown
```

For a disposable example already shipped in the repository:

```bash
bbtk evidence dossier --input examples/object-discovery/captures.har --output review.md --output-format markdown
```

Each section shows the evidence reference, captured HTTP status, inconclusive
classification, every original source reference/locator/hash and plain-language
controls to verify. Source paths, capture bodies and credentials are absent.
Output uses the existing private atomic writer and refuses existing targets.
Use a fresh output filename on each run. Dry-run writes nothing.

| Synthetic intake property | JSON-only baseline | Markdown option |
| --- | --- | --- |
| Commands to export one dossier | 1 | 1 |
| Duplicate observations after semantic dedup | Unchanged importer result | Same |
| Original source hashes and locators | Preserved | Preserved |
| Missing authorization controls | Machine identifiers | Plain-language checklist |
| Observation classifications | Inconclusive | Inconclusive, explained |

`python -m unittest tests.test_capture_dossier -v` checks preserved source hashes,
credential/path canaries, dry-run, private permissions and refusal to overwrite.
This improves presentation only; no human time savings or dossier-quality score
has been measured. Human ownership/control verification and the existing
Evidence Ledger claim verifier remain subsequent steps.
