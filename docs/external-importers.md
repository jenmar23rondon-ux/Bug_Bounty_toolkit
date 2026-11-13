# Offline external importers

Second increment of the evidence-intelligence program. Local Nuclei, OWASP ZAP,
FFUF, and SQLMap result files become one versioned hypothesis record. This does
not run those tools, does not send network traffic, and does not confirm a finding.

Offline only. No new runtime dependency. Version stays `0.2.2`.

## Audit

Base: `main` at `52640b8` (PR #112, `bbtk.capture-ingestion/1`).

| Reader | What already worked | What this PR keeps |
|---|---|---|
| `evidence_engine._nuclei_row` | Template id, severity, matcher name, matched URL, and extracted-result count from a Nuclei object. | Called for every well-formed object. Identity fields in the hypothesis come from that record. |
| `evidence_engine._nuclei_jsonl` | Parses clean JSONL. | Not used for a whole file. It raises on the first bad line and drops later rows. |
| `evidence_engine._ffuf` | URL, status, and response length/words/lines from one FFUF result object. | Called per row. Rows it skips become diagnostics instead of silent drops. |
| `fuzzing.results_parser.parse_ffuf_results` | Bounded FFUF JSON for the ffuf runner, with dedupe. | Left on the execution path. The importer does not dedupe and does not start ffuf. |
| `capture_ingestion.ingest_capture` | Normalizes textual HTTP, including partial and contradictory messages. | Used when a result file actually contains a request or response. |

ZAP and SQLMap had no hypothesis reader. Their parsers are new and file-only.

## Schema

`bbtk.external-finding/1`. The JSON Schema is `docs/schemas/external-finding-v1.schema.json`.

| Field | Meaning |
|---|---|
| `origin` | Tool, version if the file declared one, source basename, 1-based record index, SHA-256 of that input. |
| `evidence` | URL/method/status when observed, request/response presence, ingestion schema and confidence, diagnostic codes, and a short redacted excerpt. |
| `hypothesis` | Vulnerability class and claim taken from the tool. FFUF is `content_discovery` and `vulnerability_claimed` is false. |
| `status` | `candidate`, `needs_review`, or `abstain`. |
| `traceability` | Locator in the source, SHA-256 of the raw record, and which reader produced the identity. |
| `access_confirmed` | Always false. |
| `vulnerabilities_confirmed` | Always 0. |

`candidate` means the tool claim has a location and the embedded HTTP, when present, ingested as `observed`. `needs_review` means the claim is incomplete, the tool version was not recognized, or no response was embedded. `abstain` means the record has no identity, the tool itself reported a negative, or the embedded HTTP is contradictory (for example two different `Cookie` values). None of these are confirmation. A later BBTK check still has to meet its own evidence bar.

A Nuclei object that says `critical`, `classification: confirmed`, or `access_confirmed: true` is still only a candidate or weaker. A SQLMap log line that says a parameter `is vulnerable` is `needs_review` unless a request and response in the same record ingest cleanly, and even then it stays an unconfirmed candidate.

## Example

```json
{
  "schema": "bbtk.external-finding/1",
  "origin": {
    "tool": "nuclei",
    "version": null,
    "source_file": "nuclei.jsonl",
    "record_index": 1,
    "input_sha256": "<sha256 of the file>"
  },
  "evidence": {
    "url": "http://127.0.0.1:9/search",
    "method": "GET",
    "status_code": 200,
    "request_present": true,
    "response_present": true,
    "ingestion_schema": "bbtk.capture-ingestion/1",
    "ingestion_confidence": "observed",
    "ingestion_diagnostics": [],
    "excerpt": "welcome"
  },
  "hypothesis": {
    "vulnerability_class": "cross_site_scripting",
    "vulnerability_claimed": true,
    "claim": "synthetic-reflection",
    "severity_claimed": "low",
    "template_id": "synthetic-reflection"
  },
  "status": "candidate",
  "traceability": {
    "raw_locator": "line:1",
    "reader": "evidence_engine._nuclei_row"
  },
  "access_confirmed": false,
  "vulnerabilities_confirmed": 0
}
```

## CLI

The command only reads local files. `--attest-local-artifacts` records that the operator is allowed to read those files. It does not add scope, change a rate limit, or approve an active test. `--dry-run` prints the summary and writes nothing.

```sh
bbtk evidence external lab \
  --input nuclei.jsonl --tool nuclei \
  --attest-local-artifacts --dry-run

bbtk evidence external lab \
  --input zap-report.xml \
  --attest-local-artifacts --dry-run

bbtk evidence external lab \
  --input ffuf.json --tool ffuf \
  --attest-local-artifacts --dry-run

bbtk evidence external lab \
  --input ./sqlmap-output --tool sqlmap \
  --attest-local-artifacts --dry-run
```

Omit `--dry-run` to write a mode-0600 JSON document. The default path is `registros/<program>/evidence/imports/external-findings.json`. `--force` replaces that file. The summary on stdout does not include request bodies.

```sh
python -m labs.external_import_eval.evaluate
```

## Limits

- One input is at most 32 MiB, the same cap as evidence import. A larger file is `oversized_input` and is not read.
- At most 10,000 findings per input. Further rows are `record_limit`, not silent.
- A single JSONL line or CSV physical line over 1,000,000 bytes is `record_too_large`. Embedded HTTP over 256,000 bytes is `evidence_too_large` and is not ingested.
- XML is rejected when it contains a `DOCTYPE` or `ENTITY` declaration. Entities are not expanded.
- NUL bytes and non-UTF-8 text are file-level diagnostics.
- A declared tool version outside the mapped set (`nuclei` 2.x/3.x, ZAP `2.` or a `D-YYYY-MM-DD` weekly, FFUF 1.x/2.x, SQLMap 1.x) is `unknown_version`. Recognized rows are still imported and cannot be `candidate`.
- A bad row does not discard its siblings. An unreadable file does not discard other `--input` paths.
- SQLMap `session.sqlite` is recognized and refused (`session_pickle_refused`). It is not unpickled. A `dump/` directory is `sqlmap_dump_skipped` and its rows are not imported as findings.
- Cookies, authorization headers, and a CSV column named `payload` are not copied into the finding.

## Independent evaluation

`labs/external_import_eval` builds 29 synthetic cases, including malformed, truncated, empty, oversized, unknown-version, DTD, contradictory-cookie, Nuclei `critical` false positives, and SQLMap logs that claim a parameter is injectable. Hosts are `127.0.0.1` only. The set is not the frozen DEV (6), FINAL (45), or STRESS (6) corpus.

The before arm is `import_evidence`. The after arm is `import_external`. Review-time proxy is unitless: 30 crash, 25 false confirmation, 20 silent drop, 15 other miss, 5 explained refusal, 2 explained partial or abstention, 1 clean candidate. Lower is better.

| Metric | Before | After |
|---|---:|---:|
| Parse success | 0.1034 | 1.0 |
| Diagnostic rate | 0.0 | 1.0 |
| Schema-mapping accuracy | 0.0 | 1.0 |
| False confirmations | 0 | 0 |
| Candidate precision | 0.3636 | 1.0 |
| Candidate recall | 0.6154 | 1.0 |
| Review-time proxy | 568 | 77 |

False confirmations on the cases marked as tool false positives are 0. Three clean Nuclei/FFUF files already parsed in the legacy reader (parse success 3/29). That reader has no shared schema, so schema-mapping accuracy is 0. These figures are not a real-world detection rate.

Frozen DEV / FINAL / STRESS captures, labels, and `MANIFEST.sha256` are not edited. Pairing precision and recall stay 1.0, forbidden pairs stay 0, and automatic confirmations stay 0. Outcome accuracy stays 1.0 / 0.9111 / 1.0 on DEV / FINAL / STRESS. Recorded result files rebind `implementation_sha256` because it covers every `bugbounty_toolkit` Python file. Scenario outcomes are unchanged. This set was not used to change those labels.

## Limitations

- Not an HTTP/2 or HTTP/3 frame decoder. Textual exports follow the capture-ingestion contract, including its `br` and charset limits.
- FFUF output is a discovery observation. It is not a vulnerability claim and it is not sent anywhere.
- A SQLMap technique name is the tool's label. The importer does not replay, time, or confirm it.
- ZAP risk and Nuclei severity are stored as the tool's claim. They do not set BBTK severity or confirmation.
- An unrecognized file is refused with `unknown_format` rather than guessed into a class.
- Ranking which hypothesis to open first is not this PR. The next PR should explain that order and abstain when origin, evidence, or a comparison point is missing. It should still be unable to mark an imported row confirmed.

## Proposed next PR

Explainable prioritization over `bbtk.external-finding/1` plus the existing BBTK hypotheses. Rank only rows that have an origin, a location, and enough evidence to say why one comes before another. Abstain when a field needed for the comparison is missing or contradictory. Keep `access_confirmed` and `vulnerabilities_confirmed` false. Do not tune on the frozen FINAL labels.
