# Offline IDOR/BOLA Case Discovery

This workflow prepares **known-resource read cases** for the existing `access-check` engine. It never contacts targets, launches scanners/models, discovers accounts, enumerates IDs, changes server data or confirms vulnerabilities. Account/resource authorization and the meaning of response fields remain researcher declarations.

## Architecture Audit And Reuse

The mandatory pre-edit audit was performed against `origin/main` at `c187a3f`:

| Audited module | Existing capability and reuse |
| --- | --- |
| `burp_import.py` | Bounded local imports, XML item decoding, URL extraction and HTTP message separation. The new paired-exchange reader extends these helpers instead of using the lossy route-only or redacted-request importer for replay credentials. It never zips unrelated request/response lists. |
| `case_generator.py` | `generate_case`, session-context detection, non-session-header comparison, one path/query resource inference, pointers and private-marker validation. `inspect_read_pair` and `prepare_case` expose this existing logic for proposals and conversion; the original `import case` remains supported. |
| `access_control/comparison.py` | `parse_json`, JSON pointers, exact typed comparison, `account_observations`, `load_case` and `AccessControlTester`. Approval uses those predicates and the native loader; actual execution remains here. |
| `access_control/function_matrix.py` | Role/function capture validation and `AccessFunctionMatrixTester` already implement BFLA checks. Discovery does not infer roles or create a competing role engine. |
| `analysis/access_assessment.py` | `assess_access_control_data` requires ownership predicates and actual crossed evidence. A prepared case without crossed evidence remains `insufficient_evidence`, `confirmed: false`. |
| `cli.py` | Existing `import` subcommands, `ProgramPaths`, scope loading and dry-run conventions. The two new offline subcommands use those boundaries and do not construct an HTTP client or change program settings. |

No comparison or assessment algorithm, scope rule, rate limit, run budget or permission is relaxed by this feature.

## Inputs And Limits

- Accept two UTF-8 Burp XML item exports (one per account), or one raw HTTP/1.x request per account. XML messages may be base64 encoded. For raw requests, use `--owner-response` and `--actor-response` for separate complete HTTP responses.
- Raw relative requests otherwise inherit the existing HTTPS default. Supply the actual origin with `--base-url`, especially for HTTP laboratories. XML item metadata preserves the captured scheme/authority and must agree with its raw target. Host overrides are rejected.
- Keep method, origin, non-session headers, path shape and non-resource parameters consistent. Only one path segment or one query value may identify the resource. Multiple unrelated differences, identical sessions, duplicate/session-bearing query parameters and writes are not promoted.
- Limits are 32 MB per input export, 32 items per account, 1 MB per request/response, 64 proposed pairs, and 2 MB per proposal. JSON analysis permits at most 16 levels, 4096 visited nodes and 128 scalar fields. A candidate cap is explicitly reported; smaller exports are preferable.
- Inputs must be bounded regular local files. Symbolic links, FIFOs, invalid UTF-8, XML DTD/entities, malformed messages and mismatched response lengths are rejected. Responses must be complete, decoded and uncompressed, with JSON content types to suggest comparison fields. HTTP/2, chunked/gzip wire bodies and ambiguous framing headers are unsupported.
- Each XML item's response stays attached to that request, regardless of the order of other items. Request-only captures can propose structure, but cannot produce an approved case without both saved controls. No live request is used to fill a missing field.

## Propose And Review

```bash
bbtk import discover-idor my-program --owner account-a.xml --actor account-b.xml --dry-run
bbtk import discover-idor my-program --owner account-a.xml --actor account-b.xml \
  --output-dir registros/my-program/private/idor-discovery
```

Dry-run creates no files, database or program authorization. The optional `--attest-authorized-accounts` records the initial declaration but does not complete the later review. Without `--output-dir`, the new private directory is `registros/<program>/private/idor-discovery`. Existing bundles are never overwritten.

The count-only console summary is shareable: it has candidate labels, difference/field counts and pending-review status, but no capture filenames, response text, pointers, URLs, IDs, tokens or cookies. The proposal itself is **private**, not a finding/report. Raw request/response snapshots deliberately preserve credentials and structure for compatible replay. Protect the entire directory; never upload it or add it to git. POSIX directories use mode 0700 and files 0600 independently of the umask; on platforms without POSIX enforcement, enforce equivalent user-only ACLs.

Within the selected candidate, inspect `suggested_checks` and the original control responses, then complete `review`. For the repository's fixture only, the reviewed block is:

```json
{
  "success_pointer": "/success",
  "resource_pointer": "/data/id",
  "private_pointer": "/data/marker",
  "accounts_authorized": true,
  "resource_ownership_confirmed": true,
  "resource_private": true,
  "read_only_confirmed": true,
  "controls_success_confirmed": true,
  "markers_private_confirmed": true,
  "captured_origin_confirmed": true,
  "approved": true,
  "expected_cross_access": "deny"
}
```

Do not copy these declarations onto real captures without checking them. Similar sessions, matching IDs, response similarity or a field named `success` cannot prove ownership, privacy or intended permissions. A GET can have side effects. A private marker must already be present in each own test resource, satisfy the native marker rules, differ between accounts, be non-public and not be request-reflected or a credential. No resource is created or modified to invent proof.

## Explicit Offline Approval

An existing program scope is mandatory before conversion; use the actual program policy for any real target. Approval is separate from both discovery and live execution:

```bash
bbtk import approve-idor my-program \
  --proposal registros/my-program/private/idor-discovery/proposal.json \
  --candidate candidate-001 --approve --dry-run
```

Removing `--dry-run` writes `case-candidate-001.json` beside the proposal. Approval requires the explicit command flag and every review declaration, checks unchanged snapshot hashes and confined bundle references, validates the selected typed JSON resource values and markers against both captured successful controls, and validates the resulting document through `load_case`. It preserves JSON string/integer resource types. Credentials remain in the request snapshots, not in the case or console output. Sensitive fields cannot be selected as proof; private case IDs and markers still must not be shared.

An approved case does not make a finding. Its assessment without native crossed evidence is `insufficient_evidence`. Conversion does not add an enumeration declaration, inverse/anonymous request, write mode or budget override. Subsequent `access-check` execution remains separately authorized, and revalidates current controls and all existing scope, automation, rate and run-budget restrictions. Old captures can expire even after offline review.

## Reproduce Using Only The Local Lab

All data below is the repository's fixed dummy fixture. No service needs to run for discovery or approval:

```bash
bbtk import discover-idor idor-lab \
  --owner labs/idor_lab/captures/owner.txt \
  --actor labs/idor_lab/captures/actor.txt \
  --owner-response labs/idor_lab/captures/owner-response.http \
  --actor-response labs/idor_lab/captures/actor-response.http \
  --base-url http://127.0.0.1:8099 --dry-run
```

Expected: one pending candidate with one path-ID difference, distinct sessions, and suggestions for `/success`, `/data/id` and `/data/marker`; zero HTTP requests. Repeat without `--dry-run` to create the private bundle. Review its sole candidate using the fixture-specific block above. Initialize the local program and scope, then preview/perform **offline conversion**:

```bash
bbtk init idor-lab --authorization "repository loopback-only IDOR lab" --automation-allowed
bbtk scope add idor-lab http://127.0.0.1:8099/api
bbtk import approve-idor idor-lab --proposal registros/idor-lab/private/idor-discovery/proposal.json --candidate candidate-001 --approve --dry-run
bbtk import approve-idor idor-lab --proposal registros/idor-lab/private/idor-discovery/proposal.json --candidate candidate-001 --approve
bbtk access-check idor-lab --case-file registros/idor-lab/private/idor-discovery/case-candidate-001.json --max-tests 3 --dry-run
```

These commands send no target requests. To independently execute the generated case, start `bash labs/idor_lab/run.sh` in another terminal and remove `--dry-run` from **only** the last `access-check` command. That explicitly separate action sends the two controls and one cross to loopback. It should observe `candidate`, never confirmation. Do not enable a range or a write mode.

Automated reproduction covers both the deliberately vulnerable and protected local endpoints:

```bash
python -m unittest discover -s tests -p test_idor_discovery.py -v
python -m unittest discover -s tests -p test_end_to_end_idor.py -v
```

## Known Limitations

This is conservative structural matching, not semantic route discovery or an IDOR oracle. Collections/arrays and multiple ID fields can be ambiguous and need manual review or recapture. Role hierarchies, body-ID writes, signed/session queries, anonymous tests, pagination, arbitrary schema inference and freshly fetched evidence are outside preparation. Unsupported pairs remain unproposed rather than being force-normalized. Complete own-resource captures are still not proof of business ownership/privacy; only the investigator can attest that context. Hashes detect accidental snapshot changes, not an adversary who can edit the private bundle. No AI model is called and no untrusted document text becomes execution instructions.


## Handoff Case Reliability (offline classification)

When `object-handoff` materializes owner/actor pairs for `discover-idor`, conversion
eligibility is classified without networking or auto-approval:

| Status | Meaning |
| --- | --- |
| `structural_valid` | Parsed 4-way (or partial) captures with consistent structure |
| `case_eligible` | GET, same effective origin, single justified resource diff, both control responses |
| `needs_more_evidence` | Multi-diff, session-only, missing responses, insufficient sessions — remains a hypothesis |
| `security_rejected` | Non-GET / body-on-GET / method mismatch — not promoted to a read case |
| `technical_error` | Caller `--base-url` disagrees with capture Host/authority, or parse failure |

Stable codes live in `bugbounty_toolkit.analysis.handoff_case_eligibility` (for example
`CASE_ELIGIBLE`, `TECH_ORIGIN_OVERRIDE`, `REJECT_MULTI_RESOURCE_DIFF`). Origins are never
silently rewritten: materialized suggestions use the capture provenance origin; incompatible
overrides fail closed. Measurement lab: `labs/idor_handoff_case_eval` (`adv-handoff-case-1.0`).
The adversarial evaluator uses each corpus `ground_truth.origin` (adv-1.0 → `:8137`, adv-1.1 → `:8138`).
