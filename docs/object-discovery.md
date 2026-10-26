# Offline API Object Relationship Discovery

`object-discover` correlates references in authorized **local** Burp XML, raw HTTP and HAR captures. `object-candidates` ranks the resulting objects for manual IDOR/BOLA investigation. Neither command opens sockets, resolves hosts, calls a model, launches a scanner, submits HTTP requests, generates ID ranges, creates executable cases or confirms vulnerabilities. Captured POST/PUT/PATCH messages are data only and are never replayed.

## Reproduce with synthetic captures only

From a source checkout with BBTK installed, on Linux or another POSIX platform with no-follow directory descriptors:

```bash
bbtk object-discover object-demo \
  --input examples/object-discovery/captures.har \
  --attest-authorized-captures --dry-run

bbtk object-discover object-demo \
  --input examples/object-discovery/captures.har \
  --attest-authorized-captures

bbtk object-candidates object-demo \
  --graph registros/object-demo/private/object-relationships/graph.json \
  --verify-input examples/object-discovery/captures.har \
  --output registros/object-demo/private/object-relationships/candidates.json
```

No running service, Burp installation, credentials, model or Internet connection is needed. All example sessions, IDs and URLs are synthetic. The addresses refer to the existing loopback laboratory, but discovery never contacts it. There are five observations, two distinct order objects and six object candidates. The leading order and user candidates each score 70/100; ties use the opaque object reference, so their order depends on the local key. Every candidate has `confirmed: false`, `case_executable: false`, unknown ownership/privacy and required researcher review.

`--input` is repeatable. For relative raw HTTP requests, `--base-url` supplies only the actual captured origin, subject to the existing Burp importer's host checks. Burp XML pairs requests and responses by item. Raw request-only files are usable but contribute no response-reference evidence. HAR content may be UTF-8 text or base64-encoded UTF-8. HTML bodies and non-ID fields are not object evidence. Unsupported, malformed, ambiguous or excessive input fails with a generic error that does not echo the capture. For HAR files, a malformed entry is isolated with an enumerated reason code while the other entries are still analyzed; `--strict` restores whole-file rejection and `--allow-truncate` opts in to analyzing the first 32 entries of a larger export (see [HAR partial recovery](har-partial-recovery.md)).

`--attest-authorized-captures` declares permission to analyze the local files. It does not declare ownership of objects or authorize remote tests. There is no active-test option in these commands.

## Identity and relationships

An object reference is an HMAC of the program, origin, resource namespace and literal identifier. Path `987`, query `order_id=987` and JSON `"order_id": 987` can correlate as an order reference. `988` remains separate even under the same parameter name. User `987`, order `987`, different origins and strings with leading zeros remain separate. Strings retain their case; integer IDs use their decimal representation. Booleans and floating-point values are excluded.

Known collection aliases and ID field names provide **heuristic type hints**, explicitly labeled on object nodes. Unknown ID namespaces remain endpoint-qualified to avoid unjustified merging. This can miss relationships and does not prove that referenced objects exist. A literal matching reference is an observation, not evidence of business ownership or access rights.

The schema distinguishes:

| Relationship | State | Meaning |
| --- | --- | --- |
| `HAS_FIELD` | observed | An endpoint contains an identifier field/position |
| `REFERENCES` | observed | A request field contains the typed literal reference |
| `RETURNS_REFERENCE` | observed | A response JSON field contains the reference |
| `CO_OCCURS` | observed | Two references occur in the same JSON container |
| `SEEN_WITH_SESSION` | observed | The capture has this opaque request-header context |
| `PATH_CONTEXT` | inferred | Two object references occur in a nested path |

JSON array entries have separate containers; objects in different entries are not cross-linked merely because they share an array. There is no `OWNS` relationship. A session context may change through token rotation, CSRF values or other headers; two contexts are not proof of two accounts. A nested path such as `/users/123/orders/987` is an investigation hint, not an ownership assertion.

Semantic duplicate observations are merged, preserving all source provenance. Independent query-field order is normalized; repeated parameters retain their within-name position, and path case remains distinct. Repeated imports do not inflate ranking. Results are deterministic for the same program, key and input set, irrespective of file order. Changing the key changes references and tie ordering. No timestamps or random per-record IDs enter the graph.

## Explainable priority, not severity

Ranking version `1.0` sums these fixed rules once per object, with supporting observation references on each awarded component:

| Rule | Points |
| --- | ---: |
| Observed request reference | 20 |
| Also present in response JSON, with request evidence | 15 |
| Referenced by at least two normalized endpoints | 15 |
| At least two captured session contexts | 20 |
| Explicit typed ID field such as `order_id` | 10 |
| Co-occurrence with another object in a JSON container | 10 |
| Nested path context | 10 |

The maximum is 100. Scores measure available correlation signals for investigation, not exploitability, privacy, authorization failure or confidence in a vulnerability. HTTP status and response size award no points. `--limit 1..100` and `--min-score 0..100` filter candidates; ties sort by object reference. A high score still requires ownership, expected permission and direct evidence review.

## Versioned, minimized and verifiable artifacts

The graph has `type: api-object-relationship-graph`, `schema_version: 1.0`, ranking version, sources, nodes, relations, observations and zero network/confirmed-vulnerability counters. Candidate reports have `type: api-object-investigation-candidates` and retain the graph integrity reference and score breakdown.

No full requests or responses, credential values, literal IDs, hostnames or source filenames are exported. IDs, origins, session contexts and source commitments use domain-separated HMAC-SHA256 references, truncated to 128 bits. Only fixed method/collection/field vocabulary is readable; unknown path and JSON-pointer components are pseudonymized, including numeric JSON keys that might be object IDs. Field `pointer_template` preserves structure with masked components and is not an executable JSON pointer. Known credential fields/subtrees, JWT-shaped values and observed credential values copied into ID fields are excluded. Capture-derived text is never treated as instructions.

Each edge references observations, and each observation records an HMAC source commitment and a parser-generated item locator. `--verify-input` verifies exact bytes of **all** source files against these commitments without publishing their paths. Field templates and source item locators let the researcher inspect the original protected capture locally. The graph also carries a full HMAC-SHA256 integrity signature; `object-candidates` rejects tampering, a different program/key or unsupported schema/ranking versions. Integrity verifies the artifact, not the truth of the captured application behavior.

By default, a 32-byte random key is created at `registros/<program>/private/object-relationships/key.bin`. `--key-file` selects another private key. Existing keys must be owned by the invoking user, exactly 32 bytes and mode `0600`. Keep this key private and stable for a given investigation. Without it, low-entropy numeric IDs are not exposed as guessable unkeyed hashes. Key loss prevents verification; key disclosure defeats the pseudonymization/integrity guarantees. The graph still reveals minimized structure and counts, so review it before sharing.

New directories are mode `0700`, and graph, candidate and key files are mode `0600`. Writes use a same-directory exclusive temporary file, `fsync` and atomic publication. Existing outputs require `--force`; keys and source captures cannot be output destinations. Paths reject `..`, network/UNC syntax, symbolic links (including ancestor links), non-regular files and FIFOs. Directory descriptors anchor every component against link substitution. These secure I/O operations currently require POSIX; unsupported platforms fail closed rather than weakening the checks. Existing commands retain their platform behavior.

Both commands' `--dry-run` modes perform no writes, including no database, directories or global `--log-file`. A first discovery dry-run uses an ephemeral key only in memory and prints counts; it does not persist unstable references. Candidate dry-run validates the existing key/graph, verifies sources if requested and prints counts only. A normal candidate listing writes only when `--output` is provided. Artifact publication is atomic per file, not a transaction across key and graph; if publication fails after a new key is created, retain that protected key and rerun with it.

## Limits

| Input/resource | Limit |
| --- | ---: |
| Files | 16 |
| Each source file | 32 MiB (shared Burp limit) |
| Total source bytes | 64 MiB |
| Captures per file / total | 32 / 256 |
| Request/response body | 1,000,000 bytes each |
| URL / query fields | 8,192 characters / 128 |
| JSON depth / visited nodes / scalar fields | 16 / 4,096 / 128 |
| Object occurrences per capture | 64 |
| Graph nodes / edges | 10,000 / 30,000 |
| Graph and candidate JSON | 8 MiB each |
| Local path | 4,096 characters |

The shared native Burp parser additionally validates full messages, origins and response framing. Use narrowly selected authorized exports; discovery does not silently sample over-limit captures.

## Reused architecture and IDOR handoff

The pre-change audit covered Burp import, case generation/discovery, comparison/function matrix, access assessment, evidence import, API workflow/evidence graph and CLI. Reused functionality:

| Existing module | Reuse |
| --- | --- |
| `burp_import.py` | `parse_captured_exchanges`, `captured_response`, shared message/count/byte limits |
| `analysis/evidence_engine.py` | Extracted `har_capture_sources` raw adapter and `resource_path_segments` hints; old evidence imports use the same helpers |
| `idor_discovery.py` | Public bounded `json_scalar_fields`; existing proposal logic keeps its behavior |
| `access_control/comparison.py` | Strict duplicate-key JSON parsing and JSON-pointer parsing |
| `case_generator.py`, `core/redaction.py` | Existing session/secret recognizers and JWT pattern |
| `analysis/api_workflow.py` | Extracted `merge_relation` and shared graph node IDs; existing graph uses the same deduplication |
| `analysis/evidence_graph.py` | Existing graph size/count limits and epistemic-state conventions |
| `core/records.py`, `cli.py` | Program validation and standard top-level command dispatch |

The new engine adds only individual object identity/correlation and its bounded ranking. Existing minimized unified bundles contain aggregate fingerprints, which cannot reliably recover individual IDs; they are deliberately not accepted as raw capture replacements. Existing SQLite investigation graphs and their schemas are unchanged.

For a promising candidate, inspect the original local source items, confirm authorized accounts, ownership, privacy and expected permissions, then select the matching own-resource captures. Use the existing [offline case discovery and explicit approval](idor-case-discovery.md) workflow before [access-check](idor-playbook.md). Object candidates cannot bypass its eight attestations, valid control responses, scope checks, budgets or rate limits. No case, range, role matrix or action is auto-created/executed by this feature. Missing evidence remains pending; `comparison.py`, `function_matrix.py` and `access_assessment.py` remain the authorities for their existing validation flows.

## Validation

`tests/test_object_relationships.py` covers ID separation, path/query/JSON correlation, typed/cross-origin boundaries, array isolation, observed vs inferred edges, deduplication, deterministic ranking, HMAC/source verification, malformed/oversized inputs, privacy, safe paths, atomic publication, CLI dry-runs and compatibility with paired Burp IDOR proposals. Socket, DNS, HTTP-opening and subprocess entry points are patched to fail during discovery. Existing loopback IDOR/access-check tests remain separate regressions. CI runs an offline CLI smoke example, strict mypy, Ruff and the complete suite, with a 90% combined coverage floor for the new correlation/private-I/O modules.


## Offline handoff to discover-idor

`object-handoff` turns ranked object references into **reproducible owner/actor capture-pair proposals**. It never writes access-check case JSON, never calls `access-check`, never approves, and never sends HTTP. Every proposal stays `confirmed: false` / `case_executable: false` and includes the human gate that still requires the existing `import discover-idor` → attestations → `approve-idor --approve` path.

```bash
bbtk object-handoff object-demo \
  --graph registros/object-demo/private/object-relationships/graph.json \
  --verify-input examples/object-discovery/captures.har \
  --dry-run

bbtk object-handoff object-demo \
  --graph registros/object-demo/private/object-relationships/graph.json \
  --verify-input examples/object-discovery/captures.har \
  --materialize-dir registros/object-demo/private/object-handoff/pairs \
  --output registros/object-demo/private/object-handoff/proposals.json
```

Proposals link each side back to HMAC `source_ref` + parser locator provenance. With `--materialize-dir` and verified inputs, BBTK writes private mode-0600 raw HTTP snapshots and prints a ready `import discover-idor ... --dry-run` command. Without materialization, the command references export placeholders for the locators. Candidates that lack two distinct sessions with different request-side object values return `status: insufficient_evidence` instead of inventing accounts.

### Response-observed identifiers (asymmetric pairing)

Offline capture analysis often sees an object identifier first in one session's **response JSON** (for example a listing or nested object) and only later in another session's **request**. Since handoff 1.1, such identifiers can form human-review proposals with `pair_kind: asymmetric_response_request`. Symmetric request/request proposals are labeled `pair_kind: request_request` and are unchanged.

Every asymmetric proposal separates what was **observed** from what is **inferred**:

- `observed_identifiers[]` lists each side with `observed_in` (`response_json` or `request`), the type basis for response identifiers and `ownership: unknown`.
- `relation.state` is always `inferred` with `rule: response-identifier-v1`. A response containing an ID is **not** evidence of ownership, privacy or access. The owner side is only "the session whose response showed this identifier".
- Both sides keep HMAC `source_ref`, parser `locator`, `observation_ref` and `session_ref` provenance, and materialize exactly like request/request pairs.

Rule `response-identifier-v1` (guards against false links):

1. Same known `resource_type` on both sides, from **different** authorized session contexts, on the same origin; different object values.
2. The response identifier needs its **own** type evidence: a typed field name (`project_id`, `address_id`) or a collection-named JSON container (`addresses[*].id`). Bare wrapper ids such as `{"data":{"id":N}}` that are typed only by the endpoint path are observed but never linked.
3. Identifiers observed by more than one session context are treated as **shared context** (for example a common tenant) and excluded.
4. Equal numeric tokens of different types never link, because object references are HMAC(origin, type, value).
5. At least one side must be request-side; response-only on both sides stays insufficient evidence. Captures without session context are ignored.
6. Asymmetric scores are capped at 79 so they never outrank an equally evidenced request/request pair. Response sides (512) and asymmetric pairs (256) are bounded; truncation is reported.

The document's `response_identifiers` block reports observed counts, exclusions by guard, and how many asymmetric proposals were selected. Use `--request-only` to reproduce the earlier request-side-only behavior.

## Efficacy lab

`bbtk lab object-discover` runs the versioned synthetic corpus under `labs/object_discovery_lab/` (`dev/` for iteration, `eval/` holdout — do not tune rules on eval). It reports Precision@1/3/5, recall, FP/FN, per-relation coverage, timing, and a before/after comparison against the prior `object-candidates` ranking. Each split also reports `request_only_comparison` (the same corpus with response identifiers disabled) so the asymmetric rule's effect is measured in the same run. Corpus 1.1 adds response-observed, response-nested, response-collision, shared-context and incomplete-capture scenarios to both splits. Metrics measure **candidate-pair ranking efficacy** only; `vulnerabilities_confirmed` is always 0 and synthetic scores are not real bug-bounty confirmation performance.

```bash
bbtk lab object-discover --dry-run
bbtk lab object-discover --split eval --metrics-json /tmp/object-metrics.json
```
