# Offline authorization comparison workbench

Start the existing local dashboard (`bbtk dashboard --help` for its records/program options),
then follow **Authorization comparison workbench**, or open `/authorization-workbench`.
The existing loopback-only server and Host/Origin/Fetch-Site protections apply to both routes.
No new CLI command, execution gate, AI call, replay operation or write endpoint is introduced.
Version remains 0.2.2. PR #52's assessment implementation is unchanged.

## Captures and selection

Only evidence already registered in the selected program's Evidence Ledger is eligible.
`GET /api/authorization-workbench` lists at most 100 ledger artifacts and 100 captures per artifact.
`GET /api/authorization-workbench?a=ev-id@0&b=ev-id@1&c=ev-id@2` compares two or three distinct
existing records. C is optional; A and B are required together. The selection is a human assertion
of context, not identity verification. No anonymous capture or response is synthesized.

Each column retains the complete artifact SHA-256, ledger ID and zero-based capture index.
Digests identify the original artifact, not a rewritten/redacted response. Values are compared
in memory; the underlying evidence and ledger remain unchanged. Missing, altered, unsafe,
malformed or oversized artifact references are excluded and reported by ledger ID.
References must resolve under the program directory and may not traverse symlinks.

Supported existing formats:

* HAR `log.entries`: method, status and unencoded `response.content.text`. Request URLs,
  headers, cookies, filenames and account hints never enter the projection. Base64 content
  remains unavailable rather than guessed or decoded.
* Native `type: access-control`, `steps`: saved status/predicates only. These artifacts do
  **not** contain response bodies; the view reports body unavailable and does not reconstruct
  JSON from matches. A saved top-level `access_control_assessment` is shown separately and
  is never assigned to every step. Native request methods are unavailable when not saved.
* Authorized synthetic lab envelope below. The authorization flag is an input declaration,
  not an authorization decision by the workbench.

```json
{
  "type": "authorization-workbench-lab",
  "authorized_captures": true,
  "captures": [
    {"method": "GET", "status_code": 200, "body_available": true,
     "body_text": "{\"success\":true,\"owner\":\"synthetic\"}"}
  ]
}
```

Captures may include an already saved `assessment` object containing a `classification` and
`reason`; this is displayed as saved metadata, never recomputed. A present response is labeled
`denied_saved` only when that capture's saved assessment explicitly says `denied`. Status alone,
including 401/403/404 or 200, never supplies that classification. Transport errors and absent
status are `missing`, even when an unrelated assessment exists. Global assessments remain global.
Predicate-only native captures can therefore show HTTP 403 with no saved per-response decision.
The stored public engine explanations in a small display allowlist are preserved verbatim;
other free text is withheld to prevent private marker leakage. Saved boolean predicates remain
visible as deterministic reasoning. No new denial classifier exists here.

## Difference semantics and privacy limits

JSON paths align by property and arrays by index, not resource identity. Each row distinguishes
absent properties, unavailable bodies, JSON null, empty strings/objects/arrays, and scalar types.
Changed values are highlighted from a type-sensitive comparison **before** minimization.
Unavailable bodies are excluded from difference decisions; unavailable is not a denial.
Container rows also change when any descendant changes. These are observed differences, not
vulnerability findings. HTTP 200, shared resources and public content require human interpretation.

All scalar values are withheld, including innocuous strings/numbers, preventing unknown private
markers from leaking through ordinary fields. Only a small set of ordinary property names is
shown literally; other keys use opaque `field-N` labels consistently within the selected view.
Those aliases are not original RFC 6901 pointers and are not stable across different selections.
Types, shapes, array lengths, difference positions, safe keys, ledger IDs and artifact SHA-256
remain visible intentionally. Use public-safe ledger IDs. Never put secrets in ledger IDs.

Parsing rejects duplicate keys. Limits are 2 MB per artifact, depth 20 and 1,000 nodes per JSON
body. Exceeding a field/depth bound withholds the entire body projection; no partial completeness
claim is made. Non-JSON/HTML bodies are withheld. The UI uses `textContent`, never HTML injection.
The full document digest remains available; body fingerprints are never returned.

## Audit and baseline

Pinned base and observed `origin/main` both were
`bd289808600d57983f1dcacaa9b68c0d7eea0d18`, the merge of PR #52.
The isolated branch is `feature/authorization-comparison-workbench`.

Audit findings:

* `dashboard.py`: loopback middleware and read views; `/api/access-matrix` exposes predicates,
  not aligned response fields. Existing import functionality remains separate.
* `dashboard_triage.py`: validated ledger queue and minimized candidate provenance, without bodies.
* `access_control/comparison.py`: bounded JSON parser, pointers, explicit controls and predicate-only
  read evidence. Reuse its parser; never instantiate its active tester from this view.
* `access_control/function_matrix.py`: role controls/predicates; no bodies to fabricate for this view.
* `analysis/evidence_ledger.py`: append-only evidence IDs, SHA-256 and validation; the view reuses
  ledger loading/validation and does not call mutators.
* `analysis/evidence_engine.py`: HAR/native adapters and minimized correlations; minimized records
  do not restore omitted response bodies.
* `reporting/dossier_verifier.py`: integrity/claim checking is separate from visual comparison;
  changing or displaying a difference cannot advance ledger/claim state.
* `analysis/access_assessment.py` (PR #52): sole assessment authority; no algorithm changes.

Baseline was measured against the original dashboard source exported from the pinned commit,
not inferred from the modified application. Its workbench route returned 404 and supplied zero
aligned JSON fields. Comparing raw A/B/C bodies required a separate manual workflow; no human
completion time or unsupported numeric step estimate is claimed.

| Metric | Pinned baseline | Workbench, local sample |
| --- | --- | --- |
| Three-way comparison | Unavailable | Select A/B/C and compare (4 interactions) |
| Aligned JSON nodes for A/B/missing fixture | 0 | 10 |
| Legacy matrix endpoint median, 25 calls | 1.505 ms | Not the same operation |
| New projection endpoint median, 25 calls | Unavailable | 2.969 ms |
| Browser comparison DOM, one sample | Unavailable | 68.823 ms (includes automation overhead) |
| False differences, two explicit oracle checks | Not measurable in existing view | 0 |
| Lost SHA-256 references in selected columns | Not applicable | 0 |
| Missing response shown as denied | Not applicable | 0 |
| Ledger modifications | 0 | 0 |

These timings characterize this machine and fixture only; the legacy endpoint performs less work.
They are not a speedup claim. The baseline source was reconstructed after initial implementation;
it is the exact original source, but this is a deviation from measuring before edits in FASE 0.

## Validation and lab

Run `python -m labs.authorization_workbench_eval.run` for in-process measurements with socket
connect blocked. `tests/test_authorization_workbench.py` adds adversarial tests for per-run
private/JWT canaries (never printed), HTML, path/key leakage, changed/missing/symlinked references,
public/shared content, HTTP-200 saved denial, arrays, large fields, malformed JSON, body limits,
read-only behavior, Host/Origin rejection and pair/trio selection. Synthetic fixtures generate
no requests. Canaries are created in temporary test storage, never committed or reported.

Browser QA uses headless Chrome with same-origin requests fulfilled directly by the ASGI
TestClient and rejects any external page request; it verifies three columns, highlighted rows,
toggle behavior and a narrow viewport. Run the optional browser harness documented in the lab.

Final local verification: 954 tests passed with coverage instrumentation before the final duplicate-ID
hardening test; focused tests were repeated after that addition. Ruff check/format and both repository
and explicitly scoped new-module `mypy --strict` checks passed. Projection coverage was 97%, existing
dashboard 83%, and full-suite coverage met the repository threshold. Remote CI status belongs to the PR.
