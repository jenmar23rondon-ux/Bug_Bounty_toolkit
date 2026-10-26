# Offline authorized request variation planner

`analysis/request_variation_plan.py` prepares versioned, private resource diffs
from **one previously saved capture** and an explicit lab declaration. It never
sends HTTP, changes sessions, invokes tools/AI, approves cases, or confirms
findings. No ranges, arithmetic, inferred IDs or generated UUIDs are supported.
Version remains 0.2.2.

## Phase 0 audit and measured baseline

The independent branch began at
`bd289808600d57983f1dcacaa9b68c0d7eea0d18`; `origin/main` matched that SHA.
PR #52 was already merged. Its denial assessment is neither changed nor
replicated: this planner does not interpret responses as access evidence.

Audited interfaces:

| Component | Existing behavior and reuse decision |
| --- | --- |
| `idor_discovery.py` | `discover_idor` pairs real saved owner/actor captures; `approve_idor` remains the separate human gate. Do not manufacture actor captures or turn diffs into IDOR proposals. |
| `case_generator.py` | `inspect_read_pair` represents a single path/query difference, requires distinct captured sessions and rejects GET bodies. Keep these rules intact; a same-session variation is not a new two-account control. |
| `access_control/comparison.py` | `replace_pointer` supports exact JSON body replacement in the separate disposable write workflow. Reuse `exact`, duplicate-key-rejecting `parse_json`, and `pointer_parts`; do not activate write support here. |
| `object_handoff.py` | Existing graph-backed handoff/export remains authoritative for observed pairs, not a place to insert planned variants. |
| `handoff_case_eligibility.py` | A planned diff is not captured evidence or an eligible case. No eligibility status is promoted. |
| `evidence_gap_planner.py` | Follow its offline, review-only contract; no ledger, memory or confirmation changes. |
| `core/scope_validator.py` | Require existing scope rules for both original and proposed URL, including exclusions. No scope edits. |
| `burp_import.py` | Reuse `parse_captured_exchanges` for full HTTP/Burp XML syntax, Host/origin/provenance consistency and paired-response validation. |
| `core/private_files.py` | Reuse bounded no-follow input and exclusive atomic mode-0600 publication; newly created directories are mode 0700. |

Before implementing the planner, `python -m labs.request_variation_eval.baseline`
measured the existing read-pair API against seven synthetic categories. The
committed `before.json` records **3/7 representable categories**: numeric path,
UUID path, query. Two-field changes, GET JSON bodies, POST and signed query URLs
were rejected. This is a representation baseline, not a claim that the old API
planned variations. No declaration-driven offline variation planner existed;
its generation/rejection/type metrics are therefore **not applicable** before.

## Declaration and private use

The complete runnable example is `labs/request_variation_eval/example.py`.
It writes only synthetic inputs and a private diff into a new local directory.
The declaration is `bbtk-lab-resources/1`:

```json
{
  "schema_version": "bbtk-lab-resources/1",
  "lab_authorized": true,
  "origin": "https://lab.test",
  "accounts": [
    {"name": "alice", "authorized": true},
    {"name": "bob", "authorized": true}
  ],
  "resources": [
    {"name": "own", "account": "alice", "value": 101, "synthetic": true},
    {"name": "other", "account": "bob", "value": 202, "synthetic": true}
  ],
  "source": "own",
  "targets": ["other"],
  "selector": {"path_segment": 1}
}
```

`path_segment` is zero-based after leading slashes, consistent with the IDOR
read selector. Alternatively use `{"query_parameter":"id"}`. Only explicit
target references are considered; ownership and distinct accounts are never
inferred from cookies. IDs must be declared nonnegative 63-bit integers or
bounded alphanumeric/underscore/hyphen strings, including known UUIDs. A string
`"202"` cannot replace an integer `101`; no coercion between declared JSON types
is permitted. A URL field has textual wire encoding, while the diff retains the
exact declared JSON scalar types. Objects, arrays, booleans, nulls and floats are
unsupported identifiers.

```python
from pathlib import Path
from bugbounty_toolkit.analysis.request_variation_plan import save_plan

counts = save_plan(
    Path("private/capture.http"), Path("private/resources.json"),
    Path("private/scope.txt"), Path("private/variation-plan.json"),
)
```

`build_plan` returns a private dictionary. `save_plan` returns count-only output
and exclusively saves `bbtk-request-variation-plan/1` with capture/config digests,
typed single-field before/after diffs and stable incompatibility codes. There are
no raw headers, session values, full URLs, capture paths or HTTP messages in the
plan. Treat resource identifiers/diffs as private too. Publish only `summary`.
Never commit real captures, plans, secrets or canaries. New directories are 0700;
existing parent permissions are not changed and the output file is always 0600.
Symlinks, traversal, FIFOs, oversized inputs and overwriting inputs are rejected.

`validate_plan(plan, capture, declaration, scope_file)` recomputes the complete
canonical plan. It rejects forged flags/diffs, changed captures/declarations and
changed scope affecting the result. It does not authorize execution. All plan
and variant `execution_allowed`/`case_eligible` flags remain false; plan
`confirmed` and `finding_confirmed` remain false.

## Incompatibility and limitations

Only GET without a body is supported. `json_body_pointer` is syntax-validated
and explicitly marked `JSON_BODY_POINTER_INCOMPATIBLE_WITH_GET`, without body
mutation. Selecting two fields produces `MULTIPLE_FIELDS_REQUESTED`. To compare
real captures differing at two resource fields, use the unchanged IDOR pipeline,
which rejects them; do not substitute a variation for missing control evidence.
An ID repeated in unrelated fields is replaced only at the selected location.

Framing that suggests missing body bytes, multiple captures, inconsistent
origin/Host, unknown resources, duplicate query names, protected query fields,
recognizable signature headers, malformed captures and scope exclusions fail
closed. Signatures, Authorization, cookies and CSRF values are never rewritten.
Signature detection is conservative and name-based; opaque application-specific
signature conventions cannot be inferred. The researcher must declare actual
synthetic resource fields, never credentials. Loopback and reserved `.test`,
`.invalid` and `.localhost` origins are accepted without DNS resolution; public
origins are rejected even if listed in scope.

This module has no executor, case export or CLI command. A plan does not prove
that a GET has read-only application semantics or that a researcher declaration
is truthful. Existing capture collection, scope, tool policy, budget, human
approval and case-eligibility controls still govern any future work. Review the
diff against its original capture digest locally, then collect real controls
through that existing workflow. Do not present a planned variation as observed
evidence. The result contains no denial assessment.

## Reproducible lab and results

Run `python -m labs.request_variation_eval.evaluate`. The same evaluation runs
inside normal unittest discovery, so CI covers it without workflow changes.
The lab blocks socket connections and DNS. Runtime secret canaries are generated
only inside private temporary inputs, never fixture files or result output.

| Metric | Before | After (`after.json`, corpus v1) |
| --- | --- | --- |
| Existing read representation | 3/7 categories | unchanged |
| Structurally correct variations | N/A, planner absent | 5 |
| Correctly rejected incompatible scenarios | N/A | 16/16 |
| Exact declared JSON types preserved | N/A | 5/5 |
| Accidental fields altered | N/A | 0 |
| Duplicates generated / skipped | N/A | 0 / 1 |
| Unauthorized variations | N/A | 0 |
| Secrets in saved plans | N/A | 0 |
| Origin rewrites | 0 | 0 |
| HTTP requests emitted | 0 | 0 |

The 21 scenarios include numeric/UUID resources owned by two declared accounts,
query, JSON Pointer, two-field selection, sensitive cookie/CSRF/Authorization,
signed URL/header, forbidden POST/DELETE/PATCH, different origin, partial capture,
type mismatch, undeclared resource, deduplication and source mismatch. Additional
adversarial tests cover altered plans, stale inputs, exclusions on the proposed
resource, credential destinations, header ambiguity and unsafe local I/O.
These are structural synthetic-lab metrics, not vulnerability efficacy claims.

The only shared configuration change adds six files to the existing strict
mypy allowlist so CI checks the new module, lab and tests. No CLI, dependency,
workflow, public IDOR interface or version change is needed.
