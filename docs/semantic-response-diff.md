# Evidence-preserving semantic HTTP response diff

`analysis/semantic_response_diff.py` compares **two already stored** HTTP
responses. It never builds or sends requests, never executes JavaScript, never
loads external resources, and never emits a vulnerability verdict or a
`confirmed` / `finding_confirmed` state. Version remains 0.2.2.

Denial classification stays the authority of
`analysis/authorization_denial.py` (PR #52). This module only attaches that
module's public `assess_response` result verbatim on each side for context.

## Phase 0 audit and measured baseline

Independent branch from current `origin/main`
`8bbbb9b9bd12b328f2095903562c595190ea439f` (GLOBAL pin was
`bd289808600d57983f1dcacaa9b68c0d7eea0d18`; main had advanced with PRs #53–#54).
PR #52 was already merged; its algorithms are not modified.

Audited interfaces:

| Component | Existing behavior and reuse decision |
| --- | --- |
| `requests_engine/response_analyzer.py` | Extracts status, size, content-type, markers. Not a structural diff — keep as-is. |
| `access_control/comparison.py` | `exact` / duplicate-key-rejecting `parse_json` for access-check workflows. Pattern reused locally; module not changed. |
| `analysis/evidence_engine.py` | Evidence packaging; not a response comparator. Untouched. |
| `analysis/access_assessment.py` / `authorization_denial.py` | Denial authority (PR #52). Consumed only via public `assess_response`. |
| `reporting/evidence.py` | Report helpers. Untouched. |
| `authorization_workbench.py` / dashboard UI | Separate visual comparator (PR #53). **Not modified**; optional future integration. |

`python -m labs.semantic_response_diff_eval.baseline` measures naive
status + content-type + exact-body equality on the synthetic corpus. Committed
`before.json` shows high false-positive diffs on key-order / charset cases and
no field-level recall. That is a representation baseline, not a claim that a
semantic engine already existed.

## API

```python
from bugbounty_toolkit.analysis.semantic_response_diff import diff_responses

doc = diff_responses(
    {"status_code": 200, "headers": {"content-type": "application/json"},
     "body": '{"id":1,"owner":"alice","timestamp":"t1"}', "origin_ref": "a"},
    {"status_code": 200, "headers": {"content-type": "application/json"},
     "body": '{"id":1,"owner":"bob","timestamp":"t2"}', "origin_ref": "b"},
    ignore_volatile=["timestamp"],  # explicit + recorded; never hides owner/id
)
```

Compared dimensions: status; Content-Type; Location; Content-Length declared vs
observed; JSON keys / types / added / removed / value fingerprints; arrays and
order; safe HTML tag/attribute-name skeleton (data only); non-sensitive headers;
schema / body-kind shifts.

Output schema `bbtk-semantic-response-diff/1` distinguishes:

* `structural_equality` — no remaining changes after recorded normalizations
* `similarity` — identical / high / medium / low
* `behavioral_equivalence` — same status class + content-type family + schema
  shape without authz-relevant value shifts

**Structural equality is not authorized access. Behavioral equivalence is not a
vulnerability.** Reflected identifiers appear only as fingerprints.

## Safety limits

* Max body bytes (default 1_000_000), JSON depth 32, nodes 20_000, HTML tags
  5_000, emitted changes 500.
* Duplicate JSON keys rejected; malformed bodies become opaque.
* Sensitive headers report presence-only diffs.
* Values never copied into the shareable document — fingerprints + types only.
* Volatile ignore rules are explicit, listed in `normalizations_applied`, and
  refused for ownership / identity / permission / sensitive tokens.

## Lab metrics (after)

See `labs/semantic_response_diff_eval/after.json`. Aggregate targets: precision /
recall of relevant diffs, zero false equivalences that hide authz fields, zero
dangerous normalizations, valid JSON outputs, bounded latency/memory, zero
secret leaks, zero external traffic.

## Non-goals

* No requests, no dashboard / workbench UI changes, no denial-classifier edits.
* No auto-confirmation; eligibility unchanged.
* No aggressive normalization that collapses distinct authorization outcomes.
