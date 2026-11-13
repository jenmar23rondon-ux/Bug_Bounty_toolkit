# Advanced research platform: first incremental audit

Audit base: `b45520f6ee84531e3da0182f59575990ec9ef1c3` (PR #110).
This is the first bounded improvement, not completion of every platform phase.

## Existing components to preserve

| Capability | Existing implementation | Audit decision |
|---|---|---|
| Capture import and identity provenance | `burp_import`, `case_generator`, `analysis/evidence_engine`, `analysis/actor_provenance` | Reuse; session fingerprints do not prove separate accounts. |
| Object relationships and authorization | `analysis/object_relationships`, `object_handoff`, `idor_pairing_precision`, `authorization_denial`; `access_control` | Preserve pairing gates, contradiction handling and read/write approval boundaries. |
| Workflow, memory and graph | `analysis/api_workflow`, `evidence_graph`, `investigation_workflow`, `evidence_ledger` | Extend contracts rather than introduce another graph/database. |
| Planning | `analysis/business_logic_planner`, `evidence_gap_planner`, `request_variation_plan`, `skill_router` | Already implemented; plans are not proof or execution authority. |
| AI review | `analysis/ai_backend`, `evidence_review`, `artifact_review`, `live_review` | Keep optional, sanitized and separate from deterministic verdicts. |
| Native checks and dashboard | `xss`, `sqli`, `ssrf_check`, `cors_check`, `open_redirect`, `dashboard`, `dashboard_triage` | No replacement scanner or frontend needed for this increment. |
| Evaluation | `labs/independent_research_eval`, real-browser XSS lab, CI coverage gates | Preserve frozen DEV/FINAL/STRESS captures and labels. |

Recent main changes already tightened IDOR pairing, collapsed equivalent proposals,
recovered object kinds, and added repeated boolean SQLi controls. Those changes are
not reimplemented here. PR #110 was verified merged. Connector search returned an
empty result for open PRs; this is not proof that no concurrent work exists.

## Selected issue: authorization capture status integrity

The offline authorization parser recognized only HTTP/1.0 and HTTP/1.1, losing
status codes in textual HTTP/2 and HTTP/3 response exports. A clean 403 could
therefore become inconclusive and a valid owner control could become unproven.
Its previous word-boundary status matcher also accepted `200.0`, `200:OK`,
`200-OK`, `200/OK`, and Unicode digits as a successful status token.

The fix accepts complete ASCII 100–599 status tokens for supported textual
versions. Malformed or unknown status stays unknown. Existing response-body,
visibility, ownership-control and contradiction rules are unchanged. Neither
HTTP 200 nor this parser confirms an authorization vulnerability.

### Reproducible development regressions

`tests/test_authorization_capture_status.py` supplies 80 synthetic subcases:
40 protocol/scenario cases, 16 mixed-protocol controls, 12 malformed lines,
8 body/header preservation cases, and 4 absent captures. These are development
regressions, not an independent holdout or real-target effectiveness estimate.

Run:

```sh
python -m unittest tests.test_authorization_capture_status tests.test_contradictory_denial_guard -v
```

The five new test methods were run against the audit-base implementation before
the fix: 43 subcase failures. After the fix: zero failures. The combined run with
the nine existing contradiction regressions passes all 14 test methods.

### Frozen benchmark regression measurement

[Actions run 43160039562](https://github.com/jenmar23rondon-ux/Bug_Bounty_toolkit/actions/runs/43160039562)
executed the actual evaluator on Linux for both the audit base and proposed
commit `46f6f064328a6bfad076ad2e3c2ba25eb1f6020f`. The overall and per-family
scores, scenario outcomes, and frozen manifest hashes are identical:

| Split | Scenarios | Pairing precision / recall, before and after | Outcome accuracy, before and after |
|---|---:|---:|---:|
| DEV | 6 | 1.0 / 1.0 | 1.0 |
| FINAL | 45 | 1.0 / 1.0 | 0.9111 |
| STRESS | 6 | 1.0 / 1.0 | 1.0 |

False-reviewable cases, automatic confirmations, secret leaks and network
attempts remain zero on all three splits. These are synthetic corpus results,
not real-world precision estimates. The new capture regressions measure the
fix; the unchanged frozen corpus measures absence of regressions.

The three result snapshots are copied from the measured proposed artifact,
not edited scores. Artifact SHA-256 values were verified before reading:

- Base: `6024a1aede8df4a242a41c3ffe73bd0f8ffc363e4d816ab1ad3db3ea7302c596`.
- Proposed: `6ec20f8077fa0672a79ec2213bb94b94df1198f06505aaa7d7dacb9350bcf6da`.

The artifact commit and production-source digest were checked against the
checkout. Only timing/memory observations and the source binding change in
recorded results; frozen inputs and labels remain untouched.

## Validation and limits

- Baseline Ruff lint and formatting passed (539 files). New regression formatting
  and lint are checked with the same directory-wide configuration.
- A full Windows suite attempt ran 1,427 tests with 26 failures, 220 errors and
  52 skips. It is not a passing release validation. POSIX-only private filesystem
  protections fail closed on Windows; snapshot/platform checks also fail there.
- Native Windows strict mypy reported 21 existing POSIX attribute errors across
  six files. Linux-target typing and Linux CI are separate validations; neither
  means those runtime APIs work on Windows.
- Linux CI must validate the full suite, coverage and actual frozen benchmark
  snapshots before this PR is ready. No frozen labels or captures are changed.
- Textual response parsing is not an HTTP/2 or HTTP/3 binary frame decoder and
  does not extend request importers that deliberately require HTTP/1.x.
- No third-party checks, Ollama evaluation, model downloads, release or merge.

## Next highest-value work

Audit the input contracts between capture import, handoff and authorization
assessment, including malformed and incomplete exchanges. Measure on independent
development cases before another production change. Keep the frozen benchmark
as regression evidence, not a tuning set. Windows private-file portability is a
separate security design task; do not bypass its fail-closed checks to make tests
green. A real Ollama comparison remains optional and unexecuted in this increment.

That contract audit is recorded in `docs/capture-ingestion-robustness.md`.
The ingestion increment keeps clean HTTP/1.1 discovery on the strict parser,
adds a diagnostic path for incomplete and mixed captures, and does not confirm
findings. External Nuclei, ZAP, FFUF and SQLMap results now map onto
`bbtk.external-finding/1` (`docs/external-importers.md`); an imported alert
cannot become `confirmed`. The following PR should rank those hypotheses and
abstain when the information needed to compare them is missing.
