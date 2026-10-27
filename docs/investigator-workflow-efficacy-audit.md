# Investigator workflow efficacy — current-flow audit

This note records the toolkit **as it exists before** the disposable
investigator-workflow lab. No detector, label, or workflow engine code was
changed to produce it. Numbers below were executed in this workspace. Anything
not executed is `NOT_MEASURED`.

## Base

| Item | Value |
| --- | --- |
| Brief expected `origin/main` | `bbd0068f90b0f411360519434008ccdcfcbaaae0` |
| Fetched `origin/main` | `ae9d93d7c73b6747ed346b9fed96ce09adabc74d` |
| Branch base used | `ae9d93d7c73b6747ed346b9fed96ce09adabc74d` |
| Package version | `0.2.2` (`pyproject.toml`, `bugbounty_toolkit.__version__`) |
| Local interpreter | CPython 3.12.3 |

`origin/main` moved past the brief pin because other wave-5 pull requests merged
(`#72` IDOR pairing precision v4, `#75` XSS real-browser validation, `#77` IDOR
false-negative recovery, and the in-progress `#74` authorization work was not
the base). Branching from current `main` keeps the audit on the detectors an
investigator would actually run. This work does not edit those modules.

## Baseline test suite

Command: `python3 -m unittest discover -s tests -q`

| Result | Value |
| --- | --- |
| Ran | 1217 |
| Failures | 0 |
| Errors | 1 |
| Skipped | 5 |
| Runtime | 111.117s |

The error is `test_offline_lab.SuiteRunnerExclusionTests.test_excluded_tests_are_reported_as_skips_not_dropped`:
`ImportError: Start directory is not importable` on a temporary directory.
It passes when that test is loaded alone. It also passed on GitHub Actions
CPython 3.12.15 (`coverage run -m unittest discover -s tests -v`, run
`40555375131`, result `ok`). Local skips are higher than that CI run
(`skipped=2` there), consistent with Chromium not being installed in this
workspace. This audit does not change `scripts/offline_lab/run_suite.py`.

## Measured current labs (unchanged code)

`python3 -m labs.investigation_workflow_eval.run_lab`

| Metric | Value |
| --- | --- |
| scenarios | 13 |
| states_correct / states_expected | 17 / 17 |
| network_requests_sent | 0 |
| executions | 0 |
| commands_emitted | 0 |
| auto_confirmations | 0 |
| unauthorized_modifications | 0 |
| workflow_without_ai_ok | true |

`python3 -m labs.security_research_eval_v2.evaluate --split all`

| Split | Cases | Accuracy | secret_leaks | finding_confirmed_true | external_requests |
| --- | --- | --- | --- | --- | --- |
| DEV | 11 | 1.0 | 0 | 0 | 0 |
| FINAL | 14 | 1.0 | 0 | 0 | 0 |
| STRESS | 42 | 1.0 | 0 | 0 | 0 |

`bbtk lab idor --dry-run` exited 0 and printed a 12-line plan. It sent no
requests.

Historical IRB FINAL figures are **not** re-measured here. They stay as
published in `docs/independent-research-benchmark.md` (outcome accuracy 0.667
on 45 synthetic scenarios, secret leaks / auto-confirmations / network attempts
0 / 0 / 0). This audit does not edit those labels.

## What an investigator can do today

The pieces of the chain exist, but they are separate documents and commands.

| Stage the new lab will require | Where it lives now | Gap observed before any new workflow |
| --- | --- | --- |
| Scope | `docs/HUNT.md`, `bbtk scope` | Hunt names checks that can reach confirmed. It does not compare a manual control arm. |
| Lab | `labs/idor_lab`, `labs/web_vuln_lab` | IDOR and XSS/SQLi are different loopback apps. Disclosure audience is not in either app. |
| Capture → import | `docs/idor-playbook.md`, `bbtk import burp`, `docs/burp-passive-bridge.md` | Burp import and the passive bridge move already-captured bytes. They do not score a manual checklist. |
| Integrity / discovery / candidates | `investigation_workflow.py` | Review-only graph. Doc states there is no CLI subcommand. It never runs tools. |
| XSS / disclosure engines | security-research benchmark v2 | Frozen JSON cases, not a live disposable app and not a manual-vs-bbtk timing study. |
| Dossier / triage | `dossier_verifier.py`, `unified_security_triage.py` | Verifier and unified view stay read-only. `finding_confirmed` is forced false in the unified view. |
| Human review | ledger `review` | Confirmation needs an explicit human attestation. Nothing in this audit auto-confirmed a finding. |

`docs/quickstart.md` starts `bbtk lab idor` and `bbtk lab web-vuln`. It does not
describe a manual control, a dossier tutorial, or productivity metrics.

## Not measured in this audit

| Item | Reason |
| --- | --- |
| Human minutes, tool switches, researcher errors | No human investigator session was timed. |
| Manual-vs-bbtk candidate counts on one app | That comparison did not exist yet. |
| Field bug-bounty efficacy | These commands used fixtures and dry-runs only. |
| DOM browser execution | The v2 DOM rows classify stored observations. This audit did not launch Chromium. |

## Constraint check for this audit commit

- Version remains 0.2.2.
- No FINAL label or Evidence Ledger history was edited.
- `finding_confirmed` was not set true by the commands above (`finding_confirmed_true` 0 on v2; `auto_confirmations` 0 on the workflow lab).
- No third-party URL was requested by those commands (`external_requests` 0, `network_requests_sent` 0).
