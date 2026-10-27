# Stored XSS lifecycle audit

Audit of the write → store → render → browser path before the lifecycle lab.
Base commit `bbd0068f90b0f411360519434008ccdcfcbaaae0`. Package version `0.2.2`.
This note does not change those modules. DOM hooks owned by the observability
work (`dom_local.py`, the init script in `playwright_confirm.py`) stay as they
are.

## Intended lifecycle

`XssParameterTester.run` with `stored_local=True` builds a
`PlaywrightExecutionChecker` and calls `run_stored_local`.

`run_stored_local` (`bugbounty_toolkit/xss/stored_local.py`):

1. Refuses non-loopback write and render URLs via `require_literal_loopback`.
2. Posts `parameter=<payload>` through the shared `HttpClient` (scope, rate
   limit, no automatic redirects).
3. If the write returns `Location`, the render URL becomes that loopback
   location. Otherwise it uses the configured render URL.
4. Calls `checker.confirm(..., local_only=True)`.
5. Builds a `DomObservation` from `source_marker_present`, `dom_sinks`, and
   `marker_observed` / `alert_observed`, then `classify_dom_state`.
6. Writes an evidence envelope with `finding_confirmed: false` and
   `confirmed: false` on every result.

The active payload is the existing innocuous marker
`window.__bbtk_xss_marker` plus `alert`, inside an `<img onerror>`. There is
no callback and no blind-XSS endpoint.

`classify_dom_state` (`xss/evidence_record.py`) keeps execution, CSP block,
interaction, sanitization, sink-without-execution, source-only, and
inconclusive distinct. Execution is never inferred from a sink alone.
`PlaywrightExecutionChecker.confirm` (`xss/playwright_confirm.py`) is the
browser observation source. In `local_only` mode it blocks service workers
and websockets and aborts cross-origin requests.

## What current tests cover

`tests/test_xss_evidence_v2.py` checks that `run_stored_local` rejects a
non-loopback URL. The v2 corpus scores stored scenarios from synthetic
observation dictionaries. It does not run a write, a store, a second view, or
a browser against a disposable comment app. `parameter_tester` is covered for
the flag wiring, not for the seventeen lifecycle outcomes below.

## Gaps between write success and execution evidence

These are properties of the current chain, recorded here so the lab can
measure them. They are not label edits.

1. **Write-body marker is treated as a source.** `source_observed` is true
   when the marker is in the write response body, even if a later view omits
   it. A reflection on write is not stored rendering.
2. **The render body is not the source signal.** `local_only` sets
   `source_marker_present` only from `location.search` and `location.hash`.
   A comment rendered in the HTML body is invisible to that check.
3. **CSP, sanitization, interaction, and browser failure are dropped.**
   `run_stored_local` fills only source, sinks, and marker execution.
   `classify_dom_state` therefore cannot return `execution_blocked_csp`,
   `interaction_required`, or `sanitization_applied` for this chain. A CSP
   console error returned by the checker is not copied onto the result.
4. **HTTP view status is not an evidence field.** A 403 or 404 view becomes
   whatever the browser checker returns after navigation. The storage id is
   only whatever the caller put in `Location`; the result does not record it.
5. **One header set for both actors.** The writer POST and the browser GET
   share `options.headers`. The chain cannot attach a distinct viewer
   identity. The lab models the second actor as a cookieless GET.
6. **No cleanup.** The function never deletes what it wrote.
7. **No integrity hash, sanitize path, or actor on the stored-local result.**
   The lifecycle lab records those beside the chain; it does not pretend the
   chain already produced them.
8. **`finding_confirmed` stays false even when the marker executes.** That is
   intentional. Observed lab execution is not a confirmed finding.
9. **Two probes when `active_marker` is true.** The loop runs the plain marker
   first. `max_tests=1` never reaches the active `<img onerror>` payload.
   The lab sets `max_tests=2` only for cases that must see that payload.

## What the lab measures

`labs/stored_xss_lifecycle_eval/` drives cases 1–17 through `run_stored_local`
against a temp in-memory comment fixture. Expected outcomes live in
`dev/cases.json` and frozen `final/cases.json` and were written before the
FINAL measurement.

Hard rules the runner enforces on every case:

- a 2xx write does not set `finding_confirmed` or `confirmed`
- a marker in the view body does not, by itself, set execution
- cleanup leaves zero records
- Python sockets to non-loopback addresses fail and increment
  `external_requests` (must be 0)
- when Chromium is absent, the mock checker performs the loopback GET and
  live execution metrics are `NOT_MEASURED`

## FASE 0 baseline

`origin/main` resolved to `bbd0068f90b0f411360519434008ccdcfcbaaae0` (no
drift). `pyproject.toml` and `bugbounty_toolkit.__version__` are `0.2.2`.

Full `python -m unittest discover -s tests -q` before the optional extras were
installed: **1176 tests, 102.2s, 1 failure, 7 errors, 46 skipped**. Six CSRF
errors and the ruff discovery failure were missing `beautifulsoup4` / `ruff`
(`ModuleNotFoundError`). One offline-lab error was `unittest` discovery of a
temporary directory (`Start directory is not importable`). After
`pip install -e ".[dashboard,xss,sqli,jwt,http,dev]"` those CSRF, ruff, and
offline-lab tests passed in isolation (15 tests, 0.15s). Chromium was not
downloaded. Live browser execution is `NOT_MEASURED`.
