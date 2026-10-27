# DOM observability v3 — audit

FASE 1 notes for the loopback DOM observer. This does not retune any FINAL
labels and does not edit `labs/xss_real_browser_eval/` (that lab is not on this
base; it belongs to the Chromium validation work).

## Modules read

| Module | Role on this base |
| --- | --- |
| `bugbounty_toolkit/xss/dom_local.py` | Loopback preflight, query/hash probe URLs, `run_dom_local` classifications |
| `bugbounty_toolkit/xss/playwright_confirm.py` | `PlaywrightExecutionChecker.confirm` |
| `bugbounty_toolkit/xss/evidence_record.py` | `DomObservation`, `classify_dom_state`, minimized evidence |
| `bugbounty_toolkit/xss/context_classifier.py` | Offline reflected-context classifier. Not a DOM hook. Left unchanged |
| `docs/dom-xss-local.md` | Documented DOM local v2 limits |

## What DOM local v2 actually does

`run_dom_local` only accepts literal loopback routes. Each probe is a plain
marker and an execution marker, in the query and in the hash. The browser path
is `PlaywrightExecutionChecker.confirm(..., local_only=True)`:

* Hooks are installed with `context.add_init_script` before page scripts, but
  only for `innerHTML`, `outerHTML`, `insertAdjacentHTML`, `document.write`,
  and `document.writeln`.
* After `domcontentloaded`, execution is polled for at most **300ms**
  (`wait_for_function` timeout `min(timeout_ms, 300)`).
* `source_marker_present` is true when `location.search` or `location.hash`
  contains the marker. That is URL presence, not proof the page read it.
* `dom_sinks` are read from the **main** frame's `window.__bbtk_dom_sinks`.
* Non-loopback HTTP(S) is aborted. WebSockets are closed in local-only mode.
* `assess_dom_result` copies `source_marker_present` into `source_observed`.
* `classify_dom_state` never treats a sink alone as execution.
* `finding_confirmed` is false. `confirmed` is true only when execution was
  observed. v3 does not emit `confirmed: true`.

## Documented limits (`docs/dom-xss-local.md`)

The v2 document says instrumentation can miss:

1. Sinks invoked before a hook is installed.
2. Isolated frames.
3. Asynchronous code after the load event.
4. Client-side flows the fixture does not exercise.

Code reading adds three concrete gaps the document only implies:

* The 300ms post-`domcontentloaded` budget drops later timers.
* Child frames are not aggregated, including same-origin iframes.
* URL presence is reported as a source observation.

`context_classifier.py` does not observe the DOM. It stays out of this change.

## What this brief changes

| Limit | v3 behavior |
| --- | --- |
| Sink before hooks | v3 installs the init script before page scripts and records install status. A late-attach trace is still classified as a miss for v2. |
| Async after load | v3 waits a bounded 1500ms from navigation and honors declared lab interactions (`setTimeout`, `Promise`, loopback `fetch`, click, delayed render, SPA route, `hashchange`, `popstate`, late insert). |
| Frames | Same-origin frames are read through `contentDocument`. Sandboxed and cross-origin frames are `unsupported`. Missing and unmounted frames are `inconclusive`. No SOP bypass. |
| Source in the URL, never read | `source_available` may be true while `source_observed` stays false. |
| `innerHTML` alone | Still not execution. |

## Baseline before this branch

`python -m coverage run -m unittest discover -s tests -q` on
`bbd0068f90b0f411360519434008ccdcfcbaaae0`:

* 1176 tests ran
* 40 skipped
* 1 error, pre-existing: `test_offline_lab.SuiteRunnerExclusionTests.test_excluded_tests_are_reported_as_skips_not_dropped` (`ImportError: Start directory is not importable` for a temp directory)
* elapsed about 153s

Package version was `0.2.2`.

## P04 merge fields

Consumers, including a future Chromium validation lab, can merge records with
schema `bbtk.dom-observability.v3`. Field names are listed in
[dom-observability-v3.md](dom-observability-v3.md). This branch does not import
or modify that lab.
