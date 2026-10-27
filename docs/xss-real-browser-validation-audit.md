# XSS real-browser validation audit

Audit for the P04 lab (`labs/xss_real_browser_eval/`). Base `bbd0068f90b0f411360519434008ccdcfcbaaae0`. Package version `0.2.2`. This note records how browser evidence works today. It does not change detector behavior.

## Gap this lab closes

`labs/xss_evidence_v2_eval/evaluate.py` scores 16 structured scenarios from captured bodies and synthetic observation dictionaries. It blocks Python sockets, then reports `browser_time_seconds: 0.0`. That figure is parser time, not Chromium time. Nothing in that evaluator navigates a page.

The modules below already observe execution on disposable loopback apps when an operator opts in. They do not cover the A–P matrix (CSP block, hung page, external navigation, JSON non-execution, sanitize-before-sink) and they do not publish allowed/blocked request counts.

## `xss/parameter_tester.py`

`XssParameterTester.run` is the reflected batch driver.

- Default path: one request per payload, then `reflection_detector` + `result_validator` + optional `analyze_html`. No browser. `browser_execution_observed` is stored as `False`.
- `finding_confirmed` is set `False` on each result and is not turned on later.
- `confirmed` stays false unless the opt-in `--confirm-exec` path receives `PlaywrightExecutionChecker` classification `"confirmed"` (marker or alert). That flag means a harmless marker ran in the laboratory browser. It is not `finding_confirmed`.
- Context enrichment (`classify_reflected_context`) is additive and does not override `confirmed`.
- Skip / stop: transport error, HTTP 401/403/429, truncated body, browser or budget error. DOM and stored modes delegate to `run_dom_local` / `run_stored_local` and never run the reflected batch.

## `xss/playwright_confirm.py`

`PlaywrightExecutionChecker.confirm` opens headless Chromium and checks one URL.

- Missing `playwright` package: `require_playwright_installed` raises `RuntimeError` (callers surface this before navigation).
- Chromium executable missing or launch failure: `RuntimeError` naming `playwright install chromium`.
- `classify_execution`: marker or alert → `"confirmed"`; otherwise `"reflected_not_executed"` when the caller passes `reflected=True`. `confirm` always passes `reflected=True`, so the checker itself never returns `"not_reflected"`.
- The return dict has `classification`, `marker_observed`, `source_marker_present`, `alert_observed`, `dom_sinks`, `dialogs`, `console_errors`, `page_errors`. It does **not** include HTTP status, content-type, navigation origin, runtime, or allowed/blocked counts. `finding_confirmed` is absent. `confirm` does not write a vulnerability verdict.
- Marker: page sets `window.__bbtk_xss_marker` to the innocuous token. Alerts are accepted and recorded.
- Sinks hooked from an init script: `innerHTML`, `outerHTML`, `insertAdjacentHTML`, `document.write`, `document.writeln`. A cross-document navigation records `location`.
- `local_only=True` (used by `dom_local`): `require_literal_loopback` (literal `127.0.0.1` or `::1` only; `localhost` rejected), service workers `"block"`, WebSockets closed.
- Every request must match the navigation origin and `ScopeValidator` or the route is aborted. Non-loopback HTTP is aborted in local mode because the origin check fails. Aborts are not counted.
- Navigation failure becomes `ToolkitError`. Budget and rate-limit errors abort the route and propagate.

## `xss/dom_local.py`

Opt-in `--dom-local` probes. Query and hash, plain marker and execution marker (`<img src=x onerror="window.__bbtk_xss_marker=...;alert(...)">`).

Classifications: `execution_observed`, `sink_reached`, `source_present_only`, `inconclusive`, `error`.

`confirmed` is true only when the marker or alert ran. `finding_confirmed` is always false. `assess_dom_result` adds `dom_state` without inferring execution from a sink.

Skip: non-loopback URL (`ValueError` before any browser call), `max_tests` cap, browser/budget error (stops the batch).

## `xss/evidence_record.py`

DOM states, in priority order: `inconclusive_browser_error`, `execution_observed`, `execution_blocked_csp`, `interaction_required`, `sanitization_applied`, `sink_reached`, `source_observed`, `inconclusive`.

CSP blocking comes from console/page error text, not from the header alone. A sink without a marker execution stays `sink_reached`. `build_browser_evidence` always sets `finding_confirmed=False`. `assert_minimized` rejects cookies, tokens, storage, and raw HTML bodies.

## `xss/context_classifier.py`

Offline only. Locates an innocuous marker in bytes already captured. Decisions (`candidate`, `needs_browser_confirmation`, `escaped_safe`, abstentions) never claim execution. `finding_confirmed=False`. A marker inside a closed JavaScript string is `js_string` / `escaped_safe` even when surrounding bytes broke out of an outer string. This audit does not change that rule.

## `labs/web_vuln_lab`

Standard-library server on `127.0.0.1`. Routes `/xss/reflected`, `/xss/escaped`, `/xss/ambiguous` feed the reflected classifier tests. The README states the server does not launch a browser and that reflection is not execution. No CSP, hash, timeout, or external-block routes.

## `tests/test_dom_xss_local_browser.py`

Skipped unless Playwright and its Chromium binary launch. Disposable loopback page: `innerHTML` (execution) versus `textContent` (no execution) via `run_dom_local`. This is two sinks, not the A–P matrix, and it does not record request counters.

## `docs/dom-xss-local.md`

Documents the opt-in loopback command, the difference between `source_marker_present`, `sink_reached`, and `execution_observed`, and the same-origin abort of external HTTP. WebSockets blocked and service workers disabled only in `local_only` mode.

## What P04 adds (and what it leaves alone)

New code lives under `labs/xss_real_browser_eval/` and `tests/test_xss_real_browser_eval.py`. It drives the existing classifier and `evidence_record` against disposable endpoints A–P and, when Chromium is installed, records real navigation observations. It does not retune `context_classifier`, `reflection_detector`, XSS Evidence v2 labels, or any Evidence Ledger history. `finding_confirmed` stays false on every new output. Version stays `0.2.2`.
