# DOM observability v3

Additive loopback observer for local DOM XSS labs. It does not replace
`run_dom_local` and it does not confirm vulnerabilities.

```bash
python -m labs.dom_observability_v3_eval.evaluate --split all
```

The evaluator is offline. It blocks sockets and refuses a FINAL corpus whose
bytes do not match `labs/dom_observability_v3_eval/final/MANIFEST.sha256`.

## Rules

* Hooks are installed with Playwright `context.add_init_script` before page scripts whenever that API is available.
* `source_available` means the marker was placed in the navigation URL. `source_observed` means page code read a hooked source API (`document.URL`, `document.documentURI`, or `location.*` when the engine allows the hook). URL presence alone is never a read.
* On the system Chrome used for the live checks, `location.hash` / `search` / `href` are non-configurable instance accessors. Those reads are reported as `location.*_unhookable` and are **not** inferred.
* Script sinks include the v2 set plus `createContextualFragment`, `eval`, `setHTML`, and `iframe.srcdoc`. `textContent` is not a script sink.
* Execution requires `window.__bbtk_xss_marker` or a dialog whose text contains the marker. An `innerHTML` write is not execution.
* Same-origin iframes are read with the page's `contentDocument`. Sandbox without `allow-same-origin`, and any other cross-origin frame, is `unsupported`. The debugger protocol is not used to read them.
* Non-loopback fetches are rejected in the hook and aborted by the route handler. `external_requests` counts both.
* Every record has `finding_confirmed: false`.

## Integrity fields

Schema: `bbtk.dom-observability.v3`.

| Field | Meaning |
| --- | --- |
| `case_id` | Laboratory case id |
| `navigation_id` | One navigation |
| `frame_id` | Frame within that navigation |
| `frame_relation` | `main`, `same_origin`, `isolated`, `no_access`, `missing`, `unmounted`, `swapped` |
| `t_rel_ms` | `navigation_start`, `instrumentation_installed`, `source_read`, `sink_call`, `execution`, `observation_end` |
| `instrumentation_status` | `installed_before_page`, `installed_late`, `partial`, `failed`, `unsupported` |
| `source_available` / `source_observed` / `source_refs` | URL presence vs an actual read |
| `sink_refs` | Hooked sink names that saw the marker |
| `execution_evidence` | `executed`, `mechanism` (`marker_assignment` or `dialog`), `claimed_from_innerhtml_alone` (always false) |
| `csp_flags` | `csp_blocked`, `restrictive_for_inline` |
| `artifact_hash` | SHA-256 of the record without this field |
| `finding_confirmed` | always false |

These names are the merge interface for later Chromium-validation results.
This branch does not edit `labs/xss_real_browser_eval/`.

## Outcomes

`observed`, `not_observed`, `inconclusive`, `unsupported`.

`dom_state` still uses `xss.evidence_record.classify_dom_state`, so a sink
without execution stays `sink_reached`.
