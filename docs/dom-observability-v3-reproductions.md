# DOM observability v3 — reproductions

Measured on this branch after the FINAL corpus was frozen. `finding_confirmed`
stays false. Live checks used loopback `127.0.0.1` only.
`external_requests` on the live run was 0.

Bundled Playwright Chromium (the browser `PlaywrightExecutionChecker` launches
with no channel override) is **NOT_MEASURED**: it is not installed in this
environment (`Error` on `chromium.launch()`). The live rows below use system
Chrome through Playwright. Trace rows use the v2/v3 classifiers on the DEV
corpus cases.

## 1. Sink before hooks

Trace `dev-prehook-inert` (hooks modeled as installed at `domcontentloaded`,
inert `innerHTML` before that):

| Observer | Outcome | Notes |
| --- | --- | --- |
| v2 | `not_observed` | Legacy classification `source_present_only` because the marker is in the URL |
| v3 | `observed` | Sink `innerHTML`, execution false |

Live system Chrome, page assigns the marker with `innerHTML` during the inline script:

| Install | Sinks recorded | Execution |
| --- | --- | --- |
| `add_init_script` before page code | `innerHTML` | false |
| Same hook evaluated after load | none | not claimed |

DOM local v2 already uses `add_init_script`, so this inline sink is visible to
the current Playwright path. The miss is the late attach, which is what the v2
document describes.

## 2. Async sink after load

Trace `dev-settimeout` (sink and marker execution at 450ms; v2 budget is
`domcontentloaded + 300`):

| Observer | Outcome | Execution |
| --- | --- | --- |
| v2 | `not_observed` | false |
| v3 | `observed` | true, mechanism `marker_assignment` |

Live page uses `setTimeout(..., 400)`:

| Window | Execution observed |
| --- | --- |
| 150ms | false |
| 800ms | true |

## 3. Isolated frame

Trace `dev-isolated-frame` puts a sink and an execution event inside a sandbox
without `allow-same-origin`. v3 outcome is `unsupported`, with empty sink refs
and execution false. v2 does not read that frame either.

Live `<iframe sandbox>`: outcome `unsupported`, `sink_refs` empty, execution
false. The child document was not read through the debugger protocol.

## 4. Source present in the URL, never read

Trace `dev-url-unread`: v3 `source_available` true, `source_observed` false,
outcome `not_observed`. v2 legacy classification is `source_present_only`.

Live static page opened with the marker in the hash: `source_available` true,
`source_observed` false, outcome `not_observed`.

## Extra live measurement

`location.hash`, `location.search`, and `location.href` are non-configurable
instance accessors in this Chrome. The hook records
`location.hash_unhookable` and does not invent a source read. `document.URL`
is configurable and is recorded when page code reads it.
