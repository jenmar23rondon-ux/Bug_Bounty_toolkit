# XSS real-browser validation

Disposable loopback lab that checks whether existing bbtk XSS evidence code
distinguishes execution from safe negatives in **real Chromium**. This is not a
new detector. `context_classifier` and `evidence_record` are used as they are.
`finding_confirmed` stays false.

Version stays **0.2.2**.

## Endpoints

`labs/xss_real_browser_eval/server.py` binds `127.0.0.1` only.

| ID | Route | What the page does | Expected browser state |
|---|---|---|---|
| A | `/a` | Reflects the payload as HTML | `execution_observed` |
| B | `/b` | HTML-escapes the payload | `reflection_observed` |
| C | `/c` | Quoted attribute, escaped | `reflection_observed` |
| D | `/d` | Quoted attribute, raw | `execution_observed` |
| E | `/e` | JavaScript string, escaped | `reflection_observed` |
| F | `/f` | JavaScript string, raw break-out | `execution_observed` |
| G | `/g` | `application/json` body | `reflection_observed` |
| H | `/h` | `location.hash` → `innerHTML` | `execution_observed` |
| I | `/i` | `location.search` → `innerHTML` | `execution_observed` |
| J | `/j` | Strips `<>"'`` before `innerHTML` | `sanitized` |
| K | `/k` | `location.search` → `textContent` | `source_observed` |
| L | `/l` | JSON string assigned to `innerHTML` | `execution_observed` |
| M | `/m` | Raw HTML with a restrictive CSP | `execution_blocked` |
| N | `/n` | Plain marker text, no code | `reflection_observed` |
| O | `/o` | Loads `http://203.0.113.10` and a WebSocket (blocked) | `reflection_observed` |
| P | `/p` | Document waits on `/p-hold`, which outlives the budget | `inconclusive_browser_error` |

Payloads only set `window.__bbtk_xss_marker` to a `bbtkxss…` token. They do not
read cookies, touch web storage, or call an external host. Endpoint O is the
isolation control: its fixed probe is the RFC 5737 address `203.0.113.10`, and
the route layer aborts it. A relative `src=x` on an image stays on loopback and
is counted as allowed.

## Run

```bash
python -m labs.xss_real_browser_eval.freeze   # only when the spec changes
python -m labs.xss_real_browser_eval.evaluate --split all --mode live --repeat 3 --write-results
python -m labs.xss_real_browser_eval.evaluate --split dev --mode mock
```

`--mode mock` never launches Chromium. The live block is `NOT_MEASURED`. The
mock table is a pipeline self-check, not a browser result.

FINAL `scenarios.json` is pinned by `final/MANIFEST.sha256`. The evaluator
refuses a thawed FINAL. Tune on DEV only. Do not edit FINAL labels to match a
measurement.

## Parser gaps (not retuned)

Recorded from the current classifier, then left alone:

- A, D, and M are `html_attribute` / `candidate`. The event-handler regex does
  not cross the single quote that wraps the marker, so it never emits
  `event_attribute`.
- F and L are `js_string` / `escaped_safe` because the marker sits in a closed
  JavaScript string. Chromium still executes F (string break-out) and L
  (`innerHTML`). That difference is why the parser table and the Chromium table
  are separate.

## Isolation

- Literal loopback HTTP(S) only. `localhost` is rejected.
- External HTTP is aborted. WebSockets are routed and not connected (sync
  `WebSocketRoute.close()` deadlocks inside the Playwright callback, so the
  handler returns without `connect_to_server()`).
- Service workers are blocked. No screenshots.
- `external_requests` counts non-loopback HTTP that was continued.
- `external_socket_observations` counts non-loopback TCP/UDP sockets owned by
  this process tree during the scenario. Both must be 0.
- Launch flags disable background networking. This is an interception and
  socket measurement, not a packet capture.
