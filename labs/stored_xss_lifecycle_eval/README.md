# Stored XSS lifecycle evaluation

End-to-end check of the existing `xss/stored_local.py` chain:

write → store → render → browser.

The lab calls `run_stored_local`. It does not reimplement that function and it
does not change DOM hooks in `dom_local.py` or `playwright_confirm.py`.

## Layout

- `dev/cases.json` — cases 1–17 with expected outcomes declared before the run.
- `final/cases.json` — the same outcomes, frozen.
- `final/FROZEN.sha256` — integrity pin. The runner refuses a thawed FINAL.
- `server.py` — disposable in-memory comment fixture. Loopback only. Reset
  deletes every record.
- `checker.py` — mock navigation used when Chromium is not installed. It never
  reports JavaScript execution.
- `results/` — measured reports. Live execution metrics are `NOT_MEASURED`
  unless a local Chromium binary was actually launched.

## Cases

1. Saved, never rendered
2. Reflected on the write response only
3. Safe text
4. HTML-escaped on render
5. Sanitized on save
6. Sanitized on render
7. Unescaped HTML (Chromium would execute; measured only when Chromium runs)
8. Stored marker present, no execution
9. Restrictive CSP
10. Second actor view (cookieless GET)
11. Wrong permissions
12. Not found
13. Write succeeded, view missing
14. Write rejected
15. Truncated persist
16. Browser / navigation timeout
17. Execution requires an explicit click

Write success is not stored XSS. A marker in HTML is not execution.
`finding_confirmed` stays false.

## Run

```bash
python -m labs.stored_xss_lifecycle_eval.evaluate --split all --runs 3 --browser auto
```

`--browser mock` forces the loopback GET stand-in and reports live execution
as `NOT_MEASURED`. The runner never downloads Chromium. Sockets to anything
other than loopback are refused and counted. `external_requests` must be 0.

DEV may be re-run while tuning the harness. FINAL is hashed before its first
measurement and its labels are not edited to chase a score.
