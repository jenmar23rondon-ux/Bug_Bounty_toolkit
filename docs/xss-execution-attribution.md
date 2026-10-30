# Browser execution attribution and isolation

The production Playwright checker accepts an alert as execution evidence only
when its message exactly matches the per-probe marker. Unrelated dialogs remain
in sanitized evidence but do not confirm execution. The existing marker-property
check remains available. Reflection, textContent and sink observations alone do
not demonstrate JavaScript execution.

Both normal and loopback checks now block service workers and intercept every
WebSocket without opening a server connection. This complements the HTTP
same-origin, scope and shared-budget guard; it does not widen program scope.
The WebSocket callback deliberately does not call close synchronously, avoiding
a Playwright callback deadlock.

`tests/test_xss_production_isolation.py` exercises the shipped checker with real
Chromium and two disposable loopback servers. It covers an unrelated welcome
alert with escaped reflection, an exact-marker alert, and an out-of-scope
WebSocket in both modes. These tests supplement the frozen browser evaluator;
they do not change its labels or substitute a separate detector.
