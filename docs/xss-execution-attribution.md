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

## Source-integrity compatibility

The stored-lifecycle suite pins the production confirmation helper by SHA-256.
That implementation pin is updated for this reviewed security change; frozen
DEV/FINAL case bytes, expected labels, DOM hook sources and stored-write chain
are unchanged. Real Chromium regressions cover the new alert and socket behavior.

## Combined regression measurements

[Linux integration run 41157948481](https://github.com/jenmar23rondon-ux/Bug_Bounty_toolkit/actions/runs/41157948481)
measures base `93aef03` and proposed `86fe1db`, combining HTTP proof attribution,
the reviewed authorization guard and XSS browser isolation. The shared
`labs/independent_research_eval/results/` snapshots were copied from the proposed
artifact and their implementation digest verified. Frozen labels are unchanged.

DEV/FINAL/STRESS outcome accuracy remains 100% / 84.44% / 100%; pairing precision
remains 100% / 65.85% / 83.33%, with recall 100% in each split. These synthetic
IDOR regression scores do not establish XSS accuracy or real-world performance.
The other proof-attribution documents retain the provenance of their individual
measurements; their earlier source digests do not describe the combined tree.
