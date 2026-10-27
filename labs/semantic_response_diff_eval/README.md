# Semantic response diff eval

Offline synthetic corpus for `analysis/semantic_response_diff.py`.

* `fixtures.py` — 16 scenarios (timestamps, keys, types, array order, HTML denial,
  access vs denial, HTTP 200 JSON error, login redirect, sensitive fields, large
  bodies, encodings, content-length mismatch, malformed JSON, deceptive volatiles,
  key-order-only, owner preservation).
* `baseline.py` / `before.json` — Phase 0 naive status+content-type+exact-body compare.
* `evaluate.py` / `after.json` — semantic engine metrics (precision/recall, false
  equivalences, dangerous normalizations, JSON validity, latency/memory, secret
  leaks, external traffic = 0).
* `example.py` — writes a private mode-0600 diff into a new directory.

No external HTTP. No vulnerability verdicts. PR #52 remains the denial authority.
