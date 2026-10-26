# Content-aware wordlist evaluation lab

Synthetic, offline corpus for measuring filename-only vs content-aware wordlist ranking.

- `collections/synth/` — local wordlist collection (never executed).
- `ground_truth_dev.json` / `ground_truth_final.json` — relevance labels frozen before ranking rules were tuned.
- `MANIFEST.json` — SHA-256 of every list file and of both ground-truth documents.

No network, no payload execution, no credential guessing. Forbidden lists (passwords / XSS / SQLi)
must never appear in recommendations.
