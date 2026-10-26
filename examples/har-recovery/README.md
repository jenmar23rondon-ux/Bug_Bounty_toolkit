# Synthetic HAR partial-recovery fixtures

Synthetic data only (`api.example.test`, `SYNTH-SECRET` markers, `synthetic.person@example.test`).
Built deterministically by `build_fixtures.py`. See [docs/har-partial-recovery.md](../../docs/har-partial-recovery.md).

```bash
bbtk object-discover demo --input examples/har-recovery/malformed_among_valid.har --attest-authorized-captures --dry-run
bbtk object-discover demo --input examples/har-recovery/malformed_among_valid.har --attest-authorized-captures --dry-run --strict
```
