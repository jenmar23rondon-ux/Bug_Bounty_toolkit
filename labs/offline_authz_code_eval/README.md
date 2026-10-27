# Offline authorization code eval (synthetic)

`corpus/` holds synthetic FastAPI and Express apps (never executed). `*.fixture` files are malformed sources kept
out of repo linters; `evaluate.materialize` copies the corpus to a temp dir and restores their real suffix.
`expected.json` is the hand-labelled ground truth. Run `python -m labs.offline_authz_code_eval.run`.
See `docs/offline-authorization-code-audit.md` for metrics and limitations.
