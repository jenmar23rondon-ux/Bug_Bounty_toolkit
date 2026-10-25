# Changelog

Notable user-facing changes are recorded here. The project has not yet published a tagged release for the changes listed under Unreleased.

## Unreleased

- Add an offline-first `bbtk ai investigate` workflow joining evidence correlation, optional Ollama hypotheses, deterministic access assessment, registered skill routing and budgeted prioritization; the plan is never executed.
- Add deterministic investigation prioritization that keeps research priority, hypothesis confidence, potential impact and demonstrated severity separate, with scope review and human approval gates.
- Add a versioned synthetic IDOR/BOLA benchmark comparing deterministic assessment, optional local Ollama review and a conservative combined verdict, with JSON/Markdown metrics and holdout isolation.
- Expand the loopback IDOR lab with inverse-account checks, protected and ambiguous HTTP-200 controls, and server-error behavior.
- Add strict mypy and an 85% coverage gate for the synthetic IDOR/BOLA benchmark.
- Add a loopback-only deterministic IDOR/BOLA lab, raw fixture captures, a one-command end-to-end run, and an authorized-testing playbook.
- Include the lab app in Ruff CI checks and strict mypy coverage.
- Add offline `import case` generation from two distinct-account Burp GET captures, with strict origin/resource-difference validation, redacted summaries and researcher attestations.
- Add an offline unified evidence importer for Burp, HAR, ffuf, Nuclei, toolkit JSON, HTTP captures, CSV and text artifacts, with redacted typed records, provenance, semantic deduplication and descriptive endpoint correlations.
- Add optional local Ollama review for minimized evidence packets, with no remote fallback or automatic finding confirmation.
- Add shared request/time budgets, read-only diagnostics, and reviewer-ready redacted Markdown evidence drafts.
- Expand strict mypy checks to additional core and vulnerability-check modules, and raise the overall coverage gate to 77%.
- Refresh the documented package layout and add security and contribution guidance.
- Add hunt orchestration that chains contextual checks across supplied routes and parameters.
- Add offline Burp import and local AI artifact review (including APK `--ai-review`) with no remote fallback.
- Add additional bounded security checks and specialized topic skills for the executor.
- Harden CI linting gates alongside the existing coverage requirements.
