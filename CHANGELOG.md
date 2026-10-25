# Changelog

Notable user-facing changes are recorded here. The project has not yet published a tagged release for the changes listed under Unreleased.

## Unreleased

- Package all topic skills, references and the plan adapter in wheel data files; discover them from both source checkouts and clean installations.
- Add optional FastAPI local dashboard for one program: sanitized evidence import, investigation/memory views, graph search, hypothesis/control summaries, benchmark results and safe report viewing/download; no active check or model execution routes.
- Add dashboard loopback/Host/Origin guards, bounded uploads, attachment-only report downloads, optional dependency profile, Windows/Linux quick start and a release-readiness checklist.
- Make the benchmark v2 audit's shared minimized Ollama prompts explicit in generated JSON/Markdown and regression tests; its current holdout is not an independent model-prompt evaluation.
- Add opt-in saved investigation lifecycle metadata with close/status/resume commands, append-only snapshots, same-bundle resume checks, and no target-request replay.
- Extend the local XSS/SQLi end-to-end flow through persistent evidence graph ingestion and investigation-memory close/resume; accept only safe registered skill command substitutions in the graph.
- Add a deterministic loopback-only XSS/SQLi lab with vulnerable, protected, and ambiguous fixtures, bounded end-to-end checks, unified evidence import, API workflow analysis, mocked hypothesis review, skill routing, and draft reports. The SQLi fixture simulates an error string and does not connect to a database.
- Add `bbtk lab web-vuln` and a no-traffic `--dry-run` preview for the local XSS/SQLi flow, plus Windows and POSIX fixture launch scripts.
- Preserve native XSS/SQLi `route` and singular `parameter` fields when importing toolkit evidence, including non-reproducible classifications.
- Add strict typing and an 80% coverage gate for the loopback web vulnerability fixture server.
- Add persistent SQLite evidence graph and investigation memory, joining API workflow observations, bounded Ollama hypotheses, registered skill routes, deterministic access assessments and existing findings with provenance and epistemic state.
- Add offline `bbtk graph ingest` and filtered `bbtk graph search`; pseudonymize attested account/resource identifiers, reject unknown skills/commands, preserve invalid hypothesis references without linking them, and never execute router plans.
- Add strict typing and an 80% coverage gate for the persistent evidence graph.
- Add a bounded, GET-only BFLA function matrix from supplied authorized role captures, plus deterministic BOLA account-matrix and BFLA assessment without status-code-only or model-based confirmation.
- Add a BFLA playbook documenting role attestations, read-only function requirements, explicit response predicates and manual verification.
- Add strict typing and an 80% coverage gate for the BFLA function-matrix module.
- Add offline `api-workflow` graphs from unified evidence, with provenance-bearing request/response/endpoint/session/resource nodes, low-confidence route/method hypotheses, exact documentation-only OpenAPI links, and observed cookie-session continuity without storing raw values.
- Extend unified evidence bundles to schema 1.1 with optional directional request/response session fingerprints; preserve the legacy combined fingerprint and positional `EvidenceRecord` constructor compatibility.
- Add strict typing and an 80% coverage gate for API Workflow Intelligence.
- Add a synthetic IDOR/BOLA benchmark v2 corpus with disjoint raw development/holdout cases, explicit insufficient labels, confusion matrices, abstention coverage and cross-split minimized-packet overlap audits; retain v1 historical compatibility.
- Extend the loopback IDOR end-to-end run with a protected-resource path through evidence import/correlation, mocked Ollama hypothesis review, deterministic skill routing, access assessment and a redacted review report.
- Add one redacted evidence report schema for Markdown, JSON, HTML and PDF, with explicit pending fields, evidence references, contradictions, negative controls and deterministic validation states; protect existing draft files unless `--force` is supplied.
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
