## [Unreleased]

### Evidence-preserving semantic HTTP response diff

- New offline `analysis/semantic_response_diff.py` compares stored HTTP responses
  (status, content-type, location, content-length, JSON keys/types/values as
  fingerprints, array order, HTML structure as data, non-sensitive headers) with
  safe depth/size limits. Never sends requests, never confirms findings, never
  hides authz-relevant or sensitive fields behind volatile rules.
- Attaches PR #52 `assess_response` verbatim for context; denial classifier and
  authorization workbench / dashboard UI are untouched.
- Synthetic lab `labs/semantic_response_diff_eval/` (16 scenarios) with before/after
  metrics. Version stays 0.2.2; `v0.2.1` untouched.


### Authorization denial-aware case assessment

- New deterministic classifier `analysis/authorization_denial.py` separates
  structural case eligibility from evidence of successful cross-account access.
  Recognizes HTTP 401/403/404, HTTP 200 content denials, and auth redirects;
  contradictory denial-status + resource body (A06-style) stays inconclusive /
  reviewable. Status alone is never enough.
- `run_e2e_research` emits `bbtk-control-annotation/1` negative controls for
  demonstrated denials, suppresses false `requires_validation` on sibling
  positive-control pairs, and keeps public/shared resources out of the
  reviewable path. Positive vs negative controls stay differentiated; nothing
  is auto-confirmed.
- Synthetic lab `labs/authorization_denial_eval/` (DEV 8 / FINAL 12) plus
  before/after metrics on the frozen IRB FINAL 45-scenario bench (labels
  untouched): false reviewable 13→6, false reviewable after planner 9→2;
  denial/visibility false-reviewables cleared; missed eligible unchanged (2).
  Version stays 0.2.2; `v0.2.1` untouched.


### Evidence-gap guided investigation planner

- Opt-in offline planner (`bbtk investigation next-steps PROGRAM [--dry-run]`) that names
  missing controls and the next human review step from the Evidence Ledger + annotated
  evidence. Schema `bbtk-evidence-gap-plan/1`. AI never decides steps; every recommendation
  has `execution_allowed=false` and `finding_confirmed=false`.
- Reuses Evidence Ledger validation, Investigation Memory (read-only), IDOR E2E eligibility
  codes and dashboard concepts without duplicating those systems. Does not weaken the
  PR #43 tool-policy gate or PR #45 redaction.
- Synthetic lab `labs/evidence_gap_planner_eval/` (DEV + FINAL, 20 scenarios) with before/after
  metrics vs manual flow and a generic baseline. Version stays 0.2.2; `v0.2.1` untouched.

### IDOR/BOLA end-to-end research quality

- Wire the full offline research contract (capture→import→discovery→ranking→handoff→
  real eligibility codes→IDOR proposal→control review→evidence→ledger→report) in
  `analysis/idor_e2e_research.py`; resume via digest-checked artifacts; detect modified /
  expired evidence; never auto-convert, access-check, or confirm without human review.
- Align `labs/eval_integrity` with PR #34 eligibility (`pending_contracts` cleared; origins
  never rewritten). New independent synthetic lab `labs/idor_e2e_research` (15 scenarios).
  Historical corpora untouched; ranking rules unchanged. Version stays 0.2.2.

### Unified local AI investigation backend

- New `analysis/ai_backend.py`: one `AISelection` (provider + model + loopback endpoint) that routes every
  investigation AI call through the existing `AIProvider` adapters (Ollama, LM Studio/OpenAI-compatible).
  Without `--ai-provider` the legacy Ollama client path is unchanged.
- `--ai-provider` / `--ai-endpoint` on `ai hypotheses`, `ai route`, `ai investigate`, `ai benchmark`,
  `ai-review --artifact`, `report --draft-with-ai`, every live `--ai-review` scanner and `analyze evidence --ai lmstudio`.
- Prompts with residual secret-like content are refused before sending; telemetry stores only fingerprints.
- New `bbtk ai dual-review`: independent analyst + critic models, strict JSON, evidence/hypothesis/opinion claims,
  invented-ref, contradiction and unsupported-claim detection. Consensus is never confirmation.
- `labs/unified_ai_eval/run.py`: deterministic mock benchmark (CI) plus optional `--live` hook for local GPUs.
  Version remains 0.2.2.

### Evidence privacy and redaction hardening

- Destination-aware redaction policy (`private_evidence`, `minimized_artifact`, `console_summary`, `shareable_report`, `model_input`) in `core/redaction.py`.
- Structured JSON / HTTP / URL / header / HTML parsing with regex as backstop; size, depth, and time bounds; linear large-body performance.
- Provenance digests and pseudonymized identifiers without leaking preimages; AI-output scrub helper.
- Synthetic canary laboratory `labs/evidence_redaction_lab/` and docs in `docs/evidence-redaction.md`.
- Shareable reports use the shareable destination. Absolute privacy is **not** claimed; residual risks documented.
- Version stays 0.2.2.

### Hardened external tool policy gate

- Add `bugbounty_toolkit.core.secure_subprocess` as the single contract for allowlisted
  external binaries: structured argv only (never `shell=True`), wall-clock timeout,
  stdout/file caps, optional RLIMIT memory/CPU/nproc, process-tree kill on cancel/limits,
  stable error codes, redacted provenance logs, and private output under program dirs.
- `core.runner.run_tool` routes recon/nuclei/params tools through the gate; invocations that
  contact remote systems must attest authorization, scope, and execution budget or are
  rejected before exec. Rate-limit flags are not treated as absolute safety guarantees.
- `fuzzing.ffuf_runner` launches ffuf via the same contract without rewriting scanner internals.
- Synthetic local-lab tests cover success, timeout, runaway output, child-tree kill,
  allowlist/argv/path/policy rejections, cancellation, and budget exhaustion. No real
  third-party tool installs and zero lab HTTP. Version stays 0.2.2.

### Content-aware wordlist ranking (opt-in)

- Add bounded, deterministic content profiling for local wordlists (`bugbounty_toolkit.fuzzing.content_ranking`).
- Opt-in via `bbtk fuzz-plan --ranking content`; default filename ranking unchanged.
- Synthetic DEV/FINAL evaluation corpus under `labs/content_wordlist_eval/` with frozen hashes.
- Explanations include category/content signals, coverage, duplication, request cost, uncertainty, and sample SHA-256; no full payloads in reports.

# Changelog

Notable user-facing changes are recorded here.

## Unreleased

- IDOR handoff→case reliability: classify materialized pairs as `structural_valid` /
  `case_eligible` / `needs_more_evidence` / `security_rejected` / `technical_error` with
  stable codes; adversarial evaluator uses each corpus `ground_truth.origin` (never a
  hardcoded port) and separates technical origin overrides from legitimate read-case
  rejections; materialize suggestions preserve capture provenance origin. Frozen FINAL
  corpus `adv-handoff-case-1.0` (+ DEV) authored before the fix. No discovery/ranking/fuzz
  changes, no auto access-check/approve/confirm. Version stays 0.2.2.

- Add optional reproducible offline lab environment (`docker/offline-lab`, `scripts/offline_lab`):
  digest-pinned base, hash-locked deps, checksum-verified ffuf, optional Playwright image; non-root,
  read-only, cap-drop ALL, no-new-privileges, resource limits, `--network none`; build separated
  from run; `doctor` reports Playwright browser and offline-lab state without installing anything;
  `verify.sh` runs the labs/tests with a connection audit and in-container isolation checks.
  venv install and scope/approval controls unchanged. Version stays 0.2.2.

- Add offline evidence verification & coverage ledger (`bbtk ledger ...`, schema `bbtk-evidence-ledger/1`):
  surface coverage states, digest-verified evidence with provenance, distinct candidate states,
  blocked auto-confirmation, rejection reasons/blockers, broken-ref/duplicate/stale-evidence detection,
  Evidence Graph / Investigation Memory / report integration and a synthetic `lab evidence-ledger`.
  Version stays 0.2.2.

- Evidence-based Object Discovery ranking v2.0: structural signals demote shared path-parents
  and unauthenticated/response-only noise, boost path-leaf specificity and cross-session kind
  peers; explainable positive/negative breakdown + uncertainty; never discards shared/public
  candidates; no HTTP, no auto-confirm. Frozen ranking corpus `adv-ranking-1.0` (+ DEV) authored
  before the rule change. Historical `adv-1.0`/`adv-1.1` ground truths untouched. Version stays 0.2.2.

- Add offline `fuzz-plan`: context-aware discovery plans from local HAR captures, local wordlist
  collections and optional Object Discovery associations; reuses `ffuf_runner` gates; synthetic
  context-fuzz lab + before/after recommendation metrics; no downloads, no auto-execution, version stays 0.2.2.
- Resilient HAR import with per-entry partial recovery (`har_import`), CLI `--strict` / `--allow-truncate`,
  signed `capture_import` summaries and synthetic recovery fixtures (merged from PR #30).
- Object discovery/handoff: open-vocabulary resource kind inference (P1). Identifiers outside the
  19-noun vocabulary get an HMAC-keyed `kind_ref` from their collection segment or typed field stem;
  pairing requires the same kind (and same position for request/request). Bare/generic ids are
  insufficient evidence routed to review. Display `resource_type` unchanged; nothing is confirmed.
- Labs: independent frozen FINAL-evaluation corpus `adv-1.1`; `evaluate.py --corpus`.
- Add frozen independent adversarial IDOR/BOLA evaluation corpus `labs/adversarial_idor_eval` (adv-1.0) with ground truth, per-stage metrics (discovery / pairing / case proposal; confirmation not measured offline), error-cause matrix, version comparison and reproducible tests. Measurement only: no detection rule changes.
- Add offline `object-handoff` to turn object-relationship candidates into reproducible owner/actor capture-pair proposals (locators, provenance, suggested `discover-idor` command) without writing cases, calling access-check, approving, or sending HTTP.
- Add `bbtk lab object-discover` with a versioned synthetic labeled corpus (`dev`/`eval`), Precision@k/recall/FP/FN metrics, and before/after comparison against `object-candidates` ranking. Synthetic metrics do not claim real bug-bounty confirmation performance.
- Extend `object-handoff` (handoff 1.1) with offline asymmetric pairing: typed identifiers observed only in one session's response JSON (nested objects/arrays) can form human-review proposals with another session's request-side identifier. Proposals label observed identifiers vs inferred relations, never infer ownership, keep provenance, stay `confirmed=false`/`case_executable=false`, and follow the documented `response-identifier-v1` guards (own type evidence, distinct sessions, same origin, shared-context exclusion, bounded). `--request-only` restores request-side-only pairing.
- Object discovery lab corpus 1.1 adds response-observed, response-nested, collision, shared-context and incomplete-capture scenarios to DEV and EVAL and reports a same-run `request_only_comparison`.

## 0.2.2 - 2026-10-25

- Fix Playwright XSS confirmer shutdown for Playwright 1.64+ (`PlaywrightContextManager` no longer exposes `stop()`; use `__exit__`).
- Clarify `test_ruff_coverage` failure when `python -m ruff` is unavailable for the active interpreter (install `.[dev]`).
- Install Playwright Chromium in CI so XSS browser confirmation tests exercise the real binary instead of silently skipping.
- Document the human-gated release process in `docs/RELEASING.md` (tag checklist, CI gates, and what must not be automated).

- Add fully offline `object-discover` / `object-candidates` for typed object-reference correlation across local Burp/raw HTTP/HAR captures, provenance-bearing observed/inferred relationships, deterministic explainable 0-100 priority, HMAC pseudonyms/integrity, private atomic publication and no executable cases or confirmed findings.
- Reuse bounded IDOR JSON traversal, Burp/HAR adapters, API workflow edge merging and graph limits; add strict typing, offline CLI smoke coverage and synthetic examples for object discovery.

- Add offline `import discover-idor` proposals from paired Burp captures and explicit `import approve-idor --approve` conversion into native `access-check` cases, with pending ownership/privacy review, bounded inputs, private snapshot bundles and no discovery traffic or automatic findings.

- Extend local wordlist classification to discovery categories, exclude credential-guessing collections, and record SHA-256 fingerprints.
- Supervise ffuf with an explicit confirmation gate, capped unique inputs, a scoped baseline, wall-clock termination and a separately reported external request upper bound.
- Classify ffuf responses against baseline shapes, group similar responses, and import discovery into unified evidence, API workflow, the local graph, investigation memory and a non-executing access-control follow-up plan.
- Extend the loopback-only dashboard with read-only wordlist statistics, fuzz discovery summaries and predicate-only authorization matrices.
- Add an offline wordlist manager for local SecLists, Assetnote, fuzzdb and custom collections, with streaming inspection, category recommendations, disk-backed deduplication, capped preparation and request/time estimates.
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
