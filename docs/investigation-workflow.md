# Review-only investigation workflow engine

`bugbounty_toolkit/analysis/investigation_workflow.py` turns the existing
investigation stages into a deterministic, **non-executable** task graph meant
for human review. It never runs tools, never emits scan commands, never touches
scope, permissions or the Evidence Ledger and never confirms a vulnerability.

## Graph
evidence_import → integrity_validation → discovery → ranking → object_handoff →
eligibility_check → control_review → missing_evidence → human_review →
dossier_verification → report_preparation.

Each node: `task_id, stage, prerequisites, evidence_refs, status,
missing_requirements, reason_codes, source_artifacts, reviewer_required,
blocked_reason, completion_basis, execution_allowed=false, finding_confirmed=false`.

States: `pending, ready_for_review, blocked, completed_by_evidence,
requires_human_review, invalidated, not_applicable`.

## Inputs
* **Artifacts**: `{stage: {"path": <relative>, "sha256": <hex>}}`. Files are JSON
  `{"stage", "outcome", "evidence_refs", ["reviewer"]}`. The hash is verified
  before any reuse; mismatch → `invalidated`, dependents `blocked`. Paths must
  stay inside the root. Evidence refs must exist in the `evidence_import` artifact.
* **Evidence-Gap Planner** output (`build_plan`) is reused as-is for the
  `missing_evidence` stage (validated with `validate_plan`; never reprioritized).
* **Investigation Memory** record: advisory only; used when the bundle id matches
  and stored stage statuses agree with verified artifacts. `memory_stages()`
  produces a summary accepted by `InvestigationMemory.save_snapshot`.
* **prior** workflow for resumption: unchanged hashes are reused (no
  re-review); changed hashes are counted as `invalidated_by_change`.

Reviewer stages (`control_review`, `human_review`, `report_preparation`) need a
human `reviewer`; reviewers looking like a model/bot are refused. The `approved`
outcome is only accepted on reviewer stages. Human review still happens through
the existing controls; the engine only records verifiable decisions.

## Stop conditions
`no_new_evidence, permissions_missing, candidate_contradicted,
insufficient_control, documental_tasks_complete, invalid_reference,
dossier_rejected, missing_evidence, circular_dependency, no_informative_action,
task_budget_exhausted` (a documental budget, not a request budget). A plateau
never implies absence of vulnerability (`absence_of_vulnerability_inferred=false`),
and documental completion is separate from a confirmed finding.

## Optional AI explanation
`explain_workflow(workflow, explainer)` passes only `minimized_view` (ids, stages,
states, reason codes) to a local model callable (e.g. wrapping Ollama/LM Studio
via `ai_backend`). Sections citing unknown tasks/evidence, proposing actions,
approvals, commands, or state/priority changes are discarded. The workflow is
never modified and works without AI.

## Lab
`python -m labs.investigation_workflow_eval.run_lab` — 13 synthetic scenarios
plus resume/duplication/change and adversarial-model checks. Zero network.

## Limitations
* Artifacts are produced by existing stages/humans; the engine does not generate them.
* Single-candidate scope per call; no CLI subcommand yet (avoids `cli.py` conflicts).
* Reviewer identity is a declared string; authenticity relies on existing controls.
