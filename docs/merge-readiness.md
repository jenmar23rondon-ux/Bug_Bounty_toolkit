# Merge readiness checklist

Use this checklist before a PR is marked ready for review or merge.

## Required gates

- The PR addresses one root cause and one expected outcome.
- The title and summary describe the behavior change without claiming more than the evidence supports.
- The confirmation bar is respected: a single signal remains `candidate`; only second proof reaches `confirmed`.
- Rejection and gap reasons are explicit (`false_positive`, `out_of_scope`, `no_second_proof`).
- No automatic merge, release, or external submission is triggered by the tool.

## Validation evidence

Record the exact commands run and their outcome.

- Unit tests for the affected module(s): `python -m unittest ...` or `pytest ...`
- Lint and formatting checks: `ruff`, `black`, or project-equivalent formatter
- Type validation when required by the repo settings: `mypy` with the documented platform config
- Browser or synthetic regression checks for user-visible behavior

## Scope and limits

- Do not rely on third-party targets or production traffic for the final validation gate.
- Prefer locally bounded regression fixtures when the change is focused on logic or evidence classification.
- State what is still unverified instead of implying the fix is production-wide by default.

## Merge-safe wording

Prefer wording like:

- “Validated locally with targeted regression checks.”
- “Remaining validation: full CI matrix and benchmark refresh.”
- “No auto-submit or external reporting performed.”

Avoid wording like:

- “fixed” without listing the exact validation
- “ready to merge” without CI or review evidence
- “all checks passed” if only a subset of the repo was run

## Final review

A PR is merge-ready when:

- intent is narrow and specific,
- evidence is listed clearly,
- the behavior is consistent with the confirmation bar,
- and remaining validation is clearly marked as a separate gate rather than a hidden assumption.
