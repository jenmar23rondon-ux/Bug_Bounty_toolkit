# Authorization denial-aware case assessment

## Problem

Structural case eligibility (`CASE_ELIGIBLE`) only checks that two GET captures
form a valid read pair with sessions and responses. It does **not** inspect
whether the actor’s response is a denial. On captures that already contain a
successful owner control plus a denied cross-account attempt (HTTP 401 / 403 /
404, HTTP 200 with a denial body, or an auth redirect), the e2e pipeline still
marked candidates `requires_validation`. The independent research benchmark
(`irb-1.0`, PR #49) counted those as false “reviewable” cases (A02, A05, A08,
A09, C05, plus public/shared A03/E03).

## Separation of concerns

| Layer | Question answered | Module |
| --- | --- | --- |
| Structural eligibility | Is this a well-formed GET read pair? | `handoff_case_eligibility` |
| Authorization outcome | Did the actor response demonstrate access or a denial? | `authorization_denial` |
| Ledger / planner | Should a human treat this as reviewable IDOR evidence? | `idor_e2e_research` + `evidence_gap_planner` |

Structural eligibility is unchanged. Authorization outcome is new and
deterministic: status **plus** body / content / controls — never status alone.

## Classifier outcomes

- `cross_account_denied` — owner positive control + actor denial (401/403/404,
  200 content-denial, or 3xx → login/signin). Emits
  `bbtk-control-annotation/1` with `role=negative_control` and
  `contradicts_hypothesis=true`.
- `possible_access` — both sides look like successful resource payloads.
  **Never** confirmed; still needs human attestation.
- `inconclusive` — ambiguous (5xx, empty body, missing owner control, etc.).

Special cases:

- **Contradictory denial** (e.g. HTTP 403 with owner resource body, A06): treated
  as successful-looking / possible_access so it stays reviewable.
- **Public / shared visibility** in the body: not a cross-account denial; annotated
  with `resource_visibility` so the planner can `review_legitimate_access`.

## Pipeline behaviour

After materializing handoff pairs, `run_e2e_research`:

1. Assesses every owner/actor response pair.
2. Writes the control annotation into the evidence JSON.
3. If **any** pair in the run is `cross_account_denied`, sibling positive-control
   pairs inherit that signal and are **not** marked `requires_validation`.
4. Public/shared pairs are likewise kept out of `requires_validation`.
5. True possible-access cases (no denial, private resource) still become
   `requires_validation` with the usual human blockers.

Positive and negative controls stay differentiated: the owner success response
is the positive control; a denied actor response is the negative control. Denied
responses never become positive IDOR/BOLA evidence and are never auto-confirmed.

## Evaluation

- Synthetic lab: `labs/authorization_denial_eval/` (DEV 8 / FINAL 12).
- Independent bench: re-run `labs/independent_research_eval` FINAL 45 **without**
  modifying ground truth. See `labs/authorization_denial_eval/results_independent_final.json`.

## Non-goals / invariants

- No external HTTP; synthetic/local labs only.
- No auto-confirmation; no secret recording.
- Tool-policy gate and redaction hardening untouched.
- Version remains 0.2.2; no tags/releases from this change.
