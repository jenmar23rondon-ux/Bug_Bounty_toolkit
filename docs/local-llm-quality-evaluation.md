# Local LLM security-analysis quality evaluation

Lab: `labs/local_llm_quality_eval/` · Tests: `tests/test_local_llm_quality_eval.py` ·
Results schema: `bbtk.local-llm-quality-result.v1` · Corpus schema: `bbtk.local-llm-quality-corpus.v1`

## Why

Existing AI labs (`labs/unified_ai_eval`, `scripts/ai_provider_benchmark.py`,
`analysis/ai_review_eval.py`) measure plumbing: schema validation, rejected refs, leaks,
destinations, on a single access-control dataset (IDOR benchmark-v2 holdout, 14 review
scenarios). They have no family coverage beyond IDOR, no held-out families, no
missing-control scoring, no reversed dual-review order, no repeat variability and no model
digest capture. They therefore cannot answer "does Qwen / DeepSeek / both actually help".

Baseline (HEAD `40a28b4`, mock): unified_ai_eval holdout deterministic P=R=F1=1.00;
qwen-sim and deepseek-sim P=0.75 R=1.00 F1=0.857; dual honest/inventing: 0 confirmations,
14 invented citations detected, 28 unsupported claims flagged. All simulated.

## Protocol

Configurations (all through existing code; no new backend):

| | Config | Code path |
|-|-|-|
| A | Deterministic, no AI | `ai_mock_server.rule_based` predicate reference over `build_evidence_bundle` |
| B | Qwen slot, single | `multi_review.review_evidence_multi` → `AIProvider` |
| C | DeepSeek slot, single | same |
| D | Dual Qwen (analyst) → DeepSeek (critic) | `dual_review.dual_review` → `ai_backend.dispatch_chat` |
| E | Dual DeepSeek → Qwen (order inverted) | same |

Dual configs are scored twice: with the **production advisory rule** (`advisory_decision`)
and with an **evaluation-only consensus rule** (shared decision kept only if both valid,
agree, and no contradiction/unsupported/invented citation).

Corpus: 20 families (IDOR true/denied/public/shared, ambiguous auth, insufficient data,
negative controls, HTTP-200 FP, session difference, contradictions, invalid evidence,
missing refs, tool output mislabeled confirmed, unconfirmed SQLi, XSS reflection without
execution, non-exploitable CORS, misread JWT, truncation, prompt injection, synthetic
secrets). DEV = 12 families × 1 variant; FINAL = 20 families × 2 variants (8 families are
held out from DEV entirely). Labels come from the lab specification string stored with
each family, never from a model or bbtk output, and live in separate `*.labels.json`
files that the prompt path never reads. Scenario ids are opaque hashes.

Freezing: corpus and labels were generated and committed (commit `7a541ef`) before the
harness and simulated profiles were written. `MANIFEST.sha256` is verified and the
generator is re-run in memory on every load; tampering, unlisted files or generator drift
abort evaluation.

Safety: loopback-only registry providers; no tools in payloads; tool calls refused by the
adapters; model output never executed; `finding_confirmed` always false; live mode checks
that each model is already listed by the provider and **refuses** otherwise (no pull); two
reviewers resolving to the same normalized identity or digest are refused as
non-independent.

## Metrics

Quality (per config and per family): accuracy, precision/recall/F1 for `candidate`
(Wilson 95% CI when n ≥ 5), FPR, FNR, abstention rate, valid structured output rate,
rejected outputs vs provider errors (separated), invented citations, missing-control
recall (free text mapped onto a fixed 7-control vocabulary by keyword), contradictions
handled, candidates without support, automatic confirmations, decision stability across
repeats. Dual: correct/incorrect agreements, disagreements, improved/worsened vs the
analyst's own single review, correctly converted to inconclusive, extra calls per net
improvement, order effect D vs E. Performance: median/P95 latency (labelled
`mock_latency_NOT_model_latency` in mock mode), chars/4 token estimates, VRAM via
`nvidia-smi` (live only), harness Python peak memory. Privacy: canaries/secrets on the
wire, injection text on the wire, ground-truth strings in prompts, non-loopback
destinations, tool payloads.

## Simulated results (FINAL, 3 repeats) — NOT model results

| Config | Acc | P | R | FPR | Abst | Valid JSON | Invented refs | Ctrl recall |
|-|-|-|-|-|-|-|-|-|
| A deterministic | 0.70 | 0.33 | 1.00 | 0.22 | 0.35 | 1.00 | 0 | 0.46 |
| B cautious-sim | 0.75 | 0.50 | 1.00 | 0.11 | 0.60 | 1.00 | 0 | 0.46 |
| C eager-sim | 0.10 | 0.11 | 1.00 | 0.94 | 0.05 | 0.95 | 6 | 0.00 |
| D dual (prod rule) | 0.55 | – | 0.00 | 0.00 | 1.00 | 1.00 | 0 | 0.46 |
| E dual (prod rule) | 0.55 | – | 0.00 | 0.00 | 1.00 | 1.00 | 6 | 0.46 |

Privacy (720 mock requests): 0 canaries, 0 injection text, 0 ground-truth strings,
0 non-loopback destinations, 0 tool payloads, 0 confirmations.

## Findings that hold independently of any real model

1. **Production dual review can never output `candidate` or `not_observed` on these
   bundles.** `evidence_review.review_evidence` always sets `decision="review_required"`,
   which `dual_review.compare` maps to `inconclusive`, so the advisory equals the reference
   only when it is `inconclusive`. Recall of D/E is 0 by construction; dual review is a
   pure abstention filter today. (Recorded for a separate PR; not changed here.)
2. **The minimized bundle cannot express some lab facts.** Legitimate sharing, field-level
   session differences and contradictions between two cross reads collapse into counts plus
   a single `private_evidence_observed` boolean, so the deterministic reference labels
   `shared_resource`, `contradictory_evidence`, `session_difference`, `truncated_evidence`
   and `missing_references` as `candidate` (A FPR 0.22). A model only sees the same bundle.
3. **Minimization works for privacy**: canaries and prompt-injection text in bodies,
   headers and notes never reach a model; unknown `stop_reason` strings become
   `unrecognized_stop`.

## Recommendation

No model recommendation is made: no real model was measured. Rule for the RTX 3060 run:
pick the single model with the best FINAL FPR at recall ≥ the deterministic baseline;
recommend dual review only if its consensus-rule accuracy beats the best single model
outside both Wilson intervals and the extra calls per net improvement is acceptable.
With the current production advisory rule, dual review should not be recommended for
classification (finding 1).

## Limitations

Synthetic, minimized evidence only; 40 FINAL scenarios (wide CIs); keyword mapping of
missing controls is approximate; contradiction detection for single reviews uses
cited-for-and-against evidence as a proxy; token counts are estimates; LM Studio does not
expose digests/quantization through allowlisted paths; live mode cannot observe the wire,
so privacy there is a pre-scan of bundles plus the existing `dispatch_chat` sensitive gate.
