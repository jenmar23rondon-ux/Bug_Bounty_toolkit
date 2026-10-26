# Multi-provider local AI evidence review

Status: PR 1/5 (`feature/multi-provider-ai-review`). Version stays 0.2.2.

The AI is an **advisor**. It cannot confirm findings, authorize actions, run tools,
choose targets, change scope or write to the Evidence Ledger. The deterministic
engine (`analysis/evidence_review.review_evidence`) builds the minimized bundle and
remains the primary reference in every result (`deterministic_reference`).

## Baseline audit (main @ 86c9a868, before this PR)

| Area | Observed contract |
| --- | --- |
| `analysis/ollama_review.py` | Fixed `http://127.0.0.1:11434/api/chat`; urllib opener with `ProxyHandler({})` and a no-redirect handler; 64 KiB response cap; model-name regex; timeout 1–300 s; `num_predict` 1–4096; `REVIEW_SCHEMA` = `{decision ∈ candidate/not_observed/inconclusive, summary, evidence[≤5], limitations[≤5]}`, `additionalProperties:false`. Output: `provider: ollama-local`, `source_claims_unverified`, `raw_evidence_sent:false`. |
| `artifact_review.py` | Redacts HTML/HTTP artifacts (headers, JWTs, secrets), bounded chunking (≤100 chunks, ≤32 000 chars), 5 MiB cap; parameter suggestions schema. `review_evidence_with_ollama` returns `ai-evidence-review` with `status/decision/reason/assessment/notice/model/raw_evidence_sent/minimized_packet`. |
| `hypotheses.py`, `skill_router.py`, `benchmark.py`, `investigation.py` | Each calls `chat_with_ollama` directly with its own schema and token budget (benchmark: 192 tokens); deterministic results are always produced and AI is optional/fallback. |
| CLI | `ai-review` (`--evidence-file`/`--artifact`, `--ai-model/--model`, `--ai-timeout`, `--dry-run`), `ai investigate`, `ai benchmark --with-ollama`. |
| Gaps | Ollama only; evidence strings free-form (no reference checking); incomplete outputs (`done:false`) and tool-call envelopes not detected; model text not scrubbed for secrets before being printed. |

Baseline suite: 669 tests OK (2 skipped), ruff clean, `mypy --strict` clean (45 files), total coverage 82.1 %.

## Design

`analysis/ai_providers.py`

* `AIProvider` protocol: `provider_id`, `spec`, `capabilities()`, `check_availability(model)`, `generate_structured(messages, schema, model, limits)`.
* `PROVIDER_REGISTRY` (explicit allowlist): `ollama` → `127.0.0.1:11434 /api/chat` (same endpoint constant as before), `lmstudio` → `127.0.0.1:1234 /v1/chat/completions`.
* `OllamaProvider` (same payload shape as `chat_with_ollama`) and `OpenAICompatibleLocalProvider` (one adapter; `llamacpp`, `vllm`, `localai` are reserved disabled profiles of the same class — enabling one is a registry change, not a new client).
* One shared transport (`http.client` to an IP literal): no DNS, no proxy env vars, no redirects (3xx → `redirect_refused`), response cap, timeout, prompt budget, output-token budget (≤4096), per-provider concurrency semaphore (≤4).
* Endpoint policy: only loopback IP literals (`127.0.0.0/8`, `::1`) on the provider's pre-authorized port; DNS names (including `localhost`), private/public IPs, IPv4-mapped IPv6, `0.0.0.0`, HTTPS, credentials, query strings and custom paths are rejected.
* No tools are ever sent; `tool_calls`/`function_call` in a reply → `tool_call_refused`.

`analysis/multi_review.py`

* `build_evidence_bundle` → `{schema_version: bbtk.ai-evidence-bundle.v1, evidence_bundle_id: eb-<sha256>, observations: [{ref: E01, field, value}], deterministic_reference}`. Only the allowlisted counters/predicates of the existing minimizer are included; raw URLs, headers, bodies and capture text never reach the prompt.
* Strict validation of model output: incomplete, invalid JSON, invented fields, missing fields, unsupported decisions (e.g. `confirmed`), non-existent refs, same ref cited for/against, `candidate` without supporting refs → result rejected, decision forced to `inconclusive`, citations dropped.
* Model text is scrubbed for secret-like content (JWTs, `token=`, `sk-…`, AWS keys, GitHub tokens, Authorization/Cookie headers, `BBTK-CANARY-…`).
* Result `bbtk.ai-evidence-review.v1`: `evidence_bundle_id, provider, model, model_identity, decision, reason (=summary, legacy name), evidence_for, evidence_against, unresolved_questions, missing_controls, limitations, validation_status, validation_issues, deterministic_reference, execution_performed:false, finding_confirmed:false, evidence_ledger_modified:false, raw_evidence_sent:false, external_service_used:false, request_destination, notice, telemetry{provider, model, params, duration_ms, response_bytes, finish_reason, error_code, prompt_sha256, prompt_chars, prompt_stored:false}`.
* Two reviews of the same bundle → `bbtk.ai-evidence-review-comparison.v1` with agreements, disputed refs, refs cited by one side only, missing controls (agreed/union), `independence` (normalized model identity: `qwen2.5-coder:7b` on Ollama equals `Qwen2.5-Coder-7B-Instruct-GGUF` on LM Studio → `same_model_on_two_servers`, `independent:false`, `consensus_weight: single_opinion_repeated`), `consensus_is_proof:false`.

## CLI

```bash
# Legacy, unchanged output (Ollama):
bbtk ai-review PROGRAM --evidence-file ev.json [--model qwen2.5-coder:7b] [--dry-run]
# Structured v1 result with Ollama or LM Studio:
bbtk ai-review PROGRAM --evidence-file ev.json --structured
bbtk ai-review PROGRAM --evidence-file ev.json --ai-provider lmstudio --model qwen2.5-coder-7b-instruct
# Two reviews of the same minimized bundle:
bbtk ai-review PROGRAM --evidence-file ev.json --ai-provider ollama --model qwen2.5-coder:7b \
    --second-ai-provider lmstudio --second-ai-model deepseek-r1-distill-qwen-7b
# Allowlist and (loopback-only) availability:
bbtk ai providers [--check --ai-model qwen2.5-coder:7b]
```

Options: `--ai-endpoint` (may only restate the authorized `127.0.0.1:<port>`), `--ai-max-tokens` (≤4096), `--ai-concurrency` (≤4), `--ai-timeout` (1–300 s). Without a running server the command returns `status: unavailable`, `error_code: unavailable`; no fallback of any kind. No GPU or LM Studio install is required. The Docker offline lab is unchanged (container loopback ≠ host loopback); run real engines outside that profile.

## Reproducible benchmark

```bash
python scripts/ai_provider_benchmark.py                 # deterministic mocks (default, CI)
python scripts/ai_provider_benchmark.py --live \
  --reviewer ollama=qwen2.5-coder:7b --reviewer ollama=deepseek-r1:8b --repeats 3 --output my-run.json
```

Mock mode serves `/api/chat`, `/api/tags`, `/v1/chat/completions`, `/v1/models` from `bugbounty_toolkit/ai_mock_server.py` on `127.0.0.1:<ephemeral>` and runs 16 scenarios (true/false IDOR, ambiguous, non-existent refs, contradiction, prompt injection, invalid JSON, incomplete, invented fields, oversized, unavailable model, timeout, tool call, secret canaries, redirect to a loopback trap server, proxy env pointing at the trap) through the legacy path and both new providers, plus 10 non-loopback/unauthorized endpoint attempts. It measures plumbing and safety only (`measures_real_model_quality: false`).

The `--live` protocol records only what the user's own models return (validity, agreement with the synthetic reference label, duration, leaks, error codes). **No real-model quality numbers are published in this PR**: no real model was installed where it was developed.

## Measured before/after (mock harness, 3 runs, this box, Python 3.13)

| Metric (16 scenarios) | Legacy Ollama path | v1 OllamaProvider | v1 OpenAI-compatible (LM Studio) |
| --- | --- | --- | --- |
| Correct outcome (accept expected / reject bad) | 12/16 | 16/16 | 16/16 |
| Bad outputs accepted (unknown ref, contradiction, incomplete, tool call) | 4 | 0 | 0 |
| Invented refs accepted | 1 (no ref concept) | 0 | 0 |
| False confirmations | 0 | 0 | 0 |
| Secret canaries in prompt sent | 0 | 0 | 0 |
| Secret canaries in printed output (model echo) | 3 | 0 | 0 |
| Injection text forwarded to model | 0 | 0 | 0 |
| Requests to unauthorized destination (redirect/proxy trap) | 0 | 0 | 0 |
| Median latency, valid cases (ms, mock) | 7.6–8.7 | 2.6–2.9 | 2.9–3.3 |
| tracemalloc peak (KiB, whole scenario run) | ~509 | ~477 | ~483 |

Non-loopback/unauthorized endpoint attempts rejected: 10/10 (legacy has no endpoint option). Latencies are mock round-trips on loopback and say nothing about model speed.

Legacy CLI compatibility: `ai-review --evidence-file --dry-run`, `ai-review --artifact --kind request --dry-run` and `ai-review` with no server produce byte-identical output on base and head; the 669 pre-existing tests pass unchanged.

## Limitations and residual risks

* `ai hypotheses`, `ai route`, `ai investigate`, `ai benchmark` and artifact review still use the legacy Ollama client (unchanged, still loopback/no-proxy/no-redirect). Porting them is a follow-up.
* Output scrubbing is pattern-based; novel secret formats could pass. Inputs are already minimized to counters/booleans, so the model never sees raw secrets from captures.
* Model-identity normalization is heuristic (name based). Fine-tunes with renamed files could be treated as independent; Ollama digests are not compared yet.
* A loopback port can be occupied by any local process; bbtk trusts the host's loopback, not the process behind it.
* Ref validation proves citations exist, not that the model's reasoning is correct. Consensus is never proof.
* LM Studio `response_format: json_schema` behaviour varies by model/version; outputs are validated regardless.
