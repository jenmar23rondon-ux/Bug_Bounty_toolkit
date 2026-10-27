# Run a real local Qwen / DeepSeek eval on an RTX 3060

This repository does not download models. The cloud VM that prepared the branch had no NVIDIA GPU, no `nvidia-smi`, no Ollama, and no LM Studio, so every live metric is `NOT_MEASURED` in `labs/local_llm_quality_eval/results/real/not-measured.json`.

Run the steps below on the machine that has the GPU and the models. Version stays **0.2.2**. AI receives no tools and cannot confirm a finding. `finding_confirmed` stays false. The deterministic engine remains the classification primary.

## 0. Confirm the frozen corpus

```bash
python -m labs.local_llm_quality_eval.run --verify-corpus
```

A non-empty `problems` list means the frozen DEV/FINAL files changed. Stop. Do not edit `corpus/*.labels.json` or `corpus/*.scenarios.json` to make a model look better.

## 1. See the GPU

```bash
nvidia-smi --query-gpu=name,memory.total,driver_version --format=csv
```

Record the name, total VRAM, and driver. An RTX 3060 is typically 12288 MiB. The harness reads the same query in `--discover` and, on a live run, `memory.used` before and after.

```bash
python -m labs.local_llm_quality_eval.run --discover \
  --output labs/local_llm_quality_eval/results/real/discovery.json
```

`--discover` is read-only. It may run `nvidia-smi` and `ollama list` when those binaries exist, and it may GET `http://127.0.0.1:11434/api/tags` or `http://127.0.0.1:1234/v1/models` when those ports are already open. It never calls another host and never pulls a model.

## 2. Install a local server yourself

Pick one loopback server. Both reviewers must be different models (different normalized identity and, when Ollama exposes it, different digest).

### Ollama

Install Ollama from its own documentation, then start the local daemon so it listens on `127.0.0.1:11434`. Pull the weights on this machine, with your own bandwidth and disk:

```bash
ollama pull qwen2.5:7b-instruct-q4_K_M
ollama pull deepseek-r1:8b
ollama list
```

Q4 7B/8B class tags are a size that fits a 12 GB RTX 3060. Use the exact tags `ollama list` prints. The eval refuses unknown tags and does not pull them for you.

### LM Studio

Start the local server on `127.0.0.1:1234` and load one Qwen and one DeepSeek model in the UI. LM Studio does not expose digest or quantization on the allowlisted `/v1/models` path. Copy those from the UI into the results note. Digests then stay `not_exposed` in the JSON, which is honest.

## 3. DEV, then FINAL once

DEV is the only split to repeat while you check that the servers answer. FINAL is already frozen. Run it once. Do not edit prompts, schemas, or labels from a FINAL score.

The provider adapter forwards `temperature` (default 0) and does **not** forward a seed. `--seed` is stored as `requested_seed` with `applied: false` and reason `ai_provider_adapter_has_no_seed_parameter`. Repeats are the reproducibility mechanism.

```bash
python -m labs.local_llm_quality_eval.run --live --split dev --repeats 3 \
  --temperature 0 \
  --qwen ollama=qwen2.5:7b-instruct-q4_K_M \
  --deepseek ollama=deepseek-r1:8b \
  --output labs/local_llm_quality_eval/results/real/rtx3060-dev.json
```

When DEV looks structurally valid (JSON validates, `finding_confirmed` is false, `external_requests` is 0, both digests differ), run FINAL once:

```bash
python -m labs.local_llm_quality_eval.run --live --split final --repeats 3 \
  --temperature 0 \
  --qwen ollama=qwen2.5:7b-instruct-q4_K_M \
  --deepseek ollama=deepseek-r1:8b \
  --output labs/local_llm_quality_eval/results/real/rtx3060-final.json
```

LM Studio uses the same flags with `lmstudio=<model id>` on either slot. Missing models abort with `Nothing was downloaded.`

## 4. What the matrix is

| Key | Reviewers | Code path |
|---|---|---|
| A | Deterministic only | `ai_mock_server.rule_based` over `build_evidence_bundle` |
| B | Qwen alone | `multi_review.review_evidence_multi` |
| C | DeepSeek alone | same |
| D | Qwen analyst, DeepSeek critic | `dual_review.dual_review` |
| E | DeepSeek analyst, Qwen critic | same |

The model sees minimized observations. It does not see `*.labels.json`. It is not given tools. Its text is not executed. Agreement between the two models is not confirmation.

## 5. How to read the result

A live file has `"mode": "live"`. `reproducibility` should carry:

- model digest and quantization (or `not_exposed` when the server does not provide them)
- GPU name, total VRAM, driver, and used VRAM before/after when `nvidia-smi` works
- temperature actually forwarded
- seed recorded as not applied
- prompt/schema hashes and per-scenario packet hashes
- wall time and chars/4 token estimates (not tokenizer counts)

`recommendation.classification_primary` stays `deterministic`. `ai_classification_authority` stays false. A single model may be named `preferred_second_opinion` only when its false-positive rate is lower at recall at least the deterministic recall. Dual review is recommended for classification only when the production advisory rule did more than abstain and the consensus Wilson interval sits strictly above that single model. Even then the dual review may not confirm a finding (`dual_review_may_confirm` is false).

If the file says `"mode": "not_measured"`, those live cells are not scores. Do not fill them in by hand. Do not copy `frozen_historical_reference` configs B–E forward as Qwen or DeepSeek: they are the simulated profiles `cautious-sim` and `eager-sim`.

## 6. Where to put a real run

Commit `rtx3060-dev.json` and `rtx3060-final.json` under `labs/local_llm_quality_eval/results/real/` in a follow-up change, together with the `discovery.json` from that machine. Keep version 0.2.2. Leave the frozen corpus and the historical mock files untouched.
