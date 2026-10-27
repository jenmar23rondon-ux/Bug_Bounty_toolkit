# P08 audit — real local LLM eval (RTX 3060)

Audit date: 2026-10-27. Branch `eval/real-local-llm-rtx3060`. Version remains **0.2.2**.

## Base

| Item | Value |
|---|---|
| Required base | `bbd0068f90b0f411360519434008ccdcfcbaaae0` |
| Branch point | `bbd0068f90b0f411360519434008ccdcfcbaaae0` |
| `origin/main` at fetch | `494ec8365cfe78323953138f6fb8ae3758ae82c8` |

`origin/main` moved after the pinned base (merge of PR #75, XSS real-browser validation, commits `f3111f2`..`494ec83`). This branch was cut from the pinned SHA. Those commits were not rebased in. XSS browser labs, DOM hooks, and IDOR modules were not edited.

## Baseline tests (before this change)

`python -m unittest discover -s tests` on the pinned tree:

| Result | Count |
|---|---|
| Ran | 1176 |
| Skipped | 4 |
| Errors | 1 |
| Runtime | 111.4s |

The error is pre-existing and outside this brief: `tests.test_offline_lab.SuiteRunnerExclusionTests.test_excluded_tests_are_reported_as_skips_not_dropped` raises `ImportError: Start directory is not importable` when `unittest` discovers a temp directory. It was recorded and left unchanged.

## Frozen corpus

`labs/local_llm_quality_eval/corpus/MANIFEST.sha256` matches the in-memory generator (`corpus.verify()` is empty). Labels were not edited.

```
205f30eee340332b247edc203b13205587d6aa09bdb8079bef26587d71978dd7  dev.labels.json
ac4bcfff83b1a5bd0284e65334ed045b22e8a2836ac4dc146b28f040be46bec4  dev.scenarios.json
89280c4d97c68d676124efb9bba2cdad635af2f00c20e1d45b68abf11bbe8e91  final.labels.json
5e42a8063eff864ed4140ae6323ec7214ddd5f75ef739adc201906f37ceac937  final.scenarios.json
```

Manifest SHA-256: `0006eea40be2f95a21ee7e98de0c3e97bf3f400b4a5e05ba3da4867c67786118`.

Minimized packet hashes (model view only; labels excluded):

| Split | Scenarios | SHA-256 |
|---|---|---|
| DEV | 12 | `c2e73c54ace0dc9b638ea26c8120f6942a43c64e218a3047f5a1bc81a23ac54b` |
| FINAL | 40 | `d86c351c964fbfd3c5fc4215d331540f5857bfc7745b27d41df42f9042449c8f` |

Synthetic canaries in the raw scenarios are dropped by `build_evidence_bundle`. Packet scan `secret_leaks_in_packets` is 0.

## Code paths (read, not retuned)

| Module | Role on this eval | Authority |
|---|---|---|
| `analysis/ai_providers.py` | Loopback Ollama `127.0.0.1:11434` and LM Studio `127.0.0.1:1234` only. Temperature is forwarded. Tool calls raise `tool_call_refused`. No seed parameter. No download API. | Transport only |
| `analysis/ai_backend.py` | Dispatches an explicit local selection. Sensitive-content gate. Telemetry stores a prompt hash, not the prompt. `tool_calling_enabled` is false. | No confirmation |
| `analysis/multi_review.py` | Single-model review. Schema `bbtk.ai-evidence-review.v1`. Bundle `bbtk.ai-evidence-bundle.v1`. `finding_confirmed` is false. | Advice validated against bundle refs |
| `analysis/dual_review.py` | Analyst/critic. Schema `bbtk.ai-dual-review.v1`. Comparator keeps the deterministic reference only when both reviews are valid, agree with it, and raise nothing; otherwise `inconclusive`. `consensus_is_proof` is false. | Models never promote a decision |
| `analysis/evidence_review.py` | Deterministic packet. `decision` is `review_required`, which dual review maps outside `candidate` / `not_observed` / `inconclusive` onto `inconclusive`. | Reference |
| `analysis/local_ai_evidence_assistant.py` | Separate advisory helper. Deterministic baseline stays primary. `finding_confirmed` is false. This lab was not modified. | No confirmation |
| `labs/local_llm_quality_eval/` | Frozen DEV/FINAL corpus, mock harness, opt-in `--live`. Owned by this brief. | Scoring only |

Prompt identity in this commit:

| Prompt / schema | ID |
|---|---|
| Single review schema | `bbtk.ai-evidence-review.v1` |
| Bundle schema | `bbtk.ai-evidence-bundle.v1` |
| Dual review schema | `bbtk.ai-dual-review.v1` |
| Single prompt SHA-256 | `6b062f58ad03fdc2d35f045821a4dd3db69402109c15fd8b63eb5e733c714373` |
| Analyst prompt SHA-256 | `11103f7a3d6df749f8c308ad1aa5967205b4e2706ad36a54c3201524de971b5a` |
| Critic prompt SHA-256 | `4bd48fff304c21498a62091bb769a5fdec95b56ddcef422bf532db08955ad979` |

The model message is the minimized observation view. Ground-truth label files are not part of that view. Payloads do not include a tools array. Model text is not executed. Nothing in these paths writes the Evidence Ledger.

## Deterministic mismatches (labels left frozen)

On the committed mock FINAL run, configuration A (deterministic, no model) disagrees with the lab-spec label for six families. This is the minimization limit already described in `docs/local-llm-quality-evaluation.md`. The labels are the lab specification. They were not treated as label errors and were not edited. Rules were not retuned.

| Family | Held out of DEV | Expected | Deterministic prediction |
|---|---|---|---|
| `contradictory_evidence` | no | inconclusive | candidate |
| `cors_not_exploitable` | yes | not_observed | inconclusive |
| `missing_references` | yes | inconclusive | candidate |
| `session_difference` | yes | inconclusive | not_observed |
| `shared_resource` | yes | inconclusive | candidate |
| `truncated_evidence` | yes | inconclusive | candidate |

## Hardware and model discovery (this VM)

Read-only. `nvidia-smi` is not installed. `ollama` is not on `PATH`. TCP probes to `127.0.0.1:11434` and `127.0.0.1:1234` were refused. No HTTP request was sent. No model was pulled.

Recorded in `labs/local_llm_quality_eval/results/real/discovery.json`:

| Field | Value |
|---|---|
| `primary_reason` | `no_gpu` |
| `reasons` | `no_gpu`, `ollama_cli_absent`, `ollama_server_absent`, `lmstudio_server_absent`, `model_absent` |
| GPU name / VRAM / driver | `NOT_MEASURED` (`no_gpu`) |
| Qwen tags | none |
| DeepSeek tags | none |
| `model_download_attempted` | false |
| `external_requests` | 0 |
| `network_attempts` | 0 |
| `loopback_probes` | 2 (closed ports) |
| `finding_confirmed` | false |
| `tools_enabled` | false |
| `ai_classification_authority` | false |

Live Qwen / DeepSeek metrics are therefore `NOT_MEASURED`. The report is `labs/local_llm_quality_eval/results/real/not-measured.json`. How to run this on an RTX 3060 is `docs/real-local-llm-rtx3060.md`.

## What stayed in force

- `finding_confirmed` stays false. AI has no tools and no final classification authority.
- The deterministic engine stays the classification primary.
- Dual review is not recommended for classification: it was not measured on a real model, and on simulated profiles the production advisory rule only abstains (recall 0, abstention 1.0 in the frozen mock FINAL file).
- Simulated profiles `cautious-sim` and `eager-sim` are harness scores. They are not Qwen or DeepSeek results.
