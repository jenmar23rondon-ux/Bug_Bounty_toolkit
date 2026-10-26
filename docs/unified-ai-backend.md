# Unified local AI investigation backend

All AI-assisted investigation steps share one provider/model selection, built on the existing
`AIProvider` adapters. Only loopback providers are supported: `ollama` (127.0.0.1:11434) and
`lmstudio` (any OpenAI-compatible server on 127.0.0.1, default port 1234). There are no cloud providers.

```bash
bbtk ai hypotheses prog --input unified.json --ai-provider lmstudio --ai-model qwen2.5-7b-instruct
bbtk ai investigate prog --input unified.json --with-ai --ai-provider ollama --ai-model qwen2.5:7b
bbtk ai benchmark --dataset labs/idor_lab/benchmark-v2.json --with-ai --ai-provider lmstudio --ai-model deepseek-r1-distill-qwen-7b
bbtk ai dual-review prog --evidence-file case.json --analyst-provider ollama --analyst-model qwen2.5:7b \
  --critic-provider lmstudio --critic-model deepseek-r1-distill-qwen-7b
```

Without `--ai-provider`, behavior is identical to previous releases (legacy Ollama client).

Guarantees: strict JSON schemas, evidence refs validated against the bundle, untrusted capture text,
redaction plus a pre-send secret gate, no tool calling, no command execution, no scope changes, no
automatic confirmation. Dual review is advisory: when the models disagree, raise contradictions, or
leave claims unsupported, the result is `inconclusive`. Consensus never upgrades a decision.

Benchmark: `python labs/unified_ai_eval/run.py` (simulated profiles, CI) or
`python labs/unified_ai_eval/run.py --live --provider ollama --model qwen2.5:7b --split holdout` on a local GPU.
Simulated numbers are not real-model scores.
