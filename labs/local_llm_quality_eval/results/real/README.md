# Real-model results (intentionally empty)

No real Qwen or DeepSeek scores are published in this PR. The machine that built it has
no dedicated GPU and no Ollama / LM Studio server or model installed (both loopback ports
refused connections; `nvidia-smi` absent). Every number under `../mock-*.json` comes from
SIMULATED profiles and measures the harness, not a model.

To produce real results on the RTX 3060 machine (models must already be installed; nothing
is downloaded):

```bash
ollama list            # note the exact tags you already have
python -m labs.local_llm_quality_eval.run --split dev --repeats 3 \
  --qwen ollama=<your-qwen-tag> --deepseek ollama=<your-deepseek-tag> --live
# only after you are happy with DEV, run FINAL exactly once:
python -m labs.local_llm_quality_eval.run --split final --repeats 3 --live \
  --qwen ollama=<your-qwen-tag> --deepseek ollama=<your-deepseek-tag> \
  --output labs/local_llm_quality_eval/results/real/rtx3060-final.json
```

Commit the JSON here in a separate PR together with the exact `ollama --version`, driver
and GPU model.
