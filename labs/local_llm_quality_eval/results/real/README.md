# Real-model results

`discovery.json` and `not-measured.json` are from a machine with no NVIDIA GPU and no
local model server. Every live Qwen / DeepSeek metric in `not-measured.json` is
`NOT_MEASURED` (`no_gpu`, and the models were absent). Nothing was downloaded.

`../mock-dev.json` and `../mock-final.json` are SIMULATED profiles. They measure the
harness. They are not Qwen or DeepSeek scores. Config A in those files is the
deterministic engine.

Step-by-step instructions for an RTX 3060 with models you install yourself:
`docs/real-local-llm-rtx3060.md`. Audit: `docs/real-local-llm-rtx3060-audit.md`.

```bash
python -m labs.local_llm_quality_eval.run --discover
python -m labs.local_llm_quality_eval.run --not-measured \
  --output labs/local_llm_quality_eval/results/real/not-measured.json
# On the GPU machine, after you have pulled the tags yourself:
python -m labs.local_llm_quality_eval.run --live --split dev --repeats 3 --temperature 0 \
  --qwen ollama=<your-qwen-tag> --deepseek ollama=<your-deepseek-tag> \
  --output labs/local_llm_quality_eval/results/real/rtx3060-dev.json
```
