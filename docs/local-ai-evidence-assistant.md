# Local AI evidence assistant

Advisory helper over minimized evidence using **Ollama or LM Studio only**
(loopback). Deterministic baseline is always computed first and remains the
**primary** path for any confirmation-related decision.

## What it does

- Explain / summarize minimized evidence
- List pending questions and contradictions
- Draft notes for a human reviewer
- Suggest missing data / controls
- Optionally compare two local models

## What it never does

- Execute requests
- Invent evidence references
- Mutate the Evidence Ledger
- Confirm vulnerabilities (`finding_confirmed` stays false)
- Call cloud APIs
- Emit cleartext credentials
- Change program scope

## CLI

```bash
bbtk ai evidence-assist prog --evidence-file case.json --dry-run
bbtk ai evidence-assist prog --evidence-file case.json --ai-provider ollama --ai-model qwen2.5:7b
bbtk ai evidence-assist prog --evidence-file case.json \
  --ai-provider ollama --ai-model qwen2.5:7b \
  --compare-provider lmstudio --compare-model deepseek-r1-distill-qwen-7b
```

If AI advisory quality does not improve on mapped missing controls (or invents
refs / uses unsafe language), the result keeps `primary=deterministic` and
`advisory_enrichment=none`.

## Eval

```bash
python -m labs.local_ai_evidence_assistant_eval.evaluate --split all
```

Mock profiles measure the harness; they are not real Qwen/DeepSeek scores.
Version stays **0.2.2**.
