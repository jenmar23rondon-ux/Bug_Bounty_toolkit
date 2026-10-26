# Evidence redaction laboratory

Offline synthetic canaries for destination-aware redaction.

```bash
PYTHONPATH=. python labs/evidence_redaction_lab/evaluate.py
```

Measures canary leaks across private / minimized / console / shareable / model
destinations, large-body latency/memory, truncation validity, and AI-output scrubbing.
Does not claim absolute privacy; see `unrecognized_formats` and `residual_risks` in the JSON output.
