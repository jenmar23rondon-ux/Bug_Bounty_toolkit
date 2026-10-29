# Local AI response contract

The assistant now validates model output before clipping or normalizing text.
It rejects extra fields (including injected confirmation fields), wrong types,
more than eight list items, strings longer than 400 characters, oversized JSON,
excessive nesting and sensitive output recognized by the existing scanner.
The deterministic advisory remains available when a model response is rejected.

Synthetic baseline on `fac680e`: three malformed responses (extra confirmation
field, string instead of list, object instead of summary) were accepted, 3/3.
After this change those same responses are rejected, 3/3; valid schema output
continues to pass. Additional tests cover truncation hiding unsafe language,
invalid list members and item limits.

Reproduce: `python -m unittest tests.test_local_ai_evidence_assistant -v`.
The mock evaluation tests privacy, contract behavior and deterministic fallback.
Real Qwen/DeepSeek quality, latency and memory remain NOT_MEASURED here: no real
model was executed. Schema validation cannot prove factual accuracy; model text
remains untrusted advice and confirmation still requires human evidence review.
