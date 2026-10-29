# Native evidence references in local advisory text

The bundle uses refs such as `E01`, but the assistant's invented-reference check
only recognized `ev-`, `obs-`, `ref-`, and `e-` forms. A mocked response referring
to nonexistent `E99` was accepted on main `545a1e9` even when only `E01` existed.
The checker now validates native `E` refs in every advisory field against the
same bundle allowlist. Known refs remain usable; unknown refs reject the advice
and leave the deterministic result available.

Reproduce with `python -m unittest tests.test_local_ai_evidence_assistant -v`.
New tests cover all seven text/list fields and confirm that raw capture HTML,
instruction injection and a credential canary are absent from model messages.
Existing schema, redaction, frozen evaluation and fallback tests still run.

These are mocked contract/security tests, not real model-quality measurements.
Qwen/DeepSeek precision, latency and memory remain NOT_MEASURED. Reference
allowlisting cannot prove that a model's interpretation of a valid ref is true.
