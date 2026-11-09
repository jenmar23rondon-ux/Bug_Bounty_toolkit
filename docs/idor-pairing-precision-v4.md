# IDOR pairing precision v4

`evaluate_compatibility` is an opt-in assessment of whether an owner capture and an actor
capture support a human-reviewable IDOR/BOLA candidate. It does not replace
`propose_object_handoff`.

```python
from bugbounty_toolkit.analysis.idor_pairing_precision import evaluate_compatibility

assessment = evaluate_compatibility(owner_evidence, actor_evidence, context=siblings)
```

`assessment.compatibility` is one of `compatible`, `incompatible`, `insufficient_evidence`,
`conflicting_evidence`. `pairing_decision` is true only for `compatible`, and
`requires_human_review` follows that decision. `finding_confirmed` is always false.
`confidence_basis` is a citation of evidence refs and signals, not a float.

Account identity is used only when both sides carry `accounts_attested` and `account_ref`.
A session pseudonym is not an account. Route aliases apply only through `alias_rules`.

## Gate for changing the legacy default

`propose_object_handoff(..., compatibility_gate=False)` is still the default, so direct
handoff callers keep this legacy proposal set. The offline research pipeline
(`run_e2e_research`) turns the gate on. That behavior, the false-pair classes it
removes, and the frozen-split measurements are in
[idor-pairing-precision-v5.md](idor-pairing-precision-v5.md).

Hard negatives in `tests/test_idor_pairing_precision_v4.py` still apply to
`evaluate_compatibility`. `finding_confirmed` stays false.
