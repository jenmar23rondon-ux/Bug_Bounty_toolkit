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

Do not filter `propose_object_handoff` proposals by default until a follow-up change shows
all of the following on a frozen split, with labels untouched:

- DEV and FINAL `pairing_decision` precision above the IRB reference 0.65
- any recall change explained in the PR
- hard negatives in `tests/test_idor_pairing_precision_v4.py` still passing
- `finding_confirmed` still false and `network_attempts` still 0

That follow-up would add an explicit `compatibility_gate` flag defaulting to off. This
change does not add the flag and does not alter handoff, eligibility, or Evidence Ledger
schemas or historical states.
