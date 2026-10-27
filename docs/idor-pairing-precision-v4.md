# IDOR pairing precision v4

Opt-in evidence check for whether an owner capture and an actor capture refer to
the same resource. See `docs/idor-pairing-v4-audit.md` for the failure modes of
the legacy handoff path.

`bugbounty_toolkit.analysis.idor_pairing_compatibility.evaluate_compatibility`
returns `bbtk.idor-compatibility/1`:

- `compatibility`: `compatible`, `incompatible`, `insufficient_evidence`, or
  `conflicting_evidence`
- `pairing_decision`: true only when `compatibility` is `compatible` (admit to
  human review)
- `confidence_basis`: cited signals, never a float
- `finding_confirmed`: always false
- `network_requests_sent`: always 0

Same digits under two kinds do not match. A public or shared ACL, a clean
denial, a missing response, a hash mismatch, a second session of the same
attested account, or a disjoint time window is not an IDOR candidate.

`propose_object_handoff` is unchanged. Flip that default only after the gate
criteria in `compatibility_gate_status()` are met. IRB FINAL 45 ideal pair
types mostly name distinct instances of one kind; they are the wrong signal
for that flip.

Lab: `labs/idor_pairing_precision_v4/`. Version stays 0.2.2.
