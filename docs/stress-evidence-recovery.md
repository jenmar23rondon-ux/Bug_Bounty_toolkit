# Bounded recovery of the three missing STRESS cases

Baseline: main `2b6cec9`, unchanged irb-1.0 corpus and labels. DEV 6/6,
FINAL 38/45, STRESS 3/6. The failures were reproduced in the production E2E
workflow: S01 exceeded 256 accepted observations; S03 rejected its owner's
60-level JSON; S04 suppressed integer resource metadata under token-like names.

## Acceptance and implementation

Recover all three as cases requiring human validation, without promoting a
candidate to a confirmed finding or sending requests. Keep ordinary import
limits intact; explicitly record a finite research profile and apply the same
policy during handoff re-import, graph validation and benchmark stage timing.
Keep frozen inputs, manifests and labels byte-identical. Reject inputs beyond
the profile ceilings and keep credential values excluded. Propagate the body
policy into native IDOR proposal generation and credential checks, not only
graph import, so deeply nested captures do not fail in a later stage.

The existing E2E research workflow selects `bounded-research-v1`: 512 accepted
captures across all input files, body JSON depth 64. Ordinary object discovery
retains 256 accepted captures and body depth 16, with a 32-entry default HAR
window. File bytes, total bytes, declared-entry ceiling 4096, scalar-field cap
128, scalar traversal cap 4096, pointer length, graph nodes/edges, proposal caps
and source integrity checks are unchanged. The profile is signed in the graph;
handoff must use the recorded profile rather than silently reverting to defaults.

Collection names alone are not treated as credential values. Open-vocabulary
names such as token-inventory endpoints remain HMAC-only in output. Only
nonnegative integer `id` metadata under structured token-resource containers can be
used as resource references. Textual IDs, booleans, scalar tokens, passwords,
cookies and copied known credential values remain excluded. Metadata does not
prove resource privacy, distinct accounts, ownership or unauthorized access.
Integer values under password/secret/authorization/cookie/credential containers
remain credentials; the metadata exception is not a generic sensitive-field bypass.

## Measurements and limits

STRESS outcomes improve to 6/6, with missed eligible cases 3→0. DEV remains
6/6 and FINAL 38/45. False reviewable cases, secret leaks, automatic
confirmations and network attempts remain zero in these synthetic evaluations.
S05 still raises a deliberate all-damaged-input error, matching its frozen
`technical_error` label; this is the one remaining counted pipeline exception.

This does not solve ranking efficiency: STRESS redundant proposals rise
59→80, and pairing precision is 0.8333 versus 1.0 on the smaller previous
set of recovered pairs. Request-incompatible noise proposals remain rejected,
not findings. S01's useful archive is still ranked below telemetry noise.
These regression datasets are already known and are not a new blinded test.

Tests include all three original failed cases; default-vs-research behavior;
512 accepted captures with provenance-preserving handoff; rejection of 513;
depth-60 acceptance, depth-over-64 rejection, invalid policy parameters;
secret canaries, textual/numeric copied credentials and integer metadata.
Native proposal generation is also checked for errors in all three recovered
cases. A deep token copied into an otherwise benign proof-marker field is
rejected both during suggestions and during explicit approval.
The existing resume test now uses an unexpired copy of its mixed fixture:
recovery also exposes its intentionally expired token pair, whose expiry warning
must not be mistaken for a modified-file integrity regression. Frozen files are
never rewritten.

```bash
python -m unittest tests.test_stress_evidence_recovery -v
python labs/independent_research_eval/build_corpus.py --check
python labs/independent_research_eval/evaluate.py --split stress
```

Version 0.2.2 is unchanged. No tags/releases or external security tests.
