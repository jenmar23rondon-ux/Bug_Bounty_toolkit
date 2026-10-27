# Real-world protocol (opt-in, private)

This protocol is not a lab and it is not part of CI. `evaluate.py` does not
import it. `python -m labs.investigator_workflow_efficacy.real_world` exits 2
and does not open a socket, even if `BBTK_IWE_REAL_WORLD=1` is set, because
this checkout ships no authorized target list.

## When a human may run it

1. Written authorization already covers the asset, the accounts, and the
   methods. The program is the researcher's, not one named by this repository.
2. Export `BBTK_IWE_REAL_WORLD=1` in a private shell. Unset it afterwards.
3. Keep captures, tokens, and notes in a directory outside every git checkout
   (`labs/investigator_workflow_efficacy/real_world/private/` is gitignored if
   someone creates it here by mistake).
4. Use the same stage chain as workflows A/B/C: scope, capture, import,
   integrity, discovery, candidates, negative controls, deterministic eval,
   evidence review, contradictions, dossier draft, human review, finish or
   reject.
5. Leave `finding_confirmed` false until a person who did not raise the
   candidate attests a review in the ledger. The toolkit does not submit the
   report.

## What may be published

Only anonymized aggregates: counts of candidates reviewed, false positives
accepted, false negatives later found, missing evidence, and whether any
secret-redaction check failed. No hostnames, account ids, tokens, request
bytes, or screenshots that show a real session.

## What this repository records

`real_world_program` is `NOT_MEASURED`. No real program was contacted to
produce the draft pull request.
