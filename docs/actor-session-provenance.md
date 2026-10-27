# Actor and session provenance v1

`analysis.actor_provenance` is an opt-in offline sidecar API. It consumes immutable
`EvidenceRecord` instances and a local manifest, and returns `bbtk.actor-provenance/1`.
It does not execute HTTP, authorize testing, assess denials, or change finding states.
PR #52 remains the authority for denial assessment and is untouched.

## Audit and baseline

Base and `origin/main`: `bd289808600d57983f1dcacaa9b68c0d7eea0d18`.
PR #52 was verified merged at that commit. Its main Python workflow
[40417920919](https://github.com/jenmar23rondon-ux/Bug_Bounty_toolkit/actions/runs/40417920919)
completed successfully. Package version remains 0.2.2.

Audited interfaces:

- `evidence_engine`: frozen records carry source path/locator, capture time and
  24-hex HMAC session fingerprints. Request and response fingerprints can expose a
  context transition; none proves authentication or account identity. Import keys
  are ephemeral; fingerprints from separate imports need not be comparable.
- `object_relationships`: program/origin-scoped keyed session references explicitly
  retain unknown account identity; graph integrity and key checks remain unchanged.
- `investigation_memory`: lifecycle indices are local to the program database; it
  does not record actor identity. No lifecycle/schema changes are needed.
- `access_control/comparison`: captured session declarations and human authorization
  remain independent. This sidecar cannot be used as authorization or as its case input.
- `har_provenance`: per-entry locators and digests account for imports, not identity.
- `redaction`: existing secret minimization remains intact. This module emits only
  allowlisted enums, validated timestamps and keyed references, never input text.

The existing engine has no actor-manifest consumer and makes no account associations.
Before implementing the module, that behavior was measured on the frozen 11-scenario
synthetic corpus in `labs/actor_provenance_eval`: every account association abstains.
The baseline is capability-specific, not an accuracy claim for the full repository's
research or denial corpora. Existing capture/graph/denial tests remain regression checks.

## Use

```python
from bugbounty_toolkit.analysis.actor_provenance import load_manifest, associate_actors

manifest = load_manifest(local_manifest_path)
sidecar = associate_actors(records, manifest, program=program, key=private_program_key)
```

Use the program's existing private HMAC key (at least 32 bytes); never publish it.
The caller supplies only records belonging to that program from a single import/key
context. EvidenceRecord itself has no program attestation: this API rejects a mismatched
manifest but cannot establish the origin of records supplied by a dishonest caller.
No global registry, cross-program lookup or implicit association exists.

Manifest schema: `docs/schemas/actor-labels-v1.schema.json` (`bbtk.actor-labels/1`).
The runtime additionally checks duplicates, resolved selectors and alias references.

```json
{
  "schema": "bbtk.actor-labels/1",
  "program": "local-lab",
  "labels": [
    {"source_path": "/private/capture.har", "locator": "/log/entries[0]",
     "evidence_id": "existing-evidence-id-a", "label": "owner", "account": "account-a", "declared_by_human": true,
     "browser": "browser-a", "pwnfox_color": "blue"},
    {"source_path": "/private/capture.har", "locator": "/log/entries[1]",
     "evidence_id": "existing-evidence-id-b", "label": "second_account", "account": "account-b", "declared_by_human": true}
  ],
  "distinct_accounts": [["account-a", "account-b"]]
}
```

Keep this manifest private: use disposable aliases, never credentials, usernames or
email addresses. Raw paths, locators, account/browser aliases and existing fingerprints
are not copied into the sidecar. Source/locator/evidence references bind the declaration
through HMAC; these references are namespaced sidecar references, not graph IDs.
No original evidence is edited. A selector must resolve to exactly one record provenance and match its existing
`evidence_id`; replaced or reimported captures require a fresh declaration.
Duplicate, stale or missing matches fail closed. Unlabelled captures retain `unknown`.
Bound: 1 MB local JSON, 4096 label rows/captures/pairs, 300 characters per selector/alias.

`pwnfox_color` reads `X-PwnFox-Color` from captured HAR request headers or a header
mapping without Pwnfox installed. Unknown, duplicate or unsupported colors abstain.
It returns only a color. An operator must bind it to the exact selector in a manifest;
there is deliberately no color-to-account mapping. Accepted colors: red, orange,
yellow, green, cyan, blue, purple, pink. Other export formats require manual labels.

## Meaning and conflicts

`browser_ref`, `session_ref` and `account_ref` are different observations/declarations.
Same browser or same cookie never asserts same account. Account refs reflect only
explicit human declarations, not verified identity/ownership/authentication.
`distinct_accounts` requires its own explicit human pair declaration; different aliases
or fingerprints alone do not assert two different accounts.

Conflicting accounts for one label or session suppress the affected account claims to
unknown, emit an unresolved conflict, and suppress distinct-account pairs that depend on
those claims. Multiple session contexts under one label also emit an unresolved review
item; they can represent legitimate rotation or multiple sessions of one human-declared
account. They do not automatically merge sessions or revoke a consistent declaration.
Anonymous captures with session material generate a review conflict. All conflicts remain
`human_review_required`; none is automatically resolved.

Different valid capture timestamps and request/response context changes are recorded.
This reports observed fingerprint changes, not proof of token rotation, login or expiry.
Missing timestamps, fingerprints and labels remain unknown; no temporal ordering or
session lifetime is invented. Missing cookies do not prove anonymity.

## Evaluation

Run offline:

```
python -m labs.actor_provenance_eval.evaluate --baseline
python -m labs.actor_provenance_eval.evaluate
python -m unittest tests.test_actor_provenance -v
mypy --strict bugbounty_toolkit/analysis/actor_provenance.py labs/actor_provenance_eval tests/test_actor_provenance.py
```

Frozen `before.json` / `after.json` report declaration association accuracy (including
correct abstentions), label coverage, incorrect associations, correct abstentions,
conflicts and exposed runtime canaries. The corpus includes two human accounts, same
account with multiple cookies, rotation, wrong color, anonymous/unlabelled captures,
duplicate session IDs and contradictory labels. The adversarial tests separately exercise
another program, ambiguous selectors, raw fingerprints, malformed manifests, duplicate
JSON keys, missing declarations, unchanged originals, determinism, and blocked network.
These small fixtures demonstrate invariants, not production identity verification.
