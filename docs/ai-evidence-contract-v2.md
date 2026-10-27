# AI evidence contract v2

Schema: `bbtk.ai-evidence-contract.v2` (`docs/schemas/ai-evidence-contract-v2.schema.json`).

Builder: `analysis/ai_evidence_contract_v2.build_contract_packet`.

The packet is the structured view a local model may receive. It is booleans,
enums, nulls, and synthetic refs (`E01`, `ec2-…`). It is not a finding and it
does not replace `review_evidence`.

## Tri-state

Boolean fields stay `null` when the capture declares unknown or omits a value
that cannot be observed. An explicit null is never rewritten to `false` or
`true`, even when a row would otherwise imply the opposite. Enum fields use
`unknown` the same way.

`visibility` is copied from an allowlisted annotation or from allowlisted row
values. A private marker does not imply `visibility=private`, so a shared
resource can survive minimization.

Contradictions between cross-reads are objects `{ref, opposes, aspect}`. They
are not prose.

## Privacy

`lint_contract_packet` fails when a forbidden field is present or a string is
not on the allowlist. Forbidden names include cookies, authorization/bearer,
passwords, bodies, query secrets, `localStorage`, account ids, raw HTML,
secret hashes, and instruction/prompt fields. Digests of secret material
(md5, sha1, sha256) are treated as leaks. Synthetic account refs must match
`SYNTH_[A-Z0-9]{1,16}`.

The model is not given tools. `tools_available`, `requests_emitted`,
`ai_classification_authority`, and `finding_confirmed` are fixed false.
`tool_execution_observed` records a boolean declaration only. Prose that says
to run a tool does not set it.

## Opt-in dual-review advisory

`bbtk ai dual-review --normalize-advisory` (or `dual_review(..., advisory_normalization=True)`)
attaches `normalized_advisory`. The production `comparison.advisory_decision`
is unchanged.

Consensus can be `candidate` or `not_observed` only when all of these hold:

- the packet is schema-valid, unlinted, intact, and complete
- both reviews are valid and agree
- every cited ref exists and no claim was invented
- the shared decision is compatible with the packet (shared and unknown
  visibility cannot become `candidate`; unknown cannot become `not_observed`)
- a `candidate` has no missing controls

The advisory still has `finding_confirmed: false`, does not write the ledger,
and does not rewrite packet controls. Historical ledger states are not loaded.

## Lab

`labs/ai_evidence_contract_v2_eval/` is offline. DEV is for checking the
contract. FINAL is frozen (`MANIFEST.sha256`) and held out of DEV. CI runs
`python -m labs.ai_evidence_contract_v2_eval.evaluate --split all` with no
model and no sockets.

Metrics: known-fact preservation, semantic loss, unknown preservation,
privacy-leak rate, schema-valid rate, compared with the v1 minimized bundle.
Real model quality is `NOT_MEASURED`.

Version stays **0.2.2**.
