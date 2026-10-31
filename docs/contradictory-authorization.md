# Contradictory authorization evidence

A response can contain an exact resource ID and private marker while also saying
`success: false`, `error: forbidden`, or returning HTTP 401/403/404. The toolkit
preserves the resource-match predicates but treats this as inconclusive. It is
neither proof that access was denied without leakage nor a confirmed successful
cross-account operation.

This guard applies to native reads, inverse and anonymous reads, multi-account
matrices, numeric read ranges, offline response assessment, and offline pairing.
A contradictory owner response invalidates the positive control. Offline pairing
reports `conflicting_evidence`; existing review/reject/abstain distinctions remain.
Successful-looking data does not erase an explicit denial. Public/shared resource
handling and all scope, rate, request-budget and redaction requirements remain.

The regression fixtures are synthetic and use mocked transports. They include
HTTP 200 denials with private data, HTTP 403 resource bodies, invalid owner
controls, anonymous responses and both cross-account directions. Existing frozen
benchmark labels are intentionally unchanged. Real deployments still require
researcher review of ownership, privacy and the expected authorization policy.

Resource-shaped data for a third or unknown account also preserves the observed
contradiction. A missing owner-marker match does not turn that response into a
valid denial or an anonymous-policy mismatch. Fully denied account matrices
remain negative controls when all diagonal controls and off-diagonal reads finish.

Windows cannot run POSIX-private-artifact pipelines natively. The Linux PR job
records DEV/FINAL/STRESS results for the base and proposed commit separately;
those results must be reviewed alongside the unit tests before merging.

## Measured regression results

[Linux run 41003178546](https://github.com/jenmar23rondon-ux/Bug_Bounty_toolkit/actions/runs/41003178546)
evaluated base `d7973ef` and proposed `1d18351` with the unchanged frozen labels.
The checked-in snapshots were copied from its proposed artifact, not edited to
fit expectations. Metrics below are identical before and after this guard:

| Split | Cases | Outcome accuracy | Pair TP / FP / FN | Pair precision / recall |
| --- | ---: | ---: | --- | --- |
| DEV | 6 | 100% | 4 / 0 / 0 | 100% / 100% |
| FINAL | 45 | 84.44% | 27 / 14 / 0 | 65.85% / 100% |
| STRESS | 6 | 100% | 5 / 1 / 0 | 83.33% / 100% |

Both runs have zero false-reviewable cases after planning, missed eligible cases,
automatic confirmations and secret leaks. These are synthetic pipeline metrics,
not real-world detection rates. The remaining pairing false positives are not
fixed by this change. Its additional contradictory-response regressions are
separate unit fixtures, not additions to the frozen evaluation sets. Ollama
quality was not measured.
