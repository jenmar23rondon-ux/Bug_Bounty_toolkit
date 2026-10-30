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

Windows cannot run POSIX-private-artifact pipelines natively. The Linux PR job
records DEV/FINAL/STRESS results for the base and proposed commit separately;
those results must be reviewed alongside the unit tests before merging.
