# Reviewing related endpoint observations across batches

Campaign discovery already validates source and bundle hashes, namespaces
graphs per batch and authenticates reusable partitions. It previously returned
no cross-batch review index. Do not merge graphs or infer account/object identity
from matching literal IDs.

`cross_batch_endpoint_review` now indexes endpoint contexts shared by at least
two successfully validated partitions. Each group contains the pseudonymized
endpoint reference and batch-qualified observation references; the observations
retain source provenance in their original partitions. Endpoint references
include origin, method and normalized path template. Other origins or methods
remain separate. No URLs, payloads, session values or raw identifiers are added.

Each hint explicitly requires human review and declares object and account
identity `not_established`. It is an index of observations of an endpoint, not
an authorization finding, pair proposal or proof of shared ownership. Graphs,
rankings, Evidence Ledger state and confirmation decisions remain unchanged.
Work is bounded by the campaign's existing accepted graph/observation limits;
the index groups observations instead of generating quadratic pair combinations.

Acceptance and synthetic regression: two related validated batches yield
review groups (previously zero exported groups); pending/orphan batches yield
none; every reference resolves to its own batch; authenticated resume yields
the same index; canary secrets are absent and network is blocked in tests.
This does not measure time saved by a human researcher.

```bash
python -m unittest tests.test_batch_object_discovery tests.test_batch_capture_pipeline -q
```

Version 0.2.2, default offline operation and human approval remain unchanged.
