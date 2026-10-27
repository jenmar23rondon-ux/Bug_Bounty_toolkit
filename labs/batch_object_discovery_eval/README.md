# Offline batch Object Discovery evaluation

Base and audited `origin/main`: `bd289808600d57983f1dcacaa9b68c0d7eea0d18`.
Its history includes PR #51 (`a12299d`) and PR #52 (`bd28980`). Independent clone,
branch `feature/batched-object-discovery`, version 0.2.2. The existing authorization
denial assessment and resource kind/ranking algorithms are unchanged.

Audit: `CampaignPlan` carries content-addressed batch IDs and original source hashes;
`run_campaign` writes completion state and output hashes. `batch_bundle_paths` does
not validate either. `evidence_engine` normalizes and redacts values, so bundles alone
cannot recover original object IDs. Direct Object Discovery rejects a HAR over 32
entries; its aggregate capture limit is 256. Graph limits are independently 10,000
nodes, 30,000 edges, 8 MiB. These ceilings were not raised.

Reproduce from an installed source checkout:

```bash
python -m labs.batch_object_discovery_eval.run
python -m unittest tests.test_batch_object_discovery -v
ruff check bugbounty_toolkit tests scripts skills labs
ruff format --check bugbounty_toolkit tests scripts skills labs
mypy --strict
mypy --strict bugbounty_toolkit/analysis/batch_object_discovery.py labs/batch_object_discovery_eval/run.py tests/test_batch_object_discovery.py
coverage run -m unittest discover -s tests
```

All fixtures are generated in temporary storage from synthetic `.test` captures.
The benchmark and adversarial suite block socket `connect`; no service is needed.
Fixtures contain synthetic credential canaries; reports contain only counts/timings,
never captures or credentials. No key or canary is included in recorded results.

## Before / after

`run.py` executes the unmodified public object builder as the baseline before each
coordinator run. For >32 entries this reproduces the whole-input failure. The before
measurement therefore does not represent successful work of equivalent scope.
Ingestion is performed before timing discovery and excluded from after timings.
Both before and after use `tracemalloc`; values are Python allocation peaks, not RSS,
and timings are environment-specific. `results.json` records the reproducible run.

| Entries | Files | Before retained | After retained | Correct locators |
|---:|---:|---:|---:|---:|
|16|1|16|16|16|
|32|1|32|32|32|
|33|1|0|33|33|
|64|1|0|64|64|
|128|1|0|128|128|
|256|1|0|256|256|
|200|200|0|200|200|

These fixtures have a construction oracle: one order per unique literal, three
object relations per order and two shared field relations per batch. Object and
within-batch relationship recall are 100%, unexpected relationship count is zero,
technical failures zero, and every entry is reused on resume. These are checked
assertions, not estimated/model-derived scores. Cross-batch graph merges are zero by
construction of the coordinator. This does not measure cross-batch relationship
recall or establish real-world session/account identity. Peak allocation is roughly
128–131 MiB, dominated by the existing bounded input reader's allocation; no streaming
or large-capture memory improvement is claimed. Per-batch coverage is in the JSON.

## Adversarial laboratory

The accompanying unittest suite constructs the additional scenarios, without retaining
raw canaries in Git or reports:

| Scenario | Check |
|---|---|
| Duplicate entries and repeated evidence across batches | Original locators survive; partitions remain separate |
| Same literal in order/user namespaces | Distinct object nodes |
| Two sessions, inconsistent origins | Three origin-scoped session contexts, no cross-batch merge |
| Interrupted campaign and orphan bundle | Pending batch never consumed; partial flag remains |
| Resume | Authenticated prior batch reused once; fresh snapshot replaces previous |
| Modified bundle / original source | Hash refusal, zero consumed partitions |
| Tampered cache / changed key | Recompute rather than trusting modified results |
| Global entry budget exhausted | Later batch pending, partial result |
| Global graph budget exhausted | Consolidation stops, no complete claim |
| 257-entry object stage | Existing observation limit refuses batch |
| Partial graph / excessive reference list | Object rejection count and partial result |
| Invalid HAR entry | Import rejection retained in coverage |
| Ambiguous cross-batch identity | Explicit warning and no global ranking guarantee |
| Symlink bundle | Secure input reader refuses it |
| Authorization / manifest mismatch / legacy compat | Fail closed |

No HTTP, CLI, policy gate, redaction, parser or ranking changes are introduced.
Limitations and API contract are in [documentation](../../docs/batch-object-discovery.md).
