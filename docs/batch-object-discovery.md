# Batch campaigns and Object Discovery

`analysis.batch_object_discovery.discover_campaign` is an offline Python API consuming
the completed outputs of `batch_capture_pipeline`. It does not run a campaign, modify
campaign state, authorize remote tests, confirm findings or send HTTP. A caller must
attest authorization to analyze local captures and provide the existing 32-byte object
key. No CLI, shared interface, parser, ranking, denial assessment or redaction changes
are needed. Version remains 0.2.2.

```python
from bugbounty_toolkit.analysis.batch_object_discovery import discover_campaign

# plan: the original CampaignPlan; key: existing private object key, never logged
snapshot = discover_campaign(
    plan, state_dir, key, authorized=True, max_entries=1000,
)
# Resume ingestion separately, then replace the snapshot, rather than append it:
snapshot = discover_campaign(
    plan, state_dir, key, authorized=True, max_entries=1000, previous=snapshot,
)
```

Treat snapshots as **private** artifacts. Use the existing `atomic_private_write`
helper if persistence is needed; do not publish captured values, keys, bundles or
private graphs. The coordinator itself only writes temporary mode-0600 fragments
inside a mode-0700 temporary directory; they are removed on success and exceptions.
An abrupt process kill can leave that private temporary directory for local cleanup.

## Contracts and validation

The returned `bbtk.batch-object-discovery/1` dictionary contains campaign and manifest
IDs, replacement `partitions`, batch `coverage`, per-file coverage and source hashes,
accepted/rejected entry counters, importer rejections, omitted and duplicate file
counts, graph totals and limits. `processed` means attempted discovery, while
`entries_accepted_at_discovery` and `entries_rejected_at_discovery` describe recovery.
Pending batches have no invented entry denominator: `entries_imported` may be null.
Every partition contains an unchanged signed Object Discovery graph, the existing
top-100 candidate ranking, and an authenticated provenance table mapping each
fragment source/locator to campaign, batch, original file reference/hash and original
locator. Multiple mappings are retained for identical fragments; they are not guessed
to be one original capture.

The state schema, campaign ID, manifest hash and entire manifest must match the plan.
Only `completed` batches with an output hash are consumed. Bundle bytes and original
source bytes must match their recorded SHA-256 values. Pending bundles and orphan
files are ignored even if `batch_bundle_paths` lists them: that helper checks existence,
not completion or integrity, and is therefore insufficient as a validation authority.
The plan and campaign state are local trusted metadata; SHA-256 detects changed
artifacts, not a malicious actor replacing the plan, state and every digest together.

Normalized bundles deliberately omit literal IDs and credentials. They cannot safely
be reverse-engineered into raw objects. Their validated provenance selects original
entries from hash-verified local HAR sources. Public `load_har_entries` performs the
existing structural checks. Public `build_object_graph` validates each <=32-entry
fragment and the complete batch graph; its public output supplies source references.
No private object-extraction or HMAC implementation is imported or copied.

## Limits, identity and partial results

Importer limits and object limits are separate. Campaign limits are never raised:
the importer still has its original file/record/byte ceilings. Object fragments retain
the existing `MAX_EXCHANGES` (32) and `MAX_ITEM_BYTES`; a batch graph retains
`MAX_FILES` (16 fragments), `MAX_CAPTURES` (256), total byte, node, edge and export
limits. A 33-entry HAR can therefore become two valid fragments in one batch graph,
preserving relationships across the fragment boundary. A 257-observation batch is
refused, not truncated or split into supposedly complete graphs. Plan smaller batches
or pre-split local sources before ingestion when that stage cannot safely handle them.

An explicit `max_entries` is bounded by the campaign total and hard campaign ceiling.
Completed batch record counts reserve this budget in plan order, even if later source
validation fails; failed validation cannot be used to bypass the global budget.
Additionally, cumulative partition nodes, edges and serialized partition bytes may not
exceed the existing graph ceilings (10,000 / 30,000 / 8 MiB). Exhaustion stops graph
consolidation and leaves remaining batches pending. No limit is silently clamped.

Graphs stay independent across batches, even with matching salted fingerprints or
object references. The coordinator does not infer account identity, connect resources
across batches, or introduce a ranking algorithm. Namespaces, origins and session
contexts within a batch remain governed by the existing object builder. With multiple
partitions `ambiguous_joins` reports that cross-batch identity is unestablished and
`global_ranking_guaranteed` is false. Only counts and coverage are consolidated.
Cross-batch repeated evidence is retained in its original partitions, not merged or
deduplicated as if it were one session. Exact duplicate files omitted by the campaign
are counted explicitly. Resume avoids repeating discovery, not hashing: a partition
must match its campaign/bundle/limit binding and HMAC under the supplied key before
reuse. Altered cache data or a new key triggers recomputation. A snapshot never
accumulates an old batch twice.

`complete` is false when any batch is pending/rejected, an input was omitted/rejected,
HAR entries were rejected, or discovery recovered a partial graph. This flag concerns
coverage of the declared campaign, not proof that an API/object inventory is exhaustive.

Current limitation: only HAR campaigns imported in `partial` or `strict` mode are
supported. Legacy `compat` campaigns are refused because reserializing an ambiguous
entry could erase duplicate-key evidence. Burp XML/raw HTTP imports remain available
through existing APIs, but are explicitly rejected here rather than guessing locator
translations. No changes were made to those importers. Cross-batch relationship recall
and a globally complete candidate ranking are deliberately not claimed.

See [evaluation](../labs/batch_object_discovery_eval/README.md) for baseline and final
measurements, adversarial scenarios and reproduction commands.
