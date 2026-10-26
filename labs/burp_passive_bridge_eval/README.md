# Passive bridge evaluation

Audited `origin/main` and branch base: `bd289808600d57983f1dcacaa9b68c0d7eea0d18`.
Its commit subject is the merge of PR #52. No denial algorithms or existing importers
were modified. Phase 0 audited `burp_import`, `evidence_engine`, `har_import`,
`har_provenance`, `batch_capture_pipeline`, private file primitives, redaction and
README Burp import documentation. Baseline suite: **944 tests passed in 101.363 s**.

The existing XML evidence importer already preserves 50 selected messages in one
file; the discovery parser has a separate 32-item limit. The bridge validates entries
individually with that existing parser and never changes its limits. It uses the
existing evidence importer for the final optional private normalized bundle.

Run locally (Burp not required):

```sh
python -m unittest tests.test_burp_passive_bridge -v
python -m labs.burp_passive_bridge_eval.benchmark
```

`corpus.py` creates fifty runtime-only exchanges from two synthetic accounts.
Credentials are generated in memory, never committed or printed. `results.json` stores
counts and timings only. Baseline XML is reconstructed with the unchanged base importer;
the same corpus goes through export, private import and normalization for after metrics.
An additional duplicate probes storage deduplication. Socket connect is blocked during
the benchmark and the final pairing test; every supplied origin is synthetic `.invalid`.

| Metric | Before | After |
|---|---:|---:|
| Exchanges preserved | 50/50 | 50/50 |
| Correct request/response pairs | item-paired XML baseline | 50/50 checked bodies |
| Duplicate probe retained in raw transfer | native XML retains selected copies | 0 |
| Missing supplied capture timestamps | 0 | 0 (mock adapter) |
| Missing timestamps from real legacy selection | not measured | null, explicitly unavailable |
| Export errors on valid corpus | 0 | 0 |
| Secrets in minimized summary | no bridge summary | 0 |
| External requests | 0 | 0 |
| Documented manual actions for 50 messages | 3 | 6 |

Action counts are a workflow inventory, **not a human usability measurement**. Before:
select messages, save XML, invoke import. After: select messages, invoke context menu,
enter project, enter origins, confirm preview/choose destination, invoke import.
The bridge adds explicit review/provenance/private publication, not fewer clicks or
higher throughput. Timings in `results.json` are single local samples, not performance
claims; after includes validation, atomic export and import.

Adversarial tests cover one/two accounts, absent response, wrong scope, credential
canary generated at runtime, duplicates, interrupted atomic publication, truncated and
changed files, recomputed-digest scope changes, duplicate JSON keys, unsupported
version, deep JSON, oversized selection/messages/file, invalid base64/framing, non-UTF-8,
symlinks, private permissions, overwrite refusal, stable locators, no auto-confirmation
and legacy API registration/wire compatibility. Nothing tests a third-party target.

Limits: no real Burp/Jython runtime smoke test here; selected-message capture timestamps
are unavailable in the extension; cross-file/global deduplication is outside scope;
no claim that a digest authenticates an untrusted exporter. See the main bridge guide.

Quality validation: full suite 953/953 before the final two permission/CLI cases;
all 11 bridge cases pass after those additions. Ruff lint/format and strict mypy
(78 modules) pass. All existing CI coverage thresholds pass; bridge coverage is 92%.
The only shared configuration change is one explicit mypy module entry in
`pyproject.toml`; no CLI, workflow, version, importer or shared interface changed.
