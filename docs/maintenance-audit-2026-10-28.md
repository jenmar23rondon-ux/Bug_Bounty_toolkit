# Maintenance audit and refreshed synthetic metrics

Scope: capture intake/dossier publication, local AI advisory response handling,
and investigator-workflow evaluation reproducibility. This is a focused code
audit, not an assurance that every module is defect-free.

## Reproduced findings

1. Dossier publication used `Path.write_text`, following a destination symlink
   and inheriting default permissions. Fixed in PR #85 using existing private
   atomic I/O. Reproduce with `tests.test_dossier_verifier`: the linked target
   stays unchanged, existing outputs are refused, new outputs have mode 0600.
2. Local AI accepted malformed response fields before normalization, discarding
   unrecognized fields and replacing invalid lists with empty lists. PR #87
   rejects the declared-contract violations before clipping. Three baseline
   malformed responses accepted; the same three are rejected after the fix.
   Reproduce with `tests.test_local_ai_evidence_assistant`.
3. `results/metrics.json` still reported FINAL 9/12 and STRESS 9/10 even though
   the recorded dispositions and code had been corrected. This PR reruns the
   original frozen sets, records case/adapter hashes, and tests stable metric
   parity against fresh results. Timings remain machine-dependent and are not
   compared for exact equality.

## Refreshed evaluation

Command: `python -m labs.investigator_workflow_efficacy.evaluate --split all
--write labs/investigator_workflow_efficacy/results/metrics.json`.

| Frozen split | Previous stored BBTK correct | Fresh BBTK correct |
| --- | --- | --- |
| DEV | 9/9 | 9/9 |
| FINAL | 9/12 | 12/12 |
| STRESS | 9/10 | 10/10 |

All 31 synthetic cases now match their existing labels. Fresh evaluation reports
zero false positives accepted, false negatives, external requests, secret leaks
and automatic confirmations. These improvements reflect the prior classifier
fixes; regenerating this file does not itself improve detection. Frozen case
files and manifests are unchanged. The recorded metadata binds the result to the
adapter and corpus; source changes intentionally require a fresh measurement.

## Remaining limitations

- DOM results in this evaluation are static observations. Separate browser labs
  exist, but this run does not measure browser execution.
- Real Qwen/DeepSeek accuracy, memory and latency remain NOT_MEASURED. Mock schema
  tests cannot establish real model reliability or resistance to every injection.
- No investigator productivity study has been performed. Scripted wall-clock and
  action counts must not be presented as measured human time savings.
- The new capture dossier is an inconclusive intake inventory. Ownership and
  authorization still need human-supplied controls; the existing verified claim
  verifier remains the subsequent stage.
- Cross-batch identity merging is still deliberately unsupported; independent
  salted fingerprints cannot establish shared account identity.

Next iteration: evaluate independent authorized captures and measure task
completion with human investigators, then use the demonstrated bottleneck to
choose the next code change.
