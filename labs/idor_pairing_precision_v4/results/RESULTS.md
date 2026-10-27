# Pairing precision v4 measurements

Offline. `finding_confirmed` is false. `secret_leaks` is 0. `network_attempts` is 0.
IRB FINAL labels and `labs/independent_research_eval/final/MANIFEST.sha256` were not modified.
Legacy `propose_object_handoff` was not changed.

The first FINAL split was frozen (`446e72e`) before its first run. That run used
`127.0.0.1:8177` / `8178` and tripped the independent-research historical-overlap
guard. A second freeze (`34d247c`) moved the corpus to `127.0.0.1:8194` (alt
`8195`) without retuning expected decisions, and the numbers below are that
republished run. Decision metrics matched the first run.

## New lab (authored same-instance cases)

| Split | Before (`correlate_resources`) P / R / F1 | After (`evaluate_compatibility`) P / R / F1 | False pairs | Missed | Abstentions | Cross-kind admitted | Cross-program admitted |
|---|---|---|---:|---:|---:|---:|---:|
| DEV | 0.6667 / 1.0 / 0.8 | 1.0 / 1.0 / 1.0 | 0 | 0 | 1 | 0 | 0 |
| FINAL (20 cases) | 0.2857 / 1.0 / 0.4444 | **1.0 / 1.0 / 1.0** | 0 | 0 | 6 | 0 | 0 |

FINAL provenance completeness 1.0 on admitted pairs. Wall time 0.016879 s. Peak memory 32.1 KiB.
Reference next to these numbers: IRB FINAL 45 pairing precision **0.65**, recall **0.963**.

## IRB FINAL 45 re-eval (labels frozen)

| | Precision | Recall | F1 | TP | FP | FN |
|---|---:|---:|---:|---:|---:|---:|
| Frozen legacy handoff reference | 0.65 | 0.963 |  | 26 | 14 | 1 |
| `evaluate_compatibility` on same-instance pairs | **1.0** | **0.037** | 0.0714 | 1 | 0 | 26 |

Cross-kind pairs seen: 1. Cross-kind collisions admitted: 0.
The only admitted kind is `statement` on A01 (same id `73001` read by two sessions, private bodies).

### Recall regression (not accepted as a default flip)

Cause: IRB `ideal_pair_types` credit a resource *type* when legacy handoff pairs distinct instances
(owner id N with actor id N+1). `evaluate_compatibility` admits a pair only when the canonical
resource identity matches and the other controls hold (kind, namespace, endpoint, distinct
sessions, private content, intact artifacts, no shared ACL, no clean denial). Those distinct-instance
handoff proposals become missed pairs under the frozen type-level metric: A06, A10, B01, B02, B04,
B05, B07, B09, C01, C03, C08, C10, C11, D11–D18, E01, E02, E04, E06, E07.

Labels were not edited. This is why `compatibility_gate_status()` keeps
`propose_object_handoff` as the default. Do not flip that default on the IRB type-level recall.
