# Independent Adversarial Research Benchmark (`irb-1.0`)

Eval-only lab measuring how bbtk's offline IDOR/BOLA research pipeline generalizes to
scenario families it was **not** built on. It reveals weaknesses; it does not tune engines.

Pipeline under test (public interfaces only):
`run_e2e_research` (capture → import → discovery → ranking → handoff → eligibility →
reviewable case → evidence ledger → report) → `evidence_gap_planner.build_plan`.

```bash
python labs/independent_research_eval/build_corpus.py --check     # byte-identical corpus
python labs/independent_research_eval/evaluate.py --split final --json labs/independent_research_eval/results/final_metrics.json
python -m pytest tests/test_independent_research_eval.py -q
```

See `SPEC.md` (label spec), `AUDIT.md` (prior corpora), `results/` (HEAD metrics),
`docs/independent-research-benchmark.md` (diagnosis + recommendations).
Network is hard-blocked; nothing is ever confirmed or executed.
