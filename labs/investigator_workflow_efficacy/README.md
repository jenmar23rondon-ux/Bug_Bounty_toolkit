# Investigator workflow efficacy

Disposable loopback lab for three scripted workflows:

- **A** — IDOR/BOLA
- **B** — reflected XSS and static DOM sink review
- **C** — disclosure with an audience header

Each case walks `scope → lab → capture → import → integrity → discovery →
candidates → negative controls → deterministic eval → evidence review →
contradictions → dossier draft → human review gate`. The gate stops. Nothing
sets `finding_confirmed`.

Arms:

- **manual** — checklist over the captured bytes. It does not call bbtk detectors.
- **bbtk** — `correlate_resources`, `classify_reflected_context`,
  `classify_dom_state`, `assess_disclosure`, `verify_research_dossier`, and
  `build_workflow`. Those modules are not modified by this lab.

DEV / FINAL / STRESS cases live in JSON. FINAL and STRESS hashes are in
`MANIFEST.sha256`. The runner refuses to score a frozen split whose file
changed. Human minutes are `NOT_MEASURED`.

```bash
python -m labs.investigator_workflow_efficacy.freeze
python -m labs.investigator_workflow_efficacy.evaluate --split all
```

`real_world/` is an opt-in private protocol. It is not imported here and it
does not send requests.

Fixture results are not field bug-bounty efficacy. Version stays 0.2.2.
