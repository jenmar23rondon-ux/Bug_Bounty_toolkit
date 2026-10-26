# Verified research dossiers

Offline claim-to-evidence audit for investigation drafts. Improves the path
**candidate → controls → evidence → review → draft** without replacing the
existing Markdown / HTML / JSON / PDF report renderers.

## Modules

| Piece | Path |
|---|---|
| Schema | `bugbounty_toolkit/reporting/dossier_schema.py` (`bbtk-verified-dossier/1`) |
| JSON Schema | `docs/schemas/verified-dossier-v1.schema.json` |
| Verifier | `bugbounty_toolkit/reporting/dossier_verifier.py` |
| Eval lab | `labs/verified_dossier_eval/` |

## What is checked

- Evidence IDs exist in the Evidence Ledger
- Digests still match on disk (detect altered / missing files)
- Provenance has tool + captured_at
- Declared ledger state matches the ledger
- Expected behavior cites an explicit source (`lab_spec`, `program_policy`, `explicit_declaration`, `human_declared`)
- Observed / control / ownership / impact / reproduction claims cite intact evidence
- HTTP 200 is never treated as unauthorized access by itself
- Impact is never inferred from an endpoint name
- Invented reproduction steps / payloads are rejected
- Model verdicts never confirm findings
- `confirmed` requires the ledger’s existing human-validation rules

## Dossier review states

`complete_for_review`, `missing_evidence`, `stale_evidence`, `contradictory_evidence`,
`unsupported_claim`, `human_validation_required`, `invalid_provenance`

The verifier **never** mutates ledger or finding states. `finding_confirmed` is
true only when the ledger already records a still-valid human confirmation.

## PRIVATE vs SHAREABLE

- **PRIVATE**: full inventory paths under the program directory (mode 0600 discipline unchanged).
- **SHAREABLE**: `minimize_dossier_for_share()` applies `RedactionDestination.SHAREABLE_REPORT` and replaces local paths.

Rendering reuses `render_evidence_report_markdown` / `render_evidence_report_json` for attached drafts.

## Opt-in usage

```python
from pathlib import Path
from bugbounty_toolkit.analysis.evidence_ledger import load_ledger
from bugbounty_toolkit.reporting.dossier_verifier import (
    verify_research_dossier,
    build_verified_dossier_from_evidence,
    write_verified_dossier,
)

ledger = load_ledger(Path("registros/demo/ledger/evidence-ledger.json"))
dossier = verify_research_dossier(package, ledger, program_dir=Path("registros/demo"))
write_verified_dossier(dossier, Path("reports/demo-dossier.json"))
```

## Lab

```bash
python -m labs.verified_dossier_eval.run_lab --split both
```

Synthetic only. Metrics are documentary-verification accuracy, not vuln-detection accuracy.

## Non-goals

- No new full report generator
- No scanners / detection scoring changes
- No autonomous AI confirmation
- No deduplication changes
- No network I/O
