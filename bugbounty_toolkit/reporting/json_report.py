from __future__ import annotations

import json
from pathlib import Path

from ..analysis.evidence_ledger import load_ledger, validate_ledger
from ..core.records import RecordStore
from ..core.redaction import redact_data
from ..core.scope_validator import ScopeValidator


def build_program_report(store: RecordStore) -> dict[str, object]:
    evidence = []
    runs = store.runs()
    for run in runs:
        if not run["output_path"]:
            continue
        path = Path(run["output_path"])
        if path.suffix != ".json" or not path.resolve().is_relative_to(store.paths.program_dir.resolve()):
            continue
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            evidence.append({"run_id": run["id"], "path": str(path), "error": "Evidence unavailable or invalid JSON"})
            continue
        evidence.append({"run_id": run["id"], "path": str(path), "data": redact_data(data)})
    report: dict[str, object] = {
        "program": store.paths.program,
        "records_path": str(store.paths.program_dir),
        "counts": store.counts(),
        "scope": ScopeValidator(store.paths.scope_file).summary(),
        "runs": redact_data(runs),
        "reviewed": redact_data(store.reviewed()),
        "findings": store.findings(),
        "evidence": evidence,
    }
    ledger_path = store.paths.program_dir / "ledger" / "evidence-ledger.json"
    if ledger_path.is_file():
        try:
            ledger = load_ledger(ledger_path)
            validation = validate_ledger(ledger, program_dir=store.paths.program_dir)
            report["evidence_ledger"] = {
                "valid": validation["valid"],
                "error_count": validation.get("error_count", 0),
                "summary": validation["summary"],
            }
        except ValueError as exc:
            report["evidence_ledger"] = {"valid": False, "error": str(exc)[:200]}
    return report


def render_json_report(store: RecordStore, destination: Path) -> Path:
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(build_program_report(store), indent=2, sort_keys=True), encoding="utf-8")
    return destination
