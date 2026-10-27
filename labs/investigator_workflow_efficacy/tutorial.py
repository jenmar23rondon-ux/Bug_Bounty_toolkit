"""Commands for the Burp-capture tutorial. Tests execute this tuple."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]

COMMANDS: tuple[str, ...] = (
    "python3 -m labs.investigator_workflow_efficacy.capture --serve --case A-dev-vuln-order "
    '--case C-dev-public-secret --out "$ROOT/captures"',
    "BASE=$(tr -d '\\n' < \"$ROOT/captures/base_url.txt\")",
    'bbtk --records-root "$ROOT/records" init iwe-tutorial --platform local '
    '--authorization "synthetic loopback investigator workflow lab" --automation-allowed',
    'bbtk --records-root "$ROOT/records" scope add iwe-tutorial 127.0.0.1',
    'bbtk --records-root "$ROOT/records" import burp iwe-tutorial '
    '--request "$ROOT/captures/A-dev-vuln-order.request.txt" --base-url "$BASE"',
    'bbtk --records-root "$ROOT/records" evidence import iwe-tutorial '
    '--input "$ROOT/captures/A-dev-vuln-order.request.txt" --format http '
    '--output "$ROOT/records/iwe-tutorial/evidence/imports/unified-evidence.json"',
    'bbtk --records-root "$ROOT/records" analyze disclosure '
    '--input "$ROOT/captures/C-dev-public-secret.disclosure.json" '
    '--output "$ROOT/records/iwe-tutorial/reports/disclosure.json"',
    'bbtk --records-root "$ROOT/records" ledger init iwe-tutorial',
    'bbtk --records-root "$ROOT/records" ledger surface iwe-tutorial --id surf-order '
    "--kind endpoint --ref /lab/A-dev-vuln-order --status investigated",
    'bbtk --records-root "$ROOT/records" ledger evidence iwe-tutorial --id ev-order '
    "--path inputs/requests/A-dev-vuln-order-request.txt --tool burp-import",
    'bbtk --records-root "$ROOT/records" ledger candidate iwe-tutorial --id cand-order '
    "--surface surf-order --category idor --raised-by tutorial-investigator "
    '--evidence ev-order --title "Synthetic IDOR candidate for human review"',
    'bbtk --records-root "$ROOT/records" ledger validate iwe-tutorial',
    'bbtk --records-root "$ROOT/records" ledger report iwe-tutorial '
    '--output "$ROOT/records/iwe-tutorial/reports/ledger.md"',
)


def run_tutorial(root: Path) -> str:
    """Execute every tutorial command. Returns combined stdout."""
    env = os.environ.copy()
    for key in ("http_proxy", "https_proxy", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY"):
        env.pop(key, None)
    env["NO_PROXY"] = "*"
    env["ROOT"] = str(root)
    # Keep the caller's PATH first. A login shell would replace it, and the
    # offline lab image only has PyYAML inside /opt/venv/bin.
    env["PATH"] = os.pathsep.join((str(Path.home() / ".local" / "bin"), env.get("PATH", ""), "/usr/bin", "/bin"))
    chunks: list[str] = []
    script = "set -euo pipefail\n" + "\n".join(COMMANDS)
    completed = subprocess.run(
        ["bash", "-c", script],
        cwd=REPO,
        env=env,
        check=False,
        text=True,
        capture_output=True,
    )
    chunks.append(completed.stdout)
    chunks.append(completed.stderr)
    if completed.returncode != 0:
        raise RuntimeError(f"tutorial exited {completed.returncode}\n{completed.stdout}\n{completed.stderr}")
    return "\n".join(chunks)
