# From Burp Capture to Verified Security Dossier

These commands were run against the disposable investigator-workflow lab.
They stay on loopback. The ledger candidate remains `candidate`.
`finding_confirmed` stays false. Replace nothing here with a real program.

The shell variables are a temporary directory and the lab base URL written by
the capture command. Run them in one shell so `BASE` survives.

```bash
python3 -m labs.investigator_workflow_efficacy.capture --serve --case A-dev-vuln-order --case C-dev-public-secret --out "$ROOT/captures"
BASE=$(tr -d '\n' < "$ROOT/captures/base_url.txt")
bbtk --records-root "$ROOT/records" init iwe-tutorial --platform local --authorization "synthetic loopback investigator workflow lab" --automation-allowed
bbtk --records-root "$ROOT/records" scope add iwe-tutorial 127.0.0.1
bbtk --records-root "$ROOT/records" import burp iwe-tutorial --request "$ROOT/captures/A-dev-vuln-order.request.txt" --base-url "$BASE"
bbtk --records-root "$ROOT/records" evidence import iwe-tutorial --input "$ROOT/captures/A-dev-vuln-order.request.txt" --format http --output "$ROOT/records/iwe-tutorial/evidence/imports/unified-evidence.json"
bbtk --records-root "$ROOT/records" analyze disclosure --input "$ROOT/captures/C-dev-public-secret.disclosure.json" --output "$ROOT/records/iwe-tutorial/reports/disclosure.json"
bbtk --records-root "$ROOT/records" ledger init iwe-tutorial
bbtk --records-root "$ROOT/records" ledger surface iwe-tutorial --id surf-order --kind endpoint --ref /lab/A-dev-vuln-order --status investigated
bbtk --records-root "$ROOT/records" ledger evidence iwe-tutorial --id ev-order --path inputs/requests/A-dev-vuln-order-request.txt --tool burp-import
bbtk --records-root "$ROOT/records" ledger candidate iwe-tutorial --id cand-order --surface surf-order --category idor --raised-by tutorial-investigator --evidence ev-order --title "Synthetic IDOR candidate for human review"
bbtk --records-root "$ROOT/records" ledger validate iwe-tutorial
bbtk --records-root "$ROOT/records" ledger report iwe-tutorial --output "$ROOT/records/iwe-tutorial/reports/ledger.md"
```

What you should see:

- Scope contains `127.0.0.1`.
- Burp import rewrites the synthetic bearer to `[redacted]`.
- `analyze disclosure` writes a minimized summary. It does not echo the password field value and `finding_confirmed` is false.
- `ledger validate` exits 0.
- The ledger report describes one candidate. It does not mark the finding confirmed.

Stop there and review the draft yourself. Do not run `ledger review --state confirmed` from this tutorial.
