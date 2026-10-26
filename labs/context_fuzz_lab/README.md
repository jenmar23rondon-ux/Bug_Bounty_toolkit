# Context-aware fuzzing lab

Synthetic loopback API + HAR capture for offline discovery planning. No real credentials, no external hosts.

## Contents

- `fixtures/capture.har` — authorized synthetic capture (secrets marked `SYNTH-SECRET`)
- `wordlists/` — tiny local collection (api, directories, parameters, technology; passwords present only to prove exclusion)
- `ground_truth.json` — known/unknown/protected routes and expected recommendation names

## Run the fixture server (optional execution checks)

```bash
python -m bugbounty_toolkit.context_fuzz_lab_server --port 8191
# or: bash labs/context_fuzz_lab/run.sh
```

Planning stays offline and does not need the server:

```bash
bbtk wordlists register context-lab labs/context_fuzz_lab/wordlists --registry /tmp/bbtk-wl.json
bbtk fuzz-plan lab-program --har labs/context_fuzz_lab/fixtures/capture.har --registry /tmp/bbtk-wl.json --dry-run
```

Execution against this lab must stay on loopback, reuse `bbtk fuzz ... --dry-run` then `--confirm`, and never treat status codes as confirmed findings.
