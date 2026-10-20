# CLI and Plan Reference

Run from the toolkit checkout with Python 3.10+. Install with `python -m pip install -e .`. The `bbtk`, `bugbounty` and `python -m bugbounty_toolkit.cli` commands use the same implementation. ffuf is required only for live fuzzing.

## Authorized Program Setup

Use policy values supplied for the program. Retain existing configuration when it matches the request. Configure explicit domains or URL prefixes and exclusions; a bare domain authorizes only that host, while `*.domain` covers subdomains but not the apex.

```bash
python -m bugbounty_toolkit.cli init my-program --authorization "USER-SUPPLIED-POLICY-REFERENCE" --automation-allowed --config config/settings.yaml
python -m bugbounty_toolkit.cli scope import my-program config/scope.yaml
```

Omit `--automation-allowed` when the program disallows automation. Placeholder configuration does not establish permission. Rate, concurrency and test budgets cannot exceed program settings.

## Command Examples

```bash
python -m bugbounty_toolkit.cli request my-program --url "https://authorized.example/search" --param "q=example" --dry-run
python -m bugbounty_toolkit.cli request my-program --raw-request inputs/requests/captured.txt --base-url "https://authorized.example" --dry-run
python -m bugbounty_toolkit.cli fuzz my-program --url "https://authorized.example/FUZZ" --wordlist wordlists/api-endpoints.txt --rate 1 --threads 2 --dry-run
python -m bugbounty_toolkit.cli xss my-program --routes inputs/routes.txt --parameters inputs/parameters.txt --base-url "https://authorized.example" --rate 1 --max-tests 40 --dry-run
python -m bugbounty_toolkit.cli xss my-program --routes inputs/routes.txt --parameters inputs/parameters.txt --confirm-exec --max-tests 7 --dry-run
python -m bugbounty_toolkit.cli sqli my-program --routes inputs/routes.txt --parameters inputs/parameters.txt --deep --max-tests 8 --dry-run
python -m bugbounty_toolkit.cli cors-check my-program --url "https://authorized.example/account" --dry-run
python -m bugbounty_toolkit.cli open-redirect my-program --url "https://authorized.example/login?next=%2Fhome" --param next --dry-run
python -m bugbounty_toolkit.cli access-check my-program --case-file registros/my-program/private/case.json --range 1-10 --max-range 10 --max-tests 12 --min-interval 10 --concurrency 1 --dry-run
python -m bugbounty_toolkit.cli access-check lab --case-file registros/lab/private/write-case.json --lab-write --dry-run
python -m bugbounty_toolkit.cli access-check lab --case-file registros/lab/private/write-case.json --lab-write --allow-public-writes --dry-run
python -m bugbounty_toolkit.cli access-check lab --case-file registros/lab/private/write-case.json --lab-write --lab-write-range 1-10 --max-range 10 --max-tests 12 --min-interval 10 --dry-run
python -m bugbounty_toolkit.cli report my-program --format json
python -m bugbounty_toolkit.cli report my-program --format html
```

Remove `--dry-run` only for an action covered by the user's authorization. Request and XSS accept repeatable `--header`, `--cookie`, timeout and rate flags. Requests also accept `--method`, `--param` and `--data`. Use `--base-url` for relative routes or a reviewed captured-host override.

XSS inputs are newline-separated files. The parameter file contains supplied names; it does not trigger parameter discovery. Four non-executing marker variants are attempted by default. Opt-in `--confirm-exec` adds three context-breaking harmless marker/alert variants and invokes Playwright only for `possible` HTTP reflections; install the optional `xss` extra and Chromium binary. Browser requests are restricted to the exact URL origin. `--max-tests` counts HTTP probes and stays subject to the program limit.

SQLi defaults to the same complete three-request baseline/quote group. Opt-in `--deep` adds three 3-second delay probes and a boolean true/false pair, for eight requests per complete route/parameter group. It requires an eight-request minimum, compares delay probes to the measured baseline (candidate threshold 2500ms), and compares boolean response size/hash. These are noisy indicators, not proof; honor configured timeout, rate and test budget.

`cors-check` sends four GET requests with attacker-controlled Origin values and records only the CORS response headers, status and timing, not bodies or credentials. `open-redirect` requires the named query parameter to exist exactly once, sends five values, and reads Location without following it. Both require an existing automated program configuration, enforce scope/rate/timeout, support `--dry-run`, stop after access/rate failures, and write redacted evidence.

## JSON Plan Adapter

Keep private plans under ignored `registros/`; plan paths are relative to the toolkit checkout. The adapter builds literal argument arrays without a shell and never retries failed commands.

```json
{
  "program": "my-program",
  "action": "xss",
  "routes": "inputs/routes.txt",
  "parameters": "inputs/parameters.txt",
  "base_url": "https://authorized.example",
  "rate": 1,
  "max_tests": 40
}
```

```bash
python /path/to/bugbounty-executor/scripts/run_plan.py --toolkit-root /path/to/Bug_Bounty_toolkit --plan /path/to/plan.json
python /path/to/bugbounty-executor/scripts/run_plan.py --toolkit-root /path/to/Bug_Bounty_toolkit --plan /path/to/plan.json --execute
```

| Action | Required inputs | Optional inputs |
| --- | --- | --- |
| `request` | Exactly one of `url`, `raw_request` | `method`, `base_url`, `headers`, `cookies`, `params`, `data`, `timeout`, `rate` |
| `fuzz` | `url`, `wordlist` | `threads`, `timeout`, `rate`, `match_codes`, `filter_size` |
| `xss` | `routes`, `parameters` | `base_url`, `headers`, `cookies`, `timeout`, `rate`, `max_tests`, `html_parser`, `confirm_exec` |
| `sqli` | `routes`, `parameters` | `base_url`, `headers`, `cookies`, `timeout`, `rate`, `max_tests`, `deep` |
| `cors-check` | `url` | `headers`, `cookies`, `timeout`, `rate` |
| `open-redirect` | `url`, `param` | `headers`, `cookies`, `timeout`, `rate` |
| `access-check` | `case_file` | `timeout`, `rate`, `max_tests`, `range`, `max_range`, `concurrency`, `min_interval` |

`headers`, `cookies` and `params` are arrays of strings. Other text options are strings; numeric options are positive finite numbers. Unknown fields and actions fail before execution. CLI output does not display private plans or credentials.

Plan booleans `confirm_exec` and `deep` must be JSON booleans; true appends `--confirm-exec` or `--deep`, false leaves the default mode unchanged. Plan validation still uses CLI `--dry-run` before execution.

## Access Control

The native [access case](../../bugbounty-access-control/references/native-check.md) keeps captures and proof values in private files, not inline plan headers. The default check validates both controls before one crossed GET. Optional `range` requires explicit program-policy authorization and is preflighted against scope. Public defaults are 25 IDs, one worker and ten seconds; `--allow-public-range` opts in to up to 100 IDs, four workers and one second minimum. Localhost labs may configure up to 100 IDs, four workers and a 0.01-second interval without that flag. Direct `--lab-write` and `--lab-write-range` modes require disposable JSON POST/PUT/PATCH resources. Writes default to loopback; public targets require `--allow-public-writes`, and may mutate persistent remote state. These write modes and both public opt-ins are unavailable through JSON plans.

## Response Analysis

XSS records HTML parser contexts from the actual response. `html_parser` accepts `html.parser`, `lxml` or `html5lib`; unavailable parsers and non-HTML responses are explicit. Parsing never confirms JavaScript execution.

`analyze evidence --input <one-native-evidence.json>` creates the minimized [agent review packet](agent-review.md) without network traffic by default. With `--ai ollama --model <local-model>`, only that packet is sent to the local service at `127.0.0.1:11434`; proxies, redirects and remote fallback are disabled. The model result is untrusted. Offline analyzers and external-tool planning use the direct CLI, not `run_plan.py`; external plans never execute scanners.

On execution, JSON and HTML reports go to `registros/<program>/reports/`. Inspect `program-report.json` and its evidence before summarizing. If a command fails, report the failure and inspect existing evidence instead of retrying automatically.

Use `--records-root /path/to/existing/records` when program data is outside the checkout's default `registros/` directory.
