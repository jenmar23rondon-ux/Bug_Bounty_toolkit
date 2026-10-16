# CLI and Plan Reference

Run from the toolkit checkout with Python 3.10+. Install once using `python -m pip install -e .` in its environment. The commands `bbtk`, `bugbounty` and `python -m bugbounty_toolkit.cli` use the same implementation. ffuf is required only for live fuzzing, not input validation.

## Authorized Program Setup

Use policy values supplied for this program. Retain existing configuration when it already matches the request. Configure explicit domains or URL prefixes and exclusions; a bare domain authorizes only that exact host, while `*.domain` covers subdomains but not the apex.

```bash
python -m bugbounty_toolkit.cli init my-program --authorization "USER-SUPPLIED-POLICY-REFERENCE" --automation-allowed --config config/settings.yaml
python -m bugbounty_toolkit.cli scope import my-program config/scope.yaml
```

Omit `--automation-allowed` for programs that do not permit automation. Do not derive permission from the placeholder example configuration. Limits are stored per program, and CLI rate/concurrency/test overrides cannot exceed them.

## Command Examples

```bash
python -m bugbounty_toolkit.cli request my-program --url "https://authorized.example/search" --param "q=example" --dry-run
python -m bugbounty_toolkit.cli request my-program --raw-request inputs/requests/captured.txt --base-url "https://authorized.example" --dry-run
python -m bugbounty_toolkit.cli fuzz my-program --url "https://authorized.example/FUZZ" --wordlist wordlists/api-endpoints.txt --rate 1 --threads 2 --dry-run
python -m bugbounty_toolkit.cli xss my-program --routes inputs/routes.txt --parameters inputs/parameters.txt --base-url "https://authorized.example" --rate 1 --max-tests 40 --dry-run
python -m bugbounty_toolkit.cli report my-program --format json
python -m bugbounty_toolkit.cli report my-program --format html
```

Remove `--dry-run` only for an action covered by the user's authorization. Request and XSS accept repeatable `--header`, `--cookie` and timeout/rate flags. Requests also accept `--method`, `--param` and `--data`. Use `--base-url` for relative route inputs or to override a captured request's original host.

XSS inputs are newline-separated files. The parameter file contains names, not an instruction to discover extra parameters. Existing values of other query parameters are retained. Four non-executing marker variants are attempted per route/parameter until the configured budget is reached. Results are `possible`, `not_reproducible` or `error`, with `confirmed` always false.

## JSON Plan Adapter

Keep private plans inside the ignored `registros/` directory. Paths inside the plan are relative to the toolkit checkout. The adapter uses the selected Python interpreter, constructs literal argument arrays without a shell and never retries failed commands.

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

Required fields by action:

| Action | Required inputs | Optional inputs |
| --- | --- | --- |
| `request` | Exactly one of `url`, `raw_request` | `method`, `base_url`, `headers`, `cookies`, `params`, `data`, `timeout`, `rate` |
| `fuzz` | `url`, `wordlist` | `threads`, `timeout`, `rate`, `match_codes`, `filter_size` |
| `xss` | `routes`, `parameters` | `base_url`, `headers`, `cookies`, `timeout`, `rate`, `max_tests` |
| `sqli` | `routes`, `parameters` | `base_url`, `headers`, `cookies`, `timeout`, `rate`, `max_tests` |

`headers`, `cookies` and `params` are arrays of strings in the same format as their CLI flags. Other textual inputs are strings; numeric flags are positive finite numbers, with integer values for thread/test counts and fuzz timeout. Unknown fields and actions fail before a command starts. The adapter prints CLI results without displaying the plan or credentials.

`sqli` accepts the same plan fields as `xss`: routes, parameters, base_url, headers, cookies, timeout, rate and max_tests. Routes and parameters are required. Each completed route/parameter group costs three requests (baseline, appended single quote, appended double quote); an incomplete group is not started. At least three requests must fit the program budget. No time-delay, UNION, OOB or extraction payloads are used. A new SQL error is only a possible indicator.

```bash
bugbounty sqli my-program --routes inputs/routes.txt --parameters inputs/parameters.txt --rate 0.1 --max-tests 6 --dry-run
```

Network/action plans are restricted to `request`, `fuzz`, `xss` and `sqli`. Optional offline analysis and external command planning use the direct CLI described in [security-tools.md](security-tools.md); they are not scanner execution actions in run_plan.py.

On execution, JSON and HTML reports are generated under `registros/<program>/reports/`. Read `program-report.json` and its evidence before writing the result to the user. If a command fails, report the failure and inspect existing evidence instead of automatically retrying.

Use the adapter option `--records-root /path/to/existing/records` when the program data is stored outside the checkout's default `registros/` directory.
