# CLI and Plan Reference

Run from the toolkit checkout with Python 3.10+. Install with `python -m pip install -e .`. The `bbtk`, `bugbounty` and `python -m bugbounty_toolkit.cli` commands use the same implementation. ffuf is required only for live fuzzing.

Check local setup with `bbtk --version` and `bbtk doctor`; `bbtk doctor --program <name>` also checks that program's saved scope, authorization reference and settings. Diagnostics are offline. Use `--json` for machine-readable output. Missing optional extras are reported as warnings, not installed automatically.

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
python -m bugbounty_toolkit.cli ssrf-check my-program --url "https://authorized.example/fetch?url=https%3A%2F%2Fexample.org" --param url --dry-run
python -m bugbounty_toolkit.cli csrf-audit my-program --url "https://authorized.example/account" --dry-run
python -m bugbounty_toolkit.cli apk-scan my-program --apk inputs/app.apk --dry-run
python -m bugbounty_toolkit.cli apk-scan my-program --apk inputs/app.apk --ai-review
python -m bugbounty_toolkit.cli open-redirect my-program --url "https://authorized.example/login?next=%2Fhome" --param next --dry-run
python -m bugbounty_toolkit.cli request my-program --url "https://authorized.example/health" --run-max-requests 1 --run-max-seconds 30 --run-max-concurrency 1 --dry-run
python -m bugbounty_toolkit.cli access-check my-program --case-file registros/my-program/private/case.json --range 1-10 --max-range 10 --max-tests 12 --min-interval 10 --concurrency 1 --dry-run
python -m bugbounty_toolkit.cli access-check lab --case-file registros/lab/private/write-case.json --lab-write --dry-run
python -m bugbounty_toolkit.cli access-check lab --case-file registros/lab/private/write-case.json --lab-write --allow-public-writes --dry-run
python -m bugbounty_toolkit.cli access-check lab --case-file registros/lab/private/write-case.json --lab-write --lab-write-range 1-10 --max-range 10 --max-tests 12 --min-interval 10 --dry-run
python -m bugbounty_toolkit.cli report my-program --format json
python -m bugbounty_toolkit.cli report my-program --format html
python -m bugbounty_toolkit.cli report my-program --evidence-file registros/my-program/evidence/access-control/selected.json --format markdown
```

Native HTTP commands accept `--run-max-requests`, `--run-max-seconds` and `--run-max-concurrency`. One shared budget is enforced across that command's native HTTP requests, including workers and same-origin Playwright requests/subresources used by `xss --confirm-exec`; every destination also passes the program's scope validator. The summary reports request counts, errors, elapsed time, concurrency peak and hostnames. Ctrl+C cancels queued work and reports the partial run. Per-request timeout, configured rate and per-command `--max-tests` remain in force. External tools such as ffuf, nuclei and tool plans do not inherit this shared request budget; review their own limits separately. No new limits are imposed unless one of the `--run-*` flags is supplied.

`report --evidence-file ... --format markdown` creates a redacted local review draft with A/B observations when present. It deliberately omits raw response bodies and never submits a report.

`apk-scan` is a local-only analysis. It requires at least one allowed scope rule to classify referenced HTTP(S) domains, but does not require automation permission because it sends no target requests. It scans ZIP entries in memory, parses textual/binary Android manifests, reports masked secret-pattern and email matches, and never extracts or executes APK content. `--decompile` explicitly runs an installed `jadx` or `apktool` in a temporary directory, with a 120-second timeout; without either tool it stays ZIP-only. `--ai-review` sends only aggregate categories/counts to local Ollama, never APK bytes, source text, URLs, paths or raw secrets. JSON evidence is written under `registros/<program>/evidence/apk-scan/`.

Remove `--dry-run` only for an action covered by the user's authorization. Request and XSS accept repeatable `--header`, `--cookie`, timeout and rate flags. Requests also accept `--method`, `--param` and `--data`. Use `--base-url` for relative routes or a reviewed captured-host override.

XSS inputs are newline-separated files. The parameter file contains supplied names; it does not trigger parameter discovery. Four non-executing marker variants are attempted by default. Opt-in `--confirm-exec` adds three context-breaking harmless marker/alert variants and invokes Playwright only for `possible` HTTP reflections; install the optional `xss` extra and Chromium binary. Browser requests are restricted to the exact URL origin and use the same scope, rate and run budget as HTTP probes. `--max-tests` counts the command's payload probes and stays subject to the program limit.

SQLi defaults to the same complete three-request baseline/quote group. Opt-in `--deep` adds three 3-second delay probes and a boolean true/false pair, for eight requests per complete route/parameter group. It requires an eight-request minimum, compares delay probes to the measured baseline (candidate threshold 2500ms), and compares boolean response size/hash. These are noisy indicators, not proof; honor configured timeout, rate and test budget.

`cors-check` sends four GET requests with attacker-controlled Origin values and records only the CORS response headers, status and timing, not bodies or credentials. `open-redirect` requires the named query parameter to exist exactly once, sends five values, and reads Location without following it. `ssrf-check` sends the supplied baseline plus five fixed URL values to one existing query parameter, compares status/body fingerprints and records timing deltas without response bodies; all SSRF results are heuristic and unconfirmed. `csrf-audit` makes one GET to the supplied URL, parses only HTML form methods and hidden token-like fields, and summarizes response `SameSite` cookie attributes; it never submits a form and cannot confirm CSRF. These commands require an existing automated program configuration, enforce scope/rate/timeout, support `--dry-run`, stop after access/rate failures, and write redacted evidence.

`csrf-audit` needs Beautiful Soup from the `csrf` or `xss` extra. Its `protected`, `weak` and `possible_csrf` labels are heuristic. An absent form, missing parser, non-HTML response, access denial, truncation or redirect is reported as inconclusive where appropriate. Evidence contains counts and boolean/token-presence observations only, not cookie values, form values or response HTML.

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
| `xss` | `routes`, `parameters` | `base_url`, `headers`, `cookies`, `timeout`, `rate`, `max_tests`, `html_parser`, `confirm_exec`, `ai_review`, `ai_model`, `ai_timeout` |
| `sqli` | `routes`, `parameters` | `base_url`, `headers`, `cookies`, `timeout`, `rate`, `max_tests`, `deep`, `ai_review`, `ai_model`, `ai_timeout` |
| `cors-check` | `url` | `headers`, `cookies`, `timeout`, `rate`, `ai_review`, `ai_model`, `ai_timeout` |
| `ssrf-check` | `url`, `param` | `headers`, `cookies`, `timeout`, `rate` |
| `open-redirect` | `url`, `param` | `headers`, `cookies`, `timeout`, `rate`, `ai_review`, `ai_model`, `ai_timeout` |
| `access-check` | `case_file` | `timeout`, `rate`, `max_tests`, `range`, `max_range`, `concurrency`, `min_interval`, `ai_review`, `ai_model`, `ai_timeout` |
| `apk-scan` | `apk` | `decompile`, `ai_review`, `ai_model`, `ai_timeout` |

`headers`, `cookies` and `params` are arrays of strings. Other text options are strings; numeric options are positive finite numbers. Unknown fields and actions fail before execution. CLI output does not display private plans or credentials.

Plan booleans `confirm_exec`, `deep`, `decompile` and `ai_review` must be JSON booleans; true appends their matching opt-in flag, false leaves the default mode unchanged. `ai_model` and `ai_timeout` require `ai_review: true`; the timeout is 1-300 seconds. Live AI review contacts only local Ollama after candidate evidence is collected, and CLI plan validation remains a dry-run with no HTTP or model request.

## Access Control

The native [access case](../../bugbounty-access-control/references/native-check.md) keeps captures and proof values in private files, not inline plan headers. The default check validates both controls before one crossed GET. Optional `range` requires explicit program-policy authorization and is preflighted against scope. Public defaults are 25 IDs, one worker and ten seconds; `--allow-public-range` opts in to up to 100 IDs, four workers and one second minimum. Localhost labs may configure up to 100 IDs, four workers and a 0.01-second interval without that flag. Direct `--lab-write` and `--lab-write-range` modes require disposable JSON POST/PUT/PATCH resources. Writes default to loopback; public targets require `--allow-public-writes`, and may mutate persistent remote state. These write modes and both public opt-ins are unavailable through JSON plans.

## Response Analysis

XSS records HTML parser contexts from the actual response. `html_parser` accepts `html.parser`, `lxml` or `html5lib`; unavailable parsers and non-HTML responses are explicit. Parsing never confirms JavaScript execution.

`analyze evidence --input <one-native-evidence.json>` creates the minimized [agent review packet](agent-review.md) without network traffic by default. With `--ai ollama`, only that packet is sent to the local service at `127.0.0.1:11434`, using `qwen2.5-coder:7b` by default; `--model <installed-model>` overrides it. Proxies, redirects and remote fallback are disabled. The model result is untrusted and never executes tools or tests. Offline analyzers and external-tool planning use the direct CLI, not `run_plan.py`; external plans never execute scanners.

`jwt-forge --input <local-token-file> [--secret <test-secret>] [--public-key <local.pem>] [--output <json-file>]` creates local unsigned, algorithm-change and claim-change candidates; optional HMAC candidates use the supplied/common weak strings or local PEM bytes for RS256 input. It has no network client, and candidate generation does not establish server acceptance. Keep token files private and only consider separate replay in an explicitly authorized test environment.

`takeover-check <program> --host <in-scope-subdomain> --cname <captured-cname>` performs offline matching against local provider CNAME signatures. `--resolve-dns` explicitly enables one scoped CNAME lookup and requires a saved program authorization reference; `--dry-run` performs no lookup. The optional `takeover` extra installs dnspython. A matching signature is `possible_takeover`, not proof that the provider resource is unclaimed; the command never makes HTTP requests or attempts to claim a resource.
The APK topic skill handles `apk-scan` as a separate offline workflow; discovered endpoints are classified against the configured program scope but are never requested.

On execution, JSON and HTML reports go to `registros/<program>/reports/`. Inspect `program-report.json` and its evidence before summarizing. If a command fails, report the failure and inspect existing evidence instead of retrying automatically.

Use `--records-root /path/to/existing/records` when program data is outside the checkout's default `registros/` directory.
