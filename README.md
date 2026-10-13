# Bug Bounty Toolkit

An authorized testing CLI that executes the targets, routes and parameters **you supply**. Version 0.2 adds HTTP requests, Burp request replay, a controlled ffuf adapter, parameter reflection checks and JSON/HTML evidence reports to the existing toolkit.

Both `bbtk` and `bugbounty` run the same CLI. No AI API or API key is required. Reconnaissance is optional; your existing route discovery workflow can feed `inputs/routes.txt` and `inputs/parameters.txt` directly.

## Installation

Python 3.10 or later:

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -e .
```

On Windows, activate with `.venv\Scripts\Activate.ps1`. Install [ffuf](https://github.com/ffuf/ffuf#installation) separately and put its executable on `PATH`. HTTP requests, XSS reflection checks and JSON/HTML reports work without ffuf. `requirements.txt` also includes optional ReportLab support for individual PDF findings.

## Program Setup

Review the program policy first. Replace the example values in `config/settings.yaml` and `config/scope.yaml` with its permitted assets, exclusions and limits. This tool does not fetch HackerOne policies or infer permission from a public domain.

```bash
bugbounty init my-program --platform hackerone --authorization "https://hackerone.com/my-program/policy" --automation-allowed --config config/settings.yaml
bugbounty scope import my-program config/scope.yaml
```

`--automation-allowed` records your acknowledgement that the program permits automated testing. It is required for fuzzing, XSS batches and the legacy automated wrappers. Single requests still require an initialized program and valid scope. A policy URL is a local reference, not proof that the program permits a particular test.

Add individual rules instead of importing YAML:

```bash
bugbounty scope add my-program https://target-autorizado.example
bugbounty scope add my-program https://target-autorizado.example/admin --exclude
bugbounty scope add my-program "*.target-autorizado.example"
bugbounty scope add my-program legacy.target-autorizado.example --exclude
```

Scope rules:

| Rule | Meaning |
| --- | --- |
| `example.com` | Exact host, any HTTP(S) scheme/port; subdomains are separate |
| `*.example.com` | Subdomains only; add the apex separately |
| `https://example.com:8443/api` | Exact scheme, host and port; `/api` and its descendants |
| `!https://example.com/admin` | Exclusion; always takes precedence |
| `!*.legacy.example.com` | Exclude descendants of the named host |

**Migration:** version 0.1 implicitly allowed subdomains of a bare domain. Version 0.2 requires explicit subdomain rules or an authorized wildcard. Existing SQLite records and finding reports remain usable. Reinitialize existing programs with `--automation-allowed` when their policies permit automation.

## Send and Replay Requests

```bash
bugbounty request my-program --url "https://target-autorizado.example/search" --param "q=example" --header "Accept: text/html"
bugbounty request my-program --url "https://target-autorizado.example/api/search" --method POST --header "Content-Type: application/json" --data '{"query":"example"}'
bugbounty request my-program --raw-request inputs/requests/example-request.txt --base-url "https://target-autorizado.example"
```

Use repeatable `--header`, `--cookie name=value` and `--param name=value`. A Burp export supplies its original method, headers and body; CLI options can override them. Content length is recalculated. A `--base-url` changes the original host. Without it, relative requests use the Host header and assume HTTPS. Duplicate raw headers and HTTP/2 pseudoheaders are not supported.

Use `request --dry-run` to validate the request against program scope without sending it.

Responses include status, duration, headers and a redacted body preview. Redirects are recorded without being followed, so a redirect cannot silently send a second request outside scope. Review a Location header and submit another authorized request explicitly.

## Fuzzing With ffuf

```bash
bugbounty fuzz my-program --url "https://target-autorizado.example/FUZZ" --wordlist wordlists/api-endpoints.txt --dry-run
bugbounty fuzz my-program --url "https://target-autorizado.example/FUZZ" --wordlist wordlists/api-endpoints.txt --threads 2 --rate 1 --timeout 10 --match-codes "200,204,301,302,401,403" --filter-size 4242
```

The adapter checks every wordlist substitution before starting, writes explicit ffuf JSON output, enforces rate/concurrency limits and removes identical result entries. `FUZZ` must be in a path or query on a fixed authorized host. An excluded candidate stops the entire run before any requests are sent. Redirect following, recursion and auto-calibration are disabled; a separate config directory isolates the run from your normal ffufrc.

ffuf requires a whole-number rate of at least 1 request/second. Use the HTTP/XSS commands for fractional rates. The bundled wordlists are small examples, not the full SecLists files. Replace them with reviewed lists from the [official SecLists repository](https://github.com/danielmiessler/SecLists); see `wordlists/README.md` for typical paths.

## Test Supplied Parameters

`inputs/routes.txt` accepts absolute URLs or relative routes with `--base-url`. `inputs/parameters.txt` accepts parameter names, one per line. Existing values of other query parameters are preserved. Empty lines, comments and duplicate entries are ignored.

```bash
bugbounty xss my-program --routes inputs/routes.txt --parameters inputs/parameters.txt --base-url "https://target-autorizado.example" --dry-run
bugbounty xss my-program --routes inputs/routes.txt --parameters inputs/parameters.txt --base-url "https://target-autorizado.example" --rate 1 --max-tests 40
```

Use `--header` and `--cookie` for your authorized test session. The command sends four non-executing marker variants per route/parameter using GET, until its request budget is reached. It records the parameter, marker, status, duration, reflection context and request/response evidence.

Results are `possible`, `not_reproducible` or `error`. A reflection **never automatically confirms XSS**. Escaped HTML, JSON and plain text can reflect markers without executing code. `not_reproducible` means this marker was not seen in the captured response, not that the endpoint is vulnerability-free. Truncated responses are flagged. Browser execution, stored XSS and DOM XSS need separate manual validation. Add a finding only after that validation.

## Limits and Reports

`init --config` copies limits into `registros/<program>/settings.yaml`. The included defaults are 1 request/second, 5 ffuf threads, a 15-second timeout, at most 100 XSS requests and a 1 MB captured response. Per-command `--rate`, `--threads` and `--max-tests` cannot exceed program limits. Change the program configuration only to match its actual policy.

```bash
bugbounty report my-program --format html
bugbounty report my-program --format json
bugbounty status my-program
bugbounty --log-file logs/toolkit.log status my-program
```

Program reports include scope, run history, findings and embedded JSON evidence. HTML escapes all response content and payloads. Files are written under `registros/<program>/reports/`.

Authorization headers, cookies and common password/token fields are redacted from structured evidence. Redaction is best effort: unusual secret formats, user-written findings and third-party raw logs can contain private data. Keep `registros/` local and inspect evidence before sharing it. Raw ffuf output and its isolated history remain in `raw/` for debugging. They are not embedded into reports.

Individual validated findings keep the original Markdown/PDF workflow:

```bash
bbtk add-finding my-program --finding-id FINDING-001 --title "Validated finding" --category XSS --severity medium --target "https://target-autorizado.example/search" --summary "Manually validated impact and reproduction steps"
bbtk report my-program --finding-id FINDING-001 --format markdown
bbtk report my-program --finding-id FINDING-001 --format pdf
```

## Layout

```text
Bug_Bounty_toolkit/
|-- bugbounty_toolkit/
|   |-- cli.py
|   |-- core/               # Scope, HTTP, limits, settings, records
|   |-- requests_engine/    # CLI inputs and Burp replay
|   |-- fuzzing/            # ffuf adapter and parsed results
|   |-- xss/                # Controlled reflection probes
|   |-- reporting/          # JSON, HTML and evidence
|   `-- utils/
|-- config/                 # Program configuration examples
|-- inputs/                 # Supplied targets, routes, parameters, requests
|-- wordlists/              # Small replaceable examples
|-- tests/                  # Unit and local integration tests
|-- registros/              # Private per-program runtime data (ignored)
|-- reports/                # Optional exported reports (ignored)
`-- logs/                   # Optional CLI logs (ignored)
```

The existing package location is retained so imports and the original `bbtk` command continue to work. No artificial `src/` migration is needed.

The original `recon`, `scan nuclei`, `params`, `checklist`, `mark-reviewed` and `add-finding` commands remain available. Their third-party scanner behavior requires separate review against the program policy; the strict request executor covers `request`, `fuzz` and `xss`. No discovery tool is invoked by those three commands.

## AI Skill

The repository includes `skills/bugbounty-executor/` with `SKILL.md`, agent metadata, command references and `scripts/run_plan.py`. Copy that folder to your agent's skill directory. For Codex, use `$CODEX_HOME/skills/bugbounty-executor` or `~/.codex/skills/bugbounty-executor` when `CODEX_HOME` is unset. Other agents can load the same SKILL.md and run the script through their terminal tools; no AI API is required.

Invoke it with a request such as: `Use $bugbounty-executor with my authorized program, supplied routes and parameters, then generate JSON and HTML reports.`

The script accepts a JSON plan for `request`, `fuzz` or `xss`. It defaults to validation without HTTP traffic; `--execute` validates, executes once and generates reports. It never initializes authorization, changes scope or retries failures. Optional `--records-root` selects an existing records directory. Read the skill's command reference for the plan schema.

```bash
python skills/bugbounty-executor/scripts/run_plan.py --toolkit-root . --plan registros/my-program/plan.json
python skills/bugbounty-executor/scripts/run_plan.py --toolkit-root . --plan registros/my-program/plan.json --execute
```

## Tests

```bash
python -m unittest discover -s tests -v
```

Tests run HTTP/Burp replay, scope exclusions, redaction, request budgets and report generation against an ephemeral server on `127.0.0.1`. With ffuf on PATH, an additional integration test runs the real executable against that laboratory; otherwise it is marked skipped. No test scans a public target.

## License

MIT. See [LICENSE](LICENSE).
