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

### Optional Security Integrations

```bash
python -m pip install -e ".[xss,sqli,jwt]"
# Or all Python profiles, including HTTP clients and database drivers:
python -m pip install -e ".[all]"
bugbounty resources
```

The base install stays small. Extras provide Beautiful Soup/lxml/html5lib/Playwright, sqlparse, PyJWT/python-jose/cryptography/jwcrypto, requests/aiohttp/httpx and optional database drivers. External scanners, payload repositories, Burp extensions and browser binaries remain separate. The [security tools reference](skills/bugbounty-executor/references/security-tools.md) explains installation profiles and external-plan limitations. Each topic skill has its own focused tool references.

```bash
bugbounty analyze html --input registros/my-program/page.html --marker BBTK_MARKER --parser html5lib
bugbounty analyze jwt --input registros/my-program/token.private.txt
bugbounty analyze sql --input registros/my-program/own-query.sql
bugbounty sqli my-program --routes inputs/routes.txt --parameters inputs/parameters.txt --rate 0.1 --max-tests 6 --dry-run
bugbounty tool-plan my-program --tool sqlmap --url "http://localhost:3000/search?q=1" --parameter q --dry-run
```

`analyze` is offline. JWT verification additionally requires `--key-file` and an explicit `--algorithm`, with optional expected issuer/audience; decoding is not authentication. SQLi probes are bounded baseline/quote comparisons, not exploitation or extraction, and require automation permission. `tool-plan` prepares commands for sqlmap, XSStrike and Dalfox v3 but **never executes them**, even without `--dry-run`. External tools need separately reviewed runs because they do not inherit the hard request budget/scope controls. jwt_tool, JWT Editor, hashcat and John are catalogued manual tools. No automatic JWT forgery, password brute force, WAF evasion, database dumping or browser XSS confirmation is added.

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

## Native A/B Access Checks

`access-check` sends its own HTTP requests; it does not ask nuclei/ffuf to understand your account permissions. Given two authorized test-account captures and known private JSON resources, it validates both normal reads and constructs **one crossed GET** with the owner's resource URL and the actor's complete header context. It stops before the cross if either control fails. No ID guessing, write methods, inverse cross or anonymous check is added.

Prepare the [private case schema](skills/bugbounty-access-control/references/native-check.md) using exact resource/success JSON pointers and distinct controlled private markers already present in your own test resources. Assertions in that case must reflect the actual user authorization and intended sharing; the tool cannot independently grant or prove them. Captured origin and session context are checked before traffic. Session-bearing queries, bodies and host overrides are unsupported.

```bash
bugbounty access-check my-program --case-file registros/my-program/private/case.json --rate 0.1 --max-tests 3 --dry-run
bugbounty access-check my-program --case-file registros/my-program/private/case.json --rate 0.1 --max-tests 3
```

Live execution requires program automation permission. The whole group has a hard maximum of three attempted requests and shares one rate limiter; at 0.1 requests/second, starts are at least ten seconds apart. Response predicates use the complete bounded capture in memory, not its report preview. Saved evidence includes status/timing/truncation and match booleans, not session headers, resource IDs, proof values, URLs or raw bodies.

Both private resource and marker matches produce `candidate`, even if exposed in an error response. Denial without configured private evidence is only `rejected_in_this_test`; partial evidence, invalid controls, unknown JSON, redirects, truncation and rate limits are inconclusive. No IDOR is automatically confirmed or platform report submitted. For unsupported captures, use the separately reviewed manual workflow, not a scanner fallback.

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

With the `xss` extra, the command also parses the actual HTML response and records text/attribute/URL/event/script/style contexts in `context_analysis`. Choose `--html-parser html.parser`, `lxml` or `html5lib`. Non-HTML and unavailable parsers are explicit states, not completed validation. Truncated captures stop the batch. Parsing is not JavaScript execution: `browser_execution_observed` and `confirmed` remain false.

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

The repository includes one general router/executor and five separate topic skills. Install all six sibling folders together so shared references and the single plan adapter resolve. These are ordinary discoverable skills, not a nested-skill engine; the router instructs the AI to load only the requested topic and finish its evidence summary before moving to another.

| Skill | Focus |
| --- | --- |
| [bugbounty-executor](skills/bugbounty-executor/SKILL.md) | Shared authorization, HTTP/Burp, ffuf, reporting and sequential topic routing |
| [bugbounty-xss](skills/bugbounty-xss/SKILL.md) | Reflection checks, HTML contexts, payload references, XSStrike/Dalfox drafts |
| [bugbounty-sqli](skills/bugbounty-sqli/SKILL.md) | Baseline/quote probes, SQL review, sqlmap drafts |
| [bugbounty-jwt](skills/bugbounty-jwt/SKILL.md) | Offline token inspection/verification and manual JWT tools |
| [bugbounty-authentication](skills/bugbounty-authentication/SKILL.md) | Login/session/reset/MFA/OAuth review with own test accounts |
| [bugbounty-access-control](skills/bugbounty-access-control/SKILL.md) | Controlled IDOR/BOLA/role comparisons, Autorize/AuthMatrix/Authz references |

Preview or install the entire family from the repository root:

```bash
python scripts/install_skills.py
python scripts/install_skills.py --execute
# After reviewing an existing installation's changes:
python scripts/install_skills.py --execute --update
```

The installer uses `$CODEX_HOME/skills` or `~/.codex/skills`, performs no network actions and leaves unrelated files intact. Differing existing managed files need `--update`; it checks the full family for conflicts before copying anything. `--destination /path/to/agent/skills` supports another agent's skill directory. Other agents can also load the corresponding SKILL.md directly and use their terminal tools; no AI API is required. Installing a skill does not install Python extras, Burp extensions or scanner binaries. If the current agent session does not discover newly installed skills, start a new session.

Invoke the router with: `Use $bugbounty-executor for XSS and SQLi on my authorized inputs, one topic at a time.` Or select a topic directly: `Use $bugbounty-access-control with my two authorized test accounts and one known private resource.` An error, rate limit, missing authorization or invalid control stops live testing; no other scanner is started as a fallback. Requested offline HTML/SQL/JWT analysis and resource inspection can still proceed without live program configuration or a dry-run flag.

Access-control work now has native `access-check` for one known private GET/JSON resource pair; other methods/flows retain the reviewed individual-request fallback. It is not a role-matrix scanner. HTTP 200, reflected emails and extension colors are not confirmation. Admin access by an admin is a control, not escalation. Burp extensions, forced browsing, identifier enumeration, hidden-parameter discovery and nuclei templates need their own reviewed scope/budget; no password-guessing adapter is included. ParamSpider mines archived URLs rather than simply parsing local HTML/JS.

The script accepts a JSON plan for `request`, `fuzz`, `xss`, `sqli` or `access-check`. It defaults to validation without HTTP traffic; `--execute` validates, executes once and generates reports. It never initializes authorization, changes scope or retries failures. Optional `--records-root` selects an existing records directory. Read the skill's command reference for the plan schema.

```bash
python skills/bugbounty-executor/scripts/run_plan.py --toolkit-root . --plan registros/my-program/plan.json
python skills/bugbounty-executor/scripts/run_plan.py --toolkit-root . --plan registros/my-program/plan.json --execute
```

### Agent Evidence Review

The IA running the skill is the reasoning component. Export one native access-control/XSS/SQLi evidence file into a minimal local packet:

```bash
bugbounty analyze evidence --input registros/my-program/evidence/access-control/selected.json --output registros/my-program/review.json
```

The exporter drops arbitrary response text/instructions, URLs, headers and secrets; it includes allowlisted statuses, context counts and comparison booleans. It is offline and calls **no external model**. The [review workflow](skills/bugbounty-executor/references/agent-review.md) directs the calling IA to check provenance, controls, uncertainty and remaining validation before any new step. A formatted packet does not authenticate source claims or grant testing permission. No bundled LLM, API key or automatic AI vulnerability confirmation is implied.

## Tests

```bash
python -m unittest discover -s tests -v
```

Tests run HTTP/Burp replay, scope exclusions, redaction, request budgets and report generation against an ephemeral server on `127.0.0.1`. With ffuf on PATH, an additional integration test runs the real executable against that laboratory; otherwise it is marked skipped. No test scans a public target.

## License

MIT. See [LICENSE](LICENSE).
