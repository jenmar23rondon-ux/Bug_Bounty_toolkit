# Bug Bounty Toolkit

An authorized testing CLI that executes the targets, routes and parameters **you supply**. The toolkit supports bounded HTTP/Burp replay, ffuf, XSS and SQLi checks, CORS and open-redirect checks, access-control comparisons, and JSON/HTML evidence reports.

Both `bbtk` and `bugbounty` run the same CLI. No AI API or API key is required. Reconnaissance is optional; your existing route discovery workflow can feed `inputs/routes.txt` and `inputs/parameters.txt` directly.

## Installation

Python 3.10 or later:

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -e .
```

On Windows, activate with `.venv\Scripts\Activate.ps1`. Install [ffuf](https://github.com/ffuf/ffuf#installation) separately and put its executable on `PATH`. Native HTTP checks and JSON/HTML reports work without ffuf. `requirements.txt` also includes optional ReportLab support for individual PDF findings.

### Optional Security Integrations

```bash
python -m pip install -e ".[xss,sqli,jwt]"
# Or all Python profiles, including HTTP clients and database drivers:
python -m pip install -e ".[all]"
bugbounty resources
```

The base install stays small. Extras provide Beautiful Soup/lxml/html5lib/Playwright, sqlparse, PyJWT/python-jose/cryptography/jwcrypto, requests/aiohttp/httpx and optional database drivers. The `dev` extra adds Ruff, mypy, coverage.py and Hypothesis for CI. `--confirm-exec` needs the optional `xss` extra plus `python -m playwright install chromium`; browser confirmation remains off by default. External scanners, payload repositories and Burp extensions remain separate. The [security tools reference](skills/bugbounty-executor/references/security-tools.md) explains installation profiles and external-plan limitations. Each topic skill has its own focused tool references.

```bash
bugbounty analyze html --input registros/my-program/page.html --marker BBTK_MARKER --parser html5lib
bugbounty analyze jwt --input registros/my-program/token.private.txt
bugbounty analyze sql --input registros/my-program/own-query.sql
bugbounty sqli my-program --routes inputs/routes.txt --parameters inputs/parameters.txt --rate 0.1 --max-tests 6 --dry-run
bugbounty sqli my-program --routes inputs/routes.txt --parameters inputs/parameters.txt --deep --max-tests 8 --dry-run
bugbounty cors-check my-program --url "https://target-autorizado.example/account" --dry-run
bugbounty open-redirect my-program --url "https://target-autorizado.example/login?next=%2Fhome" --param next --dry-run
bugbounty tool-plan my-program --tool sqlmap --url "http://localhost:3000/search?q=1" --parameter q --dry-run
```

`analyze` is offline. JWT verification additionally requires `--key-file` and an explicit `--algorithm`, with optional expected issuer/audience; decoding is not authentication. SQLi defaults to baseline/quote comparisons; `--deep` explicitly adds time and boolean probes. `cors-check` sends four Origin variants; `open-redirect` sends five query values and never follows `Location`. These commands require automation permission, scope and program rate limits. `tool-plan` prepares commands for sqlmap, XSStrike and Dalfox v3 but **never executes them**, even without `--dry-run`. External tools need separately reviewed runs because they do not inherit the hard request budget/scope controls. jwt_tool, JWT Editor, hashcat and John are catalogued manual tools. No automatic JWT forgery, password brute force, WAF evasion or database dumping is performed.

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

`access-check` sends native HTTP requests; it does not ask nuclei/ffuf to understand your account permissions. By default, two authorized test-account captures validate normal reads before one crossed GET. Optional `--range` tests one explicitly supplied numeric interval only when the program policy permits identifier enumeration. Non-loopback defaults remain a 25-ID cap, one worker and at least ten seconds between request starts. `--allow-public-range` is an explicit opt-in that permits up to 100 IDs, four workers and a one-second minimum interval; it prints a warning and still requires `--max-range`, `--max-tests`, and the interval/concurrency values to fit those bounds. A localhost-only lab may raise the cap to 100, use up to four workers and reduce the interval to 0.01 seconds without the public opt-in. Evidence omits probed IDs and response bodies.

Prepare the [private case schema](skills/bugbounty-access-control/references/native-check.md) using exact resource/success JSON pointers and distinct controlled private markers already present in your own test resources. Assertions in that case must reflect actual authorization and intended sharing; the tool cannot independently grant or prove them. Captured origin and session context are checked before traffic. Session-bearing query parameters and host overrides are unsupported; JSON bodies are accepted only by `--lab-write` when both captures differ solely at the declared resource pointer and the case declares disposable resources.

```bash
bugbounty access-check my-program --case-file registros/my-program/private/case.json --rate 0.1 --max-tests 3 --dry-run
bugbounty access-check my-program --case-file registros/my-program/private/case.json --rate 0.1 --max-tests 3
bugbounty access-check my-program --case-file registros/my-program/private/case.json --range 1-10 --max-range 10 --max-tests 12 --min-interval 10 --concurrency 1 --dry-run
bugbounty access-check my-program --case-file registros/my-program/private/case.json --range 1-100 --max-range 100 --max-tests 102 --concurrency 4 --min-interval 1 --allow-public-range --dry-run
bugbounty access-check my-program --case-file registros/my-program/private/case.json --anonymous-check --max-tests 4 --dry-run
bugbounty access-check my-program --case-file registros/my-program/private/case.json --inverse-cross --max-tests 4 --dry-run
bugbounty access-check my-program --case-file registros/my-program/private/case.json --multi-account --max-tests 9 --dry-run
bugbounty access-check lab --case-file registros/lab/private/write-case.json --lab-write --dry-run
bugbounty access-check lab --case-file registros/lab/private/write-case.json --lab-write --allow-public-writes --dry-run
bugbounty access-check lab --case-file registros/lab/private/write-case.json --lab-write --verify-persistence --cleanup --max-tests 6 --dry-run
bugbounty access-check lab --case-file registros/lab/private/write-case.json --lab-write --inverse-write --cleanup --max-tests 8 --dry-run
bugbounty access-check lab --case-file registros/lab/private/write-case.json --lab-write --lab-write-range 1-10 --max-range 10 --max-tests 12 --min-interval 10 --dry-run
```

Live execution requires program automation permission. With no new flags a standard read check remains exactly three requests. `--anonymous-check` adds one copy of the normal actor-to-owner GET with all declared session headers removed. For `resource_private: true`, matching the configured private-resource proof is `anonymous_access` unless `expected_anonymous: "allow"` declares that behavior expected. A case with `resource_private: false` is accepted only for this opt-in check and reports `public_endpoint` informationally; any explicit `expected_anonymous` mismatch is reported separately as `anonymous_expectation_mismatch`, not mislabeled as access to private data. `expected_anonymous` may be `"deny"` or `"allow"`; absent means deny for private resources and unspecified for public ones. `--inverse-cross` adds one owner-session read of the actor's resource and reports both directions. These are separate observations, not automatic confirmation.

For `--multi-account`, keep the existing `owner_request` and `actor_request`, then add `additional_accounts` to the private case. Each entry has a safe account label plus its own exact GET capture, distinct resource ID and private marker; all captures must share the origin and differ only at the declared resource reference. Three accounts require three controls plus six off-diagonal crossings, nine requests total. The evidence matrix includes diagonal cells labeled `control_valid`, but makes no diagonal cross requests. The mode supports at most ten total accounts, is serial, and must fit `--max-tests` and the configured program budget. Every target URL is checked against scope before traffic.

Range mode includes the two account controls; non-loopback runs are capped at 27 total requests, while the local-lab cap is 102. Concurrent local work is submitted in bounded windows; after a candidate, requests already in that window may finish and are recorded as not evaluated. Response predicates use the complete bounded capture in memory, not its report preview. Saved evidence includes status/timing/truncation and match booleans, not session headers, resource IDs, proof values, URLs or raw bodies.

Write-method A/B comparisons are loopback-only by default. Use `--lab-write` with a private case that declares `resource: {json_body_pointer: /path/to/id}` and `disposable_test_resources: true`; the captured POST/PUT/PATCH requests must otherwise match. It rebuilds the actor's JSON body structurally with the owner's resource ID and validates both account controls before a crossed write. For an explicitly authorized, in-scope public target, `--allow-public-writes` opts in to remote writes and prints `[!] Public writes enabled: requests may modify remote state`; the option is rejected unless `--lab-write` is also present. Public writes can leave persistent changes even after the run, so use only disposable resources and only where the program explicitly permits automated state-changing tests. The flag does not affect GET read checks or read-range mode.

`--lab-write-range START-END` is an advanced write sweep and requires `--lab-write`, explicit `identifier_enumeration_authorized: true`, disposable resources, and a private case whose JSON captures differ only at the declared pointer. It sends owner and actor controls, then uses the actor's session to submit one write per ID, rebuilding JSON structurally. It stops on a candidate or an error; with concurrency, already-started writes in that window may still finish. Public sweeps require both `--allow-public-writes` and, to relax the external defaults, `--allow-public-range`. The latter keeps public sweeps at 25 IDs, one worker and ten seconds unless opted in; opt-in raises limits to 100 IDs, four workers and one second minimum, and prints a warning. Request budgets include two controls. Every destination must remain in scope. Treat all successful controls and probes as potential state mutations; inspect the target state and clean up disposable fixtures afterward.

Single-resource `--lab-write` keeps its three-request default. `--verify-persistence` adds one GET and requires a `persistence_check` in the private case: a captured owner-session GET, a response JSON pointer, a disposable body pointer, and a short scalar test value different from the captured original. The cross write changes only that field to the declared test value; `write_confirmed_persisted` is used only when the readback shows the owner resource and that changed value. `--inverse-write` adds owner-session → actor-resource and reports its result separately. `--cleanup` requires `cleanup_check`, sends the original captured write, then performs a final GET and compares the selected response field with its original value in the captured JSON body. That is two requests per restored resource; with `--inverse-write`, the actor resource also gets a restore write and final GET, for four cleanup requests total. Evidence reports `cleanup_confirmed`, `cleanup_unconfirmed` or `cleanup_failed` separately from the write-test classification, plus `cleanup_verified`. A 429 can prevent follow-up requests; inspect disposable fixtures after every run. These flags remain subject to loopback-only writes unless `--allow-public-writes` is explicitly supplied, scope checks, valid JSON, `disposable_test_resources: true`, and the full request budget.

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

With the `xss` extra, the command also parses the actual HTML response and records text/attribute/URL/event/script/style contexts in `context_analysis`. Choose `--html-parser html.parser`, `lxml` or `html5lib`. Non-HTML and unavailable parsers are explicit states, not completed validation. Truncated captures stop the batch. By default, reflection is not JavaScript execution. Opt-in `--confirm-exec` adds three harmless marker/alert payloads adapted to attribute, script and URL contexts, then launches headless Playwright only for responses classified `possible`. It confirms execution only when the unique marker appears on the page or an alert fires; escaped reflection becomes `reflected_not_executed`. Browser requests are restricted to the target origin and share the configured rate limiter. Playwright and Chromium are optional; the regular four-marker behavior is unchanged.

Without `--confirm-exec`, results are `possible`, `not_reproducible` or `error`, and a reflection never confirms XSS. In browser mode they can also be `confirmed`, `reflected_not_executed` or `not_reflected`. A missing marker is not proof that the endpoint is vulnerability-free. Stored and DOM XSS still need separate validation. Add a finding only after reviewing evidence and impact.

## CORS And Redirects

`cors-check <program> --url <URL>` tests the four configured Origin variants and classifies ACAO reflection with ACAC. `open-redirect <program> --url <URL> --param <name>` requires the query parameter to appear exactly once, tests five redirect values and records Location without following it. Both support `--dry-run`, scope/rate/timeout validation, and secret-free evidence. A CORS header result is not proof of sensitive-data access; an external Location is never visited by the toolkit.

## Limits and Reports

`init --config` copies limits into `registros/<program>/settings.yaml`. The included defaults are 1 request/second, 5 ffuf threads, a 15-second timeout, at most 100 XSS HTTP probes and a 1 MB captured response. Raise `max_tests` in the program's `settings.yaml` only when its policy allows the additional requests; per-command `--max-tests` cannot exceed that configured limit. Range mode defaults to 25 IDs in public scope; the separate reviewed public opt-in raises its hard cap to 100, while loopback tests can configure up to 100.

```bash
bugbounty report my-program --format html
bugbounty report my-program --format json
bugbounty status my-program
bugbounty --log-file logs/toolkit.log status my-program
```

Program reports include scope, run history, findings and embedded JSON evidence. HTML escapes all response content and payloads. Files are written under `registros/<program>/reports/`.

Authorization headers, cookies and common password/token fields are redacted from structured evidence. Redaction is best effort: unusual secret formats, user-written findings and third-party raw logs can contain private data. Keep `registros/` local and inspect evidence before sharing it. Raw ffuf output and its isolated history remain in `raw/` for debugging. They are not embedded into reports.

### Known Limitations

The case file's scope, account ownership, expected access and disposable-resource declarations are researcher attestations; the toolkit cannot independently verify program policy or account identity. `anonymous_access`, matrix candidates and write-response predicates are test evidence, not automatic vulnerability confirmation. `public_endpoint` is informational; an explicit `expected_anonymous` mismatch is separately flagged. The matrix contains only supplied accounts and known resources (at most ten accounts), and its diagonal cells are ordinary controls. Persistence verification checks only the explicitly selected scalar through the supplied owner GET. Cleanup compares a final scoped GET against each captured original value; a failed or unavailable readback is reported separately from the access-test outcome. Always inspect disposable test data after writes, including public opt-in runs.

CI runs Hypothesis properties plus Ruff formatting/lint, strict mypy for the access-comparison and write-lab modules, and a 90% coverage gate for those two critical modules. Run the same checks locally with `pip install -e ".[dev]"`.

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

The repository includes one general router/executor and seven separate topic skills. Install all eight sibling folders together so shared references and the single plan adapter resolve. These are ordinary discoverable skills, not a nested-skill engine; the router instructs the AI to load only the requested topic and finish its evidence summary before moving to another.

| Skill | Focus |
| --- | --- |
| [bugbounty-executor](skills/bugbounty-executor/SKILL.md) | Shared authorization, HTTP/Burp, ffuf, reporting and sequential topic routing |
| [bugbounty-xss](skills/bugbounty-xss/SKILL.md) | Reflection checks, HTML contexts, payload references, XSStrike/Dalfox drafts |
| [bugbounty-sqli](skills/bugbounty-sqli/SKILL.md) | Baseline/quote probes, SQL review, sqlmap drafts |
| [bugbounty-cors](skills/bugbounty-cors/SKILL.md) | CORS Origin/ACAO/ACAC comparisons |
| [bugbounty-open-redirect](skills/bugbounty-open-redirect/SKILL.md) | Supplied redirect parameter checks without following Location |
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

Access-control work has native A/B comparisons for known private GET/JSON resources, an opt-in fixed-account read matrix, a policy-authorized range mode, and JSON POST/PUT/PATCH write checks. External ranges default to 25 sequential IDs and ten seconds; `--allow-public-range` explicitly permits up to 100 IDs, four workers and a one-second minimum. Local labs can use up to 100 IDs, four workers and 0.01 seconds without that flag. Writes default to loopback; `--allow-public-writes` is a separate opt-in required for public writes, including write ranges, and remote state may change. Disposable resources and explicit program authorization remain mandatory. The account matrix compares only the supplied known resources; it does not discover roles or enumerate resources. HTTP 200, reflected emails and extension colors are not confirmation. Admin access by an admin is a control, not escalation. Burp extensions, forced browsing, hidden-parameter discovery and nuclei templates need their own reviewed scope/budget; no password-guessing adapter is included. ParamSpider mines archived URLs rather than simply parsing local HTML/JS.

The script accepts a JSON plan for `request`, `fuzz`, `xss`, `sqli`, `cors-check`, `open-redirect` or `access-check`. It defaults to validation without HTTP traffic; `--execute` validates, executes once and generates reports. It never initializes authorization, changes scope or retries failures. Optional `--records-root` selects an existing records directory. Read the skill's command reference for the plan schema.

```bash
python skills/bugbounty-executor/scripts/run_plan.py --toolkit-root . --plan registros/my-program/plan.json
python skills/bugbounty-executor/scripts/run_plan.py --toolkit-root . --plan registros/my-program/plan.json --execute
```

### Agent Evidence Review

The IA running the skill is the reasoning component. Export one native access-control/XSS/SQLi/CORS/open-redirect evidence file into a minimal local packet:

```bash
bugbounty analyze evidence --input registros/my-program/evidence/access-control/selected.json --output registros/my-program/review.json
```

The exporter drops arbitrary response text/instructions, URLs, headers and secrets; it includes allowlisted statuses, context counts and comparison booleans. It is offline by default. An explicit `--ai ollama --model <name>` sends only that minimized packet to the local Ollama service at `127.0.0.1:11434`; it has no remote fallback or tool calling. The [review workflow](skills/bugbounty-executor/references/agent-review.md) treats model output as untrusted and checks provenance, controls and uncertainty. A formatted packet does not authenticate source claims or grant testing permission, and no model automatically confirms a vulnerability.

## Tests

```bash
python -m unittest discover -s tests -v
```

Tests run HTTP/Burp replay, scope exclusions, redaction, request budgets and report generation against an ephemeral server on `127.0.0.1`. With ffuf on PATH, an additional integration test runs the real executable against that laboratory; otherwise it is marked skipped. No test scans a public target.

## License

MIT. See [LICENSE](LICENSE).
