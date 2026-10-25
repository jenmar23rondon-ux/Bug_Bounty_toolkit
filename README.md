# Bug Bounty Toolkit

An authorized testing CLI that executes the targets, routes and parameters **you supply**. The toolkit supports bounded HTTP/Burp replay, ffuf, XSS, SQLi and heuristic SSRF/CSRF checks, CORS and open-redirect checks, passive CNAME takeover candidates, access-control comparisons, and JSON/HTML evidence reports.

Both `bbtk` and `bugbounty` run the same CLI. No AI API or API key is required. Reconnaissance is optional; your existing route discovery workflow can feed `inputs/routes.txt` and `inputs/parameters.txt` directly.

## Installation

Python 3.10 or later:

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -e .
bbtk --version
bbtk doctor
```

Run the deterministic local IDOR/BOLA workflow end to end with one command. It starts an isolated loopback service, imports the checked-in fake Burp captures, runs the bounded private and public controls, and verifies JSON/HTML reports. Preview the exact steps without starting the app or sending requests with `--dry-run`:

```bash
bbtk lab idor
bbtk lab idor --dry-run
bbtk lab web-vuln
bbtk lab web-vuln --dry-run
```

The local app, disposable captures, and expected behavior are documented in [labs/idor_lab](labs/idor_lab/README.md). The automated flow is also runnable directly with `python -m unittest discover -s tests -p test_end_to_end_idor.py -v`. For authorized program testing, follow the separate [IDOR playbook](docs/idor-playbook.md).

The separate [XSS/SQLi web lab](labs/web_vuln_lab/README.md) uses a standard-library server bound to loopback, simulated SQL error responses, and no real database. Its end-to-end test runs bounded checks, imports the resulting evidence, builds the API workflow, exercises the mocked hypothesis review and deterministic skill router, and writes draft reports. Reflections and error signatures remain candidates, never proof; the test does not contact Ollama or any external target.

On Windows, activate with `.venv\Scripts\Activate.ps1`. Install [ffuf](https://github.com/ffuf/ffuf#installation) separately and put its executable on `PATH`. Native HTTP checks and JSON/HTML reports work without ffuf. `requirements.txt` also includes optional ReportLab support for individual PDF findings.

### Optional Security Integrations

```bash
python -m pip install -e ".[csrf,xss,sqli,jwt]"
# Optional dependency for takeover-check --resolve-dns; captured-CNAME matching is offline:
python -m pip install -e ".[takeover]"
# Or all Python profiles, including HTTP clients and database drivers:
python -m pip install -e ".[all]"
bugbounty resources
```

The base install stays small. The `csrf` extra adds Beautiful Soup for the HTML parser; `xss` adds Beautiful Soup/lxml/html5lib/Playwright, `takeover` adds dnspython for explicit DNS lookups, while other extras provide sqlparse, PyJWT/python-jose/cryptography/jwcrypto, requests/aiohttp/httpx and optional database drivers. Offline CNAME signature matching needs no DNS dependency. The `dev` extra adds Ruff, mypy, coverage.py, Hypothesis and the package builder for CI. `--confirm-exec` needs the optional `xss` extra plus `python -m playwright install chromium`; browser confirmation remains off by default. External scanners, payload repositories and Burp extensions remain separate. The [security tools reference](skills/bugbounty-executor/references/security-tools.md) explains installation profiles and external-plan limitations. Each topic skill has its own focused tool references.

`bbtk doctor` checks Python, required/optional dependencies, the repository and installed skill family, local settings, and (with `--program`) saved scope/authorization metadata. It is read-only and sends no HTTP. Use `bbtk doctor --json` for automation. Optional modules and ffuf are reported as warnings when absent; the command never installs anything.

```bash
bugbounty analyze html --input registros/my-program/page.html --marker BBTK_MARKER --parser html5lib
bugbounty analyze jwt --input registros/my-program/token.private.txt
bugbounty jwt-forge --input registros/my-program/token.private.txt --output registros/my-program/private/jwt-candidates.json
bugbounty takeover-check my-program --host docs.example.com --cname docs-project.github.io
bugbounty takeover-check my-program --host docs.example.com --resolve-dns --dry-run
bugbounty analyze sql --input registros/my-program/own-query.sql
bugbounty sqli my-program --routes inputs/routes.txt --parameters inputs/parameters.txt --rate 0.1 --max-tests 6 --dry-run
bugbounty sqli my-program --routes inputs/routes.txt --parameters inputs/parameters.txt --deep --max-tests 8 --dry-run
bugbounty cors-check my-program --url "https://target-autorizado.example/account" --dry-run
bugbounty ssrf-check my-program --url "https://target-autorizado.example/fetch?url=https%3A%2F%2Fexample.org" --param url --dry-run
bugbounty csrf-audit my-program --url "https://target-autorizado.example/account" --dry-run
bugbounty apk-scan my-program --apk "inputs/app.apk" --dry-run
bugbounty apk-scan my-program --apk "inputs/app.apk" --ai-review
bugbounty open-redirect my-program --url "https://target-autorizado.example/login?next=%2Fhome" --param next --dry-run
bugbounty hunt my-program --base-url "https://target-autorizado.example" --routes inputs/routes.txt --params inputs/parameters.txt --case-file registros/my-program/private/case.json --max-tests 30 --dry-run
bugbounty tool-plan my-program --tool sqlmap --url "http://localhost:3000/search?q=1" --parameter q --dry-run
```

## Shared Run Budget

Native HTTP commands (`request`, `xss`, `sqli`, `cors-check`, `ssrf-check`, `csrf-audit`, `open-redirect`, `access-check`, and `hunt`) accept a shared per-invocation budget:

```bash
bbtk request my-program --url "https://target-autorizado.example/health" --run-max-requests 1 --run-max-seconds 30 --run-max-concurrency 1 --dry-run
```

`--run-max-requests` caps total requests across all clients/workers in that command; for `xss --confirm-exec`, same-origin Playwright requests and subresources use the same budget. `--run-max-seconds` sets a cooperative deadline and clamps each new socket/browser navigation timeout to the remaining time; `--run-max-concurrency` caps simultaneous native/browser requests and cannot exceed the program's `max_concurrency`. Program scope is checked for every URL before a request is counted or sent, and configured rate limits and per-command budgets remain active. No new request/time cap is imposed unless a `--run-*` option is supplied. After opted-in runs, the CLI prints requests actually started, responses, transport errors, elapsed time, peak concurrency, stop reason and destination hostnames. Ctrl+C cancels queued requests and prints the partial summary. An already active socket read is not forcibly terminated mid-operation; its socket timeout still applies. External tools such as ffuf, nuclei and prepared scanner plans do not inherit this budget and must use their own reviewed limits.

The shared guard covers native HTTP requests and same-origin Playwright traffic. `ffuf`, `nuclei`, recon tools and external scanner plans are separate processes and do not inherit its exact request counter; use their separately reviewed tool limits. A successful run summary is not a vulnerability verdict.

## Hunt Orchestrator

`hunt` runs the supplied in-scope checks sequentially in this order: CORS, an HTML/CSRF heuristic, optional SSRF, open redirect for each supplied parameter, XSS, SQLi, then access control when a case file is supplied. CSRF uses `--csrf-url` or defaults to `--base-url`. SSRF is deliberately skipped unless both `--ssrf-url` and `--ssrf-param` are supplied; it never guesses which parameter to probe. XSS and SQLi require both route and parameter files. `--confirm-exec` opts XSS into context-labeled probes and same-origin Playwright DOM checks; `--union` opts SQLi into bounded ORDER BY/UNION NULL comparisons, while `--deep` adds timing and boolean probes. Missing optional inputs are reported as skipped; invalid inputs or module failures are recorded without suppressing later modules. A 429 stops that module only. Every native target request shares the `--max-tests` cap (default: the program setting), the configured scope and rate limiter; the optional `--run-max-*` limits further restrict the invocation.

Start with `--dry-run`, which validates the plan and creates a consolidated report without sending target requests. `--only cors-check,xss` and `--skip sqli` select modules. `--resume` continues from the saved progress file only when the program, scope, input file contents, module selection and effective request cap match; an interrupted module is restarted within the remaining budget. Module evidence remains in its normal evidence directory, while one severity/type-sorted JSON and HTML report is written under `registros/<program>/reports/`. No report is submitted automatically.

```bash
bbtk hunt my-program --base-url "https://target-autorizado.example" --routes inputs/routes.txt --params inputs/parameters.txt --case-file registros/my-program/private/case.json --max-tests 30 --dry-run
bbtk hunt my-program --base-url "https://target-autorizado.example" --routes inputs/routes.txt --params inputs/parameters.txt --case-file registros/my-program/private/case.json --confirm-exec --deep --union --max-tests 200 --ai-review
bbtk hunt my-program --base-url "https://target-autorizado.example" --ssrf-url "https://target-autorizado.example/fetch?url=x" --ssrf-param url --only ssrf-check --max-tests 6 --dry-run
```

With `--ai-review`, eligible checks may send only the existing minimized evidence-review packet to local Ollama. Its `candidate` / `not_observed` / `inconclusive` decision and reason are displayed separately from the toolkit verdict; it is a second opinion, not confirmation. Ollama failure is non-fatal. The consolidated hunt JSON and HTML include CSRF findings and explicit SSRF tasks alongside their module evidence. `apk-scan` and `jwt-forge` remain separate offline workflows because they need local APK/token inputs and JWT candidate tokens should not be folded into a live-target report.

`analyze`, `jwt-forge`, `takeover-check` without `--resolve-dns`, and `apk-scan` are offline. `jwt-forge` creates clearly labeled unsigned, algorithm-change, selected claim-change and optional HMAC test candidates, including local PEM public-key-as-HMAC candidates for RS256 input. It has no HTTP client and never submits tokens; generating a candidate does not show that a server accepts it. Keep input/output files private, use only test tokens and keys, and replay only against a local or explicitly authorized test service using accounts you control. `takeover-check` matches captured CNAMEs against local provider suffix patterns; `--resolve-dns` is a separate opt-in requiring an in-scope host and stored authorization reference. A match is only `possible_takeover`, never proof that a provider resource is unclaimed; the command performs no HTTP or resource-claim attempt. APK scanning reads bounded ZIP members in memory, parses textual or binary Android manifests, masks secret/email values and labels found HTTP(S) hosts against the program scope. It makes no network requests and never executes or extracts the APK. `--decompile` explicitly opts into local `jadx`/`apktool` parsing with a temporary output directory and timeout; the base ZIP-only mode needs no external tools. `--ai-review` sends only aggregate finding counts and secret-pattern categories to local Ollama, never APK contents or secret values. JWT verification additionally requires `--key-file` and an explicit `--algorithm`, with optional expected issuer/audience; decoding is not authentication. SQLi defaults to baseline/quote comparisons; `--deep` explicitly adds time and boolean probes, while `--union` adds at most eight ORDER BY tests and one UNION SELECT NULL comparison per parameter; neither extracts data or confirms SQLi. `cors-check` sends four Origin variants; `ssrf-check` makes one baseline and five fixed URL probes, compares status/body fingerprints and records timing without saving bodies; `csrf-audit` reads one HTML response and heuristically summarizes forms and `Set-Cookie` SameSite attributes without submitting forms; `open-redirect` sends five query values and never follows `Location`. SSRF and CSRF results are heuristic only; no metadata values or credentials are extracted, and CSRF exploitability is not confirmed. These live HTTP commands require automation permission, scope and program rate limits. `tool-plan` prepares commands for sqlmap, XSStrike and Dalfox v3 but **never executes them**, even without `--dry-run`. External tools need separately reviewed runs because they do not inherit the hard request budget/scope controls. jwt_tool, JWT Editor, hashcat and John are catalogued manual tools. No password brute force, WAF evasion or database dumping is performed.

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

With the `xss` extra, the command also parses the actual HTML response and records text/attribute/URL/event/script/style contexts in `context_analysis`. Choose `--html-parser html.parser`, `lxml` or `html5lib`. Non-HTML and unavailable parsers are explicit states, not completed validation. Truncated captures stop the batch. By default, reflection is not JavaScript execution. Opt-in `--confirm-exec` adds three harmless marker/alert payloads adapted to attribute, script and URL contexts, then launches headless Playwright only for responses classified `possible`. It confirms execution only when the unique marker appears on the page or an alert fires; escaped reflection becomes `reflected_not_executed`. Browser requests are restricted to the target origin and share the configured rate limiter and run budget. Playwright and Chromium are optional; the regular four-marker behavior is unchanged.

Without `--confirm-exec`, results are `possible`, `not_reproducible` or `error`, and a reflection never confirms XSS. In browser mode they can also be `confirmed`, `reflected_not_executed` or `not_reflected`. A missing marker is not proof that the endpoint is vulnerability-free. Stored and DOM XSS still need separate validation. Add a finding only after reviewing evidence and impact.

## CORS And Redirects

`cors-check <program> --url <URL>` tests the four configured Origin variants and classifies ACAO reflection with ACAC. `ssrf-check <program> --url <URL> --param <name>` requires one existing query parameter, compares a baseline with five fixed URL values, records timing deltas and never saves response bodies or follows redirects. `csrf-audit <program> --url <URL>` makes one GET, parses HTML forms and hidden token-like fields, and summarizes response cookie SameSite attributes. `open-redirect <program> --url <URL> --param <name>` requires the query parameter to appear exactly once, tests five redirect values and records Location without following it. These checks support `--dry-run`, scope/rate/timeout validation and redacted evidence. CORS, SSRF and CSRF results are heuristic observations, not proof; no form is submitted and an external Location is never visited by the toolkit.

## Burp Imports And Local AI Review

The Burp importer reads supported local exports only; it never sends target requests. Each program gets an isolated destination under `registros/<program>/inputs/`, so imports cannot silently overwrite another program's shared route lists. Use `--dry-run` to inspect planned paths; existing files are left untouched unless `--force` is supplied.

```bash
bbtk import burp my-program --sitemap burp-sitemap.xml --base-url https://target.example --dry-run
bbtk import burp my-program --sitemap burp-sitemap.xml --base-url https://target.example
bbtk import burp my-program --request captured-request.txt
bbtk import burp my-program --item saved-item.xml
bbtk ai-review my-program --evidence-file registros/my-program/evidence/xss/run.json
bbtk ai-review my-program --artifact registros/my-program/inputs/burp/response.html --kind html --dry-run
bbtk ai-review my-program --artifact captured-response.txt --kind response --chunk-chars 6000 --max-chunks 20
bbtk ai hypotheses my-program --input registros/my-program/evidence/imports/unified-evidence.json --dry-run
bbtk ai route my-program --input my-hypotheses.json --dry-run
bbtk ai prioritize my-program --input my-hypotheses.json --max-tests 100 --dry-run
bbtk ai investigate my-program --input registros/my-program/evidence/imports/unified-evidence.json --dry-run
bbtk ai investigate my-program --input registros/my-program/evidence/imports/unified-evidence.json --with-ollama --max-tests 100
bbtk report my-program --evidence-file registros/my-program/evidence/access-control/selected.json --format markdown
bbtk ai benchmark --dataset labs/idor_lab/benchmark-v1.json --output reports/idor-benchmark.json
bbtk ai benchmark --dataset labs/idor_lab/benchmark-v1.json --with-ollama --output reports/idor-benchmark-ollama.json
bbtk report my-program --evidence-file registros/my-program/evidence/xss/run.json --draft-with-ai
```

`ai hypotheses` recomputes endpoint correlations and can ask local Ollama for a strict, per-group hypothesis using only endpoints, methods, anonymized session/resource labels and response fingerprints. It retries malformed model JSON once, marks invented evidence IDs, and saves each non-dry-run result as a unique history file. `--dry-run` validates and shows the minimized packets without Ollama or disk writes. Every result is a second opinion, never confirmation; HTTP status alone is not evidence of IDOR.

For deterministic A/B interpretation, add `--case-file <private/case.json> --access-evidence <access-check.json>`. The evaluator requires valid owner and actor controls, and uses only application-success and configured owner-resource/private-marker predicates: `legitimate_access` describes valid own-account controls, `denied` requires an application-level denial, `possible_unauthorized_access` requires the crossed response to match both the owner's resource and private marker, and missing/conflicting proof is `insufficient_evidence`. It never treats HTTP status or Ollama's opinion as confirmation. Unified evidence fingerprints alone cannot establish which account owns a resource; without native access-check predicates the result stays insufficient.

`ai route` validates the hypotheses JSON against the installed typed registry of topic skills, maps clear categories deterministically and asks local Ollama only for ambiguous categories. If Ollama is unavailable or proposes an unknown skill, a deterministic `bugbounty-executor` fallback is used. The output contains selected skills, missing prerequisites and reviewed command templates; the router never executes them or writes files. `--max-tests` rejects a plan whose estimated HTTP checks exceed the supplied budget. Treat all route text as advisory and inspect the selected skill's `SKILL.md` before acting.

`ai prioritize` is a deterministic, offline triage layer for reviewed hypotheses. It ranks research steps using evidence counts, declared missing controls, a category-based potential-impact heuristic, the registered check cost and operational risk. It reports model-stated hypothesis confidence separately and always leaves demonstrated severity as `not_assessed`; category-based impact is not demonstrated impact. HTTP steps are blocked for human review until scope and program policy are checked, and every plan step requires human approval. Request units are estimates only; the selected command's own budget controls remain authoritative. It never calls Ollama, sends HTTP requests or executes commands. Use `--dry-run` to validate/print without writing; `--output` writes JSON and refuses overwrite unless `--force` is supplied.

`ai investigate` connects the existing evidence correlation, hypotheses, optional deterministic A/B access assessment, registered-skill routing and prioritization stages in one review artifact. It is offline by default; `--with-ollama` opts into the local model for minimized hypotheses and ambiguous skill routing. `--dry-run` overrides that flag and makes no Ollama call, target request, command execution or file write. Results are saved to a non-overwriting evidence history unless `--output` is supplied. The plan remains advisory, HTTP scope is not verified, and nothing executes; inspect the selected skill and validate authorization before running a check.

`ai benchmark` evaluates the deterministic access-control assessor on a versioned synthetic IDOR/BOLA corpus and optionally compares local Ollama plus a conservative combined result. It defaults to the `holdout` split, never sends target requests, and saves paired JSON/Markdown reports; `--dry-run` validates the dataset without model calls or writes. The included small corpus is for regression measurement, not a claim of general performance. Metrics cover only the selected synthetic cases; the binary false-positive/negative rates treat both safe and insufficient ground-truth cases as non-vulnerable. Elapsed time is local processing time, not measured human investigation time. Ollama receives only boolean predicates and cannot promote insufficient deterministic evidence or confirm a vulnerability.

### Case File Generation

Create an offline, read-only `access-check` case from two raw Burp GET captures. Each capture must use a distinct authorized account and refer to that account's own resource. The generator requires the application's response pointers, both existing private markers, and explicit researcher attestations; it will not guess these values:

```bash
bbtk import case my-program \
  --owner inputs/requests/account-a.txt --actor inputs/requests/account-b.txt \
  --resource-pointer /data/id --success-pointer /success --success-value true \
  --private-pointer /data/marker \
  --private-marker OWNER_MARKER_ALREADY_IN_A --actor-marker ACTOR_MARKER_ALREADY_IN_B \
  --attest-authorized-accounts --attest-private-resource --dry-run
```

Use `--base-url http://target.example` when the raw request target is relative and the captured origin is HTTP; otherwise relative targets assume HTTPS. The command checks that both requests share an origin and method, that the only target difference is one path segment or one non-session query value, and that the session header names match while their values differ. It reports the inferred resource selector without printing IDs or session values. `--resource-pointer`, `--private-pointer` and `--success-pointer` are syntax-checked JSON pointers only: without response captures, the importer cannot verify that they identify the intended fields or that a marker exists in a response.

The default output is `registros/<program>/private/case.json`; `--output` selects another path, and an existing case requires `--force` to replace. `--dry-run` performs local parsing and validation without creating files or making network calls. The generated JSON references the original raw captures and contains their resource IDs and marker values, but does not copy session headers. Keep the captures and case file private. Account authorization, resource privacy, marker existence and the expected denial of cross-account access remain attestations by the researcher. This command creates GET read cases only; state-changing checks require the separate lab write workflow and disposable resources.

Sitemap XML produces deduplicated `routes.txt` and `parameters.txt`; an optional base URL makes same-origin routes relative. Common static assets are skipped. Raw requests are normalized for `request --raw-request`, with authorization/cookie headers and common sensitive body/query fields redacted. Saved items yield a redacted HTML response and JWTs found in authentication/cookie headers under `inputs/burp/private/`; those JWT files are sensitive credentials and must remain local. Only Burp sitemap XML, raw HTTP requests and saved HTTP item/XML exports are supported, not Burp's HTML report export.

`ai-review --evidence-file` sends only the existing allowlisted minimized evidence packet. `--artifact` sends bounded, overlapping text chunks after local redaction; `--chunk-chars` defaults to 6000 and `--max-chunks` defaults to 20. Model JSON is validated and retried once; unparsed/oversized artifacts are reported with an explicit status. Ollama is contacted only at `127.0.0.1:11434`; if unavailable, the command reports that state without failing the toolkit. Its result is always a **second opinion, not confirmation**. It never sends target requests or submits a report. `report --draft-with-ai` uses the minimized evidence and falls back to the deterministic Markdown draft if the local model is unavailable or returns an unusable draft. The recommended local model is `qwen2.5-coder:7b`; quality and useful context depend on model size and the selected chunk limits. Review all generated text manually.

### Unified Evidence Import

The offline `evidence import` command normalizes supplied Burp XML, HAR, ffuf JSON, Nuclei JSON/JSONL, native toolkit JSON, raw HTTP captures, structured CSV, HTML, Markdown and text into one typed JSON bundle. Import multiple files together to compare their account/session fingerprints consistently:

```bash
bbtk evidence import my-program --input burp-history.xml traffic.har ffuf.json nuclei.jsonl --dry-run
bbtk evidence import my-program --input burp-history.xml traffic.har ffuf.json nuclei.jsonl
bbtk evidence correlate my-program --input registros/my-program/evidence/imports/unified-evidence.json --dry-run
bbtk api-workflow my-program --input registros/my-program/evidence/imports/unified-evidence.json --openapi inputs/openapi.yaml --dry-run
```

The importer stores source paths and record locators, extracts endpoint templates and parameter names, records response fingerprints/shape fingerprints, and merges semantically duplicate observations while preserving each provenance reference. Evidence bundles are schema 1.1; optional request-side and response-issued session fingerprints are stored separately from the legacy combined fingerprint. Session and resource identifiers are HMAC-fingerprinted using a random per-import salt, so identities correlate only among files imported together; raw cookies, tokens, body text and parameter values are not stored. Re-importing does not overwrite the default bundle unless `--force` is used. `--dry-run` parses and summarizes without creating output files. Correlations report endpoint, session, resource and response differences only; they are not vulnerability findings, do not prove authorization, and do not send network requests or call Ollama.

### API Workflow Intelligence

`bbtk api-workflow <program> --input <unified-evidence.json>` builds an offline graph of captured requests, responses, endpoint templates, opaque session fingerprints and resource fingerprints. `--openapi <file>` optionally adds documentation-only operations from local OpenAPI JSON or YAML. The graph records exact evidence references, minimized provenance and whether a relationship is observed or documented; it never calls Ollama or sends requests. `--dry-run` validates and summarizes without writing, and an existing graph requires `--force` to replace.

```bash
bbtk api-workflow my-program --input registros/my-program/evidence/imports/unified-evidence.json --openapi inputs/openapi.yaml --dry-run
bbtk api-workflow my-program --input registros/my-program/evidence/imports/unified-evidence.json --openapi inputs/openapi.yaml
```

Path names such as `login`, `users` or `profile` create low-confidence hypotheses only. HTTP methods are read/write hints, not proof of behavior. Request-session fingerprints are kept separate from response-issued cookie fingerprints; the graph records cookie continuity only when opaque values match and timestamps are ordered. Legacy bundles without directional fingerprints cannot establish that transition. A session is not an account. Resource fingerprints do not establish ownership or privacy, and HTTP 200 does not confirm access. OpenAPI paths are exact documentation matches only; documentation does not prove that an endpoint exists or behaves as described. The model creates no ownership or permission relationship without direct evidence supporting it.

### Persistent Evidence Graph and Investigation Memory

`bbtk graph ingest <program> --input <unified-evidence.json>` extends the existing API workflow graph into the program's local SQLite database. Optional `--hypotheses`, `--route`, `--case-file` plus `--access-evidence`, and `--openapi` inputs join AI hypotheses, registered skill suggestions, deterministic access assessments and documentation links. Relationships retain evidence references, provenance, observation time, epistemic state and limitations. Re-ingestion is idempotent for graph nodes/edges and adds a history row. `--dry-run` validates and counts the plan without creating the records directory or database.

```bash
bbtk graph ingest my-program --input registros/my-program/evidence/imports/unified-evidence.json --hypotheses registros/my-program/evidence/ai-hypotheses/review.json --dry-run
bbtk graph search my-program --endpoint /api/orders/{id}
bbtk graph search my-program --account owner
bbtk graph search my-program --category access_control
bbtk graph search my-program --finding-id FINDING-001
```

Search accepts exact endpoint, case account label, resource ID/opaque fingerprint, category or finding ID and returns matched nodes with one-hop relations. Account labels and case resource IDs are HMAC-pseudonymized using a local per-program key stored in the SQLite database; raw session headers, private markers and resource identifiers are not retained. Protect the local database because the pseudonym key is stored alongside it. The graph can join imported observations only where evidence IDs match; per-import session/resource fingerprints still cannot correlate identity across separate imports. Access-case ownership and roles remain researcher attestations. Model hypotheses remain `hypothesis` state, invalid evidence references are marked and not linked, and skill plans are validated but never executed.

## Limits and Reports

`init --config` copies limits into `registros/<program>/settings.yaml`. The included defaults are 1 request/second, 5 ffuf threads, a 15-second timeout, at most 100 XSS HTTP probes and a 1 MB captured response. Raise `max_tests` in the program's `settings.yaml` only when its policy allows the additional requests; per-command `--max-tests` cannot exceed that configured limit. Range mode defaults to 25 IDs in public scope; the separate reviewed public opt-in raises its hard cap to 100, while loopback tests can configure up to 100.

```bash
bugbounty report my-program --format html
bugbounty report my-program --format json
bugbounty status my-program
bugbounty --log-file logs/toolkit.log status my-program
```

Program reports include scope, run history, findings and embedded JSON evidence. HTML escapes all response content and payloads. Files are written under `registros/<program>/reports/`.

Create a reviewer-ready, redacted report from a native JSON evidence file with `bbtk report my-program --evidence-file <evidence.json> --format markdown`. The format choices are `markdown`, `json`, `html` and `pdf`. Every format uses the same schema: evidence references, source, endpoint/method, category/CWE, hypothesis, expected and observed outcomes, evidence for and against, negative controls, limitations, remediation, impact and severity fields. Missing facts are labeled `Información pendiente`; the generator does not infer reproduction steps, impact or severity. JSON/HTML/PDF evidence reports are deterministic, while `--draft-with-ai` remains an optional Markdown-only second opinion. Existing outputs are never replaced without `--force`. Reports are local drafts and are never submitted automatically.

Validation state is derived from the recorded technical predicates, not AI output or HTTP status. `validated` is reserved for an XSS result that records a confirmed classification, browser execution, and an observed harmless marker or alert; this verifies script execution in that browser run only, not authorization, scope or impact. Other candidate classifications remain `candidate`, explicit no-signal results are `not_observed`, and incomplete or unsupported evidence is `inconclusive`.

Authorization headers, cookies and common password/token fields are redacted from structured evidence. Redaction is best effort: unusual secret formats, user-written findings and third-party raw logs can contain private data. Keep `registros/` local and inspect evidence before sharing it. Raw ffuf output and its isolated history remain in `raw/` for debugging. They are not embedded into reports.

### Known Limitations

The case file's scope, account ownership, expected access and disposable-resource declarations are researcher attestations; the toolkit cannot independently verify program policy or account identity. Case generation from Burp requests is offline: pointers are syntax-checked, while marker existence and pointer meaning require separate response evidence. Generated case files contain resource identifiers and private markers and must stay local. `anonymous_access`, matrix candidates and write-response predicates are test evidence, not automatic vulnerability confirmation. `public_endpoint` is informational; an explicit `expected_anonymous` mismatch is separately flagged. The matrix contains only supplied accounts and known resources (at most ten accounts), and its diagonal cells are ordinary controls. Persistence verification checks only the explicitly selected scalar through the supplied owner GET. Cleanup compares a final scoped GET against each captured original value; a failed or unavailable readback is reported separately from the access-test outcome. Always inspect disposable test data after writes, including public opt-in runs.

The IDOR lab contains a deliberate one-way cross-account read flaw, a protected resource path, an HTTP 200 denial page, a server-error path and a public negative control. Its tokens and markers are fake fixtures and have no value outside the loopback demo. `bbtk lab idor` runs the vulnerable and protected end-to-end scenarios, including evidence correlation, skill routing, deterministic assessment and review reporting; generated records and reports are temporary and removed when the test finishes. The range authorization added by that test is scoped to the disposable fixture and must never be copied to a real program without explicit policy approval. The first benchmark dataset is small, synthetic and IDOR/BOLA-only; it does not establish real-world precision, recall, analyst time saved, or comparative model quality. Its development and holdout splits are evaluated separately; do not tune prompts or rules against the holdout and then describe the same results as independent evaluation.

The route-oriented Burp importer is offline and supports only sitemap XML, raw HTTP requests and saved items; it does not interpret Burp HTML reports. The unified evidence importer additionally accepts HAR, ffuf/Nuclei JSON, toolkit JSON, raw HTTP, CSV, HTML, Markdown and text. Those adapters are bounded and best-effort; arbitrary document text is not retained, but redaction cannot identify every proprietary secret format. Provenance paths can disclose local filenames and are included for traceability. Per-import HMAC fingerprints cannot correlate identities across separate import runs. API workflow and persistent evidence graphs inherit that limit and do not infer account identity, resource ownership or privacy from fingerprints, route names, documentation or HTTP status. The persistent graph is local investigation memory, not a source of independent truth; its pseudonym key shares the program database and should be protected with it. Ollama is a local second opinion only: it does not confirm findings, send target requests or submit reports. Artifact review sends redacted chunks to the local model; context can be incomplete when `--max-chunks` truncates a file, and analysis quality depends on the installed model and its context capacity. AI report drafts must be manually checked against the source evidence. The evidence report generator uses only allowlisted fields and generic category remediations; a reported validation state is bounded by the saved result predicates and does not replace researcher confirmation of scope, ownership, impact or severity.

CI runs Ruff lint and formatting across `bugbounty_toolkit/`, `tests/`, `scripts/` and `skills/`; a guard test verifies every Python file under the package and tests is included in Ruff's discovered file set. Strict mypy covers the access comparison/write lab/function matrix, shared budget and runner, CORS/redirect, SQLi/XSS, diagnostics, hunt, SSRF/CSRF, JWT forge, takeover, APK scan, IDOR/BOLA benchmark and assessment, prioritization, investigation orchestration, API workflow, persistent evidence graph and evidence finding report modules. Coverage gates require at least 90% combined for the two critical access-control modules, at least 80% for the BFLA function matrix, API workflow intelligence and persistent evidence graph, at least 80% combined for `hunt.py`, `ssrf_check.py`, `csrf_audit.py` and `jwt_forge.py`, at least 85% each for the evidence engine, IDOR/BOLA benchmark, prioritization, investigation orchestration and evidence finding report modules, plus the existing 77% package-wide floor across `bugbounty_toolkit`, the skill installer and plan runner. The CLI and some older modules remain outside strict mypy. Run the same checks locally with `pip install -e ".[dev]"`.

The installed version is synchronized in `pyproject.toml` and `bugbounty_toolkit/__init__.py`; `bbtk --version` prints it. Pushing a matching `v<version>` tag runs the release workflow, rechecks tests/coverage, builds wheel and source archives, and publishes a GitHub Release with generated notes. The workflow rejects tags that do not match package metadata.

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
|   |-- idor_lab_server.py  # Loopback-only deterministic IDOR/BOLA fixture
|   |-- apk_scan.py          # Bounded offline APK and Android manifest inspection
|   |-- burp_import.py       # Offline Burp sitemap, raw request and saved-item importer
|   |-- access_control/     # Read/write comparisons, ranges and guards
|   |-- analysis/           # Evidence Engine, API workflows, persistent graph, hypotheses, routing and Ollama
|   |-- core/               # Scope, HTTP, budgets, settings and records
|   |-- fuzzing/            # ffuf adapter, wordlists and result parsing
|   |-- integrations/       # External plan/catalog adapters
|   |-- reporting/          # JSON, HTML, Markdown and evidence
|   |-- requests_engine/    # Request replay and response analysis
|   |-- sqli/               # Bounded SQLi probes
|   |-- xss/                # Reflection and optional browser confirmation
|   |-- cors_check.py       # CORS response checks
|   |-- csrf_audit.py       # Heuristic forms and cookie attributes
|   |-- diagnostics.py      # Read-only environment diagnostics
|   |-- open_redirect.py    # Supplied-parameter redirect checks
|   `-- ssrf_check.py       # Bounded SSRF response comparisons
|-- config/                 # Program configuration examples
|-- docs/                   # Checklists and project documentation
|-- inputs/                 # Supplied targets, routes, parameters, requests
|-- labs/idor_lab/          # Local IDOR app, fake Burp captures and run scripts
|-- scripts/                # Skill installer and maintenance utilities
|-- skills/                 # General router and topic-specific skills
|-- wordlists/              # Small replaceable examples
|-- tests/                  # Unit and local integration tests
|-- registros/              # Private per-program runtime data (ignored)
|-- reports/                # Optional exported reports (ignored)
`-- logs/                   # Optional CLI logs (ignored)
```

The existing package location is retained so imports and the original `bbtk` command continue to work. No artificial `src/` migration is needed.

Project practices and change history: [Contributing](CONTRIBUTING.md), [Security](SECURITY.md), and [Changelog](CHANGELOG.md).

The original `recon`, `scan nuclei`, `params`, `checklist`, `mark-reviewed` and `add-finding` commands remain available. Their third-party scanner behavior requires separate review against the program policy; the strict request executor covers `request`, `fuzz` and `xss`. No discovery tool is invoked by those three commands.

## AI Skill

The repository includes one general router/executor and ten separate topic skills. Install all eleven sibling folders together so shared references and the single plan adapter resolve. These are ordinary discoverable skills, not a nested-skill engine; the router instructs the AI to load only the requested topic and finish its evidence summary before moving to another.

| Skill | Focus |
| --- | --- |
| [bugbounty-executor](skills/bugbounty-executor/SKILL.md) | Shared authorization, HTTP/Burp, ffuf, reporting and sequential topic routing |
| [bugbounty-apk-analysis](skills/bugbounty-apk-analysis/SKILL.md) | Offline APK endpoints, secret-patterns, Firebase references and Android deep links |
| [bugbounty-takeover](skills/bugbounty-takeover/SKILL.md) | Offline provider-CNAME candidates and optional scoped DNS lookup |
| [bugbounty-xss](skills/bugbounty-xss/SKILL.md) | Reflection checks, HTML contexts, payload references, XSStrike/Dalfox drafts |
| [bugbounty-sqli](skills/bugbounty-sqli/SKILL.md) | Baseline/quote probes, SQL review, sqlmap drafts |
| [bugbounty-cors](skills/bugbounty-cors/SKILL.md) | CORS Origin/ACAO/ACAC comparisons |
| [bugbounty-ssrf](skills/bugbounty-ssrf/SKILL.md) | One supplied URL parameter, five bounded SSRF indicators, no response-body retention |
| [bugbounty-csrf](skills/bugbounty-csrf/SKILL.md) | Heuristic form-token and cookie SameSite audit; never submits a form |
| [bugbounty-open-redirect](skills/bugbounty-open-redirect/SKILL.md) | Supplied redirect parameter checks without following Location |
| [bugbounty-jwt](skills/bugbounty-jwt/SKILL.md) | Offline token inspection/verification and local test-candidate generation |
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

For role-to-function authorization, `access-check --function-matrix` adds a separate read-only BFLA comparison from exact supplied GET captures. Each function requires explicit allowed roles, a passing positive control, an application-level denial predicate, a unique private response marker, and `read_only_attested: true`. It uses no role or route discovery, caps the matrix at 100 requests, respects scope and budget, and classifies a possible issue only when a restricted role receives both configured success and marker evidence after allowed-role controls pass. HTTP status alone never decides the result. See [the BFLA playbook](docs/bfla-playbook.md) for the private case format and review steps. Role-based writes are not part of this mode.

The script accepts a JSON plan for `request`, `fuzz`, `xss`, `sqli`, `cors-check`, `ssrf-check`, `csrf-audit`, `open-redirect`, `access-check` or `apk-scan`. It defaults to validation without HTTP traffic; `--execute` validates, executes once and generates reports. It never initializes authorization, changes scope or retries failures. Optional `--records-root` selects an existing records directory. Read the skill's command reference for the plan schema.

```bash
python skills/bugbounty-executor/scripts/run_plan.py --toolkit-root . --plan registros/my-program/plan.json
python skills/bugbounty-executor/scripts/run_plan.py --toolkit-root . --plan registros/my-program/plan.json --execute
```

### Agent Evidence Review

The IA running the skill is the reasoning component. Export one native access-control/XSS/SQLi/CORS/SSRF/CSRF/open-redirect evidence file into a minimal local packet:

```bash
bugbounty analyze evidence --input registros/my-program/evidence/access-control/selected.json --output registros/my-program/review.json
```

The exporter drops arbitrary response text/instructions, URLs, headers and secrets; it includes allowlisted statuses, context counts and comparison booleans. It is offline by default. An explicit `--ai ollama` sends only that minimized packet to the local Ollama service at `127.0.0.1:11434`, using `qwen2.5-coder:7b` by default; `--model <name>` overrides the model. There is no remote fallback or tool calling. `bbtk doctor` checks for the local Ollama executable without contacting the service. The [review workflow](skills/bugbounty-executor/references/agent-review.md) treats model output as untrusted and checks provenance, controls and uncertainty. A formatted packet does not authenticate source claims or grant testing permission, and no model automatically confirms a vulnerability.

Live `access-check`, `xss`, `sqli`, `cors-check`, `ssrf-check`, `csrf-audit`, `open-redirect` and `hunt` commands can opt in after a candidate with `--ai-review`; `--ai-model` and `--ai-timeout` configure the local reviewer (defaults: `qwen2.5-coder:7b` and 120 seconds). The saved evidence gets an `ai_review` field. Only the minimized allowlisted packet is sent, Ollama failure is non-fatal, and the AI can return only `candidate`, `not_observed` or `inconclusive` with a short reason; the toolkit verdict remains authoritative.

## Tests

```bash
python -m unittest discover -s tests -v
```

Tests run HTTP/Burp replay, scope exclusions, redaction, request budgets and report generation against an ephemeral server on `127.0.0.1`. With ffuf on PATH, an additional integration test runs the real executable against that laboratory; otherwise it is marked skipped. No test scans a public target.

## License

MIT. See [LICENSE](LICENSE).
