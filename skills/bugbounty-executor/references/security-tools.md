# Shared Security Tool Mechanics

## Install And Inspect

```bash
python -m pip install -e ".[xss,sqli,jwt]"
python -m pip install -e ".[all]"
bugbounty resources
```

| Extra | Packages | Actual role |
| --- | --- | --- |
| `xss` | beautifulsoup4, lxml, html5lib, playwright | Offline HTML context analysis; optional browser API |
| `http` | requests, aiohttp, httpx | Optional clients, not the built-in scoped transport |
| `sqli` | sqlparse | Offline SQL syntax analysis; HTTP quote probes need no SQL library |
| `jwt` | PyJWT, python-jose, cryptography, jwcrypto | Local token inspection/verification and reviewed crypto work |
| `databases` | PyMySQL, psycopg2-binary | Separately authorized direct database work |
| `all` | All above | No scanner binaries, browser engines, Burp extensions or payload repositories |

`resources` is an offline availability catalog, not an installer or a scanner. A Python module or PATH executable does not establish a compatible version. Do not silently install tools, download payload collections or run their example commands. Direct requests/aiohttp/httpx calls do not inherit HttpClient's scope, rate, redaction or no-redirect behavior.

## Topic References

Read only the selected topic, not every linked file:

- [XSS parsers, context, payloads and scanners](../../bugbounty-xss/references/tools.md).
- [SQLi controls, sqlmap and database tools](../../bugbounty-sqli/references/tools.md).
- [JWT libraries and manual tools](../../bugbounty-jwt/references/tools.md).
- [Authentication flows and credential-list boundaries](../../bugbounty-authentication/references/flows.md).
- [Access-control extensions and discovery tools](../../bugbounty-access-control/references/tools.md).

## External Scanner Plans

Initialize the actual program's authorization and scope first. Offline planning does not require automation permission, but a draft does not authorize execution. These commands send no requests:

```bash
bugbounty tool-plan my-program --tool sqlmap --url "http://localhost:3000/search?q=1" --parameter q --dry-run
bugbounty tool-plan my-program --tool xsstrike --url "http://localhost:3000/search?q=marker" --parameter q --script /reviewed/XSStrike/xsstrike.py
bugbounty tool-plan my-program --tool dalfox --url "http://localhost:3000/search?q=marker" --parameter q
```

Without `--dry-run`, only a private JSON argv draft is written under `registros/<program>/raw/external-plans/`. No scanner starts. `--script` accepts reviewed local sqlmap.py/xsstrike.py files. Arbitrary arguments, shell commands, cookies and tokens are not accepted. Plans with private URL values must remain local.

Plans use one worker and a policy-derived delay. XSStrike requires exactly one query parameter. Dalfox requires v3, explicitly validates TLS and disables discovery/mining; redirects are off by default. Its [CLI docs](https://dalfox.hahwul.com/reference/cli/) describe HTTP 429 retries even with retries=0. Tools can inherit local configurations/proxies and exceed a request count; NONE is executed by run_plan.py. Review version/help, per-request scope/exclusions, destinations, total budget, session controls, rate handling and outputs before a separately authorized run. Scanner labels still need attributable reproducible evidence.

## Timing Across Invocations

HttpClient's rate limiter belongs to one process. Native `access-check` shares one client across its two controls and crossed read, so `--rate 0.1` enforces ten-second start intervals within that group. Multiple individual CLI invocations do not share timestamps: explicitly wait between those invocations and topic transitions. Count controls and repetitions in the overall budget.
