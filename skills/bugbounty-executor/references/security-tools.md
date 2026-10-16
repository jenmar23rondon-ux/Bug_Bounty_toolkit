# Optional Security Resources

## Install And Inspect

```bash
python -m pip install -e ".[xss,sqli,jwt]"
python -m pip install -e ".[all]"
bugbounty resources
```

| Extra | Python packages | Actual role |
| --- | --- | --- |
| `xss` | beautifulsoup4, lxml, html5lib, playwright | Offline HTML context analysis; optional browser API |
| `http` | requests, aiohttp | Available for separate clients; built-in traffic still uses scoped HttpClient |
| `sqli` | sqlparse | Offline SQL syntax analysis; built-in HTTP error probes need no SQL library |
| `jwt` | PyJWT, python-jose, cryptography, jwcrypto | Local token inspection/verification and separately reviewed cryptographic workflows |
| `databases` | PyMySQL, psycopg2-binary | Direct database clients only with separate database authorization |
| `all` | All the above | Does not install scanners, browser binaries, Burp extensions or payload repositories |

`sqlite3` is Python's standard library. sqlmap is external, not a SQL driver. `blind-sqli` is an ambiguous package name and is deliberately not installed; review a maintained project and version instead. Missing optional dependencies produce an installation hint, not a silent network install.

Playwright browser binaries are separate: `python -m playwright install chromium`. Installing Playwright does not confirm XSS; the skill does not launch browsers automatically. A browser test must bound all network destinations, subresources, traffic, sessions and side effects. `html5lib` builds an HTML5 tree, not a JavaScript runtime.

## XSS Context And Resources

Sources, not vendored payloads or automatic scan queues:

- [PayloadsAllTheThings XSS Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSS%20Injection).
- [SecLists Fuzzing/XSS](https://github.com/danielmiessler/SecLists/tree/master/Fuzzing/XSS).
- [XSStrike](https://github.com/s0md3v/XSStrike).
- [Dalfox CLI](https://dalfox.hahwul.com/reference/cli/): plans target v3, not legacy Go/v2 flags.
- [Beautiful Soup parsers](https://www.crummy.com/software/BeautifulSoup/bs4/doc/#installing-a-parser).
- [Playwright Python](https://playwright.dev/python/docs/intro).

Select small reviewed lists and respect upstream licenses; do not download or send entire collections by default. Find a non-executing marker in a captured HTML file:

```bash
bugbounty analyze html --input registros/my-program/page.html --marker BBTK_MARKER --parser html5lib --output registros/my-program/html-context.json
```

Contexts include HTML text, comments, tag/attribute names, attribute values, URL attributes, event attributes, script and style. Source reflection is recorded even when the parser cannot identify a context. Output excludes surrounding private text and always reports `confirmed: false`. Parser entity decoding does not establish injectable quotes. Script type, quoting, escaping, CSP, user interaction and browser behavior matter. There is no universal payload: `<img ...>` is not applicable when both `<` and `>` are removed.

Browser confirmation needs the own test account, exact URL/parameter, harmless unique execution marker, attributable evidence and cleanup. Scanner AST/reflection labels are not runtime confirmation. Stored/blind XSS and remote callbacks are separate tests, not automatic follow-ups.

## SQL Injection

- [PayloadsAllTheThings SQL Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection).
- [SecLists Fuzzing/Databases](https://github.com/danielmiessler/SecLists/tree/master/Fuzzing/Databases): Linux paths are case-sensitive. Do not assume `databases/` or `Fuzzing/SQLi/` exists in every version.
- [sqlmap usage](https://github.com/sqlmapproject/sqlmap/wiki/Usage).

Built-in `sqli` sends baseline plus two appended quote probes per supplied route/parameter, on GET only. It respects configured scope/rate/budget and stops on transport errors, 401/403/429 or truncated bodies. Compare errors against baseline: existing SQL errors or dynamic response differences alone are not confirmed SQLi.

```bash
bugbounty sqli my-program --routes inputs/routes.txt --parameters inputs/parameters.txt --rate 0.1 --max-tests 6 --dry-run
bugbounty analyze sql --input registros/my-program/own-query.sql
```

`analyze sql` parses an application's own query text without a database connection; syntax alone cannot establish parameterization. HTTP probes do not implement boolean/time-based, UNION, OOB or extraction workflows. Those need separately reviewed controls, dynamic-page handling, low-impact timing thresholds and explicit permission where appropriate. `--dbs`, `--tables`, `--dump`, SQL shells and database drivers are not enabled by generated detection plans.

## External Scanner Plans

Initialize the actual program's authorization and scope first. Offline planning does not require automation permission, but the resulting draft does not authorize execution. These commands send no requests:

```bash
bugbounty tool-plan my-program --tool sqlmap --url "http://localhost:3000/rest/products/search?q=1" --parameter q --dry-run
bugbounty tool-plan my-program --tool sqlmap --url "http://localhost:3000/rest/products/search?q=1" --parameter q
bugbounty tool-plan my-program --tool xsstrike --url "http://localhost:3000/search?q=marker" --parameter q --script /reviewed/XSStrike/xsstrike.py
bugbounty tool-plan my-program --tool dalfox --url "http://localhost:3000/search?q=marker" --parameter q
```

Without `--dry-run`, only a private JSON argv plan is written under `registros/<program>/raw/external-plans/`. No scanner starts. `--script` accepts a reviewed local sqlmap.py/xsstrike.py file. No arbitrary arguments, shell commands, cookies or tokens are accepted. Do not publish a plan with private URL values.

Plans use one worker and a policy-derived delay. XSStrike requires exactly one query parameter. Dalfox requires v3, explicitly validates TLS and disables discovery/mining; redirects are off by default. Its docs say HTTP 429 may be retried even with retries=0. External scanners can exceed the built-in request count and inherit local configuration/proxies; NONE is executed by run_plan.py. Review version/help, per-request scope/exclusions, network destinations, total budget, session checks, rate-limit handling and outputs before a separately authorized run. Scanner claims still need reproducible evidence.

## JWT And Authentication

- [PyJWT API and algorithm warning](https://pyjwt.readthedocs.io/en/stable/api.html).
- [python-jose](https://github.com/mpdavis/python-jose), [cryptography](https://cryptography.io/), [jwcrypto](https://jwcrypto.readthedocs.io/).
- [jwt_tool](https://github.com/ticarpi/jwt_tool), [JWT Editor for Burp](https://github.com/PortSwigger/jwt-editor).
- [hashcat](https://hashcat.net/hashcat/), [John](https://www.openwall.com/john/): separate offline tools for specifically authorized test material.

```bash
bugbounty analyze jwt --input registros/my-program/token.private.txt
bugbounty analyze jwt --input registros/my-program/token.private.txt --key-file registros/my-program/public-key.pem --algorithm RS256 --issuer https://issuer.example --audience own-test-app
```

Decoding without verification shows claim NAMES, key-reference presence and verification flags, not tokens or claim values. Verification requires a local key and one explicit allowed algorithm, requires/checks `exp`, and separately reports issuer/audience checks. Never select algorithms from the token, mix RSA public keys into HMAC verification, fetch `jku`/`x5u`, or treat unverified `kid` as a path. Never upload live tokens to jwt.io or other online decoders.

alg/claim/exp/kid/jku/x5u tampering, signature confusion and weak-secret checks are review topics, NOT operations performed by `analyze jwt`. Creating a token with a known key does not prove an application accepts it. jwt_tool/JWT Editor mutation and hashcat/John cracking need separate explicit plans; no guessing or forging adapter is installed.

For auth/IDOR, use the user's own authorized test accounts: valid normal control for each, then only the specified crossed read. Verify private-resource ownership, status AND application result and repeatability. A reflected email or HTTP 200 alone does not confirm IDOR; rejection does not establish global security. Default credentials, wordlists, forced browsing, session fixation, reset poisoning, 2FA and OAuth changes each need separate scope and side-effect review. No automatic auth bypass or password brute force is part of this skill.
