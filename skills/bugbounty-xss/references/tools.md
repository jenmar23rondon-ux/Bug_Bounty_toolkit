# XSS Tools And Context

Install optional parsers with `python -m pip install -e ".[xss]"`. Beautiful Soup locates markers; lxml/html5lib provide alternate trees. html5lib parses HTML5 but does not run JavaScript. Playwright's Python package is included in this profile; browser binaries remain a separate install, and no built-in command launches a browser.

| Resource | Integration | Official source |
| --- | --- | --- |
| PayloadsAllTheThings | Context reference, not an automatic scan queue | [XSS Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSS%20Injection) |
| SecLists | Reviewed local payload subset | [Fuzzing/XSS](https://github.com/danielmiessler/SecLists/tree/master/Fuzzing/XSS) |
| XSStrike | Private argv draft only | [Project](https://github.com/s0md3v/XSStrike) |
| Dalfox | Private argv draft for v3 only | [CLI](https://dalfox.hahwul.com/reference/cli/) |
| Beautiful Soup | Offline HTML analysis | [Parsers](https://www.crummy.com/software/BeautifulSoup/bs4/doc/#installing-a-parser) |
| Playwright | Separate reviewed browser workflow | [Python docs](https://playwright.dev/python/docs/intro) |

```bash
bugbounty analyze html --input registros/my-program/page.html --marker BBTK_MARKER --parser html5lib
bugbounty xss my-program --routes inputs/routes.txt --parameters inputs/parameters.txt --rate 0.1 --max-tests 4 --dry-run
bugbounty tool-plan my-program --tool dalfox --url "http://localhost:3000/search?q=marker" --parameter q --dry-run
```

The analyzer returns text, comment, tag/attribute name, attribute, URL, event, script and style contexts without surrounding private text. Source reflection can be present even when no parser context is identified. Entity decoding is not proof that a quote can escape an attribute. Script type, quoting, escaping, sanitization, CSP and required user interaction change exploitability. There is no universal payload; an image tag does not solve a context that removes both angle brackets.

Select small context-specific lists and respect upstream licenses. No blind callbacks, WAF evasion or stored mutations are automatic. Browser confirmation needs an attributable harmless execution marker in the actual affected origin, not arbitrary local evaluation. Read the shared [external-plan limitations](../../bugbounty-executor/references/security-tools.md) before separately reviewing scanner execution.
