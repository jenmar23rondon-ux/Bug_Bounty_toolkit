# XSS Tools And Context

Install optional parsers and Playwright with `python -m pip install -e ".[xss]"`. Install its browser separately with `python -m playwright install chromium`. `--confirm-exec` launches headless Chromium only after a response contains a possible reflection; third-party browser requests are blocked. Default XSS mode does not launch a browser.

| Resource | Integration | Official source |
| --- | --- | --- |
| PayloadsAllTheThings | Context reference, not an automatic scan queue | [XSS Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSS%20Injection) |
| SecLists | Reviewed local payload subset | [Fuzzing/XSS](https://github.com/danielmiessler/SecLists/tree/master/Fuzzing/XSS) |
| XSStrike | Private argv draft only | [Project](https://github.com/s0md3v/XSStrike) |
| Dalfox | Private argv draft for v3 only | [CLI](https://dalfox.hahwul.com/reference/cli/) |
| Beautiful Soup | Offline HTML analysis | [Parsers](https://www.crummy.com/software/BeautifulSoup/bs4/doc/#installing-a-parser) |
| Playwright | Separate reviewed browser workflow | [Python docs](https://playwright.dev/python/docs/intro) |

The opt-in browser payloads are generated around a unique `window.__bbtk_xss_marker` assignment and `alert(marker)`. The HTML-attribute, script-breakout and JavaScript-URL shapes are adapted from the [PayloadsAllTheThings XSS context reference](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSS%20Injection); the toolkit does not queue or copy its full payload lists.

```bash
bugbounty analyze html --input registros/my-program/page.html --marker BBTK_MARKER --parser html5lib
bugbounty xss my-program --routes inputs/routes.txt --parameters inputs/parameters.txt --rate 0.1 --max-tests 4 --dry-run
bugbounty xss my-program --routes inputs/routes.txt --parameters inputs/parameters.txt --confirm-exec --max-tests 7 --dry-run
bugbounty tool-plan my-program --tool dalfox --url "http://localhost:3000/search?q=marker" --parameter q --dry-run
```

The offline analyzer and live `xss` response analysis return text, comment, tag/attribute name, attribute, URL, event, script and style contexts without surrounding private text. Live `--html-parser` selects the parser; `context_analysis.status` is analyzed, unavailable or not_html. A missing parser does not silently count as completed context validation. Context is computed from the in-memory capture, not an 8000-character evidence preview. Truncation stops the batch as incomplete. Source reflection can exist without an identified parser context. Entity decoding is not proof that a quote escapes an attribute. Script type, quoting, escaping, sanitization, CSP and required interaction change exploitability. There is no universal payload; an image tag does not solve a context that removes both angle brackets. `browser_execution_observed` remains false.

Select small context-specific tests and respect upstream licenses. No blind callbacks, WAF evasion or stored mutations are automatic. Browser confirmation loads only the supplied in-scope URL, blocks cross-origin requests, and accepts alert dialogs for the harmless marker. Review CSP, user interaction and DOM-only sources separately; this reflected test does not cover stored/blind XSS. Read the shared [external-plan limitations](../../bugbounty-executor/references/security-tools.md) before separately reviewing scanner execution.
