# Access-Control Tools And Wordlists

These resources are catalogued for reviewed manual workflows. Nothing here installs Burp, extensions, binaries or wordlists, and `resources` never starts them.

| Tool | Use and limitation | Official source |
| --- | --- | --- |
| Autorize | Replays observed privileged traffic under another session/optionally anonymous; heuristic indicators need validation | [Project](https://github.com/PortSwigger/autorize) |
| AuthMatrix | Explicit users/roles/requests matrix; combinations multiply traffic | [Project](https://github.com/SecurityInnovation/AuthMatrix) |
| Authz | Selected request replay with another cookie; review compatibility of the older extension | [BApp](https://portswigger.net/bappstore/4316cc18ac5f434884b2089831c7d19e) |
| Intruder | Manually selected request mutations, no adapter | [Burp docs](https://portswigger.net/burp/documentation/desktop/tools/intruder) |
| ffuf | Existing fixed-host bounded wordlist adapter; not an IDOR oracle or session matrix | [Project](https://github.com/ffuf/ffuf) |
| feroxbuster | Recursive content discovery, separate scope/budget review | [Project](https://github.com/epi052/feroxbuster) |
| gobuster | Directory/content discovery, no built-in integration | [Project](https://github.com/OJ/gobuster) |
| arjun / x8 | Hidden parameter discovery, no built-in integration | [Arjun](https://github.com/s0md3v/Arjun), [x8](https://github.com/Sh1Yo/x8) |
| ParamSpider | URL mining from web archives, not simply local HTML/JS parsing | [Project](https://github.com/devanshbatham/ParamSpider) |
| nuclei | Separately reviewed specific templates; legacy wrapper is not scoped like the HTTP executor | [Project](https://github.com/projectdiscovery/nuclei) |
| curl | Manual single replay, no inherited scope/redaction protections | [Docs](https://curl.se/docs/manpage.html) |

For a reviewed Burp run, restrict hosts, exact requests and read operations before enabling replay. Keep automatic interception off until the reviewed configuration is ready. Inspect effective cookie/header replacement, CSRF pairing, anonymous credential removal, any redirect behavior, concurrency, request amplification and stopping controls. AuthMatrix Run All or Autorize while browsing can resend state-changing traffic. If the extension cannot enforce the required budget/interval, use individual scoped HTTP replays instead. Color indicators and regex/length matches are candidates only.

## SecLists

Use a small reviewed subset from the local [Web-Content directory](https://github.com/danielmiessler/SecLists/tree/master/Discovery/Web-Content). Filenames can change; check the installed checkout.

| Path under SecLists | Role |
| --- | --- |
| `Discovery/Web-Content/common.txt` | Route candidates |
| `Discovery/Web-Content/raft-medium-directories.txt` | Directory candidates |
| `Discovery/Web-Content/api/api-endpoints.txt` | API route candidates |
| `Discovery/Web-Content/burp-parameter-names.txt` | Parameter names |

Route/parameter discovery is a separate requested operation; these lists do not contain known owned-resource IDs and do not authorize enumeration. `Passwords/Common-Credentials/best1050.txt` belongs to authentication/password review, not BAC. No password list is sent by this skill.

## Python Clients

`python -m pip install -e ".[http]"` provides requests, aiohttp and [httpx](https://www.python-httpx.org/); httpx is the Python library, not the similarly named reconnaissance CLI. These are optional dependencies, not replacements for the scoped HttpClient. Direct async clients do not inherit rate/scope/stop/evidence controls. HTML parsers and PyJWT are in their separate extras and do not prove authorization. No live session matrix or admin-bypass adapter is implemented.
