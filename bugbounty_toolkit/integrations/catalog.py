from __future__ import annotations

import importlib.util
import shutil


PYTHON_MODULES = {
    "csrf": ("bs4",),
    "xss": ("bs4", "lxml", "html5lib", "playwright"),
    "http": ("requests", "aiohttp", "httpx"),
    "sqli": ("sqlparse",),
    "jwt": ("jwt", "jose", "cryptography", "jwcrypto"),
    "databases": ("pymysql", "psycopg2"),
    "takeover": ("dns.resolver",),
}
RESOURCES = (
    ("payloadsallthethings", "reference", "https://github.com/swisskyrepo/PayloadsAllTheThings", None),
    ("seclists-xss", "wordlists", "https://github.com/danielmiessler/SecLists/tree/master/Fuzzing/XSS", None),
    ("seclists-sqli", "wordlists", "https://github.com/danielmiessler/SecLists/tree/master/Fuzzing/Databases", None),
    ("xsstrike", "external-plan", "https://github.com/s0md3v/XSStrike", "xsstrike"),
    ("dalfox", "external-plan-v3", "https://dalfox.hahwul.com/reference/cli/", "dalfox"),
    ("sqlmap", "external-plan", "https://github.com/sqlmapproject/sqlmap", "sqlmap"),
    ("jwt_tool", "manual", "https://github.com/ticarpi/jwt_tool", "jwt_tool"),
    ("jwt-editor", "burp-extension", "https://github.com/PortSwigger/jwt-editor", None),
    ("hashcat", "offline-manual", "https://hashcat.net/hashcat/", "hashcat"),
    ("john", "offline-manual", "https://www.openwall.com/john/", "john"),
    ("jwt.io", "reference-no-live-tokens", "https://jwt.io/", None),
    ("autorize", "burp-extension", "https://github.com/PortSwigger/autorize", None),
    ("authmatrix", "burp-extension", "https://github.com/SecurityInnovation/AuthMatrix", None),
    ("authz", "burp-extension", "https://portswigger.net/bappstore/4316cc18ac5f434884b2089831c7d19e", None),
    ("intruder", "burp-manual", "https://portswigger.net/burp/documentation/desktop/tools/intruder", None),
    ("ffuf", "bounded-adapter", "https://github.com/ffuf/ffuf", "ffuf"),
    ("feroxbuster", "manual-discovery", "https://github.com/epi052/feroxbuster", "feroxbuster"),
    ("gobuster", "manual-discovery", "https://github.com/OJ/gobuster", "gobuster"),
    ("arjun", "manual-discovery", "https://github.com/s0md3v/Arjun", "arjun"),
    ("x8", "manual-discovery", "https://github.com/Sh1Yo/x8", "x8"),
    ("paramspider", "manual-archive-mining", "https://github.com/devanshbatham/ParamSpider", "paramspider"),
    ("nuclei", "separately-reviewed-legacy-wrapper", "https://github.com/projectdiscovery/nuclei", "nuclei"),
    ("curl", "manual-http", "https://curl.se/docs/manpage.html", "curl"),
    (
        "seclists-web-content",
        "wordlists",
        "https://github.com/danielmiessler/SecLists/tree/master/Discovery/Web-Content",
        None,
    ),
    (
        "seclists-passwords",
        "reference-no-guessing-adapter",
        "https://github.com/danielmiessler/SecLists/tree/master/Passwords/Common-Credentials",
        None,
    ),
    ("sqlite3", "python-stdlib", "https://docs.python.org/3/library/sqlite3.html", None),
    ("blind-sqli", "unverified-package-not-installed", "https://github.com/sqlmapproject/sqlmap/wiki/Techniques", None),
)


def _module_available(module: str) -> bool:
    try:
        return importlib.util.find_spec(module) is not None
    except (ImportError, ValueError):
        return False


def catalog() -> dict:
    return {
        "python_extras": {
            extra: {module: _module_available(module) for module in modules}
            for extra, modules in PYTHON_MODULES.items()
        },
        "resources": [
            {
                "name": name,
                "mode": mode,
                "source": source,
                "on_path": shutil.which(binary) is not None if binary else None,
            }
            for name, mode, source, binary in RESOURCES
        ],
        "network_requests_sent": 0,
        "note": "Availability is not a version/security check. No downloads, installs or scanner execution are performed.",
    }
