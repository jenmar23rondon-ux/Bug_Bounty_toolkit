from __future__ import annotations

import importlib.util
import shutil


PYTHON_MODULES = {
    "xss": ("bs4", "lxml", "html5lib", "playwright"),
    "http": ("requests", "aiohttp"), "sqli": ("sqlparse",),
    "jwt": ("jwt", "jose", "cryptography", "jwcrypto"),
    "databases": ("pymysql", "psycopg2"),
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
    ("sqlite3", "python-stdlib", "https://docs.python.org/3/library/sqlite3.html", None),
    ("blind-sqli", "unverified-package-not-installed", "https://github.com/sqlmapproject/sqlmap/wiki/Techniques", None),
)


def catalog() -> dict:
    return {"python_extras": {extra: {module: importlib.util.find_spec(module) is not None for module in modules}
                              for extra, modules in PYTHON_MODULES.items()},
            "resources": [{"name": name, "mode": mode, "source": source,
                           "on_path": shutil.which(binary) is not None if binary else None}
                          for name, mode, source, binary in RESOURCES],
            "network_requests_sent": 0,
            "note": "Availability is not a version/security check. No downloads, installs or scanner execution are performed."}
