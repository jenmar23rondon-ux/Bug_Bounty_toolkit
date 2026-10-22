from __future__ import annotations

import math
from pathlib import Path
import re
import sys
from urllib.parse import parse_qsl, urlsplit

from ..core.scope_validator import ScopeValidator
from ..core.settings import ExecutorSettings
from ..core.target import normalize_url


TOOLS = ("sqlmap", "xsstrike", "dalfox")


def build_external_plan(
    tool: str, url: str, parameter: str, scope: ScopeValidator, settings: ExecutorSettings, script: Path | None = None
) -> dict:
    if tool not in TOOLS or not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.\[\]-]{0,99}", parameter):
        raise ValueError("Select a supported tool and one explicit parameter name.")
    url = normalize_url(url)
    scope.require(url)
    names = [name for name, _ in parse_qsl(urlsplit(url).query, keep_blank_values=True)]
    if parameter not in names or len(names) != len(set(names)):
        raise ValueError("The URL must contain the selected parameter and no duplicate query names.")
    if tool == "xsstrike" and names != [parameter]:
        raise ValueError("XSStrike plans require a URL containing only the selected query parameter.")
    if script is not None and (tool == "dalfox" or not script.is_file() or script.suffix != ".py"):
        raise ValueError("A script must be a reviewed local Python file for sqlmap or XSStrike.")
    prefix = [sys.executable, str(script.resolve())] if script else [tool]
    delay = 1 / settings.requests_per_second
    timeout = math.ceil(settings.timeout)
    if tool == "sqlmap":
        command = prefix + [
            "-u",
            url,
            "-p",
            parameter,
            "--batch",
            "--level=1",
            "--risk=1",
            "--technique=BE",
            "--threads=1",
            f"--delay={delay:.9g}",
            f"--timeout={timeout}",
            "--retries=0",
            "--ignore-redirects",
            "--abort-code=401,403,429",
            "--disable-coloring",
        ]
    elif tool == "xsstrike":
        command = prefix + ["-u", url, "-t", "1", "-d", str(math.ceil(delay)), "--timeout", str(timeout), "--skip-dom"]
    else:
        milliseconds = math.ceil(delay * 1000)
        if milliseconds > 60000 or timeout > 3600:
            raise ValueError("Dalfox v3 cannot represent these limits; use the bounded built-in executor.")
        command = prefix + [
            "scan",
            url,
            "-p",
            parameter + ":query",
            "--workers",
            "1",
            "--delay",
            str(milliseconds),
            "--timeout",
            str(timeout),
            "--retries",
            "0",
            "--insecure=false",
            "--skip-discovery",
            "--skip-mining",
            "--skip-reflection-header",
            "--skip-reflection-cookie",
            "--skip-reflection-path",
            "--skip-waf-probe",
            "--format",
            "json",
        ]
    return {
        "type": "external-tool-plan",
        "tool": tool,
        "required_version": "3.x" if tool == "dalfox" else "review installed --help",
        "command": command,
        "shell": False,
        "executed": False,
        "target": url,
        "parameter": parameter,
        "minimum_delay_seconds": delay,
        "automatic_request_budget_enforced": False,
        "requires_manual_review": True,
        "warnings": [
            "This command is not executed by the toolkit or the skill runner.",
            "Review program permission, tool version, inherited configuration, redirects, network destinations and total request count before a separate run.",
            "External tools do not inherit HttpClient scope/stop controls; Dalfox v3 may retry HTTP 429 even with retries=0.",
            "No database enumeration/dump, OAST, credential guessing or JWT forgery is enabled by this plan.",
        ],
    }
