"""ProjectDiscovery argv builders. Commands are lists and are never passed to a shell."""

from __future__ import annotations

import re

from ..utils.exceptions import ExternalToolError

_SEVERITY = re.compile(r"^(?:info|low|medium|high|critical)(?:,(?:info|low|medium|high|critical))*$")
_NUCLEI = re.compile(
    r"^\[(?P<template>[A-Za-z0-9_.:-]{1,80})\] \[[A-Za-z0-9_-]{1,20}\] "
    r"\[(?P<severity>info|low|medium|high|critical)\] (?P<url>https?://\S+)$"
)
_FORBIDDEN = (";", "`", "|", "$(", "${", "\n", "\r", "&&", "||")


class ToolMissing(ExternalToolError):
    """The allowlisted binary is not on PATH. Nothing was executed through a shell."""

    def __init__(self, name: str) -> None:
        self.tool = name
        super().__init__(
            f"{name} is not installed or not on PATH. Install the ProjectDiscovery {name} binary and retry. "
            "The toolkit never invokes external tools through a shell."
        )


def assert_argv(argv: list[str]) -> None:
    if not argv or any(not isinstance(token, str) or any(marker in token for marker in _FORBIDDEN) for token in argv):
        raise ValueError("Tool arguments must be a list of strings without shell metacharacters.")


def parse_severity(value: str) -> str:
    cleaned = ",".join(part.strip().lower() for part in value.split(",") if part.strip())
    if _SEVERITY.fullmatch(cleaned) is None:
        raise ValueError("Severity must be a comma-separated subset of info, low, medium, high, critical.")
    return cleaned


def passive_tool_argv(name: str, domain: str) -> list[str]:
    if name == "subfinder":
        argv = ["subfinder", "-silent", "-d", domain]
    elif name == "amass":
        argv = ["amass", "enum", "-passive", "-d", domain]
    else:
        raise ValueError(f"Unsupported passive tool: {name}")
    assert_argv(argv)
    return argv


def active_tool_argv(name: str, hosts_file: str, rate: int, timeout: int) -> list[str]:
    if rate < 1 or timeout < 1:
        raise ValueError("Active tools need a positive whole-number rate and timeout.")
    if name == "dnsx":
        argv = ["dnsx", "-silent", "-l", hosts_file, "-retry", "1"]
    elif name == "httpx":
        argv = [
            "httpx",
            "-silent",
            "-l",
            hosts_file,
            "-rl",
            str(rate),
            "-timeout",
            str(timeout),
            "-no-fallback",
        ]
    else:
        raise ValueError(f"Unsupported active tool: {name}")
    assert_argv(argv)
    return argv


def nuclei_argv(hosts_file: str, rate: int, timeout: int, severity: str, concurrency: int) -> list[str]:
    if rate < 1 or timeout < 1 or concurrency < 1:
        raise ValueError("Nuclei needs a positive rate, timeout, and concurrency.")
    argv = [
        "nuclei",
        "-l",
        hosts_file,
        "-silent",
        "-disable-update-check",
        "-ni",
        "-severity",
        parse_severity(severity),
        "-etags",
        "dos,intrusive,fuzz",
        "-rl",
        str(rate),
        "-c",
        str(min(concurrency, 5)),
        "-timeout",
        str(min(timeout, 15)),
    ]
    assert_argv(argv)
    return argv


def parse_nuclei_line(line: str) -> tuple[str, str, str] | None:
    """Return template id, severity, and URL. Lines that do not match are ignored."""
    match = _NUCLEI.fullmatch(line.strip())
    if match is None:
        return None
    return match.group("template"), match.group("severity"), match.group("url")
