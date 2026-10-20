"""Run a bounded Bug Bounty Toolkit plan without shell interpolation."""

from __future__ import annotations

import argparse
import json
import math
from pathlib import Path
import re
import subprocess
import sys


FIELDS = {
    "request": {"url", "raw_request", "method", "base_url", "headers", "cookies", "params", "data", "timeout", "rate"},
    "fuzz": {"url", "wordlist", "threads", "timeout", "rate", "match_codes", "filter_size"},
    "xss": {"routes", "parameters", "base_url", "headers", "cookies", "timeout", "rate", "max_tests", "html_parser", "confirm_exec"},
    "sqli": {"routes", "parameters", "base_url", "headers", "cookies", "timeout", "rate", "max_tests", "deep"},
    "cors-check": {"url", "headers", "cookies", "timeout", "rate"},
    "open-redirect": {"url", "param", "headers", "cookies", "timeout", "rate"},
    "access-check": {"case_file", "timeout", "rate", "max_tests", "range", "max_range", "concurrency", "min_interval"},
}
LIST_OPTIONS = {"headers": "header", "cookies": "cookie", "params": "param"}
NUMERIC_OPTIONS = {"threads", "timeout", "rate", "max_tests", "max_range", "concurrency", "min_interval"}
BOOLEAN_OPTIONS = {"confirm_exec": "confirm-exec", "deep": "deep"}


def build_command(plan: dict, python: str = sys.executable) -> list[str]:
    if not isinstance(plan, dict):
        raise ValueError("Plan must be a JSON object.")
    action = plan.get("action")
    if not isinstance(action, str) or action not in FIELDS:
        raise ValueError("Action must be request, fuzz, xss, sqli, cors-check, open-redirect or access-check.")
    program = plan.get("program")
    if not isinstance(program, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,79}", program):
        raise ValueError("A valid program name is required.")
    if set(plan) - FIELDS[action] - {"program", "action"}:
        raise ValueError("Plan contains unsupported fields.")
    required = {"fuzz": ("url", "wordlist"), "xss": ("routes", "parameters"), "sqli": ("routes", "parameters"),
                "cors-check": ("url",), "open-redirect": ("url", "param"), "access-check": ("case_file",)}.get(action, ())
    if any(not isinstance(plan.get(key), str) or not plan[key].strip() for key in required):
        raise ValueError("Required action inputs are missing.")
    if action == "request" and sum(key in plan for key in ("url", "raw_request")) != 1:
        raise ValueError("Request requires exactly one of url or raw_request.")
    command = [python, "-m", "bugbounty_toolkit.cli", action, program]
    for key, value in plan.items():
        if key in {"program", "action"}:
            continue
        if key in BOOLEAN_OPTIONS:
            if not isinstance(value, bool):
                raise ValueError(f"{key} must be a boolean.")
            if value:
                command.append("--" + BOOLEAN_OPTIONS[key])
        elif key in LIST_OPTIONS:
            if not isinstance(value, list) or not all(isinstance(item, str) and item for item in value):
                raise ValueError(f"{key} must be an array of nonempty strings.")
            command.extend(f"--{LIST_OPTIONS[key]}={item}" for item in value)
        elif key in NUMERIC_OPTIONS:
            if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or value <= 0:
                raise ValueError(f"{key} must be a positive finite number.")
            integer = key in {"threads", "max_tests", "max_range", "concurrency"} or (action == "fuzz" and key == "timeout")
            if integer and value != int(value):
                raise ValueError(f"{key} must be a whole number.")
            command.append(f"--{key.replace('_', '-')}={int(value) if integer else value}")
        else:
            if not isinstance(value, str) or (key != "data" and not value.strip()):
                raise ValueError(f"{key} must be a string.")
            command.append(f"--{key.replace('_', '-')}={value}")
    return command


def run_plan(plan: dict, toolkit_root: Path, execute: bool = False, records_root: Path | None = None) -> int:
    root = toolkit_root.resolve()
    if not (root / "bugbounty_toolkit" / "cli.py").is_file():
        raise ValueError("Toolkit root must contain bugbounty_toolkit/cli.py.")
    command = build_command(plan)
    prefix = command[:3]
    if records_root is not None:
        prefix = prefix + [f"--records-root={records_root.resolve()}"]
        command = prefix + command[3:]
    validation = subprocess.run(command + ["--dry-run"], cwd=root, check=False)
    if validation.returncode or not execute:
        return validation.returncode
    result = subprocess.run(command, cwd=root, check=False)
    if result.returncode:
        return result.returncode
    for report_format in ("json", "html"):
        result = subprocess.run(
            prefix + ["report", plan["program"], f"--format={report_format}"],
            cwd=root, check=False,
        )
        if result.returncode:
            return result.returncode
    return 0


def main() -> None:
    parser = argparse.ArgumentParser(description="Validate or execute a supplied Bug Bounty Toolkit JSON plan")
    parser.add_argument("--toolkit-root", type=Path, required=True)
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--records-root", type=Path, help="Optional existing records directory; defaults to the checkout's registros/")
    parser.add_argument("--execute", action="store_true", help="After validation, execute once and generate reports")
    args = parser.parse_args()
    try:
        plan = json.loads(args.plan.read_text(encoding="utf-8"))
        raise SystemExit(run_plan(plan, args.toolkit_root, args.execute, args.records_root))
    except (ValueError, OSError) as exc:
        parser.exit(1, f"Error: {exc}\n")
    except KeyboardInterrupt:
        parser.exit(130, "Interrupted.\n")


if __name__ == "__main__":
    main()
