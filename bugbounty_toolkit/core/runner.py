from __future__ import annotations

import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path

from .records import RecordStore


def tool_exists(name: str) -> bool:
    return shutil.which(name) is not None


def run_tool(store: RecordStore, command_name: str, target: str | None, command: list[str]) -> Path:
    if not tool_exists(command[0]):
        raise RuntimeError(f"Required tool not found in PATH: {command[0]}")

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    output_path = store.paths.raw_dir / f"{timestamp}-{command_name}.txt"
    with output_path.open("w", encoding="utf-8") as output:
        process = subprocess.run(command, stdout=output, stderr=subprocess.STDOUT, text=True, check=False)

    store.add_run(command_name, target, command, process.returncode, output_path)
    if process.returncode != 0:
        raise RuntimeError(f"{command_name} exited with code {process.returncode}. See {output_path}")
    return output_path
