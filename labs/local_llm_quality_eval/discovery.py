"""Read-only GPU and local-model inventory for the RTX 3060 evaluation.

This module never downloads a model, never contacts a non-loopback host, and
never executes model output. ``ollama list`` and ``nvidia-smi`` are queried
only when those binaries are already installed.
"""

from __future__ import annotations

import shutil
import socket
import subprocess
from dataclasses import dataclass, field
from typing import Any

from bugbounty_toolkit.analysis.ai_providers import (
    PROVIDER_REGISTRY,
    AIProviderError,
    _request_json,
)

DISCOVERY_SCHEMA = "bbtk.local-llm-rtx3060-discovery.v1"
NOT_MEASURED = "NOT_MEASURED"
LOOPBACK_HOSTS = frozenset({"127.0.0.1", "::1"})
_MUTATING_ARGV = frozenset({"pull", "push", "create", "run", "rm", "cp", "delete", "blob"})
_PROBE_TIMEOUT_S = 0.4


def not_measured(reason: str) -> dict[str, str]:
    return {"value": NOT_MEASURED, "reason": reason}


@dataclass
class ProbeLedger:
    """Counts connection attempts. ``external_requests`` counts non-loopback attempts only."""

    external_requests: int = 0
    loopback_probes: int = 0
    model_download_attempted: bool = False
    commands: list[list[str]] = field(default_factory=list)


def assert_readonly_argv(argv: list[str]) -> None:
    """Refuse any argv that would pull, create, or delete a model."""
    if any(part in _MUTATING_ARGV for part in argv[1:]):
        raise RuntimeError("model_download_or_mutation_refused")


def probe_port(host: str, port: int, ledger: ProbeLedger) -> bool:
    """Open a TCP connection only to loopback. Non-loopback hosts are counted and refused."""
    if host not in LOOPBACK_HOSTS:
        ledger.external_requests += 1
        raise RuntimeError("non_loopback_refused")
    ledger.loopback_probes += 1
    try:
        with socket.create_connection((host, port), timeout=_PROBE_TIMEOUT_S):
            return True
    except OSError:
        return False


def _run_readonly(argv: list[str], ledger: ProbeLedger) -> subprocess.CompletedProcess[str] | None:
    assert_readonly_argv(argv)
    ledger.commands.append(list(argv))
    try:
        return subprocess.run(  # noqa: S603 - fixed local binary and args, no shell
            argv,
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None


def gpu_inventory(ledger: ProbeLedger | None = None) -> dict[str, Any]:
    """Record GPU name, total VRAM and driver via ``nvidia-smi``, or ``no_gpu`` when it is absent."""
    book = ledger if ledger is not None else ProbeLedger()
    absent: dict[str, Any] = {
        "present": False,
        "reason": "no_gpu",
        "name": not_measured("no_gpu"),
        "vram_total_mib": not_measured("no_gpu"),
        "driver": not_measured("no_gpu"),
        "devices": [],
        "rtx_3060": False,
    }
    exe = shutil.which("nvidia-smi")
    if exe is None:
        return absent
    proc = _run_readonly(
        [exe, "--query-gpu=name,memory.total,driver_version", "--format=csv,noheader,nounits"],
        book,
    )
    if proc is None or proc.returncode != 0 or not proc.stdout.strip():
        absent["reason"] = "nvidia_smi_failed" if exe else "no_gpu"
        return absent
    devices: list[dict[str, Any]] = []
    for line in proc.stdout.splitlines():
        parts = [part.strip() for part in line.split(",")]
        if len(parts) < 3 or not parts[0]:
            continue
        try:
            vram: int | str = int(float(parts[1]))
        except ValueError:
            vram = NOT_MEASURED
        devices.append({"name": parts[0], "vram_total_mib": vram, "driver": parts[2]})
    if not devices:
        return absent
    first = devices[0]
    return {
        "present": True,
        "reason": None,
        "name": first["name"],
        "vram_total_mib": first["vram_total_mib"],
        "driver": first["driver"],
        "devices": devices,
        "rtx_3060": any("3060" in str(item["name"]) for item in devices),
    }


def _model_rows(provider: str, payload: Any) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    if not isinstance(payload, dict):
        return rows
    if provider == "ollama":
        raw = payload.get("models", [])
        if not isinstance(raw, list):
            return rows
        for item in raw:
            if not isinstance(item, dict) or not isinstance(item.get("name"), str):
                continue
            raw_details = item.get("details")
            details: dict[str, Any] = raw_details if isinstance(raw_details, dict) else {}
            digest = item.get("digest")
            quant = details.get("quantization_level")
            parameter_size = details.get("parameter_size")
            size = item.get("size")
            rows.append(
                {
                    "name": item["name"],
                    "digest": digest if isinstance(digest, str) else "not_exposed",
                    "quantization": quant if isinstance(quant, str) else "not_exposed",
                    "parameter_size": parameter_size if isinstance(parameter_size, str) else "not_exposed",
                    "size_bytes": size if isinstance(size, int) else "not_exposed",
                }
            )
        return rows
    raw = payload.get("data", [])
    if not isinstance(raw, list):
        return rows
    for item in raw:
        if isinstance(item, dict) and isinstance(item.get("id"), str):
            rows.append(
                {
                    "name": item["id"],
                    "digest": "not_exposed",
                    "quantization": "not_exposed",
                    "parameter_size": "not_exposed",
                    "size_bytes": "not_exposed",
                }
            )
    return rows


def list_provider(provider: str, ledger: ProbeLedger) -> dict[str, Any]:
    """GET the provider's allowlisted model list on loopback. Never pulls a model."""
    spec = PROVIDER_REGISTRY[provider]
    if spec.host not in LOOPBACK_HOSTS:
        ledger.external_requests += 1
        raise RuntimeError("non_loopback_refused")
    reachable = probe_port(spec.host, spec.port, ledger)
    base: dict[str, Any] = {"provider": provider, "host": spec.host, "port": spec.port, "reachable": reachable}
    if not reachable:
        return {**base, "models": [], "error_code": "unavailable"}
    try:
        payload, _nbytes = _request_json(spec, "GET", spec.models_path, None, 5.0, 1_048_576)
    except AIProviderError as exc:
        return {**base, "models": [], "error_code": exc.code}
    return {**base, "models": _model_rows(provider, payload), "error_code": None}


def ollama_cli_list(ledger: ProbeLedger) -> dict[str, Any]:
    """Run ``ollama list`` when the CLI exists. ``ollama pull`` is refused."""
    exe = shutil.which("ollama")
    if exe is None:
        return {"cli_present": False, "models": [], "exit_code": None, "reason": "ollama_cli_absent"}
    proc = _run_readonly([exe, "list"], ledger)
    if proc is None:
        return {"cli_present": True, "models": [], "exit_code": None, "reason": "ollama_cli_failed"}
    names: list[str] = []
    for line in proc.stdout.splitlines():
        cells = line.split()
        if not cells or cells[0] in {"NAME", "name"}:
            continue
        names.append(cells[0])
    reason = None if proc.returncode == 0 else "ollama_cli_failed"
    return {"cli_present": True, "models": names, "exit_code": proc.returncode, "reason": reason}


def _unique(names: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for name in names:
        if name not in seen:
            seen.add(name)
            out.append(name)
    return out


def discover() -> dict[str, Any]:
    """Inventory GPU and already-installed local models. Does not download anything."""
    ledger = ProbeLedger()
    gpu = gpu_inventory(ledger)
    cli = ollama_cli_list(ledger)
    providers = {
        "ollama": list_provider("ollama", ledger),
        "lmstudio": list_provider("lmstudio", ledger),
    }
    listed: list[str] = list(cli["models"])
    for provider in providers.values():
        listed.extend(str(row["name"]) for row in provider["models"] if isinstance(row, dict))
    listed = _unique(listed)
    qwen = [name for name in listed if "qwen" in name.lower()]
    deepseek = [name for name in listed if "deepseek" in name.lower()]
    reasons: list[str] = []
    if not gpu["present"]:
        reasons.append(str(gpu["reason"]))
    if not cli["cli_present"]:
        reasons.append("ollama_cli_absent")
    if not providers["ollama"]["reachable"]:
        reasons.append("ollama_server_absent")
    if not providers["lmstudio"]["reachable"]:
        reasons.append("lmstudio_server_absent")
    if not qwen or not deepseek:
        reasons.append("model_absent")
    live_possible = bool(gpu["present"] and qwen and deepseek)
    if live_possible:
        primary = "ready"
    elif "no_gpu" in reasons:
        primary = "no_gpu"
    elif "model_absent" in reasons:
        primary = "model_absent"
    else:
        primary = reasons[0] if reasons else "not_executed"
    return {
        "schema_version": DISCOVERY_SCHEMA,
        "finding_confirmed": False,
        "tools_enabled": False,
        "ai_classification_authority": False,
        "model_download_attempted": ledger.model_download_attempted,
        "external_requests": ledger.external_requests,
        "network_attempts": ledger.external_requests,
        "loopback_probes": ledger.loopback_probes,
        "commands": ledger.commands,
        "gpu": gpu,
        "ollama_cli": cli,
        "providers": providers,
        "installed_model_names": listed,
        "qwen_tags": qwen,
        "deepseek_tags": deepseek,
        "reasons": reasons,
        "primary_reason": primary,
        "live_measurement_possible": live_possible,
    }
