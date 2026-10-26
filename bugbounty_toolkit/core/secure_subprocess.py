"""Centralized policy gate for external tool subprocesses.

Every external binary invocation must prove an allowlisted executable, structured
argv (never shell=True), wall-clock timeout, output/file caps, and process-tree
cleanup. Invocations that would contact remote systems must also prove human
authorization, in-scope targeting, and remaining execution budget *before*
the process starts. Failure to prove policy rejects the run; there is no
fallback to an unapproved tool.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
import logging
import os
from pathlib import Path
import signal
import subprocess
import threading
import time
from typing import Callable, Mapping, Sequence

from ..utils.exceptions import ExternalToolError, ToolkitError

logger = logging.getLogger(__name__)

# Basenames only. PATH resolution must still yield this exact basename.
DEFAULT_ALLOWED_EXECUTABLES: frozenset[str] = frozenset(
    {
        "subfinder",
        "amass",
        "httpx",
        "nuclei",
        "paramspider",
        "arjun",
        "ffuf",
    }
)

# Stable machine-readable failure codes (also embedded in exception messages).
CODE_EXECUTABLE_NOT_ALLOWED = "policy_executable_not_allowed"
CODE_SHELL_FORBIDDEN = "policy_shell_forbidden"
CODE_ARGS_INVALID = "policy_args_invalid"
CODE_PATH_REJECTED = "policy_path_rejected"
CODE_SYMLINK_REJECTED = "policy_symlink_rejected"
CODE_MISSING_APPROVAL = "policy_missing_approval"
CODE_SCOPE_UNPROVEN = "policy_scope_unproven"
CODE_BUDGET_EXHAUSTED = "policy_budget_exhausted"
CODE_TOOL_NOT_FOUND = "tool_not_found"
CODE_TIMEOUT = "timeout"
CODE_OUTPUT_LIMIT = "output_limit"
CODE_CANCELLED = "cancelled"
CODE_PERMISSION_DENIED = "permission_denied"
CODE_NONZERO_EXIT = "nonzero_exit"

_FORBIDDEN_ARG_MARKERS = (";", "`", "|", "$(", "${", "\n", "\r", "&&", "||")
_DEFAULT_TIMEOUT = 300.0
_DEFAULT_MAX_OUTPUT = 10_000_000
_DEFAULT_MAX_FILE = 50_000_000
_KILL_GRACE_SECONDS = 5.0


@dataclass(frozen=True)
class SecureToolLimits:
    """Hard caps applied to a single external invocation."""

    timeout_seconds: float = _DEFAULT_TIMEOUT
    max_output_bytes: int = _DEFAULT_MAX_OUTPUT
    max_output_file_bytes: int = _DEFAULT_MAX_FILE
    max_memory_bytes: int | None = None
    max_cpu_seconds: int | None = None
    max_processes: int | None = None

    def __post_init__(self) -> None:
        if (
            isinstance(self.timeout_seconds, bool)
            or not isinstance(self.timeout_seconds, (int, float))
            or self.timeout_seconds <= 0
        ):
            raise ValueError("timeout_seconds must be a positive number.")
        for name in ("max_output_bytes", "max_output_file_bytes"):
            value = getattr(self, name)
            if type(value) is not int or value <= 0:
                raise ValueError(f"{name} must be a positive integer.")
        for name in ("max_memory_bytes", "max_cpu_seconds", "max_processes"):
            value = getattr(self, name)
            if value is not None and (type(value) is not int or value <= 0):
                raise ValueError(f"{name} must be a positive integer when set.")


@dataclass(frozen=True)
class SecureToolRequest:
    """Fully specified external invocation. Built only after policy checks pass."""

    executable_name: str
    argv: tuple[str, ...]
    output_path: Path
    limits: SecureToolLimits = field(default_factory=SecureToolLimits)
    cwd: Path | None = None
    env: Mapping[str, str] | None = None
    allowed_path_roots: tuple[Path, ...] = ()
    contact_external: bool = True
    authorization_attested: bool = False
    scope_attested: bool = False
    budget_attested: bool = False
    cancel_event: threading.Event | None = None
    allowed_executables: frozenset[str] = DEFAULT_ALLOWED_EXECUTABLES


@dataclass(frozen=True)
class SecureToolResult:
    """Outcome of a supervised external run (success or controlled failure)."""

    returncode: int
    status: str
    error_code: str | None
    duration_seconds: float
    bytes_written: int
    truncated: bool
    timed_out: bool
    cancelled: bool
    killed: bool
    output_path: Path
    argv_provenance: tuple[str, ...]
    executable_path: str


class PolicyRejected(ExternalToolError):
    """Raised before a process starts when policy cannot be proven."""

    def __init__(self, code: str, message: str) -> None:
        self.code = code
        super().__init__(f"[{code}] {message}")


class SecureSubprocessError(ExternalToolError):
    """Raised after a process was started and then stopped for a policy limit."""

    def __init__(self, code: str, message: str, result: SecureToolResult | None = None) -> None:
        self.code = code
        self.result = result
        super().__init__(f"[{code}] {message}")


def tool_exists(name: str) -> bool:
    """True when an allowlisted basename resolves on PATH."""
    if name not in DEFAULT_ALLOWED_EXECUTABLES and "/" in name:
        return False
    return _resolve_executable(name, DEFAULT_ALLOWED_EXECUTABLES) is not None


def _is_under_roots(path: Path, roots: tuple[Path, ...]) -> bool:
    if not roots:
        return True
    for root in roots:
        try:
            path.resolve(strict=False).relative_to(root.resolve(strict=False))
            return True
        except (ValueError, OSError):
            continue
    return False


def _resolve_executable(
    name: str,
    allowed: frozenset[str],
    *,
    argv0: str | None = None,
    allowed_path_roots: tuple[Path, ...] = (),
) -> Path | None:
    if not name or name != Path(name).name or name in {".", ".."}:
        return None
    if name not in allowed:
        return None
    import shutil

    if argv0:
        candidate = Path(argv0)
        try:
            if candidate.name == name and candidate.is_file():
                resolved_explicit = candidate.resolve(strict=False)
                if _is_under_roots(resolved_explicit, allowed_path_roots):
                    return resolved_explicit
        except OSError:
            pass

    found = shutil.which(name)
    if found is None:
        return None
    resolved = Path(found)
    if resolved.name != name:
        return None
    return resolved


def _looks_like_path(value: str) -> bool:
    if not value or value.startswith("-"):
        return False
    if "://" in value:
        return False
    if value.startswith("/") or value.startswith("./") or value.startswith("../"):
        return True
    return os.sep in value


def _validate_path_arg(value: str, roots: tuple[Path, ...]) -> None:
    candidate = Path(value)
    try:
        # Refuse symlink leaves for operator-supplied file paths.
        if candidate.exists() and candidate.is_symlink():
            raise PolicyRejected(CODE_SYMLINK_REJECTED, "Argument path must not be a symbolic link.")
        resolved = candidate.resolve(strict=False)
    except OSError as exc:
        raise PolicyRejected(CODE_PATH_REJECTED, "Argument path could not be resolved.") from exc
    if ".." in candidate.parts:
        raise PolicyRejected(CODE_PATH_REJECTED, "Argument path must not contain parent traversal.")
    if not roots:
        return
    for root in roots:
        try:
            resolved.relative_to(root.resolve(strict=False))
            return
        except ValueError:
            continue
    raise PolicyRejected(CODE_PATH_REJECTED, "Argument path is outside authorized directories.")


def _validate_argv_token(token: str) -> None:
    if not isinstance(token, str) or "\x00" in token:
        raise PolicyRejected(CODE_ARGS_INVALID, "Arguments must be non-null strings.")
    # Defense in depth: argv is never passed to a shell, but reject clear injection markers.
    # URL query separators such as & and = remain allowed for httpx/ffuf/arjun targets.
    if any(marker in token for marker in _FORBIDDEN_ARG_MARKERS):
        raise PolicyRejected(CODE_ARGS_INVALID, "Shell metacharacters are forbidden in tool arguments.")


def redact_argv(argv: Sequence[str]) -> tuple[str, ...]:
    """Return argv safe for logs/records: drop values that look like secrets."""
    redacted: list[str] = []
    sensitive_flags = {"-H", "--header", "-b", "--cookie", "--token", "--api-key"}
    skip_next = False
    for item in argv:
        if skip_next:
            redacted.append("<redacted>")
            skip_next = False
            continue
        lower = item.lower()
        if item in sensitive_flags:
            redacted.append(item)
            skip_next = True
            continue
        if (
            lower.startswith(("-h=", "--header=", "--cookie=", "--token=", "--api-key="))
            or "authorization:" in lower
            or lower.startswith("cookie:")
        ):
            key = item.split("=", 1)[0] if "=" in item else item.split(":", 1)[0]
            redacted.append(f"{key}=<redacted>")
            continue
        if len(item) > 200:
            redacted.append(item[:40] + "...<truncated>")
        else:
            redacted.append(item)
    return tuple(redacted)


def prove_policy(request: SecureToolRequest) -> Path:
    """Reject before exec when the invocation cannot prove policy. Returns resolved executable."""
    if request.executable_name not in request.allowed_executables:
        raise PolicyRejected(
            CODE_EXECUTABLE_NOT_ALLOWED,
            f"Executable {request.executable_name!r} is not in the allowlist.",
        )
    if not request.argv:
        raise PolicyRejected(CODE_ARGS_INVALID, "Command argv must not be empty.")
    if Path(request.argv[0]).name != request.executable_name and request.argv[0] != request.executable_name:
        # argv[0] must be the allowlisted name or its resolved path basename.
        raise PolicyRejected(CODE_ARGS_INVALID, "argv[0] must match the allowlisted executable name.")
    for token in request.argv:
        _validate_argv_token(token)
    if request.allowed_path_roots:
        for token in request.argv[1:]:
            if _looks_like_path(token):
                _validate_path_arg(token, request.allowed_path_roots)
        out = request.output_path
        _validate_path_arg(str(out), request.allowed_path_roots)

    if request.contact_external:
        if not request.authorization_attested:
            raise PolicyRejected(
                CODE_MISSING_APPROVAL,
                "External-contacting tools require attested human authorization.",
            )
        if not request.scope_attested:
            raise PolicyRejected(
                CODE_SCOPE_UNPROVEN,
                "External-contacting tools require attested in-scope targeting.",
            )
        if not request.budget_attested:
            raise PolicyRejected(
                CODE_BUDGET_EXHAUSTED,
                "External-contacting tools require an attested execution budget.",
            )

    resolved = _resolve_executable(
        request.executable_name,
        request.allowed_executables,
        argv0=request.argv[0],
        allowed_path_roots=request.allowed_path_roots,
    )
    if resolved is None:
        raise PolicyRejected(CODE_TOOL_NOT_FOUND, f"Required tool not found in PATH: {request.executable_name}")
    return resolved


def _preexec_resource_limits(limits: SecureToolLimits) -> Callable[[], None] | None:
    if os.name != "posix":
        return None

    def _apply() -> None:
        try:
            import resource
        except ImportError:
            return
        try:
            if limits.max_memory_bytes is not None:
                resource.setrlimit(resource.RLIMIT_AS, (limits.max_memory_bytes, limits.max_memory_bytes))
        except (ValueError, OSError):
            pass
        try:
            if limits.max_cpu_seconds is not None:
                resource.setrlimit(resource.RLIMIT_CPU, (limits.max_cpu_seconds, limits.max_cpu_seconds))
        except (ValueError, OSError):
            pass
        try:
            if limits.max_processes is not None and hasattr(resource, "RLIMIT_NPROC"):
                resource.setrlimit(resource.RLIMIT_NPROC, (limits.max_processes, limits.max_processes))
        except (ValueError, OSError):
            pass

    return _apply


def kill_process_tree(process: subprocess.Popen[bytes], *, grace_seconds: float = _KILL_GRACE_SECONDS) -> bool:
    """Terminate a process and its children. Returns True if a kill signal was used."""
    if process.poll() is not None:
        return False
    killed = False
    try:
        if os.name != "nt" and process.pid:
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except (ProcessLookupError, PermissionError, OSError):
                process.terminate()
        else:
            process.terminate()
    except ProcessLookupError:
        return False
    try:
        process.wait(timeout=grace_seconds)
        return killed
    except subprocess.TimeoutExpired:
        killed = True
        try:
            if os.name != "nt" and process.pid:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except (ProcessLookupError, PermissionError, OSError):
                    process.kill()
            else:
                process.kill()
        except ProcessLookupError:
            pass
        try:
            process.wait(timeout=grace_seconds)
        except subprocess.TimeoutExpired:
            pass
    return killed


def run_secure_subprocess(request: SecureToolRequest) -> SecureToolResult:
    """Execute an allowlisted tool under hard limits. Never uses shell=True."""
    started = time.monotonic()
    resolved = prove_policy(request)
    argv = list(request.argv)
    argv[0] = str(resolved)
    provenance = redact_argv(argv)
    output_path = request.output_path
    output_path.parent.mkdir(parents=True, exist_ok=True)

    env = dict(os.environ) if request.env is None else dict(request.env)
    for key in list(env):
        upper = key.upper()
        if any(part in upper for part in ("SECRET", "TOKEN", "PASSWORD", "API_KEY", "AUTHORIZATION")):
            env.pop(key, None)

    preexec = _preexec_resource_limits(request.limits)
    cwd = str(request.cwd) if request.cwd is not None else None
    creationflags = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0) if os.name == "nt" else 0
    start_new_session = os.name != "nt"

    bytes_written = 0
    truncated = False
    stop_reason: str | None = None
    lock = threading.Lock()

    logger.info(
        "secure_subprocess.start tool=%s timeout=%s max_output=%s at=%s",
        request.executable_name,
        request.limits.timeout_seconds,
        request.limits.max_output_bytes,
        datetime.now(timezone.utc).isoformat(),
    )

    try:
        process = subprocess.Popen(
            argv,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            stdin=subprocess.DEVNULL,
            env=env,
            shell=False,
            cwd=cwd,
            creationflags=creationflags,
            start_new_session=start_new_session,
            preexec_fn=preexec if start_new_session else None,
        )
    except PermissionError as exc:
        raise PolicyRejected(CODE_PERMISSION_DENIED, f"Permission denied executing {request.executable_name}.") from exc
    except OSError as exc:
        raise PolicyRejected(CODE_TOOL_NOT_FOUND, f"Failed to start {request.executable_name}: {exc}") from exc

    assert process.stdout is not None
    cap = min(request.limits.max_output_bytes, request.limits.max_output_file_bytes)

    def _reader() -> None:
        nonlocal bytes_written, truncated, stop_reason
        assert process.stdout is not None
        try:
            with output_path.open("wb") as handle:
                while True:
                    chunk = process.stdout.read(65536)
                    if not chunk:
                        return
                    with lock:
                        if stop_reason is not None:
                            return
                        remaining = cap - bytes_written
                        if remaining <= 0:
                            truncated = True
                            stop_reason = CODE_OUTPUT_LIMIT
                            return
                        if len(chunk) > remaining:
                            handle.write(chunk[:remaining])
                            bytes_written += remaining
                            truncated = True
                            stop_reason = CODE_OUTPUT_LIMIT
                            return
                        handle.write(chunk)
                        bytes_written += len(chunk)
        except Exception:
            with lock:
                if stop_reason is None:
                    stop_reason = CODE_OUTPUT_LIMIT

    reader = threading.Thread(target=_reader, name=f"bbtk-tool-{request.executable_name}", daemon=True)
    reader.start()

    timed_out = False
    cancelled = False
    killed = False
    deadline = started + float(request.limits.timeout_seconds)

    while reader.is_alive() or process.poll() is None:
        if request.cancel_event is not None and request.cancel_event.is_set():
            cancelled = True
            with lock:
                stop_reason = CODE_CANCELLED
            killed = kill_process_tree(process) or True
            break
        if time.monotonic() >= deadline:
            timed_out = True
            with lock:
                stop_reason = CODE_TIMEOUT
            killed = kill_process_tree(process) or True
            break
        with lock:
            hit_output_limit = stop_reason == CODE_OUTPUT_LIMIT
        if hit_output_limit:
            killed = kill_process_tree(process) or True
            break
        reader.join(timeout=0.1)
        if process.poll() is not None and not reader.is_alive():
            break

    reader.join(timeout=_KILL_GRACE_SECONDS)
    if process.poll() is None:
        killed = kill_process_tree(process) or killed
    try:
        if process.stdout is not None:
            process.stdout.close()
    except Exception:
        pass

    returncode = process.returncode if process.returncode is not None else (-9 if timed_out else -15)
    duration = max(0.0, time.monotonic() - started)
    with lock:
        final_bytes = bytes_written
        final_truncated = truncated
        final_stop = stop_reason

    if timed_out or final_stop == CODE_TIMEOUT:
        status = "timed_out"
        error_code: str | None = CODE_TIMEOUT
    elif cancelled or final_stop == CODE_CANCELLED:
        status = "cancelled"
        error_code = CODE_CANCELLED
    elif final_truncated or final_stop == CODE_OUTPUT_LIMIT:
        status = "output_limit"
        error_code = CODE_OUTPUT_LIMIT
    elif returncode != 0:
        status = "nonzero_exit"
        error_code = CODE_NONZERO_EXIT
    else:
        status = "completed"
        error_code = None

    result = SecureToolResult(
        returncode=int(returncode),
        status=status,
        error_code=error_code,
        duration_seconds=duration,
        bytes_written=final_bytes,
        truncated=final_truncated,
        timed_out=timed_out or status == "timed_out",
        cancelled=cancelled or status == "cancelled",
        killed=killed,
        output_path=output_path,
        argv_provenance=provenance,
        executable_path=str(resolved),
    )
    logger.info(
        "secure_subprocess.end tool=%s status=%s code=%s duration=%.3fs bytes=%s killed=%s",
        request.executable_name,
        result.status,
        result.error_code,
        result.duration_seconds,
        result.bytes_written,
        result.killed,
    )
    if error_code in {CODE_TIMEOUT, CODE_OUTPUT_LIMIT, CODE_CANCELLED}:
        raise SecureSubprocessError(error_code, f"{request.executable_name} stopped: {status}.", result)
    return result


def require_budget_available(budget: object | None) -> None:
    """Attest that an ExecutionBudget (if provided) still has capacity."""
    if budget is None:
        raise PolicyRejected(CODE_BUDGET_EXHAUSTED, "No execution budget was provided for an external tool.")
    cancel = getattr(budget, "cancel_event", None)
    if cancel is not None and cancel.is_set():
        raise PolicyRejected(CODE_BUDGET_EXHAUSTED, "Execution budget already cancelled.")
    check = getattr(budget, "remaining_seconds", None)
    if callable(check):
        try:
            remaining = check()
        except ToolkitError as exc:
            raise PolicyRejected(CODE_BUDGET_EXHAUSTED, str(exc)) from exc
        if remaining is not None and remaining <= 0:
            raise PolicyRejected(CODE_BUDGET_EXHAUSTED, "Execution time budget exhausted.")
