"""Program-scoped external tool runner backed by the secure subprocess gate."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
import threading
from typing import Sequence

from .execution_budget import ExecutionBudget
from .records import RecordStore
from .secure_subprocess import (
    DEFAULT_ALLOWED_EXECUTABLES,
    CODE_NONZERO_EXIT,
    PolicyRejected,
    SecureSubprocessError,
    SecureToolLimits,
    SecureToolRequest,
    require_budget_available,
    run_secure_subprocess,
    tool_exists,
)
from ..utils.exceptions import ExternalToolError

__all__ = ["tool_exists", "run_tool", "DEFAULT_ALLOWED_EXECUTABLES"]


def run_tool(
    store: RecordStore,
    command_name: str,
    target: str | None,
    command: list[str] | Sequence[str],
    *,
    timeout_seconds: float | None = None,
    max_output_bytes: int | None = None,
    execution_budget: ExecutionBudget | None = None,
    cancel_event: threading.Event | None = None,
    contact_external: bool = True,
    authorization_attested: bool = False,
    scope_attested: bool = False,
    budget_attested: bool = False,
    allowed_executables: frozenset[str] | None = None,
    allowed_path_roots: tuple[Path, ...] | None = None,
) -> Path:
    """Run an allowlisted external tool with timeout, output caps, and process-tree cleanup.

    Callers that contact remote systems must pass authorization_attested,
    scope_attested, and either budget_attested or a live execution_budget.
    When policy cannot be proven the invocation is rejected before exec.
    """
    argv = [str(part) for part in command]
    if not argv:
        raise PolicyRejected("policy_args_invalid", "Command argv must not be empty.")
    executable_name = Path(argv[0]).name

    if contact_external and not budget_attested:
        require_budget_available(execution_budget)
        budget_attested = True
    if contact_external and execution_budget is not None and cancel_event is None:
        cancel_event = execution_budget.cancel_event
        remaining = execution_budget.remaining_seconds()
        if remaining is not None:
            timeout_seconds = remaining if timeout_seconds is None else min(float(timeout_seconds), remaining)

    default_limits = SecureToolLimits()
    limits = SecureToolLimits(
        timeout_seconds=float(timeout_seconds) if timeout_seconds is not None else default_limits.timeout_seconds,
        max_output_bytes=int(max_output_bytes) if max_output_bytes is not None else default_limits.max_output_bytes,
    )

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    output_path = store.paths.raw_dir / f"{timestamp}-{command_name}.txt"
    roots = allowed_path_roots if allowed_path_roots is not None else (store.paths.program_dir.resolve(),)

    request = SecureToolRequest(
        executable_name=executable_name,
        argv=tuple(argv),
        output_path=output_path,
        limits=limits,
        allowed_path_roots=roots,
        contact_external=contact_external,
        authorization_attested=authorization_attested,
        scope_attested=scope_attested,
        budget_attested=budget_attested,
        cancel_event=cancel_event,
        allowed_executables=allowed_executables or DEFAULT_ALLOWED_EXECUTABLES,
    )

    try:
        result = run_secure_subprocess(request)
    except PolicyRejected:
        store.add_run(command_name, target, list(argv), 126, None)
        raise
    except SecureSubprocessError as exc:
        code = {"timeout": 124, "output_limit": 125, "cancelled": 130}.get(exc.code, 1)
        path = exc.result.output_path if exc.result is not None else output_path
        recorded = list(exc.result.argv_provenance) if exc.result is not None else list(argv)
        store.add_run(command_name, target, recorded, code, path)
        raise

    store.add_run(command_name, target, list(result.argv_provenance), result.returncode, result.output_path)
    if result.returncode != 0:
        raise ExternalToolError(
            f"[{CODE_NONZERO_EXIT}] {command_name} exited with code {result.returncode}. See {result.output_path}"
        )
    return result.output_path
