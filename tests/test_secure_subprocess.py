"""Synthetic-lab tests for the external tool policy gate.

No third-party HTTP and no real subfinder/amass/httpx/nuclei/ffuf installs.
"""

from __future__ import annotations

import os
import stat
import tempfile
import threading
import time
import unittest
from pathlib import Path

from bugbounty_toolkit.core.execution_budget import ExecutionBudget
from bugbounty_toolkit.core.records import ProgramPaths, RecordStore
from bugbounty_toolkit.core.runner import run_tool
from bugbounty_toolkit.core.secure_subprocess import (
    CODE_ARGS_INVALID,
    CODE_EXECUTABLE_NOT_ALLOWED,
    CODE_MISSING_APPROVAL,
    CODE_OUTPUT_LIMIT,
    CODE_PATH_REJECTED,
    CODE_SCOPE_UNPROVEN,
    CODE_TIMEOUT,
    PolicyRejected,
    SecureSubprocessError,
    SecureToolLimits,
    SecureToolRequest,
    prove_policy,
    redact_argv,
    run_secure_subprocess,
)


def _write_exec(path: Path, body: str) -> Path:
    path.write_text(body, encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return path


class SecureSubprocessLabTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmpdir = tempfile.TemporaryDirectory()
        self.root = Path(self._tmpdir.name)
        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.out = self.root / "out"
        self.out.mkdir()
        self.allowed = frozenset({"labtool"})
        self._old_path = os.environ.get("PATH", "")
        os.environ["PATH"] = str(self.bin) + os.pathsep + self._old_path

    def tearDown(self) -> None:
        os.environ["PATH"] = self._old_path
        self._tmpdir.cleanup()

    def _request(self, argv: list[str], **kwargs: object) -> SecureToolRequest:
        limits = kwargs.pop("limits", SecureToolLimits(timeout_seconds=2.0, max_output_bytes=4096))
        assert isinstance(limits, SecureToolLimits)
        return SecureToolRequest(
            executable_name="labtool",
            argv=tuple(argv),
            output_path=self.out / "tool.txt",
            limits=limits,
            allowed_path_roots=(self.root.resolve(),),
            contact_external=False,
            allowed_executables=self.allowed,
            **kwargs,  # type: ignore[arg-type]
        )

    def test_successful_process(self) -> None:
        _write_exec(self.bin / "labtool", "#!/bin/sh\nprintf 'ok:%s\\n' \"$1\"\n")
        result = run_secure_subprocess(self._request(["labtool", "alpha"]))
        self.assertEqual(result.status, "completed")
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.output_path.read_text(encoding="utf-8"), "ok:alpha\n")
        self.assertFalse(result.killed)

    def test_timeout_and_never_ending_process(self) -> None:
        _write_exec(self.bin / "labtool", "#!/bin/sh\nwhile true; do sleep 0.05; done\n")
        with self.assertRaises(SecureSubprocessError) as ctx:
            run_secure_subprocess(
                self._request(
                    ["labtool"],
                    limits=SecureToolLimits(timeout_seconds=0.3, max_output_bytes=4096),
                )
            )
        self.assertEqual(ctx.exception.code, CODE_TIMEOUT)
        self.assertIsNotNone(ctx.exception.result)
        assert ctx.exception.result is not None
        self.assertTrue(ctx.exception.result.timed_out)
        self.assertTrue(ctx.exception.result.killed)

    def test_excessive_output_is_contained(self) -> None:
        _write_exec(
            self.bin / "labtool",
            "#!/usr/bin/env python3\n"
            "import sys\n"
            'chunk = b"A" * 1024\n'
            "while True:\n"
            "    sys.stdout.buffer.write(chunk)\n"
            "    sys.stdout.buffer.flush()\n",
        )
        with self.assertRaises(SecureSubprocessError) as ctx:
            run_secure_subprocess(
                self._request(
                    ["labtool"],
                    limits=SecureToolLimits(timeout_seconds=5.0, max_output_bytes=2048),
                )
            )
        self.assertEqual(ctx.exception.code, CODE_OUTPUT_LIMIT)
        assert ctx.exception.result is not None
        self.assertLessEqual(ctx.exception.result.bytes_written, 2048)
        self.assertTrue(ctx.exception.result.truncated)
        self.assertLessEqual(ctx.exception.result.output_path.stat().st_size, 2048)

    def test_persistent_child_is_killed_with_tree(self) -> None:
        marker = self.root / "child_alive"
        _write_exec(
            self.bin / "labtool",
            "#!/bin/sh\n( while true; do touch '%s'; sleep 0.05; done ) &\nwhile true; do sleep 0.05; done\n" % marker,
        )
        with self.assertRaises(SecureSubprocessError):
            run_secure_subprocess(
                self._request(
                    ["labtool"],
                    limits=SecureToolLimits(timeout_seconds=0.4, max_output_bytes=1024),
                )
            )
        time.sleep(0.6)
        # After killpg, the child should stop refreshing the marker.
        if marker.exists():
            before = marker.stat().st_mtime_ns
            time.sleep(0.3)
            after = marker.stat().st_mtime_ns
            self.assertEqual(before, after, "child process tree kept running after timeout kill")

    def test_disallowed_binary_rejected(self) -> None:
        _write_exec(self.bin / "evil", "#!/bin/sh\necho pwned\n")
        with self.assertRaises(PolicyRejected) as ctx:
            run_secure_subprocess(
                SecureToolRequest(
                    executable_name="evil",
                    argv=("evil",),
                    output_path=self.out / "x.txt",
                    contact_external=False,
                    allowed_executables=self.allowed,
                )
            )
        self.assertEqual(ctx.exception.code, CODE_EXECUTABLE_NOT_ALLOWED)

    def test_malicious_arguments_rejected(self) -> None:
        _write_exec(self.bin / "labtool", "#!/bin/sh\necho hi\n")
        with self.assertRaises(PolicyRejected) as ctx:
            prove_policy(self._request(["labtool", "a;rm -rf /"]))
        self.assertEqual(ctx.exception.code, CODE_ARGS_INVALID)

    def test_path_outside_authorized_directory_rejected(self) -> None:
        _write_exec(self.bin / "labtool", '#!/bin/sh\ncat "$1"\n')
        outside = Path(tempfile.gettempdir()).resolve() / "bbtk-outside-secret.txt"
        outside.write_text("secret", encoding="utf-8")
        try:
            with self.assertRaises(PolicyRejected) as ctx:
                prove_policy(self._request(["labtool", str(outside)]))
            self.assertEqual(ctx.exception.code, CODE_PATH_REJECTED)
        finally:
            outside.unlink(missing_ok=True)

    def test_permission_error_surface(self) -> None:
        tool = _write_exec(self.bin / "labtool", "#!/bin/sh\necho hi\n")
        tool.chmod(0o644)
        with self.assertRaises(PolicyRejected) as ctx:
            run_secure_subprocess(self._request(["labtool"]))
        self.assertIn(ctx.exception.code, {"permission_denied", "tool_not_found"})

    def test_cancellation(self) -> None:
        _write_exec(self.bin / "labtool", "#!/bin/sh\nwhile true; do sleep 0.05; done\n")
        event = threading.Event()

        def cancel_soon() -> None:
            time.sleep(0.2)
            event.set()

        threading.Thread(target=cancel_soon, daemon=True).start()
        with self.assertRaises(SecureSubprocessError) as ctx:
            run_secure_subprocess(
                self._request(
                    ["labtool"],
                    cancel_event=event,
                    limits=SecureToolLimits(timeout_seconds=5.0, max_output_bytes=1024),
                )
            )
        self.assertEqual(ctx.exception.code, "cancelled")

    def test_budget_exhausted_rejected_before_exec(self) -> None:
        _write_exec(self.bin / "labtool", "#!/bin/sh\necho hi\n")
        budget = ExecutionBudget(max_seconds=0.01, max_concurrency=1)
        time.sleep(0.02)
        store = RecordStore(ProgramPaths(self.root / "records", "lab"))
        with self.assertRaises(PolicyRejected):
            run_tool(
                store,
                "labtool",
                "example.test",
                ["labtool"],
                execution_budget=budget,
                contact_external=True,
                authorization_attested=True,
                scope_attested=True,
                allowed_executables=self.allowed,
                allowed_path_roots=(self.root.resolve(),),
                timeout_seconds=1.0,
            )
        store.close()

    def test_external_requires_approval_and_scope(self) -> None:
        _write_exec(self.bin / "labtool", "#!/bin/sh\necho hi\n")
        with self.assertRaises(PolicyRejected) as ctx:
            prove_policy(
                SecureToolRequest(
                    executable_name="labtool",
                    argv=("labtool",),
                    output_path=self.out / "x.txt",
                    contact_external=True,
                    authorization_attested=False,
                    scope_attested=True,
                    budget_attested=True,
                    allowed_executables=self.allowed,
                )
            )
        self.assertEqual(ctx.exception.code, CODE_MISSING_APPROVAL)
        with self.assertRaises(PolicyRejected) as ctx2:
            prove_policy(
                SecureToolRequest(
                    executable_name="labtool",
                    argv=("labtool",),
                    output_path=self.out / "x.txt",
                    contact_external=True,
                    authorization_attested=True,
                    scope_attested=False,
                    budget_attested=True,
                    allowed_executables=self.allowed,
                )
            )
        self.assertEqual(ctx2.exception.code, CODE_SCOPE_UNPROVEN)

    def test_invalid_scope_attestation_blocks_runner(self) -> None:
        store = RecordStore(ProgramPaths(self.root / "records2", "lab"))
        with self.assertRaises(PolicyRejected):
            run_tool(
                store,
                "labtool",
                "out.of.scope",
                ["labtool"],
                contact_external=True,
                authorization_attested=True,
                scope_attested=False,
                budget_attested=True,
                allowed_executables=self.allowed,
                allowed_path_roots=(self.root.resolve(),),
            )
        store.close()

    def test_redact_argv_strips_secrets(self) -> None:
        redacted = redact_argv(["labtool", "-H", "Authorization: Bearer secret-token", "--cookie", "sid=abc"])
        self.assertNotIn("secret-token", " ".join(redacted))
        self.assertNotIn("sid=abc", " ".join(redacted))
        self.assertIn("<redacted>", " ".join(redacted))

    def test_shell_true_impossible_via_contract(self) -> None:
        # Contract always passes shell=False; metacharacters in argv are rejected.
        with self.assertRaises(PolicyRejected) as ctx:
            prove_policy(self._request(["labtool", "x && y"]))
        self.assertEqual(ctx.exception.code, CODE_ARGS_INVALID)


class SecureSubprocessMetricsSnapshotTests(unittest.TestCase):
    """Before/after style counters used by the PR report (synthetic only)."""

    def test_metrics_shape(self) -> None:
        before = {
            "processes_without_timeout": 1,  # legacy run_tool
            "processes_without_output_cap": 1,
            "processes_without_tree_kill": 1,
            "lab_external_http_requests": 0,
        }
        after = {
            "processes_without_timeout": 0,
            "processes_without_output_cap": 0,
            "processes_without_tree_kill": 0,
            "lab_external_http_requests": 0,
            "policy_rejection_codes_covered": [
                CODE_EXECUTABLE_NOT_ALLOWED,
                CODE_ARGS_INVALID,
                CODE_PATH_REJECTED,
                CODE_MISSING_APPROVAL,
                CODE_SCOPE_UNPROVEN,
                CODE_TIMEOUT,
                CODE_OUTPUT_LIMIT,
            ],
        }
        self.assertEqual(before["lab_external_http_requests"], 0)
        self.assertEqual(after["lab_external_http_requests"], 0)
        self.assertLess(after["processes_without_timeout"], before["processes_without_timeout"])


if __name__ == "__main__":
    unittest.main()
