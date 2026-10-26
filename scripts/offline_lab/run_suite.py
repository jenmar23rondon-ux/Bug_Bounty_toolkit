"""Run the bbtk unit suite inside the minimal offline lab image.

The core lab image deliberately ships only what the selected labs need. A few
existing tests require optional tooling that image omits on purpose, or write
into tracked source files (refused by the read-only filesystem). Those tests
are reported as skipped WITH their reason, never silently dropped. They still
run in the normal venv/CI suite, which remains the regression gate.
"""

from __future__ import annotations

import importlib.util
import sys
import unittest
from collections.abc import Iterator

# test id prefix -> (reason, condition under which the exclusion applies)
EXCLUSIONS: dict[str, tuple[str, bool]] = {
    "test_csrf_audit.CsrfAuditTests": (
        "needs beautifulsoup4 (optional 'csrf' extra, intentionally not in the minimal lab image)",
        importlib.util.find_spec("bs4") is None,
    ),
    "test_ruff_coverage.RuffCoverageTests.test_package_and_test_python_files_are_in_ruff_discovery": (
        "needs ruff (dev tool, intentionally not in the lab image)",
        importlib.util.find_spec("ruff") is None,
    ),
    "test_object_ranking_eval.RankingCorpusTests.test_regeneration_is_byte_identical": (
        "rewrites the tracked frozen corpus in place; refused by the read-only filesystem (pre-existing test design)",
        True,
    ),
    "test_secure_subprocess.SecureSubprocessLabTests.test_successful_process": (
        "spawns a synthetic local helper under tmpfs; offline lab image is not the process-exec gate (covered by smoke-test)",
        True,
    ),
    "test_secure_subprocess.SecureSubprocessLabTests.test_timeout_and_never_ending_process": (
        "spawns a synthetic local helper under tmpfs; offline lab image is not the process-exec gate (covered by smoke-test)",
        True,
    ),
    "test_secure_subprocess.SecureSubprocessLabTests.test_excessive_output_is_contained": (
        "spawns a synthetic local helper under tmpfs; offline lab image is not the process-exec gate (covered by smoke-test)",
        True,
    ),
    "test_secure_subprocess.SecureSubprocessLabTests.test_persistent_child_is_killed_with_tree": (
        "spawns a synthetic local helper under tmpfs; offline lab image is not the process-exec gate (covered by smoke-test)",
        True,
    ),
    "test_secure_subprocess.SecureSubprocessLabTests.test_cancellation": (
        "spawns a synthetic local helper under tmpfs; offline lab image is not the process-exec gate (covered by smoke-test)",
        True,
    ),
    "test_secure_subprocess.SecureSubprocessLabTests.test_permission_error_surface": (
        "spawns a synthetic local helper under tmpfs; offline lab image is not the process-exec gate (covered by smoke-test)",
        True,
    ),
    "test_secure_subprocess.SecureSubprocessLabTests.test_budget_exhausted_rejected_before_exec": (
        "resolves a synthetic helper under tmpfs; offline lab image is not the process-exec gate (covered by smoke-test)",
        True,
    ),
    "test_core_utilities.CoreUtilityTests.test_external_runner_records_success_and_failure_without_shell": (
        "runs a synthetic fixture binary under tmpfs via the secure gate; covered by smoke-test",
        True,
    ),
}


def flatten(suite: unittest.TestSuite) -> Iterator[unittest.TestCase]:
    for item in suite:
        if isinstance(item, unittest.TestSuite):
            yield from flatten(item)
        else:
            yield item


def excluded_reason(test_id: str) -> str | None:
    for prefix, (reason, applies) in EXCLUSIONS.items():
        if applies and (test_id == prefix or test_id.startswith(prefix + ".")):
            return reason
    return None


def build_suite(start: str = "tests") -> tuple[unittest.TestSuite, dict[str, str]]:
    discovered = unittest.defaultTestLoader.discover(start)
    suite = unittest.TestSuite()
    skipped: dict[str, str] = {}
    for test in flatten(discovered):
        reason = excluded_reason(test.id())
        if reason is None:
            suite.addTest(test)
            continue
        skipped[test.id()] = reason
        method = getattr(test, test._testMethodName)
        setattr(test, test._testMethodName, unittest.skip(f"offline-lab exclusion: {reason}")(method))
        suite.addTest(test)
    return suite, skipped


def main() -> int:
    suite, skipped = build_suite()
    for test_id, reason in sorted(skipped.items()):
        print(f"[offline-lab exclusion] {test_id}: {reason}", file=sys.stderr)
    outcome = unittest.TextTestRunner(verbosity=1).run(suite)
    print(
        f"@@BBTK-SUITE ran={outcome.testsRun} failures={len(outcome.failures)} errors={len(outcome.errors)} "
        f"skipped={len(outcome.skipped)} offline_lab_exclusions={len(skipped)}"
    )
    return 0 if outcome.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())
