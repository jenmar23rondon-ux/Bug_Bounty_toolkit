"""Static and host-safe checks for the optional Docker offline lab environment.

These tests need no Docker daemon. They pin the hardening contract of the
Dockerfile, run profile, Compose file and lock files, and exercise the
diagnostics and verification helpers. Network activity is loopback only.
"""

from __future__ import annotations

import importlib.util
import io
import json
import os
import re
import shutil
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from types import ModuleType
from unittest.mock import patch

import yaml

from bugbounty_toolkit import diagnostics

ROOT = Path(__file__).resolve().parents[1]
LAB = ROOT / "docker" / "offline-lab"
SCRIPTS = ROOT / "scripts" / "offline_lab"


def load_module(name: str, path: Path) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


class DockerfileContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.dockerfile = read(LAB / "Dockerfile")

    def test_base_image_is_official_and_pinned_by_digest(self) -> None:
        match = re.search(r"^ARG PYTHON_IMAGE=(\S+)$", self.dockerfile, re.MULTILINE)
        self.assertIsNotNone(match)
        image = match.group(1) if match else ""
        self.assertRegex(image, r"^python:3\.\d+-slim-[a-z]+@sha256:[0-9a-f]{64}$")
        for line in re.findall(r"^FROM\s+(\S+)", self.dockerfile, re.MULTILINE):
            self.assertIn(line, {"${PYTHON_IMAGE}", "build", "lab"}, f"unpinned FROM {line}")

    def test_runtime_targets_end_as_unprivileged_user(self) -> None:
        for target in ("lab", "lab-playwright"):
            section = self.dockerfile.split(f" AS {target}\n", 1)[1]
            next_stage = section.find("\nFROM ")
            section = section if next_stage < 0 else section[:next_stage]
            users = re.findall(r"^USER\s+(\S+)", section, re.MULTILINE)
            self.assertTrue(users, f"{target} sets no USER")
            self.assertEqual(users[-1], "10001:10001", f"{target} must finish as the lab user")

    def test_ffuf_download_is_checksum_verified(self) -> None:
        for arch in ("AMD64", "ARM64"):
            self.assertRegex(self.dockerfile, rf"ARG FFUF_SHA256_{arch}=[0-9a-f]{{64}}\n")
        self.assertIn("ffuf checksum mismatch", self.dockerfile)
        self.assertIn('filter="data"', self.dockerfile)

    def test_python_dependencies_are_hash_locked_wheels(self) -> None:
        installs = re.findall(r"pip install ([^\n\\]+)", self.dockerfile)
        self.assertTrue(installs)
        for command in installs:
            self.assertIn("--require-hashes", command)
            self.assertIn("--only-binary=:all:", command)
            self.assertIn("--no-deps", command)
        for lock in ("requirements-core.lock", "requirements-playwright.lock"):
            text = read(LAB / lock)
            pins = re.findall(r"^([a-z0-9_.-]+)==([^\s\\]+) \\$", text, re.MULTILINE)
            self.assertTrue(pins, lock)
            for name, _version in pins:
                block = text.split(f"{name}==", 1)[1].split("# via", 1)[0]
                self.assertRegex(block, r"--hash=sha256:[0-9a-f]{64}", f"{name} has no hash in {lock}")
        self.assertIn("playwright==", read(LAB / "requirements-playwright.lock"))
        self.assertNotIn("playwright", read(LAB / "requirements-core.lock"))

    def test_failure_masking_is_scoped_to_the_setuid_cleanup(self) -> None:
        # `a && b || true` would hide a failed install; only the find cleanup may be tolerated.
        for line in self.dockerfile.splitlines():
            if "|| true" in line:
                self.assertTrue(line.strip().startswith("&& { find"), f"unscoped failure masking: {line.strip()}")

    def test_runtime_disables_package_index_and_marks_offline_lab(self) -> None:
        self.assertIn("PIP_NO_INDEX=1", self.dockerfile)
        self.assertIn("BBTK_OFFLINE_LAB=1", self.dockerfile)
        self.assertIn("PLAYWRIGHT_BROWSERS_PATH=/opt/ms-playwright", self.dockerfile)

    def test_dockerignore_is_an_allowlist_without_private_paths(self) -> None:
        lines = [line.strip() for line in read(ROOT / ".dockerignore").splitlines() if line.strip()]
        rules = [line for line in lines if not line.startswith("#")]
        self.assertEqual(rules[0], "*")
        allowed = {line[1:].rstrip("/") for line in rules if line.startswith("!")}
        for private in (".git", ".venv", "registros", "logs", "reports", "inputs", ".env", "dist", ".test-tmp"):
            self.assertNotIn(private, allowed)
        for pattern in ("**/.env", "**/*.pem", "**/*.key", "**/.netrc", "**/.test-tmp/"):
            self.assertIn(pattern, rules)


class RunProfileContractTests(unittest.TestCase):
    FORBIDDEN = (
        re.compile(r"--privileged"),
        re.compile(r"docker\.sock"),
        re.compile(r"(?<![\w-])-v\s+\S*:|--volume\b|--mount\b"),
        re.compile(r"--env-file"),
        re.compile(r"--network[ =](host|bridge)"),
        re.compile(r"--cap-add"),
        re.compile(r"seccomp=unconfined|apparmor=unconfined"),
    )

    def test_common_profile_contains_every_required_control(self) -> None:
        common = read(SCRIPTS / "common.sh")
        for flag in (
            "--network none",
            "--read-only",
            "--cap-drop ALL",
            "--security-opt no-new-privileges",
            '--memory "$memory" --memory-swap "$memory"',
            '--cpus "$BBTK_LAB_CPUS"',
            '--pids-limit "$BBTK_LAB_PIDS"',
            "--pull never",
            '--user "${BBTK_LAB_UID}:${BBTK_LAB_UID}"',
            "nosuid,nodev",
        ):
            self.assertIn(flag, common)

    def test_scripts_never_grant_host_access(self) -> None:
        for script in sorted(SCRIPTS.glob("*.sh")):
            text = "\n".join(line for line in read(script).splitlines() if not line.lstrip().startswith("#"))
            for pattern in self.FORBIDDEN:
                self.assertIsNone(pattern.search(text), f"{script.name} matches {pattern.pattern}")

    def test_run_step_never_builds_or_pulls(self) -> None:
        for name in ("verify.sh", "run.sh"):
            text = read(SCRIPTS / name)
            self.assertNotRegex(text, r"\$DOCKER\"? (build|pull)\b", name)
            self.assertIn("bbtk_lab_require_image", text)
            self.assertIn("timeout", text)

    def test_compose_matches_the_hardened_profile(self) -> None:
        compose = yaml.safe_load(read(LAB / "compose.yaml"))
        services = compose["services"]
        self.assertEqual(set(services), {"lab", "lab-playwright"})
        self.assertEqual(services["lab-playwright"]["profiles"], ["playwright"])
        for name, service in services.items():
            self.assertNotIn("build", service, name)
            self.assertNotIn("volumes", service, name)
            self.assertNotIn("privileged", service, name)
            self.assertNotIn("env_file", service, name)
            self.assertEqual(service["network_mode"], "none", name)
            self.assertIs(service["read_only"], True, name)
            self.assertEqual(service["user"], "10001:10001", name)
            self.assertEqual(service["cap_drop"], ["ALL"], name)
            self.assertIn("no-new-privileges:true", service["security_opt"], name)
            self.assertEqual(service["pull_policy"], "never", name)
            self.assertEqual(service["mem_limit"], service["memswap_limit"], name)
            self.assertGreater(service["pids_limit"], 0, name)
            for mount in service["tmpfs"]:
                self.assertIn("nosuid", mount)
                self.assertIn("uid=10001", mount)


class PlaywrightDiagnosticsTests(unittest.TestCase):
    def test_browser_root_resolution_per_platform(self) -> None:
        root = diagnostics.playwright_browsers_root
        self.assertEqual(root({"PLAYWRIGHT_BROWSERS_PATH": "/opt/ms-playwright"}), Path("/opt/ms-playwright"))
        self.assertIsNone(root({"PLAYWRIGHT_BROWSERS_PATH": "0"}))
        self.assertEqual(root({"HOME": "/h"}, "linux"), Path("/h/.cache/ms-playwright"))
        self.assertEqual(root({"HOME": "/h", "XDG_CACHE_HOME": "/c"}, "linux"), Path("/c/ms-playwright"))
        self.assertEqual(root({"HOME": "/h"}, "darwin"), Path("/h/Library/Caches/ms-playwright"))
        self.assertEqual(root({"LOCALAPPDATA": "C:/L"}, "win32"), Path("C:/L/ms-playwright"))
        self.assertIsNone(root({}, "win32"))

    def test_browser_check_states_never_install(self) -> None:
        check = diagnostics.playwright_browser_check
        self.assertEqual(check(False, Path("/x"))[0], "warning")
        self.assertEqual(check(True, None)[0], "warning")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            status, detail = check(True, root)
            self.assertEqual(status, "warning")
            self.assertIn("never downloads browsers automatically", detail)
            self.assertEqual(check(True, root / "missing")[0], "warning")
            (root / "chromium_headless_shell-1248").mkdir()
            (root / "firefox-1").mkdir()
            status, detail = check(True, root)
            self.assertEqual(status, "ok")
            self.assertIn("chromium_headless_shell-1248", detail)
            self.assertNotIn("firefox", detail)

    def test_doctor_reports_browser_and_offline_lab_without_network(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            with (
                patch.dict(os.environ, {"BBTK_OFFLINE_LAB": "1", "PLAYWRIGHT_BROWSERS_PATH": directory}),
                patch("socket.create_connection", side_effect=AssertionError("doctor must stay offline")),
                patch("subprocess.run", side_effect=AssertionError("doctor must not install anything")),
            ):
                result = diagnostics.diagnose(Path(directory) / "records")
        names = {check["name"]: check for check in result["checks"]}  # type: ignore[union-attr]
        self.assertIn("tool:playwright-browser", names)
        self.assertEqual(names["environment:offline-lab"]["status"], "ok")
        self.assertEqual(result["network_requests_sent"], 0)

    def test_offline_lab_marker_absent_outside_the_image(self) -> None:
        env = {key: value for key, value in os.environ.items() if key != "BBTK_OFFLINE_LAB"}
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, env, clear=True):
            result = diagnostics.diagnose(Path(directory) / "records")
        names = {check["name"] for check in result["checks"]}  # type: ignore[union-attr]
        self.assertNotIn("environment:offline-lab", names)


class ConnectAuditHookTests(unittest.TestCase):
    def test_hook_records_only_non_loopback_targets(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "audit.jsonl"
            with patch.dict(os.environ, {"BBTK_CONNECT_AUDIT": str(target)}):
                with patch("sys.addaudithook") as install:
                    module = load_module("bbtk_connect_audit", SCRIPTS / "connect_audit" / "sitecustomize.py")
                install.assert_called_once()
            hook = module._hook
            hook("socket.connect", (object(), ("127.0.0.1", 80)))
            hook("socket.connect", (object(), ("::1", 80, 0, 0)))
            hook("socket.connect", (object(), "/run/unix.sock"))
            hook("socket.getaddrinfo", ("localhost", 80))
            hook("open", ("/etc/passwd",))
            hook("socket.connect", (object(), ("192.0.2.1", 443)))
            hook("socket.getaddrinfo", ("example.invalid", 80))
            records = [json.loads(line) for line in target.read_text(encoding="utf-8").splitlines()]
        self.assertEqual([item["host"] for item in records], ["192.0.2.1", "example.invalid"])
        self.assertFalse(module._is_local(None))
        self.assertTrue(module._is_local(""))

    def test_hook_is_inert_without_target(self) -> None:
        env = {key: value for key, value in os.environ.items() if key != "BBTK_CONNECT_AUDIT"}
        with patch.dict(os.environ, env, clear=True), patch("sys.addaudithook") as install:
            module = load_module("bbtk_connect_audit_inert", SCRIPTS / "connect_audit" / "sitecustomize.py")
        install.assert_not_called()
        module._hook("socket.connect", (object(), ("192.0.2.1", 443)))  # no target: must not raise


class IsolationChecksHostSafeTests(unittest.TestCase):
    """Run the loopback-only checks on the host; network/namespace checks need the container."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.checks = load_module("bbtk_isolation_checks", SCRIPTS / "isolation_checks.py")
        cls.checks.REPO = ROOT

    def test_bbtk_scope_control_refuses_out_of_scope_target(self) -> None:
        with patch.dict(os.environ, {"PYTHONPATH": str(ROOT)}):
            outcome = self.checks.check_scope_blocks_out_of_scope()
        self.assertEqual(outcome["status"], "pass", outcome["detail"])

    def test_canary_secret_is_delivered_but_never_persisted(self) -> None:
        with patch.dict(os.environ, {"PYTHONPATH": str(ROOT)}):
            outcome = self.checks.check_secret_not_leaked()
        self.assertEqual(outcome["status"], "pass", outcome["detail"])
        self.assertIn("leaks=none", str(outcome["detail"]))

    def test_loopback_synthetic_service_is_reachable(self) -> None:
        self.assertEqual(self.checks.check_loopback_allowed()["status"], "pass")

    @unittest.skipUnless(shutil.which("ffuf"), "ffuf binary not installed")
    def test_ffuf_finds_exactly_the_synthetic_paths(self) -> None:
        outcome = self.checks.check_ffuf_against_synthetic()
        self.assertEqual(outcome["status"], "pass", outcome["detail"])

    def test_unreadable_private_path_counts_as_absent(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            self.assertFalse(self.checks._accessible(Path(directory) / "missing"))
            self.assertTrue(self.checks._accessible(Path(directory)))
            with patch.object(Path, "exists", side_effect=PermissionError):
                self.assertFalse(self.checks._accessible(Path(directory)))

    def test_seccomp_absence_is_unverified_not_passed(self) -> None:
        with patch.object(self.checks, "proc_status_field", return_value="0"):
            self.assertEqual(self.checks.check_seccomp()["status"], "unverified")
        with patch.object(self.checks, "proc_status_field", return_value=None):
            self.assertEqual(self.checks.check_seccomp()["status"], "unverified")
        with patch.object(self.checks, "proc_status_field", return_value="2"):
            self.assertEqual(self.checks.check_seccomp()["status"], "pass")

    def test_require_seccomp_turns_unverified_into_failure(self) -> None:
        unverified = {"name": "seccomp-filter", "status": "unverified", "detail": "Seccomp=0"}
        with patch.dict(self.checks.CHECKS, {"seccomp-filter": lambda: unverified}, clear=True):
            with redirect_stdout(io.StringIO()) as relaxed:
                self.assertEqual(self.checks.main([]), 0)
            with redirect_stdout(io.StringIO()):
                self.assertEqual(self.checks.main(["--require-seccomp"]), 1)
        self.assertEqual(json.loads(relaxed.getvalue())["summary"]["unverified"], ["seccomp-filter"])

    def test_a_raising_check_is_reported_as_failure(self) -> None:
        def boom() -> dict[str, object]:
            raise RuntimeError("synthetic")

        with patch.dict(self.checks.CHECKS, {"boom": boom}, clear=True), redirect_stdout(io.StringIO()) as out:
            self.assertEqual(self.checks.main([]), 1)
        self.assertIn("RuntimeError", out.getvalue())


class SuiteRunnerExclusionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.runner = load_module("bbtk_offline_suite", SCRIPTS / "run_suite.py")

    def test_exclusions_require_reason_and_exact_prefix(self) -> None:
        exclusions = {"pkg.Case": ("needs tool", True), "pkg.Other.test_x": ("inactive", False)}
        with patch.dict(self.runner.EXCLUSIONS, exclusions, clear=True):
            self.assertEqual(self.runner.excluded_reason("pkg.Case.test_a"), "needs tool")
            self.assertEqual(self.runner.excluded_reason("pkg.Case"), "needs tool")
            self.assertIsNone(self.runner.excluded_reason("pkg.CaseTwo.test_a"))
            self.assertIsNone(self.runner.excluded_reason("pkg.Other.test_x"))
        for reason, _applies in self.runner.EXCLUSIONS.values():
            self.assertGreater(len(reason), 20)

    def test_excluded_tests_are_reported_as_skips_not_dropped(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            (Path(directory) / "test_sample.py").write_text(
                "import unittest\n"
                "class Keep(unittest.TestCase):\n    def test_ok(self):\n        pass\n"
                "class Drop(unittest.TestCase):\n    def test_bad(self):\n        raise AssertionError\n",
                encoding="utf-8",
            )
            exclusions = {"test_sample.Drop": ("synthetic exclusion for this test", True)}
            with patch.dict(self.runner.EXCLUSIONS, exclusions, clear=True):
                suite, skipped = self.runner.build_suite(directory)
            outcome = unittest.TextTestRunner(stream=io.StringIO()).run(suite)
            sys.modules.pop("test_sample", None)
        self.assertEqual(list(skipped), ["test_sample.Drop.test_bad"])
        self.assertEqual(outcome.testsRun, 2)
        self.assertEqual(len(outcome.skipped), 1)
        self.assertTrue(outcome.wasSuccessful())


if __name__ == "__main__":
    unittest.main()
