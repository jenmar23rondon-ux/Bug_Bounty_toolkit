from pathlib import Path
import subprocess
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]


class RuffCoverageTests(unittest.TestCase):
    def test_package_and_test_python_files_are_in_ruff_discovery(self):
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "ruff",
                "check",
                "--show-files",
                "bugbounty_toolkit",
                "tests",
                "scripts",
                "skills",
            ],
            cwd=ROOT,
            check=True,
            capture_output=True,
            text=True,
        )
        discovered = {Path(line).resolve() for line in result.stdout.splitlines() if line.strip()}
        expected = {
            path.resolve() for root in (ROOT / "bugbounty_toolkit", ROOT / "tests") for path in root.rglob("*.py")
        }
        missing = sorted(path.relative_to(ROOT).as_posix() for path in expected - discovered)
        self.assertFalse(missing, f"Python files omitted from Ruff discovery: {missing}")


if __name__ == "__main__":
    unittest.main()
