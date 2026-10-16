import importlib.util
from pathlib import Path
import re
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import yaml

from bugbounty_toolkit.core.request_builder import parse_raw_http_request


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("bbtk_install_skills", ROOT / "scripts" / "install_skills.py")
installer = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(installer)


class SkillFamilyTests(unittest.TestCase):
    def test_explicit_captured_origin_preserves_http_without_sending(self):
        raw = "GET /private/resource?id=own-test-id HTTP/1.1\r\nHost: localhost:3000\r\n\r\n"
        with patch("socket.create_connection", side_effect=AssertionError("prepare only")):
            request = parse_raw_http_request(raw, "http://localhost:3000")
            self.assertEqual(request.prepared_url(), "http://localhost:3000/private/resource?id=own-test-id")

    def test_each_skill_is_discoverable_and_relative_links_resolve(self):
        for name in installer.SKILL_NAMES:
            folder = ROOT / "skills" / name
            content = (folder / "SKILL.md").read_text(encoding="utf-8")
            front = yaml.safe_load(content.split("---", 2)[1])
            self.assertEqual(front["name"], name)
            self.assertIsInstance(front["description"], str)
            metadata = yaml.safe_load((folder / "agents" / "openai.yaml").read_text(encoding="utf-8"))
            self.assertIn("$" + name, metadata["interface"]["default_prompt"])
            self.assertTrue(metadata["policy"]["allow_implicit_invocation"])
            for document in folder.rglob("*.md"):
                for link in re.findall(r"\]\(([^)]+)\)", document.read_text(encoding="utf-8")):
                    if "://" not in link and not link.startswith("#"):
                        self.assertTrue((document.parent / link.split("#")[0]).is_file(), f"Broken link in {document}: {link}")

    def test_preview_writes_nothing_and_full_install_preserves_siblings(self):
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "skills"
            with patch("socket.create_connection", side_effect=AssertionError("offline install")), patch("subprocess.run") as process:
                preview = installer.install_skills(ROOT / "skills", destination)
                self.assertFalse(destination.exists())
                self.assertFalse(preview["executed"])
                self.assertEqual(preview["network_requests_sent"], 0)
                installer.install_skills(ROOT / "skills", destination, execute=True)
                process.assert_not_called()
            unrelated = destination / "other-skill.txt"
            unrelated.write_text("keep this", encoding="utf-8")
            for name in installer.SKILL_NAMES:
                self.assertEqual((destination / name / "SKILL.md").read_bytes(), (ROOT / "skills" / name / "SKILL.md").read_bytes())
            self.assertEqual(installer.install_skills(ROOT / "skills", destination, execute=True)["files_changed"], 0)
            self.assertEqual(unrelated.read_text(), "keep this")
            # The shared adapter must still work outside its repository location.
            spec = importlib.util.spec_from_file_location("installed_runner", destination / "bugbounty-executor" / "scripts" / "run_plan.py")
            runner = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(runner)
            with patch.object(runner.subprocess, "run", return_value=SimpleNamespace(returncode=0)) as run:
                self.assertEqual(runner.run_plan({"program": "lab", "action": "request", "raw_request": "registros/lab/control.http"}, ROOT), 0)
            run.assert_called_once()
            self.assertIn("--dry-run", run.call_args.args[0])

    def test_conflict_preflight_does_not_partially_install_and_update_is_explicit(self):
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "skills"
            last = destination / installer.SKILL_NAMES[-1]
            last.mkdir(parents=True)
            existing = last / "SKILL.md"
            existing.write_text("user customization", encoding="utf-8")
            custom = last / "custom.txt"
            custom.write_text("keep custom", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "--update"):
                installer.install_skills(ROOT / "skills", destination, execute=True)
            self.assertFalse((destination / "bugbounty-executor").exists())
            self.assertEqual(existing.read_text(), "user customization")
            installer.install_skills(ROOT / "skills", destination, execute=True, update=True)
            self.assertEqual(existing.read_bytes(), (ROOT / "skills" / installer.SKILL_NAMES[-1] / "SKILL.md").read_bytes())
            self.assertEqual(custom.read_text(), "keep custom")

    def test_overlap_and_parent_file_rejected_before_writes(self):
        with self.assertRaisesRegex(ValueError, "overlap"):
            installer.install_skills(ROOT / "skills", ROOT / "skills" / "nested", execute=True)
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "skills"
            destination.mkdir()
            (destination / installer.SKILL_NAMES[-1]).write_text("blocked", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "parent"):
                installer.install_skills(ROOT / "skills", destination, execute=True)
            self.assertFalse((destination / "bugbounty-executor").exists())

    def test_linked_destination_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "real"
            target.mkdir()
            link = root / "linked"
            try:
                link.symlink_to(target, target_is_directory=True)
            except OSError:
                self.skipTest("symlink creation unavailable")
            with self.assertRaisesRegex(ValueError, "symlinks"):
                installer.install_skills(ROOT / "skills", link / "skills", execute=True)
            self.assertEqual(list(target.iterdir()), [])
