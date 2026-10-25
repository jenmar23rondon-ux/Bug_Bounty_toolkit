from __future__ import annotations

from contextlib import redirect_stdout
import json
from io import StringIO
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from bugbounty_toolkit import cli
from bugbounty_toolkit.analysis.ollama_review import OllamaUnavailableError
from bugbounty_toolkit.analysis.skill_router import SKILL_REGISTRY, SKILLS_ROOT, route_hypotheses, route_hypotheses_file


class SkillRouterTests(unittest.TestCase):
    def setUp(self) -> None:
        test_tmp = Path(__file__).resolve().parents[1] / ".test-tmp"
        test_tmp.mkdir(exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(dir=test_tmp)
        self.root = Path(self.temp.name)
        self.input_path = self.root / "hypotheses.json"
        self.hypothesis = {
            "category": "xss",
            "summary": "A reflected marker was observed in a response.",
            "evidence_for": [{"record_id": "a" * 24, "why": "The response fingerprint changed."}],
            "evidence_against": [],
            "missing_controls": ["Browser execution was not checked."],
            "confidence": "medium",
            "next_check": {
                "kind": "offline",
                "suggestion": "Inspect the response context.",
                "why": "Reflection alone is not execution.",
            },
            "status": "hypothesis",
        }

    def tearDown(self) -> None:
        self.temp.cleanup()

    def _write(self, hypotheses: list[dict[str, object]]) -> None:
        self.input_path.write_text(
            json.dumps(
                {
                    "type": "ai-hypotheses",
                    "notice": "Segunda opinión, nunca confirmación.",
                    "groups": [
                        {"group_id": f"{index:024x}", "status": "reviewed", "hypothesis": hypothesis}
                        for index, hypothesis in enumerate(hypotheses, start=1)
                    ],
                }
            ),
            encoding="utf-8",
        )

    def test_registry_matches_installed_skills_and_has_typed_fields(self) -> None:
        self.assertEqual(len(SKILL_REGISTRY), 12)
        for skill in SKILL_REGISTRY.values():
            self.assertTrue((SKILLS_ROOT / skill.name / "SKILL.md").is_file())
            self.assertTrue(skill.when)
            self.assertTrue(skill.requires)
            self.assertTrue(skill.produces)
            self.assertTrue(skill.commands)

    def test_known_category_uses_deterministic_route_without_ollama(self) -> None:
        result = route_hypotheses({}, [("a" * 24, self.hypothesis)], "sample", 100)
        self.assertEqual(result.keys(), {"selected", "missing_inputs", "plan"})
        self.assertEqual(result["selected"][0]["skill"], "bugbounty-xss")
        self.assertIn("--dry-run", result["plan"][0]["command"])

    def test_ollama_unavailable_falls_back_to_executor_rules(self) -> None:
        ambiguous = dict(self.hypothesis, category="unknown")
        with patch(
            "bugbounty_toolkit.analysis.skill_router.chat_with_ollama",
            side_effect=OllamaUnavailableError("offline"),
        ):
            result = route_hypotheses({}, [("a" * 24, ambiguous)], "sample", 100)
        self.assertEqual(result["selected"][0]["skill"], "bugbounty-executor")
        self.assertTrue(any("Ollama unavailable" in item for item in result["missing_inputs"]))

    def test_unknown_skill_from_ollama_is_rejected_and_falls_back(self) -> None:
        ambiguous = dict(self.hypothesis, category="info_disclosure")
        response = json.dumps(
            {"selected": [{"skill": "bugbounty-made-up", "reason": "bad", "confidence": "high"}], "missing_inputs": []}
        )
        with patch("bugbounty_toolkit.analysis.skill_router.chat_with_ollama", return_value=response) as chat:
            result = route_hypotheses({}, [("a" * 24, ambiguous)], "sample", 100)
        self.assertEqual(chat.call_count, 2)
        self.assertEqual(result["selected"][0]["skill"], "bugbounty-executor")
        self.assertTrue(any("unknown skill" in item for item in result["missing_inputs"]))

    def test_plan_over_budget_fails_before_returning_commands(self) -> None:
        cors = dict(self.hypothesis, category="cors")
        redirect = dict(self.hypothesis, category="open_redirect")
        with self.assertRaisesRegex(ValueError, "exceeding --max-tests"):
            route_hypotheses({}, [("a" * 24, cors), ("b" * 24, redirect)], "sample", 5)

    def test_route_cli_dry_run_does_not_write_files_or_execute_plan(self) -> None:
        ambiguous = dict(self.hypothesis, category="unknown")
        self._write([ambiguous])
        old_root = cli.RECORDS_ROOT
        cli.RECORDS_ROOT = self.root / "records"
        response = json.dumps({"selected": [], "missing_inputs": []})
        try:
            args = cli.build_parser().parse_args(
                ["ai", "route", "sample", "--input", str(self.input_path), "--dry-run"]
            )
            output = StringIO()
            with (
                patch("bugbounty_toolkit.analysis.skill_router.chat_with_ollama", return_value=response),
                redirect_stdout(output),
            ):
                cli.cmd_ai_route(args)
            self.assertFalse((self.root / "records").exists())
            rendered = output.getvalue()
            result = json.loads(rendered[rendered.index("{\n") :])
            self.assertEqual(set(result), {"selected", "missing_inputs", "plan"})
            self.assertEqual(result["selected"][0]["skill"], "bugbounty-executor")
            self.assertIn("No skill command", rendered)
        finally:
            cli.RECORDS_ROOT = old_root

    def test_route_file_rejects_non_hypothesis_input(self) -> None:
        self.input_path.write_text(json.dumps({"groups": []}), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "output from `bbtk ai hypotheses`"):
            route_hypotheses_file(self.input_path, "sample", 10)


if __name__ == "__main__":
    unittest.main()
