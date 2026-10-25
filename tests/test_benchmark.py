from __future__ import annotations

import json
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from bugbounty_toolkit import cli
from bugbounty_toolkit.analysis.benchmark import (
    _load_dataset,
    _minimized_packet,
    render_benchmark_markdown,
    run_idor_benchmark,
    write_benchmark_reports,
)
from bugbounty_toolkit.analysis.ollama_review import OllamaUnavailableError


DATASET = Path(__file__).resolve().parents[1] / "labs" / "idor_lab" / "benchmark-v1.json"
DATASET_V2 = Path(__file__).resolve().parents[1] / "labs" / "idor_lab" / "benchmark-v2.json"


class BenchmarkTests(unittest.TestCase):
    def test_deterministic_holdout_reports_transparent_metrics(self) -> None:
        result = run_idor_benchmark(DATASET)
        self.assertEqual(result["case_count"], 8)
        self.assertEqual(result["network_requests_sent"], 0)
        metrics = result["methods"]["deterministic"]["metrics"]
        self.assertEqual(metrics["true_positive"], 2)
        self.assertEqual(metrics["false_positive"], 0)
        self.assertEqual(metrics["true_negative"], 6)
        self.assertEqual(metrics["false_negative"], 0)
        self.assertEqual(metrics["f1"], 1.0)
        self.assertEqual(result["methods"]["ollama"]["status"], "not_requested")
        self.assertEqual(result["methods"]["combined"]["status"], "deterministic_fallback")
        self.assertIn("not a measured human investigation duration", result["time_metric_note"])

    def test_holdout_is_isolated_from_development_split(self) -> None:
        _, selected = _load_dataset(DATASET, "holdout")
        self.assertEqual(len(selected), 8)
        self.assertNotIn("development-denial-example", {item["id"] for item in selected})
        _, development = _load_dataset(DATASET, "development")
        self.assertEqual([item["id"] for item in development], ["development-denial-example"])

    def test_v2_holdout_reports_labeled_metrics_and_abstention_coverage(self) -> None:
        result = run_idor_benchmark(DATASET_V2)
        self.assertEqual(result["dataset_schema_version"], "2.0")
        self.assertEqual(result["case_count"], 12)
        self.assertEqual(result["network_requests_sent"], 0)
        self.assertEqual(
            result["dataset_audit"]["truth_counts"],
            {"vulnerable": 3, "safe": 5, "insufficient": 4},
        )
        self.assertEqual(result["dataset_audit"]["unique_case_evidence_inputs"], 12)
        self.assertEqual(result["dataset_audit"]["cross_split_shared_minimized_packets"], 7)
        metrics = result["methods"]["deterministic"]["metrics"]
        self.assertEqual(metrics["true_positive"], 3)
        self.assertEqual(metrics["false_positive"], 0)
        self.assertEqual(metrics["true_negative"], 5)
        self.assertEqual(metrics["false_negative"], 0)
        self.assertEqual(metrics["insufficient_truth_count"], 4)
        self.assertEqual(metrics["inconclusive_count"], 5)
        self.assertEqual(metrics["labeled_inconclusive_count"], 1)
        self.assertEqual(metrics["decision_coverage"], 0.875)
        self.assertEqual(metrics["overall_decision_coverage"], 0.583333)
        self.assertEqual(metrics["truth_by_decision"]["safe"]["inconclusive"], 1)

    def test_v2_splits_and_scenario_families_are_independent(self) -> None:
        _, holdout = _load_dataset(DATASET_V2, "holdout")
        _, development = _load_dataset(DATASET_V2, "development")
        self.assertEqual(len(holdout), 12)
        self.assertEqual(len(development), 12)
        self.assertFalse(
            {item["scenario_family"] for item in holdout} & {item["scenario_family"] for item in development}
        )
        for split in (holdout, development):
            canonical = {
                json.dumps({"case": item["case"], "evidence": item["evidence"]}, sort_keys=True) for item in split
            }
            self.assertEqual(len(canonical), len(split))

    def test_v2_rejects_duplicate_inputs_and_cross_split_family_reuse(self) -> None:
        data = json.loads(DATASET_V2.read_text(encoding="utf-8"))
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "dataset.json"
            duplicated = json.loads(json.dumps(data))
            duplicate = json.loads(json.dumps(duplicated["cases"][0]))
            duplicate["id"] = "distinct-id-same-input"
            duplicate["scenario_family"] = "development_distinct_family"
            duplicated["cases"].append(duplicate)
            path.write_text(json.dumps(duplicated), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "independent case/evidence"):
                _load_dataset(path, "all")

            reused = json.loads(json.dumps(data))
            reused["cases"][-1]["scenario_family"] = reused["cases"][0]["scenario_family"]
            path.write_text(json.dumps(reused), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "cannot appear in both"):
                _load_dataset(path, "all")

    def test_v2_markdown_discloses_insufficient_truth_and_coverage(self) -> None:
        result = run_idor_benchmark(DATASET_V2)
        markdown = render_benchmark_markdown(result)
        self.assertIn("Insufficient truth", markdown)
        self.assertIn("Labeled coverage", markdown)
        self.assertIn("Overall coverage", markdown)
        self.assertIn("Ground truth | Candidate | Not observed | Inconclusive", markdown)
        self.assertIn("excluded from binary rates", markdown)
        self.assertIn("unique minimized Ollama packets", markdown)
        self.assertIn("shared across development/holdout", markdown)

    def test_v2_ollama_receives_neither_labels_nor_scenario_metadata(self) -> None:
        def respond(messages, *_args):
            prompt = messages[1]["content"]
            self.assertNotIn("invoice_private_content", prompt)
            self.assertNotIn("another user's invoice", prompt)
            self.assertNotIn("The two controls pass", prompt)
            return json.dumps({"decision": "inconclusive", "reason": "Synthetic predicates only."})

        with patch("bugbounty_toolkit.analysis.benchmark.chat_with_ollama", side_effect=respond) as chat:
            result = run_idor_benchmark(DATASET_V2, split="holdout", with_ollama=True)
        self.assertEqual(chat.call_count, 12)
        self.assertEqual(result["methods"]["ollama"]["status"], "complete")

    def test_minimized_packet_contains_only_boolean_predicates(self) -> None:
        _, cases = _load_dataset(DATASET, "holdout")
        packet = _minimized_packet(cases[0]["case"], cases[0]["evidence"])
        rendered = json.dumps(packet)
        self.assertNotIn("owner-marker", rendered)
        self.assertNotIn("owner-1", rendered)
        self.assertNotIn("status_code", rendered)
        self.assertIn('"owner_private_match": true', rendered)

    def test_dry_run_does_not_call_ollama_or_write_files(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "result.json"
            with patch("bugbounty_toolkit.analysis.benchmark.chat_with_ollama") as chat:
                result = run_idor_benchmark(DATASET, with_ollama=True, dry_run=True)
                self.assertFalse(output.exists())
                chat.assert_not_called()
        self.assertTrue(result["dry_run"])
        self.assertEqual(result["ollama_calls"], 0)

    def test_ollama_is_second_opinion_and_combined_never_promotes_insufficient(self) -> None:
        def respond(messages, *_args):
            text = messages[1]["content"]
            self.assertNotIn("owner-marker", text)
            self.assertNotIn("owner-1", text)
            return json.dumps({"decision": "candidate", "reason": "Model opinion only."})

        with patch("bugbounty_toolkit.analysis.benchmark.chat_with_ollama", side_effect=respond):
            result = run_idor_benchmark(DATASET, with_ollama=True, split="development")
        self.assertEqual(result["methods"]["ollama"]["status"], "complete")
        self.assertEqual(result["methods"]["ollama"]["predictions"][0]["decision"], "candidate")
        self.assertEqual(result["methods"]["combined"]["predictions"][0]["decision"], "inconclusive")
        self.assertTrue(result["second_opinion_only"])

    def test_ollama_unavailable_falls_back_without_failing_benchmark(self) -> None:
        with patch(
            "bugbounty_toolkit.analysis.benchmark.chat_with_ollama",
            side_effect=OllamaUnavailableError("offline"),
        ):
            result = run_idor_benchmark(DATASET, with_ollama=True)
        self.assertEqual(result["methods"]["ollama"]["status"], "unavailable")
        self.assertEqual(result["methods"]["ollama"]["metrics"], None)
        self.assertEqual(result["methods"]["combined"]["status"], "deterministic_fallback")
        self.assertEqual(result["methods"]["combined"]["metrics"], result["methods"]["deterministic"]["metrics"])

    def test_invalid_model_json_retries_once_then_marks_inconclusive(self) -> None:
        with patch(
            "bugbounty_toolkit.analysis.benchmark.chat_with_ollama",
            side_effect=["plain text", "still not json"],
        ) as chat:
            result = run_idor_benchmark(DATASET, with_ollama=True, split="development")
        chat.assert_has_calls(chat.call_args_list)
        self.assertEqual(chat.call_count, 2)
        self.assertEqual(result["methods"]["ollama"]["predictions"][0]["status"], "unparsed")
        self.assertEqual(result["methods"]["combined"]["predictions"][0]["decision"], "not_observed")

    def test_malformed_dataset_and_duplicate_ids_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "dataset.json"
            path.write_text("{", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "UTF-8 JSON"):
                _load_dataset(path, "holdout")
            data = json.loads(DATASET.read_text(encoding="utf-8"))
            data["cases"].append(data["cases"][0])
            path.write_text(json.dumps(data), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "unique"):
                _load_dataset(path, "holdout")

    def test_reports_are_json_and_markdown_and_do_not_overwrite_by_default(self) -> None:
        result = run_idor_benchmark(DATASET)
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "idor.json"
            json_path, markdown_path = write_benchmark_reports(result, output)
            self.assertEqual(json.loads(json_path.read_text(encoding="utf-8"))["case_count"], 8)
            markdown = markdown_path.read_text(encoding="utf-8")
            self.assertIn("FPR", markdown)
            self.assertIn("nunca confirmación", markdown)
            with self.assertRaises(FileExistsError):
                write_benchmark_reports(result, output)
            write_benchmark_reports(result, output, force=True)
            with self.assertRaisesRegex(ValueError, "end in .json"):
                write_benchmark_reports(result, Path(directory) / "output.txt")

    def test_dry_run_markdown_has_notice(self) -> None:
        result = run_idor_benchmark(DATASET, dry_run=True)
        markdown = render_benchmark_markdown(result)
        self.assertIn("segunda opinión", markdown.lower())

    def test_cli_dry_run_validates_dataset_without_writing(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output_path = Path(directory) / "benchmark.json"
            args = cli.build_parser().parse_args(
                ["ai", "benchmark", "--dataset", str(DATASET), "--output", str(output_path), "--dry-run"]
            )
            output = StringIO()
            with redirect_stdout(output):
                args.func(args)
            self.assertIn("No Ollama call", output.getvalue())
            self.assertFalse(output_path.exists())
            self.assertFalse(output_path.with_suffix(".md").exists())

    def test_cli_writes_paired_reports(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output_path = Path(directory) / "benchmark.json"
            args = cli.build_parser().parse_args(
                ["ai", "benchmark", "--dataset", str(DATASET), "--output", str(output_path)]
            )
            output = StringIO()
            with redirect_stdout(output):
                args.func(args)
            self.assertTrue(output_path.is_file())
            self.assertTrue(output_path.with_suffix(".md").is_file())
            self.assertIn("Segunda opinión", output.getvalue())

    def test_cli_runs_v2_all_splits_and_writes_metrics(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output_path = Path(directory) / "idor-v2.json"
            args = cli.build_parser().parse_args(
                [
                    "ai",
                    "benchmark",
                    "--dataset",
                    str(DATASET_V2),
                    "--split",
                    "all",
                    "--output",
                    str(output_path),
                ]
            )
            with redirect_stdout(StringIO()):
                args.func(args)
            result = json.loads(output_path.read_text(encoding="utf-8"))
            self.assertEqual(result["case_count"], 24)
            self.assertEqual(result["dataset_schema_version"], "2.0")
            self.assertEqual(result["methods"]["deterministic"]["metrics"]["insufficient_truth_count"], 8)


if __name__ == "__main__":
    unittest.main()
