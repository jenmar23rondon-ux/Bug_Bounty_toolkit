"""RTX 3060 local-LLM harness tests. No GPU, no model download, loopback inventory only."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from typing import Any
from unittest.mock import patch

from bugbounty_toolkit import __version__
from bugbounty_toolkit.analysis.ai_providers import GenerationLimits
from labs.local_llm_quality_eval import corpus, discovery, harness, metadata
from labs.local_llm_quality_eval import run as cli

SCHEMA_PATH = (
    Path(__file__).resolve().parents[1] / "labs/local_llm_quality_eval/schemas/rtx3060-run-metadata.v1.schema.json"
)


def _quality(
    recall: float,
    fpr: float,
    *,
    abstention: float = 0.0,
    confirmations: int = 0,
    ci: list[float] | None = None,
) -> dict[str, Any]:
    return {
        "accuracy": 0.5,
        "recall": recall,
        "false_positive_rate": fpr,
        "abstention_rate": abstention,
        "automatic_confirmations": confirmations,
        "accuracy_ci95": ci,
    }


class DiscoveryTests(unittest.TestCase):
    def test_absent_gpu_and_models_are_not_measured_and_offline(self) -> None:
        with (
            patch("labs.local_llm_quality_eval.discovery.shutil.which", return_value=None),
            patch.object(discovery, "probe_port", return_value=False) as probe,
        ):
            report = discovery.discover()
        self.assertFalse(report["gpu"]["present"])
        self.assertEqual(report["gpu"]["name"]["value"], "NOT_MEASURED")
        self.assertEqual(report["gpu"]["name"]["reason"], "no_gpu")
        self.assertEqual(report["primary_reason"], "no_gpu")
        self.assertIn("model_absent", report["reasons"])
        self.assertEqual(report["qwen_tags"], [])
        self.assertEqual(report["deepseek_tags"], [])
        self.assertFalse(report["live_measurement_possible"])
        self.assertFalse(report["model_download_attempted"])
        self.assertEqual(report["external_requests"], 0)
        self.assertEqual(report["network_attempts"], 0)
        self.assertFalse(report["finding_confirmed"])
        self.assertFalse(report["tools_enabled"])
        self.assertFalse(report["ai_classification_authority"])
        self.assertEqual(report["commands"], [])
        hosts = [call.args[0] for call in probe.call_args_list]
        self.assertTrue(hosts)
        self.assertTrue(all(host == "127.0.0.1" for host in hosts))

    def test_nvidia_smi_output_is_parsed_without_downloading(self) -> None:
        def which(name: str) -> str | None:
            return "/usr/bin/" + name if name in {"nvidia-smi", "ollama"} else None

        def run(argv: list[str], **_kwargs: Any) -> Any:
            self.assertNotIn("pull", argv)
            discovery.assert_readonly_argv(argv)
            if argv[0].endswith("nvidia-smi"):
                stdout = "NVIDIA GeForce RTX 3060, 12288, 550.90\n"
                code = 0
            else:
                stdout = "NAME ID SIZE MODIFIED\nqwen2.5:7b-instruct-q4_K_M abc 4GB today\n"
                code = 0
            return subprocess_result(stdout, code)

        with (
            patch("labs.local_llm_quality_eval.discovery.shutil.which", side_effect=which),
            patch("labs.local_llm_quality_eval.discovery.subprocess.run", side_effect=run),
            patch.object(discovery, "probe_port", return_value=False),
        ):
            report = discovery.discover()
        self.assertTrue(report["gpu"]["present"])
        self.assertEqual(report["gpu"]["name"], "NVIDIA GeForce RTX 3060")
        self.assertEqual(report["gpu"]["vram_total_mib"], 12288)
        self.assertEqual(report["gpu"]["driver"], "550.90")
        self.assertTrue(report["gpu"]["rtx_3060"])
        self.assertEqual(report["ollama_cli"]["models"], ["qwen2.5:7b-instruct-q4_K_M"])
        self.assertIn("model_absent", report["reasons"])
        self.assertNotIn("no_gpu", report["reasons"])
        self.assertFalse(report["model_download_attempted"])
        self.assertTrue(all("pull" not in " ".join(cmd) for cmd in report["commands"]))

    def test_non_loopback_probe_does_not_connect(self) -> None:
        ledger = discovery.ProbeLedger()

        def boom(*_args: Any, **_kwargs: Any) -> None:
            raise AssertionError("non-loopback connect attempted")

        with patch("labs.local_llm_quality_eval.discovery.socket.create_connection", side_effect=boom):
            with self.assertRaisesRegex(RuntimeError, "non_loopback_refused"):
                discovery.probe_port("198.51.100.9", 80, ledger)
        self.assertEqual(ledger.external_requests, 1)
        self.assertEqual(ledger.loopback_probes, 0)

    def test_mutating_argv_is_refused(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "model_download_or_mutation_refused"):
            discovery.assert_readonly_argv(["ollama", "pull", "qwen2.5:7b"])

    def test_closed_loopback_port_is_not_an_external_request(self) -> None:
        ledger = discovery.ProbeLedger()
        with patch(
            "labs.local_llm_quality_eval.discovery.socket.create_connection", side_effect=ConnectionRefusedError
        ):
            self.assertFalse(discovery.probe_port("127.0.0.1", 11434, ledger))
        self.assertEqual(ledger.external_requests, 0)
        self.assertEqual(ledger.loopback_probes, 1)


def subprocess_result(stdout: str, code: int) -> Any:
    class _Proc:
        def __init__(self) -> None:
            self.stdout = stdout
            self.stderr = ""
            self.returncode = code

    return _Proc()


class MetadataTests(unittest.TestCase):
    def test_not_measured_report_never_presents_mocks_as_live_scores(self) -> None:
        with (
            patch("labs.local_llm_quality_eval.discovery.shutil.which", return_value=None),
            patch.object(discovery, "probe_port", return_value=False),
        ):
            report = metadata.build_not_measured_report(temperature=0.0, seed=None)
        self.assertEqual(report["mode"], "not_measured")
        self.assertEqual(report["measurement_status"], "NOT_MEASURED")
        self.assertEqual(report["primary_reason"], "no_gpu")
        self.assertEqual(report["version"], "0.2.2")
        self.assertEqual(__version__, "0.2.2")
        self.assertFalse(report["finding_confirmed"])
        self.assertFalse(report["ai_classification_authority"])
        self.assertFalse(report["tools_enabled"])
        self.assertFalse(report["tool_calling_enabled"])
        self.assertFalse(report["model_output_executed"])
        self.assertFalse(report["evidence_ledger_modified"])
        self.assertFalse(report["final_labels_modified"])
        self.assertEqual(report["classification_primary"], "deterministic")
        self.assertTrue(report["deterministic_remains_primary"])
        self.assertFalse(report["dual_review_recommended_for_classification"])
        self.assertFalse(report["dual_review_may_confirm"])
        self.assertFalse(report["model_download_attempted"])
        self.assertEqual(report["external_requests"], 0)
        self.assertEqual(report["network_attempts"], 0)
        self.assertEqual(report["secret_leaks"], 0)
        self.assertTrue(report["corpus"]["verified"])
        self.assertFalse(report["corpus"]["labels_modified"])
        self.assertEqual(corpus.verify(), [])
        for key, block in report["matrix"].items():
            self.assertIn(key, "ABCDE")
            self.assertFalse(block["real_model"])
            for metric in metadata.LIVE_METRICS:
                self.assertEqual(block["live"][metric]["value"], "NOT_MEASURED", metric)
                self.assertEqual(block["live"][metric]["reason"], "no_gpu")
        frozen = report["frozen_historical_reference"]
        self.assertIn("NOT Qwen or DeepSeek", frozen["notice"])
        self.assertEqual(frozen["configs"]["A"]["kind"], "deterministic_no_model")
        self.assertEqual(frozen["configs"]["B"]["kind"], "SIMULATED_not_a_real_model")
        self.assertFalse(frozen["configs"]["B"]["real_model"])
        historical = json.loads(metadata.MOCK_FINAL.read_text(encoding="utf-8"))
        self.assertEqual(frozen["configs"]["A"]["accuracy"], historical["configs"]["A"]["quality"]["accuracy"])
        repro = report["reproducibility"]
        required = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))["required"]
        self.assertTrue(set(required) <= set(repro))
        self.assertEqual(repro["schema_version"], metadata.METADATA_SCHEMA)
        self.assertEqual(repro["model_digest"]["B"]["value"], "NOT_MEASURED")
        self.assertEqual(repro["seed"]["applied"], False)
        self.assertEqual(repro["seed"]["value"], "NOT_MEASURED")
        self.assertEqual(repro["temperature"]["applied"], False)
        self.assertEqual(repro["temperature"]["value"], "NOT_MEASURED")
        self.assertFalse(repro["packet_hash"]["final"]["labels_included"])
        self.assertEqual(repro["packet_hash"]["final"]["secret_leaks_in_packets"], 0)
        self.assertGreater(repro["packet_hash"]["final"]["count"], 0)
        self.assertTrue(repro["prompt_schema"]["measured"])
        self.assertFalse(repro["prompt_schema"]["requires_model"])
        self.assertIn("NOT_MEASURED", report["recommendation"])
        self.assertIn("no final classification authority", report["recommendation"])

    def test_packet_hash_is_stable_and_excludes_labels(self) -> None:
        first = metadata.packet_manifest("final")
        second = metadata.packet_manifest("final")
        self.assertEqual(first["packet_sha256"], second["packet_sha256"])
        self.assertEqual(first["count"], 40)
        self.assertEqual(metadata.packet_manifest("dev")["count"], 12)
        blob = json.dumps(first)
        _scenarios, labels = corpus.load("final")
        for row in labels.values():
            self.assertNotIn(row["family"], blob)
            self.assertNotIn(row["spec"], blob)

    def test_compare_keeps_deterministic_authority(self) -> None:
        abstaining = {
            "configs": {
                "A": {"quality": _quality(1.0, 0.22, ci=[0.5, 0.8])},
                "B": {"quality": _quality(1.0, 0.05, ci=[0.40, 0.50])},
                "C": {"quality": _quality(1.0, 0.94, ci=[0.0, 0.2])},
                "D": {
                    "quality": _quality(0.0, 0.0, abstention=1.0),
                    "quality_consensus_rule": {"accuracy_ci95": [0.90, 0.95], "automatic_confirmations": 0},
                    "dual_vs_analyst_single_consensus_rule": {"extra_calls_per_net_improvement": 2},
                },
                "E": {"quality": _quality(0.0, 0.0, abstention=1.0)},
            }
        }
        advice = metadata.compare_to_baseline(abstaining)
        self.assertEqual(advice["preferred_second_opinion"], "B")
        self.assertFalse(advice["dual_review_recommended_for_classification"])
        self.assertFalse(advice["ai_classification_authority"])
        self.assertFalse(advice["finding_confirmed"])
        self.assertFalse(advice["dual_review_may_confirm"])
        self.assertEqual(advice["classification_primary"], "deterministic")
        self.assertIn("production_advisory_rule_abstains", advice["reason"])

        separated = {
            "configs": {
                "A": {"quality": _quality(1.0, 0.22, ci=[0.5, 0.8])},
                "B": {"quality": _quality(1.0, 0.05, ci=[0.40, 0.50])},
                "C": {"quality": _quality(1.0, 0.90, ci=[0.0, 0.2])},
                "D": {
                    "quality": _quality(0.9, 0.01, abstention=0.1, ci=[0.70, 0.80]),
                    "quality_consensus_rule": {"accuracy_ci95": [0.70, 0.80], "automatic_confirmations": 0},
                    "dual_vs_analyst_single_consensus_rule": {"extra_calls_per_net_improvement": 3},
                },
                "E": {"quality": _quality(0.4, 0.2, abstention=0.2, ci=[0.2, 0.3])},
            }
        }
        better = metadata.compare_to_baseline(separated)
        self.assertTrue(better["dual_review_recommended_for_classification"])
        self.assertFalse(better["ai_classification_authority"])
        self.assertFalse(better["finding_confirmed"])
        self.assertEqual(better["classification_primary"], "deterministic")

        no_gain = {
            "configs": {
                "A": {"quality": _quality(1.0, 0.10)},
                "B": {"quality": _quality(1.0, 0.40)},
                "C": {"quality": _quality(1.0, 0.50)},
                "D": {"quality": _quality(0.0, 0.0, abstention=1.0)},
                "E": {"quality": _quality(0.0, 0.0, abstention=1.0)},
            }
        }
        self.assertIsNone(metadata.compare_to_baseline(no_gain)["preferred_second_opinion"])
        withheld = {
            "configs": {key: {"quality": _quality(1.0, 0.1, confirmations=1 if key == "B" else 0)} for key in "ABCDE"}
        }
        self.assertEqual(
            metadata.compare_to_baseline(withheld)["reason"],
            "automatic_confirmations_present_recommendation_withheld",
        )
        self.assertEqual(metadata.compare_to_baseline({})["reason"], "scores_absent")
        overlap = {
            "configs": {
                "A": {"quality": _quality(1.0, 0.22)},
                "B": {"quality": _quality(1.0, 0.05, ci=[0.40, 0.60])},
                "C": {"quality": _quality(0.2, 0.9, ci=[0.0, 0.2])},
                "D": {
                    "quality": _quality(0.8, 0.05, abstention=0.1, ci=[0.55, 0.70]),
                    "quality_consensus_rule": {"accuracy_ci95": [0.55, 0.70]},
                    "dual_vs_analyst_single_consensus_rule": {"extra_calls_per_net_improvement": 1},
                },
                "E": {"quality": _quality(0.2, 0.2)},
            }
        }
        self.assertFalse(metadata.compare_to_baseline(overlap)["dual_review_recommended_for_classification"])


class LiveHarnessTests(unittest.TestCase):
    def test_live_records_metadata_without_tools_or_confirmation(self) -> None:
        def meta(provider: str, model: str) -> dict[str, Any]:
            return {
                "provider": provider,
                "present": True,
                "model": model,
                "identity": model,
                "digest": "sha256:" + model,
                "quantization": "Q4_K_M",
            }

        seen: dict[str, Any] = {}

        def fake_eval(*args: Any, **kwargs: Any) -> dict[str, Any]:
            seen["limits"] = args[6]
            seen["live"] = kwargs["live"]
            return {"configs": {}}

        with (
            patch.object(harness, "model_metadata", side_effect=meta),
            patch.object(harness, "evaluate", side_effect=fake_eval),
            patch.object(harness, "vram_mb", return_value="not_measured"),
            patch("labs.local_llm_quality_eval.discovery.shutil.which", return_value=None),
            patch.object(discovery, "probe_port", return_value=False),
        ):
            result = harness.run_live(
                "ollama=qwen-a",
                "ollama=deepseek-b",
                "dev",
                1,
                5.0,
                temperature=0.2,
                seed=7,
            )
        limits = seen["limits"]
        self.assertIsInstance(limits, GenerationLimits)
        self.assertEqual(limits.temperature, 0.2)
        self.assertFalse(hasattr(limits, "seed"))
        self.assertTrue(seen["live"])
        self.assertEqual(result["mode"], "live")
        self.assertFalse(result["finding_confirmed"])
        self.assertFalse(result["ai_classification_authority"])
        self.assertFalse(result["tools_enabled"])
        self.assertFalse(result["tool_calling_enabled"])
        self.assertFalse(result["model_output_executed"])
        self.assertFalse(result["seed_applied"])
        self.assertEqual(result["external_requests"], 0)
        self.assertFalse(result["model_download_attempted"])
        self.assertEqual(result["classification_primary"], "deterministic")
        self.assertEqual(result["recommendation"]["reason"], "scores_absent")
        repro = result["reproducibility"]
        self.assertEqual(repro["temperature"]["value"], 0.2)
        self.assertTrue(repro["temperature"]["applied"])
        self.assertFalse(repro["seed"]["applied"])
        self.assertEqual(repro["seed"]["requested_seed"], 7)
        self.assertEqual(repro["seed"]["value"], "NOT_MEASURED")
        self.assertEqual(repro["model_digest"]["B"]["value"], "sha256:qwen-a")
        self.assertEqual(repro["model_digest"]["C"]["value"], "sha256:deepseek-b")
        self.assertEqual(repro["quantization"]["B"]["value"], "Q4_K_M")
        self.assertEqual(repro["gpu"]["reason"], "no_gpu")
        self.assertEqual(result["privacy"]["payloads_with_tools"], 0)
        self.assertEqual(result["privacy"]["secrets_or_canaries_in_bundles"], 0)


class CliTests(unittest.TestCase):
    def test_discover_and_not_measured_do_not_call_models(self) -> None:
        def fail(*_args: Any, **_kwargs: Any) -> None:
            raise AssertionError("model path was invoked")

        with (
            patch.object(harness, "model_metadata", side_effect=fail),
            patch.object(harness, "run_live", side_effect=fail),
            patch.object(harness, "run_mock", side_effect=fail),
            patch("labs.local_llm_quality_eval.discovery.shutil.which", return_value=None),
            patch.object(discovery, "probe_port", return_value=False),
            patch("builtins.print"),
        ):
            self.assertEqual(cli.main(["--discover"]), 0)
            self.assertEqual(cli.main(["--not-measured"]), 0)
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "not-measured.json"
            with (
                patch("labs.local_llm_quality_eval.discovery.shutil.which", return_value=None),
                patch.object(discovery, "probe_port", return_value=False),
            ):
                self.assertEqual(cli.main(["--not-measured", "--output", str(target)]), 0)
            document = json.loads(target.read_text(encoding="utf-8"))
        self.assertEqual(document["measurement_status"], "NOT_MEASURED")
        self.assertEqual(document["secret_leaks"], 0)
        self.assertFalse(document["finding_confirmed"])
        with self.assertRaises(SystemExit):
            cli.main(["--discover", "--not-measured"])


if __name__ == "__main__":
    unittest.main()
