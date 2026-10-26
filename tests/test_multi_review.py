import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from bugbounty_toolkit import ai_mock_server as mocks
from bugbounty_toolkit.analysis import ai_review_eval
from bugbounty_toolkit.analysis.ai_providers import PROVIDER_REGISTRY, GenerationLimits, provider_for_spec
from bugbounty_toolkit.analysis.ai_review_eval import (
    CANARIES,
    INJECTION,
    SCENARIOS,
    run_live_protocol,
    run_mock_evaluation,
)
from bugbounty_toolkit.analysis.multi_review import (
    MODEL_OUTPUT_SCHEMA,
    RESULT_SCHEMA_VERSION,
    build_evidence_bundle,
    compare_reviews,
    review_evidence_multi,
    validate_model_output,
)
from bugbounty_toolkit.cli import build_parser

TRUE_IDOR = SCENARIOS[0]["data"]
REQUIRED_RESULT_FIELDS = {
    "evidence_bundle_id",
    "provider",
    "model",
    "decision",
    "evidence_for",
    "evidence_against",
    "unresolved_questions",
    "limitations",
    "validation_status",
    "execution_performed",
    "finding_confirmed",
}


def spec(pid, port):
    return replace(PROVIDER_REGISTRY[pid], port=port, allowed_ports=(port,))


def valid(**changes):
    body = {
        "decision": "inconclusive",
        "summary": "ok",
        "evidence_for": [],
        "evidence_against": [{"ref": "E01", "note": "n"}],
        "unresolved_questions": [],
        "missing_controls": [],
        "limitations": [],
    }
    body.update(changes)
    return json.dumps(body)


class BundleTests(unittest.TestCase):
    def test_bundle_is_minimized_stable_and_ref_addressed(self):
        data = dict(SCENARIOS[-1]["data"], notes=INJECTION)
        first = build_evidence_bundle(data)
        second = build_evidence_bundle(json.loads(json.dumps(data)))
        self.assertEqual(first["evidence_bundle_id"], second["evidence_bundle_id"])
        text = json.dumps(first)
        for canary in CANARIES:
            self.assertNotIn(canary, text)
        self.assertNotIn("IGNORE ALL", text)
        self.assertNotIn("victim.example", text)
        refs = [row["ref"] for row in first["observations"]]
        self.assertEqual(refs, sorted(set(refs)))
        self.assertFalse(first["deterministic_reference"]["confirmed"])
        self.assertNotEqual(
            first["evidence_bundle_id"], build_evidence_bundle(SCENARIOS[1]["data"])["evidence_bundle_id"]
        )


class ValidationTests(unittest.TestCase):
    refs = {"E01", "E02"}

    def check(self, content, status, complete=True):
        assessment, got, issues = validate_model_output(content, complete, self.refs)
        self.assertEqual(got, status, issues)
        return assessment, issues

    def test_valid_and_invalid_outputs(self):
        self.check(valid(), "valid")
        self.check(valid(), "incomplete", complete=False)
        self.check("not json", "invalid_json")
        self.check("[]", "schema_violation")
        self.check(json.dumps({"decision": "candidate"}), "schema_violation")
        _, issues = self.check(valid(finding_confirmed=True), "schema_violation")
        self.assertIn("invented_fields:finding_confirmed", issues)
        self.check(valid(decision="confirmed"), "schema_violation")
        self.check(valid(summary=5), "schema_violation")
        self.check(valid(summary="x" * 1300), "schema_violation")
        self.check(valid(evidence_for="E01"), "schema_violation")
        self.check(valid(evidence_for=[{"ref": "E01"}]), "schema_violation")
        self.check(valid(evidence_for=[{"ref": 1, "note": "x"}]), "schema_violation")
        self.check(valid(limitations=[1]), "schema_violation")
        self.check(valid(limitations=["x"] * 20), "schema_violation")
        self.check(valid(evidence_against=[{"ref": "E77", "note": "x"}]), "invalid_reference")
        self.check(
            valid(decision="candidate", evidence_for=[{"ref": "E01", "note": "a"}]),
            "contradictory",
        )
        self.check(valid(decision="candidate", evidence_against=[]), "contradictory")
        self.check(
            valid(decision="not_observed", evidence_for=[{"ref": "E02", "note": "a"}], evidence_against=[]),
            "contradictory",
        )
        assessment, _ = self.check(
            valid(decision="candidate", evidence_for=[{"ref": "E02", "note": "a"}]),
            "valid",
        )
        self.assertEqual(assessment["decision"], "candidate")

    def test_secret_like_model_text_is_redacted(self):
        text = valid(
            summary=f"see {CANARIES[0]} and {CANARIES[2]}",
            limitations=[f"key {CANARIES[1]}", "Authorization: Bearer abc"],
            evidence_against=[{"ref": "E01", "note": "token=abcdef"}],
        )
        assessment, issues = self.check(text, "valid")
        self.assertIn("secret_like_model_text_redacted", issues)
        dumped = json.dumps(assessment)
        for canary in CANARIES:
            self.assertNotIn(canary, dumped)
        self.assertNotIn("abcdef", dumped)

    def test_schema_requires_no_extra_fields(self):
        self.assertFalse(MODEL_OUTPUT_SCHEMA["additionalProperties"])


class ReviewTests(unittest.TestCase):
    def test_result_contract_for_both_providers(self):
        with mocks.MockLocalAIServer() as server:
            for pid in ("ollama", "lmstudio"):
                provider = provider_for_spec(spec(pid, server.port))
                result = review_evidence_multi(TRUE_IDOR, [(provider, "mock-model")], GenerationLimits(timeout=5))
                self.assertEqual(result["schema_version"], RESULT_SCHEMA_VERSION)
                self.assertTrue(REQUIRED_RESULT_FIELDS <= set(result))
                self.assertEqual(result["validation_status"], "valid")
                self.assertEqual(result["decision"], "candidate")
                self.assertIs(result["execution_performed"], False)
                self.assertIs(result["finding_confirmed"], False)
                self.assertIs(result["evidence_ledger_modified"], False)
                telemetry = result["telemetry"]
                self.assertFalse(telemetry["prompt_stored"])
                self.assertEqual(len(telemetry["prompt_sha256"]), 64)
                self.assertNotIn("messages", json.dumps(telemetry))

    def test_scenarios_never_confirm_and_reject_bad_outputs(self):
        with mocks.MockLocalAIServer() as server:
            provider = provider_for_spec(spec("lmstudio", server.port))
            for scenario in SCENARIOS:
                server.behavior = scenario["behavior"]
                result = review_evidence_multi(
                    scenario["data"],
                    [(provider, scenario.get("model", "mock-model"))],
                    GenerationLimits(timeout=scenario.get("timeout", 5.0)),
                )
                with self.subTest(scenario=scenario["id"]):
                    self.assertIs(result["finding_confirmed"], False)
                    if scenario["expect"] == "reject":
                        self.assertNotEqual(result["validation_status"], "valid")
                        self.assertEqual(result["decision"], "inconclusive")
                        self.assertEqual(result["evidence_for"], [])
                    else:
                        self.assertEqual(result["decision"], scenario["expect"])
                    for canary in CANARIES:
                        self.assertNotIn(canary, json.dumps(result))
            for row in server.requests:
                sent = row.get("raw", b"").decode()
                self.assertNotIn(INJECTION, sent)
                for canary in CANARIES:
                    self.assertNotIn(canary, sent)

    def test_dual_review_disagreement_and_independence(self):
        def by_model(bundle):
            return mocks.rule_based(bundle)

        with mocks.MockLocalAIServer(models=("qwen2.5-coder:7b", "deepseek-r1:8b")) as server:
            server.behavior = by_model
            first = provider_for_spec(spec("ollama", server.port))
            second = provider_for_spec(spec("lmstudio", server.port))
            result = review_evidence_multi(TRUE_IDOR, [(first, "qwen2.5-coder:7b"), (second, "deepseek-r1:8b")])
            comparison = result["comparison"]
            self.assertTrue(comparison["independence"]["independent"])
            self.assertEqual(comparison["consensus_weight"], "advisory_only")
            self.assertFalse(comparison["consensus_is_proof"])
            self.assertTrue(comparison["decision_agreement"])
            self.assertIs(result["finding_confirmed"], False)
            same = review_evidence_multi(TRUE_IDOR, [(first, "qwen2.5-coder:7b"), (first, "qwen2.5-coder:7b")])
            self.assertEqual(same["comparison"]["independence"]["reason"], "same_model_same_server")
        a = {
            "model_identity": "a",
            "provider": "ollama",
            "request_destination": "x",
            "validation_status": "valid",
            "decision": "candidate",
            "evidence_for": [{"ref": "E01"}],
            "evidence_against": [],
            "missing_controls": ["m1"],
        }
        b = dict(
            a,
            model_identity="b",
            decision="not_observed",
            evidence_for=[],
            evidence_against=[{"ref": "E01"}],
            missing_controls=["m2"],
        )
        comparison = compare_reviews(a, b)
        self.assertEqual(comparison["disputed_evidence"], ["E01"])
        self.assertFalse(comparison["decision_agreement"])
        self.assertEqual(comparison["independence"]["reason"], "different_models_same_server")
        self.assertEqual(comparison["missing_controls_union"], ["m1", "m2"])
        with self.assertRaises(ValueError):
            review_evidence_multi(TRUE_IDOR, [])

    def test_works_without_any_local_server(self):
        provider = provider_for_spec(spec("lmstudio", 1))  # nothing listens on port 1
        result = review_evidence_multi(TRUE_IDOR, [(provider, "qwen")], GenerationLimits(timeout=1))
        self.assertEqual(result["status"], "unavailable")
        self.assertEqual(result["telemetry"]["error_code"], "unavailable")
        self.assertIs(result["finding_confirmed"], False)


class EvaluationHarnessTests(unittest.TestCase):
    def test_mock_evaluation_metrics(self):
        report = run_mock_evaluation()
        self.assertFalse(report["measures_real_model_quality"])
        self.assertEqual(
            report["endpoint_policy"]["rejected"], report["endpoint_policy"]["non_loopback_or_unauthorized_attempts"]
        )
        by_path = {row["path"]: row["summary"] for row in report["paths"]}
        for name in ("v1_ollama_provider", "v1_openai_compatible_provider"):
            summary = by_path[name]
            self.assertEqual(summary["correct"], summary["scenarios"])
            for key in (
                "false_confirmations",
                "invented_refs_accepted",
                "secret_leaks_prompt",
                "secret_leaks_output",
                "unauthorized_destination_requests",
                "unsupported_outputs_accepted",
            ):
                self.assertEqual(summary[key], 0, key)
        self.assertFalse(report["dual_review_same_model"]["independence"]["independent"])

    def test_live_protocol_runs_against_registry_endpoints(self):
        with mocks.MockLocalAIServer(models=("qwen2.5-coder:7b", "deepseek-r1:8b")) as server:
            registry = {"ollama": spec("ollama", server.port), "lmstudio": spec("lmstudio", server.port)}
            with patch.dict(PROVIDER_REGISTRY, registry):
                report = run_live_protocol([("ollama", "qwen2.5-coder:7b"), ("lmstudio", "deepseek-r1:8b")], timeout=5)
                single = run_live_protocol([("ollama", "qwen2.5-coder:7b")], timeout=5)
        self.assertEqual(set(report["summary"]), {"ollama:qwen2.5-coder:7b", "lmstudio:deepseek-r1:8b"})
        self.assertTrue(all(not row["finding_confirmed"] for row in report["results"]))
        self.assertEqual(len(single["summary"]), 1)
        with self.assertRaises(ValueError):
            run_live_protocol([], timeout=5)

    def test_benchmark_script(self):
        from scripts import ai_provider_benchmark as script

        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "r.json"
            with redirect_stdout(io.StringIO()):
                self.assertEqual(script.main(["--output", str(out)]), 0)
            self.assertEqual(json.loads(out.read_text())["mode"], "deterministic_mock")
            with self.assertRaises(SystemExit), redirect_stdout(io.StringIO()), patch("sys.stderr", io.StringIO()):
                script.main(["--output", str(out)])
        with self.assertRaises(SystemExit), patch("sys.stderr", io.StringIO()):
            script.main(["--reviewer", "ollama=x"])
        with self.assertRaises(SystemExit), patch("sys.stderr", io.StringIO()):
            script.main(["--live", "--reviewer", "bad"])
        with patch.object(script, "run_live_protocol", return_value={"mode": "live"}) as live:
            with redirect_stdout(io.StringIO()):
                script.main(["--live", "--reviewer", "ollama=qwen2.5-coder:7b"])
        live.assert_called_once_with([("ollama", "qwen2.5-coder:7b")], 120.0, 1)

    def test_eval_module_exposes_legacy_comparison(self):
        self.assertTrue(callable(ai_review_eval._legacy_call(1)))


class CliStructuredReviewTests(unittest.TestCase):
    def run_cli(self, argv):
        args = build_parser().parse_args(argv)
        out = io.StringIO()
        with redirect_stdout(out):
            args.func(args)
        text = out.getvalue()
        return json.loads(text[text.index("{") :])

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.evidence = Path(self.tmp.name) / "e.json"
        self.evidence.write_text(json.dumps(SCENARIOS[-1]["data"]), encoding="utf-8")
        patcher = patch("bugbounty_toolkit.cli.RECORDS_ROOT", Path(self.tmp.name) / "records")
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_structured_dry_run_contacts_nothing(self):
        with patch("http.client.HTTPConnection") as conn:
            data = self.run_cli(
                ["ai-review", "p", "--evidence-file", str(self.evidence), "--ai-provider", "lmstudio", "--dry-run"]
            )
        conn.assert_not_called()
        self.assertEqual(data["status"], "dry_run")
        self.assertEqual(data["reviewers"][0]["endpoint"], "127.0.0.1:1234")
        for canary in CANARIES:
            self.assertNotIn(canary, json.dumps(data))

    def test_structured_dual_review_via_cli(self):
        with mocks.MockLocalAIServer(models=("qwen2.5-coder:7b", "deepseek-r1:8b")) as server:
            registry = {"ollama": spec("ollama", server.port), "lmstudio": spec("lmstudio", server.port)}
            with patch.dict(PROVIDER_REGISTRY, registry):
                data = self.run_cli(
                    [
                        "ai-review",
                        "p",
                        "--evidence-file",
                        str(self.evidence),
                        "--ai-provider",
                        "lmstudio",
                        "--model",
                        "deepseek-r1:8b",
                        "--second-ai-provider",
                        "ollama",
                        "--second-ai-model",
                        "qwen2.5-coder:7b",
                    ]
                )
                single = self.run_cli(["ai-review", "p", "--evidence-file", str(self.evidence), "--structured"])
        self.assertEqual(data["type"], "ai-evidence-review-comparison")
        self.assertEqual(len(data["reviews"]), 2)
        self.assertIs(data["finding_confirmed"], False)
        self.assertEqual(single["provider"], "ollama")
        self.assertFalse((Path(self.tmp.name) / "records" / "p" / "evidence-ledger").exists())

    def test_structured_cli_errors(self):
        artifact = Path(self.tmp.name) / "a.html"
        artifact.write_text("<p>x</p>", encoding="utf-8")
        base = ["ai-review", "p", "--evidence-file", str(self.evidence)]
        for argv in (
            ["ai-review", "p", "--artifact", str(artifact), "--kind", "html", "--ai-provider", "lmstudio"],
            base + ["--second-ai-provider", "ollama"],
            base + ["--ai-provider", "lmstudio", "--ai-endpoint", "192.168.0.2:1234"],
            base + ["--ai-provider", "lmstudio", "--ai-endpoint", "localhost:1234"],
            base + ["--structured", "--ai-max-tokens", "9000"],
        ):
            with self.subTest(argv=argv), self.assertRaises(ValueError):
                self.run_cli(argv)
        bad = Path(self.tmp.name) / "bad.json"
        bad.write_text("[", encoding="utf-8")
        with self.assertRaises(ValueError):
            self.run_cli(["ai-review", "p", "--evidence-file", str(bad), "--structured"])
        bad.write_text("[]", encoding="utf-8")
        with self.assertRaises(ValueError):
            self.run_cli(["ai-review", "p", "--evidence-file", str(bad), "--structured"])

    def test_legacy_ai_review_output_unchanged(self):
        data = self.run_cli(["ai-review", "p", "--evidence-file", str(self.evidence), "--dry-run"])
        self.assertEqual(
            set(data),
            {"type", "status", "decision", "reason", "notice", "model", "raw_evidence_sent", "minimized_packet"},
        )


if __name__ == "__main__":
    unittest.main()
