import io
import json
import os
import unittest
from contextlib import redirect_stdout
from dataclasses import replace
from unittest.mock import patch

from bugbounty_toolkit import ai_mock_server as mocks
from bugbounty_toolkit.analysis import ai_providers
from bugbounty_toolkit.analysis.ai_providers import (
    PROVIDER_REGISTRY,
    AIProviderError,
    EndpointRejectedError,
    GenerationLimits,
    OllamaProvider,
    OpenAICompatibleLocalProvider,
    build_provider,
    list_providers,
    normalize_model_identity,
    provider_for_spec,
    resolve_provider,
    validate_loopback_host,
)
from bugbounty_toolkit.analysis.ollama_review import OLLAMA_CHAT_URL
from bugbounty_toolkit.cli import build_parser

MESSAGES = [{"role": "system", "content": "s"}, {"role": "user", "content": "Evidence bundle: {}"}]
SCHEMA = {"type": "object"}


def spec(provider_id, port):
    return replace(PROVIDER_REGISTRY[provider_id], port=port, allowed_ports=(port,))


class EndpointPolicyTests(unittest.TestCase):
    def test_registry_is_explicit_loopback_only(self):
        self.assertEqual(sorted(PROVIDER_REGISTRY), ["lmstudio", "ollama"])
        self.assertEqual(f"http://{PROVIDER_REGISTRY['ollama'].endpoint()}/api/chat", OLLAMA_CHAT_URL)
        self.assertEqual(PROVIDER_REGISTRY["lmstudio"].endpoint(), "127.0.0.1:1234")
        for row in list_providers():
            self.assertFalse(row["capabilities"]["tool_calling"])
            self.assertFalse(row["capabilities"]["remote"])
        self.assertIsInstance(build_provider("ollama"), OllamaProvider)
        self.assertIsInstance(build_provider("lmstudio"), OpenAICompatibleLocalProvider)

    def test_rejects_unknown_reserved_and_remote_providers(self):
        for name in ("openai", "gemini", "claude", "llamacpp", "vllm", "localai", "", None):
            with self.subTest(name=name), self.assertRaises(EndpointRejectedError):
                resolve_provider(name)  # type: ignore[arg-type]

    def test_rejects_non_loopback_dns_and_unauthorized_endpoints(self):
        for endpoint in (
            "http://10.0.0.5:1234",
            "192.168.1.10:1234",
            "172.16.0.1:1234",
            "8.8.8.8:1234",
            "localhost:1234",
            "lmstudio.example:1234",
            "[::ffff:127.0.0.1]:1234",
            "0.0.0.0:1234",
            "127.0.0.1:9999",
            "127.0.0.1",
            "http://127.0.0.1:1234/v1/other",
            "https://127.0.0.1:1234",
            "http://user:pw@127.0.0.1:1234",
            "http://127.0.0.1:1234/?q=1",
            "127.0.0.1:abc",
            "127.0.0.1:1234 ",
            "x" * 80,
        ):
            with self.subTest(endpoint=endpoint), self.assertRaises(EndpointRejectedError):
                resolve_provider("lmstudio", endpoint)
        self.assertEqual(resolve_provider("lmstudio", "http://127.0.0.1:1234").port, 1234)
        self.assertEqual(resolve_provider("lmstudio", "127.0.0.1:1234/").host, "127.0.0.1")
        self.assertEqual(validate_loopback_host("[::1]"), "::1")
        with self.assertRaises(EndpointRejectedError):
            validate_loopback_host("")

    def test_spec_validation_rejects_tampered_specs(self):
        with self.assertRaises(EndpointRejectedError):
            provider_for_spec(replace(PROVIDER_REGISTRY["ollama"], host="10.1.1.1"))
        with self.assertRaises(EndpointRejectedError):
            provider_for_spec(replace(PROVIDER_REGISTRY["ollama"], chat_path="/../etc"))
        with self.assertRaises(EndpointRejectedError):
            provider_for_spec(replace(PROVIDER_REGISTRY["ollama"], family="cloud"))
        with self.assertRaises(EndpointRejectedError):
            provider_for_spec(ai_providers.RESERVED_OPENAI_COMPATIBLE_PROFILES["vllm"])
        with self.assertRaises(EndpointRejectedError):
            OllamaProvider(PROVIDER_REGISTRY["lmstudio"])
        with self.assertRaises(EndpointRejectedError):
            OpenAICompatibleLocalProvider(PROVIDER_REGISTRY["ollama"])
        with self.assertRaises(ValueError):
            OllamaProvider(max_concurrency=9)

    def test_limits_validation(self):
        for limits in (
            GenerationLimits(timeout=0),
            GenerationLimits(timeout=True),  # type: ignore[arg-type]
            GenerationLimits(max_output_tokens=5000),
            GenerationLimits(max_prompt_chars=10),
            GenerationLimits(max_response_bytes=10),
            GenerationLimits(temperature=True),  # type: ignore[arg-type]
            GenerationLimits(temperature=2),
        ):
            with self.subTest(limits=limits), self.assertRaises(ValueError):
                limits.validate()

    def test_model_identity_normalization(self):
        self.assertEqual(
            normalize_model_identity("qwen2.5-coder:7b"),
            normalize_model_identity("lmstudio-community/Qwen2.5-Coder-7B-Instruct-GGUF"),
        )
        self.assertNotEqual(normalize_model_identity("qwen2.5-coder:7b"), normalize_model_identity("deepseek-r1:8b"))
        self.assertEqual(normalize_model_identity("llama3.2:latest"), normalize_model_identity("llama3.2"))


class TransportTests(unittest.TestCase):
    def test_both_providers_send_bounded_toolless_payloads(self):
        with mocks.MockLocalAIServer() as server:
            for pid in ("ollama", "lmstudio"):
                provider = provider_for_spec(spec(pid, server.port))
                result = provider.generate_structured(MESSAGES, SCHEMA, "mock-model", GenerationLimits(timeout=5))
                self.assertTrue(result.complete)
                self.assertEqual(result.reported_model, "mock-model")
                body = server.requests[-1]["body"]
                self.assertNotIn("tools", body)
                self.assertNotIn("tool_choice", body)
                self.assertEqual(body["model"], "mock-model")
                if pid == "ollama":
                    self.assertEqual(server.requests[-1]["path"], "/api/chat")
                    self.assertEqual(body["options"], {"temperature": 0.0, "num_predict": 512})
                    self.assertEqual(body["keep_alive"], 0)
                    self.assertEqual(body["format"], SCHEMA)
                else:
                    self.assertEqual(server.requests[-1]["path"], "/v1/chat/completions")
                    self.assertEqual(body["max_tokens"], 512)
                    self.assertEqual(body["response_format"]["type"], "json_schema")
                self.assertNotIn("Authorization", server.requests[-1]["headers"])

    def test_availability(self):
        with mocks.MockLocalAIServer(models=("qwen2.5-coder:7b",)) as server:
            for pid in ("ollama", "lmstudio"):
                provider = provider_for_spec(spec(pid, server.port))
                self.assertTrue(provider.check_availability("qwen2.5-coder:7b").model_present)
                missing = provider.check_availability("deepseek-r1:8b")
                self.assertFalse(missing.model_present)
                self.assertEqual(missing.as_dict()["error_code"], "model_unavailable")
            port = server.port
        down = provider_for_spec(spec("ollama", port)).check_availability("x", timeout=1)
        self.assertFalse(down.reachable)
        self.assertEqual(down.error_code, "unavailable")

    def test_availability_invalid_envelope(self):
        with mocks.MockLocalAIServer() as server:
            provider = provider_for_spec(spec("ollama", server.port))
            with patch.object(OllamaProvider, "_models", side_effect=KeyError("models")):
                self.assertEqual(provider.check_availability("x").error_code, "invalid_envelope")

    def test_error_codes(self):
        cases = {
            "redirect_refused": lambda b: {"status": 302, "headers": {"Location": "http://203.0.113.9/"}},
            "http_error": lambda b: {"status": 500},
            "oversized": lambda b: {"content": "A" * 70_000},
            "invalid_envelope": lambda b: {"raw_envelope": b"not json"},
            "tool_call_refused": lambda b: {"content": "{}", "tool_calls": True},
            "timeout": lambda b: {"sleep": 1.5, "content": "{}"},
        }
        with mocks.MockLocalAIServer() as server:
            for pid in ("ollama", "lmstudio"):
                provider = provider_for_spec(spec(pid, server.port))
                for code, behavior in cases.items():
                    server.behavior = behavior
                    with self.subTest(pid=pid, code=code), self.assertRaises(AIProviderError) as ctx:
                        provider.generate_structured(MESSAGES, SCHEMA, "mock-model", GenerationLimits(timeout=1))
                    self.assertEqual(ctx.exception.code, code)
                server.behavior = lambda b: {"raw_envelope": b'{"unexpected": 1}'}
                with self.assertRaises(AIProviderError) as ctx:
                    provider.generate_structured(MESSAGES, SCHEMA, "mock-model", GenerationLimits(timeout=2))
                self.assertEqual(ctx.exception.code, "invalid_envelope")
                with self.assertRaises(AIProviderError) as ctx:
                    provider.generate_structured(MESSAGES, SCHEMA, "absent", GenerationLimits(timeout=2))
                self.assertEqual(ctx.exception.code, "model_unavailable")

    def test_incomplete_outputs_are_flagged(self):
        with mocks.MockLocalAIServer(behavior=lambda b: {"content": "{}", "complete": False}) as server:
            for pid in ("ollama", "lmstudio"):
                result = provider_for_spec(spec(pid, server.port)).generate_structured(
                    MESSAGES, SCHEMA, "mock-model", GenerationLimits(timeout=2)
                )
                self.assertFalse(result.complete)
                self.assertEqual(result.finish_reason, "length")

    def test_input_validation(self):
        provider = OllamaProvider()
        with self.assertRaises(ValueError):
            provider.generate_structured([{"role": "tool", "content": "x"}], SCHEMA, "m", GenerationLimits())
        with self.assertRaises(ValueError):
            provider.generate_structured(MESSAGES, {"type": "array"}, "m", GenerationLimits())
        with self.assertRaises(ValueError):
            provider.generate_structured(MESSAGES, SCHEMA, "http://evil/model", GenerationLimits())
        with self.assertRaises(AIProviderError) as ctx:
            provider.generate_structured(
                [{"role": "user", "content": "x" * 400}], SCHEMA, "m", GenerationLimits(max_prompt_chars=256)
            )
        self.assertEqual(ctx.exception.code, "prompt_budget_exceeded")

    def test_proxy_environment_is_ignored(self):
        with mocks.MockLocalAIServer() as server, mocks.MockLocalAIServer() as trap:
            env = {"HTTP_PROXY": f"http://127.0.0.1:{trap.port}", "http_proxy": f"http://127.0.0.1:{trap.port}"}
            with patch.dict(os.environ, env):
                provider_for_spec(spec("lmstudio", server.port)).generate_structured(
                    MESSAGES, SCHEMA, "mock-model", GenerationLimits(timeout=2)
                )
            self.assertEqual(trap.requests, [])
            self.assertEqual(len(server.requests), 1)

    def test_concurrency_limit(self):
        gate = ai_providers._semaphore("ollama", 1)
        self.assertTrue(gate.acquire(timeout=1))
        try:
            with self.assertRaises(AIProviderError) as ctx:
                OllamaProvider().generate_structured(MESSAGES, SCHEMA, "m", GenerationLimits(timeout=1))
            self.assertEqual(ctx.exception.code, "concurrency_limit")
        finally:
            gate.release()

    def test_request_path_allowlist(self):
        with self.assertRaises(EndpointRejectedError):
            ai_providers._request_json(PROVIDER_REGISTRY["ollama"], "GET", "/api/pull", None, 1, 1024)


class CliProviderTests(unittest.TestCase):
    def run_cli(self, argv):
        args = build_parser().parse_args(argv)
        out = io.StringIO()
        with redirect_stdout(out):
            args.func(args)
        text = out.getvalue()
        return json.loads(text[text.index("{") :])

    def test_ai_providers_listing_and_check(self):
        data = self.run_cli(["ai", "providers"])
        self.assertFalse(data["remote_providers_enabled"])
        with mocks.MockLocalAIServer(models=("qwen2.5-coder:7b",)) as server:
            with patch.dict(
                PROVIDER_REGISTRY, {"ollama": spec("ollama", server.port), "lmstudio": spec("lmstudio", server.port)}
            ):
                data = self.run_cli(["ai", "providers", "--check"])
        checked = [row for row in data["providers"] if row["enabled"]]
        self.assertTrue(all(row["availability"]["model_present"] for row in checked))

    def test_legacy_parser_defaults_unchanged(self):
        args = build_parser().parse_args(["ai-review", "p", "--evidence-file", "x.json"])
        self.assertEqual(args.ai_provider, "ollama")
        self.assertFalse(args.structured)
        self.assertIsNone(args.second_ai_provider)
        with self.assertRaises(SystemExit), redirect_stdout(io.StringIO()), patch("sys.stderr", io.StringIO()):
            build_parser().parse_args(["ai-review", "p", "--evidence-file", "x", "--ai-provider", "openai"])


if __name__ == "__main__":
    unittest.main()
