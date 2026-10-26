"""Local-only AI provider adapters for bounded, structured second opinions.

Every provider talks to a pre-authorized loopback endpoint (IP literal and fixed
port) through one shared transport. The transport never resolves DNS names,
never consults proxy environment variables, never follows redirects, caps the
response size and enforces a timeout plus a per-provider concurrency limit.
Models receive no tools, no file access and no ability to execute code; their
output is untrusted text that callers must validate.
"""

from __future__ import annotations

import hashlib
import http.client
import ipaddress
import json
import re
import threading
from dataclasses import dataclass, field, replace
from time import perf_counter
from typing import Any, Protocol
from urllib.parse import urlsplit

from .ollama_review import MAX_RESPONSE_BYTES, OLLAMA_CHAT_URL, validate_ollama_config

MAX_OUTPUT_TOKENS = 4096
MAX_PROMPT_CHARS = 48_000
MAX_CONCURRENCY = 4
OPENAI_COMPATIBLE_FAMILY = "openai-compatible"
OLLAMA_FAMILY = "ollama"
_OLLAMA_URL = urlsplit(OLLAMA_CHAT_URL)


class AIProviderError(ValueError):
    """A local provider call failed; ``code`` is a stable, secret-free reason."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


class EndpointRejectedError(AIProviderError):
    def __init__(self, message: str) -> None:
        super().__init__("endpoint_rejected", message)


@dataclass(frozen=True)
class ProviderSpec:
    """A pre-authorized local endpoint. Only registry entries are reachable from the CLI."""

    provider_id: str
    family: str
    host: str
    port: int
    chat_path: str
    models_path: str
    allowed_ports: tuple[int, ...]
    description: str
    enabled: bool = True

    def endpoint(self) -> str:
        host = f"[{self.host}]" if ":" in self.host else self.host
        return f"{host}:{self.port}"


@dataclass(frozen=True)
class ProviderCapabilities:
    structured_output: str
    tool_calling: bool = False
    code_execution: bool = False
    file_access: bool = False
    streaming: bool = False
    remote: bool = False
    max_output_tokens: int = MAX_OUTPUT_TOKENS

    def as_dict(self) -> dict[str, object]:
        return {
            "structured_output": self.structured_output,
            "tool_calling": self.tool_calling,
            "code_execution": self.code_execution,
            "file_access": self.file_access,
            "streaming": self.streaming,
            "remote": self.remote,
            "max_output_tokens": self.max_output_tokens,
        }


@dataclass(frozen=True)
class GenerationLimits:
    timeout: float = 120.0
    max_output_tokens: int = 512
    max_prompt_chars: int = 24_000
    max_response_bytes: int = MAX_RESPONSE_BYTES
    temperature: float = 0.0

    def validate(self) -> None:
        if isinstance(self.timeout, bool) or not isinstance(self.timeout, (int, float)) or not 1 <= self.timeout <= 300:
            raise ValueError("AI timeout must be between 1 and 300 seconds.")
        if type(self.max_output_tokens) is not int or not 1 <= self.max_output_tokens <= MAX_OUTPUT_TOKENS:
            raise ValueError(f"AI output budget must be between 1 and {MAX_OUTPUT_TOKENS} tokens.")
        if type(self.max_prompt_chars) is not int or not 256 <= self.max_prompt_chars <= MAX_PROMPT_CHARS:
            raise ValueError(f"AI prompt budget must be between 256 and {MAX_PROMPT_CHARS} characters.")
        if type(self.max_response_bytes) is not int or not 1024 <= self.max_response_bytes <= MAX_RESPONSE_BYTES:
            raise ValueError(f"AI response cap must be between 1024 and {MAX_RESPONSE_BYTES} bytes.")
        if isinstance(self.temperature, bool) or not isinstance(self.temperature, (int, float)):
            raise ValueError("AI temperature must be numeric.")
        if not 0 <= self.temperature <= 1:
            raise ValueError("AI temperature must be between 0 and 1.")

    def as_dict(self) -> dict[str, object]:
        return {
            "timeout": float(self.timeout),
            "max_output_tokens": self.max_output_tokens,
            "max_prompt_chars": self.max_prompt_chars,
            "max_response_bytes": self.max_response_bytes,
            "temperature": float(self.temperature),
        }


@dataclass(frozen=True)
class GenerationResult:
    content: str
    complete: bool
    finish_reason: str
    response_bytes: int
    duration_ms: float
    reported_model: str | None = None


@dataclass(frozen=True)
class AvailabilityResult:
    reachable: bool
    model_present: bool | None
    error_code: str | None = None
    models: tuple[str, ...] = field(default_factory=tuple)

    def as_dict(self) -> dict[str, object]:
        return {
            "reachable": self.reachable,
            "model_present": self.model_present,
            "error_code": self.error_code,
            "model_count": len(self.models),
        }


PROVIDER_REGISTRY: dict[str, ProviderSpec] = {
    "ollama": ProviderSpec(
        provider_id="ollama",
        family=OLLAMA_FAMILY,
        host=_OLLAMA_URL.hostname or "127.0.0.1",
        port=_OLLAMA_URL.port or 11434,
        chat_path=_OLLAMA_URL.path,
        models_path="/api/tags",
        allowed_ports=(11434,),
        description="Ollama native chat API on IPv4 loopback (legacy bbtk endpoint).",
    ),
    "lmstudio": ProviderSpec(
        provider_id="lmstudio",
        family=OPENAI_COMPATIBLE_FAMILY,
        host="127.0.0.1",
        port=1234,
        chat_path="/v1/chat/completions",
        models_path="/v1/models",
        allowed_ports=(1234,),
        description="LM Studio OpenAI-compatible local server on IPv4 loopback.",
    ),
}
# Reserved profiles for the same OpenAI-compatible adapter. They are documented but
# deliberately disabled until each server/model pair is verified on real hardware.
RESERVED_OPENAI_COMPATIBLE_PROFILES: dict[str, ProviderSpec] = {
    "llamacpp": ProviderSpec(
        "llamacpp",
        OPENAI_COMPATIBLE_FAMILY,
        "127.0.0.1",
        8080,
        "/v1/chat/completions",
        "/v1/models",
        (8080,),
        "llama.cpp llama-server (reserved, disabled).",
        enabled=False,
    ),
    "vllm": ProviderSpec(
        "vllm",
        OPENAI_COMPATIBLE_FAMILY,
        "127.0.0.1",
        8000,
        "/v1/chat/completions",
        "/v1/models",
        (8000,),
        "vLLM OpenAI-compatible server (reserved, disabled).",
        enabled=False,
    ),
    "localai": ProviderSpec(
        "localai",
        OPENAI_COMPATIBLE_FAMILY,
        "127.0.0.1",
        8080,
        "/v1/chat/completions",
        "/v1/models",
        (8080,),
        "LocalAI OpenAI-compatible server (reserved, disabled).",
        enabled=False,
    ),
}
ALLOWED_PROVIDERS = tuple(sorted(PROVIDER_REGISTRY))
_SEMAPHORES: dict[str, threading.BoundedSemaphore] = {}
_SEMAPHORE_LOCK = threading.Lock()


def validate_loopback_host(host: str) -> str:
    """Accept only a loopback IP literal; names (including ``localhost``) are never resolved."""
    if not isinstance(host, str) or not host:
        raise EndpointRejectedError("AI endpoint host must be a loopback IP literal.")
    candidate = host[1:-1] if host.startswith("[") and host.endswith("]") else host
    try:
        address = ipaddress.ip_address(candidate)
    except ValueError as exc:
        raise EndpointRejectedError("AI endpoint must be a loopback IP literal; DNS names are rejected.") from exc
    mapped = address.ipv4_mapped if isinstance(address, ipaddress.IPv6Address) else None
    if mapped is not None or not address.is_loopback:
        raise EndpointRejectedError("AI endpoint must be loopback; non-loopback and private addresses are rejected.")
    return str(address)


def validate_spec(spec: ProviderSpec) -> ProviderSpec:
    if spec.family not in {OLLAMA_FAMILY, OPENAI_COMPATIBLE_FAMILY}:
        raise EndpointRejectedError("Unsupported AI provider family.")
    if not spec.enabled:
        raise EndpointRejectedError(f"AI provider profile {spec.provider_id!r} is reserved and disabled.")
    host = validate_loopback_host(spec.host)
    if type(spec.port) is not int or spec.port not in spec.allowed_ports or not 1 <= spec.port <= 65535:
        raise EndpointRejectedError("AI endpoint port is not pre-authorized for this provider.")
    for path in (spec.chat_path, spec.models_path):
        if not re.fullmatch(r"/[A-Za-z0-9/_.-]{1,64}", path) or ".." in path:
            raise EndpointRejectedError("AI endpoint path is not an allowlisted local API path.")
    return replace(spec, host=host)


def resolve_provider(provider_id: str, endpoint: str | None = None) -> ProviderSpec:
    """Return a registry spec. ``endpoint`` may only restate the authorized ``host:port``."""
    if not isinstance(provider_id, str) or provider_id not in PROVIDER_REGISTRY:
        if isinstance(provider_id, str) and provider_id in RESERVED_OPENAI_COMPATIBLE_PROFILES:
            raise EndpointRejectedError(f"AI provider {provider_id!r} is reserved and not enabled in this release.")
        raise EndpointRejectedError(f"AI provider must be one of: {', '.join(ALLOWED_PROVIDERS)}.")
    spec = validate_spec(PROVIDER_REGISTRY[provider_id])
    if endpoint is None:
        return spec
    return validate_spec(replace(spec, **_parse_endpoint(endpoint, spec)))


def _parse_endpoint(endpoint: str, spec: ProviderSpec) -> dict[str, Any]:
    if not isinstance(endpoint, str) or len(endpoint) > 64 or any(ch.isspace() for ch in endpoint):
        raise EndpointRejectedError("AI endpoint must be a short host:port value.")
    if "://" in endpoint:
        parts = urlsplit(endpoint)
        if parts.scheme != "http" or parts.username or parts.password or parts.query or parts.fragment:
            raise EndpointRejectedError("AI endpoint URLs may only use plain http to loopback without credentials.")
        if parts.path not in {"", "/"}:
            raise EndpointRejectedError("AI endpoint paths are fixed per provider; arbitrary URLs are rejected.")
        netloc = parts.netloc
    else:
        netloc = endpoint
    parts = urlsplit("//" + netloc)
    try:
        port = parts.port
    except ValueError as exc:
        raise EndpointRejectedError("AI endpoint port is invalid.") from exc
    if parts.hostname is None or port is None:
        raise EndpointRejectedError("AI endpoint must include a loopback IP literal and an authorized port.")
    host = validate_loopback_host(parts.hostname)
    if port not in spec.allowed_ports:
        raise EndpointRejectedError("AI endpoint port is not pre-authorized for this provider.")
    return {"host": host, "port": port}


def _semaphore(provider_id: str, limit: int) -> threading.BoundedSemaphore:
    key = f"{provider_id}:{limit}"
    with _SEMAPHORE_LOCK:
        if key not in _SEMAPHORES:
            _SEMAPHORES[key] = threading.BoundedSemaphore(limit)
        return _SEMAPHORES[key]


def _request_json(
    spec: ProviderSpec,
    method: str,
    path: str,
    payload: dict[str, Any] | None,
    timeout: float,
    max_bytes: int,
) -> tuple[Any, int]:
    """One bounded HTTP exchange with a validated loopback endpoint; no proxies or redirects."""
    spec = validate_spec(spec)
    if path not in {spec.chat_path, spec.models_path}:
        raise EndpointRejectedError("AI request path is not allowlisted for this provider.")
    body = None if payload is None else json.dumps(payload, ensure_ascii=True).encode("utf-8")
    headers = {"Accept": "application/json", "Connection": "close"}
    if body is not None:
        headers["Content-Type"] = "application/json"
    # http.client connects to the literal address only: no DNS, no proxy env, no redirect handling.
    connection = http.client.HTTPConnection(spec.host, spec.port, timeout=float(timeout))
    try:
        connection.request(method, path, body=body, headers=headers)
        response = connection.getresponse()
        raw = response.read(max_bytes + 1)
        status = response.status
    except TimeoutError as exc:
        raise AIProviderError("timeout", "Local AI provider timed out; no remote fallback was attempted.") from exc
    except (OSError, http.client.HTTPException) as exc:
        raise AIProviderError(
            "unavailable", "Local AI provider is unavailable; no remote fallback was attempted."
        ) from exc
    finally:
        connection.close()
    if 300 <= status < 400:
        raise AIProviderError("redirect_refused", "Local AI provider attempted a redirect; it was not followed.")
    if status == 404:
        raise AIProviderError("model_unavailable", "Local AI provider reported the model or route as unavailable.")
    if status >= 400:
        raise AIProviderError("http_error", f"Local AI provider returned HTTP {status}.")
    if len(raw) > max_bytes:
        raise AIProviderError("oversized", "Local AI response exceeded its size limit.")
    try:
        return json.loads(raw.decode("utf-8")), len(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AIProviderError("invalid_envelope", "Local AI provider returned a non-JSON envelope.") from exc


def _validate_messages(messages: list[dict[str, str]], limits: GenerationLimits) -> None:
    if (
        not isinstance(messages, list)
        or not messages
        or any(
            not isinstance(message, dict)
            or set(message) != {"role", "content"}
            or message["role"] not in {"system", "user"}
            or not isinstance(message["content"], str)
            for message in messages
        )
    ):
        raise ValueError("AI messages must contain only system/user role/content text pairs.")
    if sum(len(message["content"]) for message in messages) > limits.max_prompt_chars:
        raise AIProviderError("prompt_budget_exceeded", "Minimized prompt exceeded the configured prompt budget.")


def prompt_fingerprint(messages: list[dict[str, str]]) -> str:
    canonical = json.dumps(messages, sort_keys=True, ensure_ascii=True).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


class AIProvider(Protocol):
    """Structured, non-executing local generation."""

    @property
    def provider_id(self) -> str: ...

    @property
    def spec(self) -> ProviderSpec: ...

    def capabilities(self) -> ProviderCapabilities: ...

    def check_availability(self, model: str, timeout: float = 5.0) -> AvailabilityResult: ...

    def generate_structured(
        self, messages: list[dict[str, str]], schema: dict[str, Any], model: str, limits: GenerationLimits
    ) -> GenerationResult: ...


class _BaseLocalProvider:
    def __init__(self, spec: ProviderSpec, max_concurrency: int = 1) -> None:
        if type(max_concurrency) is not int or not 1 <= max_concurrency <= MAX_CONCURRENCY:
            raise ValueError(f"AI concurrency must be between 1 and {MAX_CONCURRENCY}.")
        self._spec = validate_spec(spec)
        self._max_concurrency = max_concurrency

    @property
    def provider_id(self) -> str:
        return self._spec.provider_id

    @property
    def spec(self) -> ProviderSpec:
        return self._spec

    def _models(self, payload: Any) -> tuple[str, ...]:
        raise NotImplementedError

    def _chat_payload(
        self, messages: list[dict[str, str]], schema: dict[str, Any], model: str, limits: GenerationLimits
    ) -> dict[str, Any]:
        raise NotImplementedError

    def _parse_chat(self, envelope: Any) -> tuple[str, bool, str, str | None]:
        raise NotImplementedError

    def check_availability(self, model: str, timeout: float = 5.0) -> AvailabilityResult:
        validate_ollama_config(model, timeout)
        try:
            payload, _ = _request_json(self._spec, "GET", self._spec.models_path, None, timeout, MAX_RESPONSE_BYTES)
            models = self._models(payload)
        except AIProviderError as exc:
            return AvailabilityResult(False, None, exc.code)
        except (KeyError, TypeError, ValueError):
            return AvailabilityResult(True, None, "invalid_envelope")
        return AvailabilityResult(True, model in models, None if model in models else "model_unavailable", models)

    def generate_structured(
        self, messages: list[dict[str, str]], schema: dict[str, Any], model: str, limits: GenerationLimits
    ) -> GenerationResult:
        validate_ollama_config(model, limits.timeout)
        limits.validate()
        _validate_messages(messages, limits)
        if not isinstance(schema, dict) or schema.get("type") != "object":
            raise ValueError("Structured generation requires an object JSON schema.")
        payload = self._chat_payload(messages, schema, model, limits)
        gate = _semaphore(self._spec.provider_id, self._max_concurrency)
        if not gate.acquire(timeout=float(limits.timeout)):
            raise AIProviderError("concurrency_limit", "Local AI concurrency limit reached.")
        started = perf_counter()
        try:
            envelope, size = _request_json(
                self._spec, "POST", self._spec.chat_path, payload, limits.timeout, limits.max_response_bytes
            )
        finally:
            gate.release()
        duration_ms = (perf_counter() - started) * 1000
        try:
            content, complete, finish_reason, reported = self._parse_chat(envelope)
        except (KeyError, TypeError, IndexError) as exc:
            raise AIProviderError("invalid_envelope", "Local AI provider returned an unexpected envelope.") from exc
        return GenerationResult(content, complete, finish_reason, size, round(duration_ms, 3), reported)


class OllamaProvider(_BaseLocalProvider):
    """Ollama native ``/api/chat``; same endpoint and payload shape as ``chat_with_ollama``."""

    def __init__(self, spec: ProviderSpec | None = None, max_concurrency: int = 1) -> None:
        super().__init__(spec or PROVIDER_REGISTRY["ollama"], max_concurrency)
        if self._spec.family != OLLAMA_FAMILY:
            raise EndpointRejectedError("OllamaProvider requires an Ollama provider spec.")

    def capabilities(self) -> ProviderCapabilities:
        return ProviderCapabilities(structured_output="ollama_format_json_schema")

    def _models(self, payload: Any) -> tuple[str, ...]:
        return tuple(str(item["name"]) for item in payload["models"] if isinstance(item, dict))

    def _chat_payload(
        self, messages: list[dict[str, str]], schema: dict[str, Any], model: str, limits: GenerationLimits
    ) -> dict[str, Any]:
        return {
            "model": model,
            "messages": messages,
            "stream": False,
            "keep_alive": 0,
            "options": {"temperature": float(limits.temperature), "num_predict": limits.max_output_tokens},
            "format": schema,
        }

    def _parse_chat(self, envelope: Any) -> tuple[str, bool, str, str | None]:
        message = envelope["message"]
        content = message["content"]
        if not isinstance(content, str):
            raise TypeError("non-text content")
        if message.get("tool_calls"):
            raise AIProviderError("tool_call_refused", "Local model attempted a tool call; tools are disabled.")
        done = envelope.get("done", True) is True
        reason = envelope.get("done_reason", "stop" if done else "incomplete")
        reason = reason if isinstance(reason, str) and len(reason) <= 32 else "unknown"
        reported = envelope.get("model") if isinstance(envelope.get("model"), str) else None
        return content, done and reason != "length", reason, reported


class OpenAICompatibleLocalProvider(_BaseLocalProvider):
    """One adapter for OpenAI-compatible local servers (LM Studio now; llama.cpp/vLLM/LocalAI later)."""

    def __init__(self, spec: ProviderSpec | None = None, max_concurrency: int = 1) -> None:
        super().__init__(spec or PROVIDER_REGISTRY["lmstudio"], max_concurrency)
        if self._spec.family != OPENAI_COMPATIBLE_FAMILY:
            raise EndpointRejectedError("OpenAICompatibleLocalProvider requires an OpenAI-compatible spec.")

    def capabilities(self) -> ProviderCapabilities:
        return ProviderCapabilities(structured_output="openai_response_format_json_schema")

    def _models(self, payload: Any) -> tuple[str, ...]:
        return tuple(str(item["id"]) for item in payload["data"] if isinstance(item, dict))

    def _chat_payload(
        self, messages: list[dict[str, str]], schema: dict[str, Any], model: str, limits: GenerationLimits
    ) -> dict[str, Any]:
        return {
            "model": model,
            "messages": messages,
            "stream": False,
            "temperature": float(limits.temperature),
            "max_tokens": limits.max_output_tokens,
            "response_format": {
                "type": "json_schema",
                "json_schema": {"name": "bbtk_evidence_review", "strict": True, "schema": schema},
            },
        }

    def _parse_chat(self, envelope: Any) -> tuple[str, bool, str, str | None]:
        choice = envelope["choices"][0]
        message = choice["message"]
        if message.get("tool_calls") or message.get("function_call"):
            raise AIProviderError("tool_call_refused", "Local model attempted a tool call; tools are disabled.")
        content = message["content"]
        if not isinstance(content, str):
            raise TypeError("non-text content")
        reason = choice.get("finish_reason") or "unknown"
        reason = reason if isinstance(reason, str) and len(reason) <= 32 else "unknown"
        reported = envelope.get("model") if isinstance(envelope.get("model"), str) else None
        return content, reason == "stop", reason, reported


def build_provider(provider_id: str, endpoint: str | None = None, max_concurrency: int = 1) -> AIProvider:
    spec = resolve_provider(provider_id, endpoint)
    if spec.family == OLLAMA_FAMILY:
        return OllamaProvider(spec, max_concurrency)
    return OpenAICompatibleLocalProvider(spec, max_concurrency)


def provider_for_spec(spec: ProviderSpec, max_concurrency: int = 1) -> AIProvider:
    """Construct a provider for an explicitly authorized spec (used by tests and local mock labs)."""
    spec = validate_spec(spec)
    if spec.family == OLLAMA_FAMILY:
        return OllamaProvider(spec, max_concurrency)
    return OpenAICompatibleLocalProvider(spec, max_concurrency)


_QUANT_SUFFIX = re.compile(
    r"(?:[-_.:](?:gguf|q\d(?:_[a-z0-9]+)*|f16|fp16|bf16|int4|int8|awq|gptq|mlx|latest|instruct))+$"
)


def normalize_model_identity(model: str) -> str:
    """Collapse publisher prefixes, tags and quantization suffixes so one model on two servers matches."""
    name = model.strip().lower()
    name = name.rsplit("/", 1)[-1]
    previous = None
    while previous != name:
        previous = name
        name = _QUANT_SUFFIX.sub("", name)
    name = name.replace(":", "-").replace("_", "-").replace(".", "-")
    return re.sub(r"-+", "-", name).strip("-")


def list_providers() -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    for spec in list(PROVIDER_REGISTRY.values()) + list(RESERVED_OPENAI_COMPATIBLE_PROFILES.values()):
        caps = ProviderCapabilities(
            structured_output="ollama_format_json_schema"
            if spec.family == OLLAMA_FAMILY
            else "openai_response_format_json_schema"
        )
        rows.append(
            {
                "provider": spec.provider_id,
                "family": spec.family,
                "endpoint": spec.endpoint(),
                "enabled": spec.enabled,
                "description": spec.description,
                "capabilities": caps.as_dict(),
            }
        )
    return rows
