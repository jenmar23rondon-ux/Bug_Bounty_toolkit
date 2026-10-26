"""Provider/model selection for every AI-assisted investigation call site.

This module is a thin dispatch layer over the existing :mod:`ai_providers`
adapters (``AIProvider`` / ``OllamaProvider`` / ``OpenAICompatibleLocalProvider``).
It does not define a second provider architecture: it only resolves an explicit
``AISelection`` into a registry provider, applies a last-chance sensitive-content
gate to the already minimized prompt, and records secret-free telemetry
(provider, model, endpoint, duration, error code, prompt hash; never the prompt).

``selection=None`` keeps the legacy behaviour of each caller (the historical
``chat_with_ollama`` client against 127.0.0.1:11434) so existing commands keep
their exact contract. Models never receive tools, never execute anything and
never change scope; every reply is untrusted text validated by the caller.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass, field
from time import perf_counter
from typing import Any

from .ai_providers import (
    ALLOWED_PROVIDERS,
    AIProvider,
    AIProviderError,
    GenerationLimits,
    ProviderSpec,
    build_provider,
    prompt_fingerprint,
    provider_for_spec,
    resolve_provider,
)
from .ollama_review import (
    DEFAULT_OLLAMA_MODEL,
    REVIEW_SCHEMA,
    OllamaUnavailableError,
    review_messages,
    review_with_ollama,
    validate_ollama_config,
    validate_review_assessment,
)

LEGACY_DESTINATION = "127.0.0.1:11434"
# Transport/availability failures map onto the legacy "unavailable" exception so
# every existing caller keeps its fallback path. Everything else is a ValueError
# (invalid/unsafe model output) that callers already treat as unusable output.
UNAVAILABLE_CODES = frozenset({"unavailable", "timeout", "model_unavailable", "concurrency_limit", "http_error"})
SENSITIVE_PATTERNS = (
    re.compile(r"\bsk-[A-Za-z0-9_-]{12,}"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}"),
    re.compile(r"BBTK[-_]CANARY[-_][A-Za-z0-9_-]+"),
    re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"),
    re.compile(r"(?i)\b(?:cookie|set-cookie|authorization)\s*[:=]\s*(?!\[redacted\])[^\s\"',;]{6,}"),
    re.compile(r"(?i)\bbearer\s+(?!\[redacted\])[A-Za-z0-9._~+/=-]{12,}"),
)


class AIBackendUnavailableError(OllamaUnavailableError):
    """The selected local provider was unreachable; ``code`` is stable and secret-free."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class AISelection:
    """An explicit, allowlisted local provider + model choice.

    ``spec`` is only for tests and local mock labs: it must still pass the
    loopback/port/path validation in :func:`ai_providers.validate_spec`.
    """

    provider: str = "ollama"
    model: str = DEFAULT_OLLAMA_MODEL
    endpoint: str | None = None
    timeout: float = 120.0
    spec: ProviderSpec | None = field(default=None, compare=False, repr=False)

    def validate(self) -> AISelection:
        validate_ollama_config(self.model, self.timeout)
        if self.spec is None:
            resolve_provider(self.provider, self.endpoint)
        elif self.spec.provider_id != self.provider:
            raise ValueError("AI selection spec does not match the selected provider.")
        return self

    def build(self) -> AIProvider:
        if self.spec is not None:
            return provider_for_spec(self.spec)
        return build_provider(self.provider, self.endpoint)

    def destination(self) -> str:
        if self.spec is not None:
            return self.spec.endpoint()
        return resolve_provider(self.provider, self.endpoint).endpoint()

    def describe(self) -> dict[str, object]:
        return {
            "provider": self.provider,
            "model": self.model,
            "endpoint": self.destination(),
            "timeout": float(self.timeout),
            "remote": False,
            "tool_calling": False,
        }


def selection_from_args(
    provider: str | None, model: str | None, timeout: float, endpoint: str | None = None
) -> AISelection | None:
    """CLI helper: ``None`` (no ``--ai-provider``) keeps the legacy client; ``--ai-endpoint`` needs a provider."""
    if provider is None:
        if endpoint is not None:
            raise ValueError("--ai-endpoint requires --ai-provider.")
        return None
    if provider not in ALLOWED_PROVIDERS:
        raise ValueError(f"--ai-provider must be one of: {', '.join(ALLOWED_PROVIDERS)}.")
    return AISelection(provider, model or DEFAULT_OLLAMA_MODEL, endpoint, float(timeout)).validate()


@dataclass
class AICallLog:
    """Secret-free per-run telemetry. Prompts are fingerprinted, never stored."""

    calls: list[dict[str, object]] = field(default_factory=list)

    def record(self, entry: dict[str, object]) -> None:
        self.calls.append(entry)

    def summary(self) -> dict[str, object]:
        errors: dict[str, int] = {}
        for call in self.calls:
            code = call.get("error_code")
            if isinstance(code, str):
                errors[code] = errors.get(code, 0) + 1
        durations = [value for c in self.calls if isinstance((value := c.get("duration_ms")), (int, float))]
        first = self.calls[0] if self.calls else {}
        return {
            "provider": first.get("provider"),
            "model": first.get("model"),
            "endpoint": first.get("endpoint"),
            "path": first.get("path"),
            "calls": len(self.calls),
            "errors": dict(sorted(errors.items())),
            "duration_ms_total": round(sum(durations), 3),
            "prompt_stored": False,
            "tool_calling_enabled": False,
            "execution_performed": False,
        }


def sensitive_content_findings(messages: list[dict[str, str]]) -> int:
    return sum(len(pattern.findall(message["content"])) for message in messages for pattern in SENSITIVE_PATTERNS)


def _entry(path: str, provider: str, model: str, endpoint: str, messages: list[dict[str, str]]) -> dict[str, object]:
    return {
        "path": path,
        "provider": provider,
        "model": model,
        "endpoint": endpoint,
        "prompt_sha256": prompt_fingerprint(messages),
        "prompt_chars": sum(len(message["content"]) for message in messages),
        "prompt_stored": False,
        "error_code": None,
    }


def dispatch_chat(
    selection: AISelection | None,
    messages: list[dict[str, str]],
    schema: dict[str, Any],
    max_tokens: int,
    legacy: Callable[[], str],
    log: AICallLog | None = None,
) -> str:
    """Send one minimized, structured request to the selected local provider and return its raw text.

    ``legacy`` is the caller's historical ``chat_with_ollama`` invocation, used only when
    ``selection`` is ``None``. Raises :class:`OllamaUnavailableError` (or the subclass
    :class:`AIBackendUnavailableError`) for unreachable providers and ``ValueError`` for
    unsafe/invalid output, matching the legacy exception contract.
    """
    if selection is None:
        entry = _entry("legacy_ollama", "ollama", "legacy", LEGACY_DESTINATION, messages)
        started = perf_counter()
        try:
            return legacy()
        except OllamaUnavailableError:
            entry["error_code"] = "unavailable"
            raise
        except ValueError:
            entry["error_code"] = "invalid_response"
            raise
        finally:
            entry["duration_ms"] = round((perf_counter() - started) * 1000, 3)
            if log is not None:
                log.record(entry)
    selection.validate()
    entry = _entry("ai_provider", selection.provider, selection.model, selection.destination(), messages)
    started = perf_counter()
    try:
        if sensitive_content_findings(messages):
            raise AIProviderError(
                "sensitive_content_refused", "Prompt still contained secret-like content after minimization."
            )
        limits = GenerationLimits(
            timeout=float(selection.timeout),
            max_output_tokens=max_tokens,
            max_prompt_chars=48_000,
        )
        result = selection.build().generate_structured(messages, schema, selection.model, limits)
        entry.update(
            {
                "response_bytes": result.response_bytes,
                "finish_reason": result.finish_reason,
                "reported_model": result.reported_model,
            }
        )
        if not result.complete:
            raise AIProviderError("incomplete", "Local model output was truncated before completion.")
        return result.content
    except AIProviderError as exc:
        entry["error_code"] = exc.code
        if exc.code in UNAVAILABLE_CODES:
            raise AIBackendUnavailableError(exc.code, "Local AI provider unavailable; no remote fallback.") from exc
        raise
    finally:
        entry["duration_ms"] = round((perf_counter() - started) * 1000, 3)
        if log is not None:
            log.record(entry)


TEXT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {"markdown": {"type": "string"}},
    "required": ["markdown"],
    "additionalProperties": False,
}


def destination(selection: AISelection | None) -> str:
    return LEGACY_DESTINATION if selection is None else selection.destination()


def provider_label(selection: AISelection | None) -> str:
    return "ollama-local" if selection is None else f"{selection.provider}-local"


def review_packet(
    packet: dict[str, Any],
    model: str,
    timeout: float,
    selection: AISelection | None = None,
    log: AICallLog | None = None,
) -> dict[str, Any]:
    """Legacy minimized-packet review (``review_with_ollama`` contract) on the selected provider."""
    if selection is None:
        return review_with_ollama(packet, model, timeout)
    selection.validate()
    messages = review_messages(packet)
    content = dispatch_chat(selection, messages, REVIEW_SCHEMA, 512, lambda: "", log)
    assessment = validate_review_assessment(content)
    return {
        "provider": provider_label(selection),
        "model": selection.model,
        "assessment": assessment,
        "source_claims_unverified": True,
        "external_service_used": False,
        "request_destination": selection.destination(),
        "raw_evidence_sent": False,
        "finding_confirmed": False,
    }
