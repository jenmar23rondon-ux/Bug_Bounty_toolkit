from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from .ai_backend import AISelection, review_packet, selection_from_args
from .evidence_review import review_evidence
from .ollama_review import DEFAULT_OLLAMA_MODEL, review_with_ollama, validate_ollama_config


DEFAULT_AI_REVIEW_TIMEOUT = 120.0


def add_ai_review_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--ai-review",
        action="store_true",
        help="Optionally ask local Ollama to classify minimized candidate evidence",
    )
    parser.add_argument("--ai-model", help=f"Installed local Ollama model (default: {DEFAULT_OLLAMA_MODEL})")
    parser.add_argument(
        "--ai-timeout",
        type=float,
        help=f"Local Ollama timeout in seconds (default: {DEFAULT_AI_REVIEW_TIMEOUT:g})",
    )
    parser.add_argument(
        "--ai-provider",
        choices=("ollama", "lmstudio"),
        help="Allowlisted local provider for --ai-review (default: legacy Ollama client)",
    )
    parser.add_argument("--ai-endpoint", help="Optional restatement of the provider's authorized loopback host:port")


def resolve_ai_review_config(
    enabled: bool,
    model: str | None,
    timeout: float | None,
    provider: str | None = None,
    endpoint: str | None = None,
) -> tuple[str, float] | tuple[str, float, AISelection] | None:
    """Return ``(model, timeout)`` for the legacy client, or ``(model, timeout, selection)``."""
    if not enabled:
        if model is not None or timeout is not None or provider is not None or endpoint is not None:
            raise ValueError("--ai-model, --ai-timeout, --ai-provider and --ai-endpoint require --ai-review.")
        return None

    selected_model = model or DEFAULT_OLLAMA_MODEL
    selected_timeout = DEFAULT_AI_REVIEW_TIMEOUT if timeout is None else timeout
    validate_ollama_config(selected_model, selected_timeout)
    selection = selection_from_args(provider, selected_model, float(selected_timeout), endpoint)
    if selection is None:
        return selected_model, float(selected_timeout)
    return selected_model, float(selected_timeout), selection


def config_selection(config: tuple[object, ...]) -> AISelection | None:
    return next((item for item in config if isinstance(item, AISelection)), None)


def has_review_candidate(evidence: dict[str, Any]) -> bool:
    topic = evidence.get("type")
    classification = evidence.get("classification")
    if classification in {"candidate", "possible"} or (topic == "csrf-audit" and classification == "possible_csrf"):
        return True
    rows = evidence.get("steps" if topic == "access-control" else "results", [])
    if not isinstance(rows, list):
        return False
    accepted = {"candidate", "possible"}
    if topic in {"cors", "open-redirect"}:
        accepted.add("VULNERABLE")
    elif topic == "csrf-audit":
        accepted.add("possible_csrf")
    return any(isinstance(row, dict) and row.get("classification") in accepted for row in rows)


def review_evidence_file(
    path: Path, model: str, timeout: float, selection: AISelection | None = None
) -> dict[str, Any] | str:
    evidence = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(evidence, dict):
        raise ValueError("Native evidence must be a JSON object.")

    if not has_review_candidate(evidence):
        ai_review: dict[str, Any] | str = {"status": "skipped", "reason": "no_candidate_or_possible_finding"}
    else:
        try:
            packet = review_evidence(evidence)
            result = (
                review_with_ollama(packet, model, timeout)
                if selection is None
                else review_packet(packet, model, timeout, selection)
            )
            ai_review = {"status": "available", **result}
            assessment = result.get("assessment")
            if isinstance(assessment, dict) and isinstance(assessment.get("summary"), str):
                ai_review["reason"] = " ".join(assessment["summary"].split())[:1200]
        except Exception:
            ai_review = "unavailable"

    evidence["ai_review"] = ai_review
    path.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return ai_review


def format_ai_review(ai_review: dict[str, Any] | str, toolkit_verdict: str) -> str:
    if isinstance(ai_review, str):
        return f"[i] AI second opinion: {ai_review}; toolkit verdict remains {toolkit_verdict}. AI does not confirm findings."
    if ai_review.get("status") == "skipped":
        return f"[i] AI second opinion skipped (no candidate/possible finding); toolkit verdict: {toolkit_verdict}."
    assessment = ai_review.get("assessment", ai_review)
    if not isinstance(assessment, dict):
        assessment = ai_review
    decision = assessment.get("decision") if isinstance(assessment, dict) else None
    if decision not in {"candidate", "not_observed", "inconclusive"}:
        decision = "inconclusive"
    reason = assessment.get("summary", assessment.get("reason")) if isinstance(assessment, dict) else None
    if not isinstance(reason, str) or not reason.strip():
        reason = "No reason was returned."
    reason = " ".join(reason.split())[:500]
    return (
        f"[i] AI second opinion: {decision} ({reason}); toolkit verdict: {toolkit_verdict}. "
        "AI does not confirm findings."
    )
