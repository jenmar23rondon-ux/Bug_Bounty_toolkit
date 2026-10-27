from __future__ import annotations

from .reflection_detector import ReflectionResult


def classify_reflection(reflection: ReflectionResult, content_type: str) -> dict[str, object]:
    """Reflection alone is candidate; never confirmed without Playwright/DOM execution."""
    if not reflection.reflected:
        return {
            "classification": "not_reproducible",
            "finding_state": "not_observed",
            "confirmed": False,
            "confirmation_gap": None,
            "rejection_reason": None,
            "reason": "The marker was not reflected in the response.",
        }
    if reflection.reflected_unescaped and "text/html" in content_type.lower():
        return {
            "classification": "possible",
            "finding_state": "candidate",
            "confirmed": False,
            "confirmation_gap": "no_second_proof",
            "rejection_reason": None,
            "reason": "The marker appeared unescaped in an HTML response. Browser execution proof is required to confirm.",
        }
    return {
        "classification": "possible",
        "finding_state": "candidate",
        "confirmed": False,
        "confirmation_gap": "no_second_proof",
        "rejection_reason": None,
        "reason": "The marker was reflected, but reflection alone does not confirm XSS.",
    }
