from __future__ import annotations

from .reflection_detector import ReflectionResult


def classify_reflection(reflection: ReflectionResult, content_type: str) -> dict[str, object]:
    if not reflection.reflected:
        return {
            "classification": "not_reproducible",
            "confirmed": False,
            "reason": "The marker was not reflected in the response.",
        }
    if reflection.reflected_unescaped and "text/html" in content_type.lower():
        return {
            "classification": "possible",
            "confirmed": False,
            "reason": "The marker appeared unescaped in an HTML response. Manual browser validation is required.",
        }
    return {
        "classification": "possible",
        "confirmed": False,
        "reason": "The marker was reflected, but reflection alone does not confirm XSS.",
    }
