from __future__ import annotations

import json
import re
from pathlib import Path
from urllib.parse import urlsplit

from .deduplicator import deduplicate_results

MAX_FFUF_OUTPUT_BYTES = 25 * 1024 * 1024
MAX_FFUF_RESULTS = 100_000
_ID_SEGMENT = re.compile(r"^(?:[0-9]+|[a-f0-9]{8}-[a-f0-9-]{27,}|[a-f0-9]{24,})$", re.IGNORECASE)


def _optional_nonnegative_int(value: object) -> int | None:
    return value if type(value) is int and value >= 0 else None


def _safe_input(value: object) -> object:
    if isinstance(value, dict):
        return {
            str(key)[:100]: str(item)[:4096]
            for key, item in value.items()
            if isinstance(key, str) and isinstance(item, (str, int, float, bool))
        }
    if isinstance(value, str):
        return value[:4096]
    return None


def _parse_result_rows(data: object) -> list[dict[str, object]]:
    if not isinstance(data, dict) or not isinstance(data.get("results"), list):
        raise ValueError("ffuf JSON must contain a results array.")
    raw_results = data["results"]
    if len(raw_results) > MAX_FFUF_RESULTS:
        raise ValueError(f"ffuf output exceeds the {MAX_FFUF_RESULTS:,}-result limit.")
    parsed: list[dict[str, object]] = []
    for result in raw_results:
        if not isinstance(result, dict):
            continue
        url = result.get("url")
        status = result.get("status")
        if not isinstance(url, str) or len(url) > 8192 or type(status) is not int or not 100 <= status <= 599:
            continue
        redirect = result.get("redirectlocation")
        parsed.append(
            {
                "url": url,
                "status": status,
                "length": _optional_nonnegative_int(result.get("length")),
                "words": _optional_nonnegative_int(result.get("words")),
                "lines": _optional_nonnegative_int(result.get("lines")),
                "redirectlocation": redirect[:8192] if isinstance(redirect, str) else None,
                "input": _safe_input(result.get("input")),
            }
        )
    return parsed


def parse_ffuf_results(path: Path) -> list[dict[str, object]]:
    """Parse bounded ffuf JSON and skip malformed result rows safely."""
    if not path.exists():
        raise FileNotFoundError(path)
    if path.stat().st_size > MAX_FFUF_OUTPUT_BYTES:
        raise ValueError(f"ffuf JSON exceeds the {MAX_FFUF_OUTPUT_BYTES:,}-byte safety limit.")
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise ValueError("ffuf output is not valid UTF-8 JSON.") from exc
    return deduplicate_results(_parse_result_rows(data))


def _response_signature(result: dict[str, object]) -> tuple[object, object, object, object]:
    return (result.get("status"), result.get("length"), result.get("words"), result.get("lines"))


def _matches_baseline(result: dict[str, object], baseline: dict[str, object]) -> bool:
    if result.get("status") != baseline.get("status") or baseline.get("body_truncated") is True:
        return False
    result_length = result.get("length")
    baseline_length = baseline.get("length")
    result_words = result.get("words")
    baseline_words = baseline.get("words")
    result_lines = result.get("lines")
    baseline_lines = baseline.get("lines")
    if not all(type(value) is int for value in (result_length, baseline_length, result_words, baseline_words)):
        return False
    length_tolerance = max(32, int(baseline_length * 0.08))
    return (
        abs(result_length - baseline_length) <= length_tolerance
        and abs(result_words - baseline_words) <= max(2, int(baseline_words * 0.1))
        and (
            type(result_lines) is not int or type(baseline_lines) is not int or abs(result_lines - baseline_lines) <= 2
        )
        and (
            result.get("status") not in {301, 302, 303, 307, 308}
            or result.get("redirectlocation") == baseline.get("redirectlocation")
        )
    )


def _endpoint_group(url: str) -> str:
    parsed = urlsplit(url)
    parts = ["{id}" if _ID_SEGMENT.fullmatch(part) else part for part in parsed.path.split("/")]
    return f"{parsed.scheme.lower()}://{parsed.netloc.lower()}{'/'.join(parts)}"


def _classify(status: int, baseline_match: bool, redirect_location: object, url: str) -> str:
    if status == 429:
        return "rate_limited"
    if status == 401:
        return "authentication_required"
    if status == 403:
        return "access_denied"
    if status >= 500:
        return "server_error"
    if baseline_match:
        return "generic_response"
    if 300 <= status < 400:
        location = redirect_location.casefold() if isinstance(redirect_location, str) else ""
        if any(marker in location for marker in ("/login", "/signin", "/auth", "/session")):
            return "authentication_redirect"
        return "redirect"
    path_parts = {part.casefold() for part in urlsplit(url).path.split("/") if part}
    if path_parts.intersection({"login", "signin", "authenticate", "auth", "session"}):
        return "authentication_route"
    if status == 404:
        return "not_found"
    if 200 <= status < 300:
        return "endpoint_candidate"
    return "inconclusive"


def classify_ffuf_results(
    results: list[dict[str, object]], baseline: dict[str, object] | None
) -> list[dict[str, object]]:
    """Classify response shapes as discovery signals, never as security findings."""
    signatures: dict[tuple[object, object, object, object], str] = {}
    grouped: list[dict[str, object]] = []
    for result in results:
        status = result.get("status")
        if type(status) is not int:
            continue
        signature = _response_signature(result)
        group = signatures.setdefault(signature, f"response-{len(signatures) + 1:04d}")
        baseline_match = baseline is not None and _matches_baseline(result, baseline)
        classified = {
            **result,
            "classification": _classify(
                status, baseline_match, result.get("redirectlocation"), str(result.get("url", ""))
            ),
            "baseline_match": baseline_match,
            "response_group": group,
            "endpoint_group": _endpoint_group(str(result.get("url", ""))),
        }
        if baseline is None:
            classified["classification"] = "inconclusive"
            classified["baseline_match"] = None
        grouped.append(classified)
    return grouped


def build_authorization_followups(results: list[dict[str, object]]) -> list[dict[str, object]]:
    """Suggest manual authorization review for observed resource-shaped routes."""
    resource_names = {"users", "accounts", "orders", "invoices", "documents", "profiles", "addresses", "files"}
    followups: list[dict[str, object]] = []
    seen: set[str] = set()
    for result in results:
        if result.get("classification") != "endpoint_candidate":
            continue
        url = result.get("url")
        if not isinstance(url, str):
            continue
        parts = [part for part in urlsplit(url).path.split("/") if part]
        for index, part in enumerate(parts[:-1]):
            resource_id = parts[index + 1]
            if part.casefold() not in resource_names or not _ID_SEGMENT.fullmatch(resource_id):
                continue
            route_template = "/" + "/".join([*parts[: index + 1], "{id}", *parts[index + 2 :]])
            if route_template in seen:
                break
            seen.add(route_template)
            followups.append(
                {
                    "route_template": route_template,
                    "status_observed": result.get("status"),
                    "classification": "candidate_for_authorization_review",
                    "resource_privacy": "unknown",
                    "why": "A resource-shaped route returned a response different from the not-found baseline.",
                    "missing_controls": [
                        "owner account can read its own known resource",
                        "second authorized account can read its own known resource",
                        "cross-account read with a known resource ID",
                    ],
                    "next_step": "Prepare a reviewed private case.json and run access-check in dry-run first.",
                    "vulnerability_confirmed": False,
                }
            )
            break
    return followups
