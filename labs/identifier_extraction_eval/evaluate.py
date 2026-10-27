"""Run the adversarial corpus against the new extractor and the legacy baseline."""

from __future__ import annotations

import resource
import time
from typing import Any

from bugbounty_toolkit.analysis.identifier_candidates import extract_candidates

from .fixtures import cases
from .legacy_baseline import legacy_extract
from .metrics import aggregate, score


def _match_fields(expected: dict[str, Any], predicted: dict[str, Any]) -> bool:
    return all(predicted.get(key) == expected[key] for key in expected)


def _filter_predictions(expected: list[dict[str, Any]], predicted: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Keep predicted fields that the ground truth cares about for scoring."""
    filtered: list[dict[str, Any]] = []
    for item in predicted:
        for truth in expected:
            if all(item.get(key) == truth[key] for key in truth):
                filtered.append({key: item[key] for key in truth})
                break
        else:
            # Extra prediction: keep a reduced key set so precision is penalised.
            filtered.append(
                {
                    "value": item.get("value"),
                    "value_type": item.get("value_type"),
                    "id_format": item.get("id_format"),
                    "source": item.get("source"),
                    "locator": item.get("locator"),
                }
            )
    return filtered


def _run_one(extractor: Any, case: dict[str, Any]) -> dict[str, Any]:
    kwargs = {
        key: case[key] for key in ("url", "json_body", "xml_body", "form_body", "declared_references") if key in case
    }
    if extractor is extract_candidates:
        result = extract_candidates(**kwargs)
        predicted = [candidate.as_dict() for candidate in result.candidates]
        rejected = list(result.rejected)
        uncertain = list(result.uncertain)
    else:
        predicted = legacy_extract(**kwargs)
        rejected = []
        uncertain = []
    expected = case.get("expected", [])
    # Align predicted shapes to the fields asserted by the ground truth.
    aligned = []
    used: set[int] = set()
    for truth in expected:
        for index, item in enumerate(predicted):
            if index in used:
                continue
            if all(item.get(key) == truth[key] for key in truth):
                aligned.append(dict(truth))
                used.add(index)
                break
    # Unmatched predictions count against precision.
    for index, item in enumerate(predicted):
        if index not in used:
            aligned.append(
                {
                    "value": item.get("value"),
                    "value_type": item.get("value_type"),
                    "id_format": item.get("id_format"),
                    "source": item.get("source"),
                    "locator": item.get("locator"),
                }
            )
    metrics = score(expected, aligned)
    secret_leak = False
    for item in predicted:
        name = str(item.get("field_name", ""))
        value = str(item.get("value", ""))
        if "token" in name.lower() or "password" in name.lower() or "csrf" in name.lower():
            secret_leak = True
        if value.startswith("eyJ"):
            secret_leak = True
    for forbidden in case.get("must_not_include", []):
        if any(item.get("value") == forbidden for item in predicted):
            secret_leak = True
    types_preserved = (
        all(
            any(
                item.get("value") == truth["value"] and item.get("value_type") == truth.get("value_type")
                for item in predicted
            )
            for truth in expected
            if "value_type" in truth
        )
        if expected
        else True
    )
    locators_valid = all(isinstance(item.get("locator"), str) and item["locator"].startswith("/") for item in predicted)
    rejected_ok = (not case.get("expect_rejected")) or bool(rejected) or (not predicted)
    return {
        "id": case["id"],
        "metrics": metrics,
        "secret_leak": secret_leak,
        "types_preserved": types_preserved,
        "locators_valid": locators_valid,
        "rejected_ok": rejected_ok,
        "predicted_count": len(predicted),
        "rejected": rejected,
        "uncertain": uncertain,
    }


def evaluate(extractor: Any = extract_candidates) -> dict[str, Any]:
    started = time.perf_counter()
    rss_before = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    rows = [_run_one(extractor, case) for case in cases()]
    elapsed = time.perf_counter() - started
    rss_after = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    by_format: dict[str, list[dict[str, float]]] = {}
    for case, row in zip(cases(), rows):
        for expected in case.get("expected", []) or [{"source": "none"}]:
            source = expected.get("source", "none")
            by_format.setdefault(source, []).append(row["metrics"])
    format_recall = {source: aggregate(group)["recall"] for source, group in by_format.items() if source != "none"}
    overall = aggregate([row["metrics"] for row in rows])
    return {
        "overall": overall,
        "format_recall": format_recall,
        "secret_leaks": sum(1 for row in rows if row["secret_leak"]),
        "types_preserved": all(row["types_preserved"] for row in rows),
        "locators_valid": all(row["locators_valid"] for row in rows),
        "rejected_ok": all(row["rejected_ok"] for row in rows),
        "cases": rows,
        "elapsed_seconds": elapsed,
        "rss_kb": max(rss_before, rss_after),
    }


def compare() -> dict[str, Any]:
    before = evaluate(legacy_extract)
    after = evaluate(extract_candidates)
    return {"before": before, "after": after}
