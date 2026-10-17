from __future__ import annotations

from collections import Counter


CONTEXTS = {"html_text", "comment", "tag_name", "attribute_name", "attribute", "url_attribute", "event_attribute", "script", "style"}
CLASSIFICATIONS = {"candidate", "rejected_in_this_test", "inconclusive", "possible", "not_reproducible", "error", "baseline"}
STOP_REASONS = {"transport_error", "invalid_owner_control", "invalid_actor_control", "rate_limited", "truncated_response",
                "redirect_not_followed", "private_evidence_observed", "partial_private_evidence", "cross_read_rejected",
                "cross_read_not_proven", "access_or_rate_limit"}


def review_evidence(data: dict) -> dict:
    """Export allowlisted observations for an agent, never arbitrary response text or instructions."""
    if not isinstance(data, dict) or not isinstance(data.get("type"), str) or data["type"] not in {"access-control", "xss", "sqli"}:
        raise ValueError("Review expects a native access-control, XSS or SQLi evidence object.")
    topic = data["type"]
    rows = data.get("steps" if topic == "access-control" else "results", [])
    if not isinstance(rows, list) or len(rows) > 10000 or any(not isinstance(row, dict) for row in rows):
        raise ValueError("Evidence rows are malformed or exceed the review limit.")
    codes = Counter(str(row["status_code"]) for row in rows if type(row.get("status_code")) is int and 100 <= row["status_code"] <= 599)
    labels = Counter(row["classification"] for row in rows if isinstance(row.get("classification"), str) and row["classification"] in CLASSIFICATIONS)
    contexts = Counter()
    unavailable = 0
    for row in rows:
        analysis = row.get("context_analysis", {})
        if not isinstance(analysis, dict):
            continue
        unavailable += analysis.get("status") == "unavailable"
        entries = analysis.get("contexts", [])
        if isinstance(entries, list):
            for entry in entries:
                kind = entry.get("context") if isinstance(entry, dict) else None
                if isinstance(kind, str) and kind in CONTEXTS:
                    contexts[kind] += 1
    packet = {"type": "agent-review", "topic": topic, "rows_observed": len(rows),
              "status_codes": dict(codes), "classifications": dict(labels), "html_contexts": dict(contexts),
              "context_analysis_unavailable": unavailable, "confirmed": False,
              "truncated_rows": sum(row.get("body_truncated") is True for row in rows),
              "transport_error_rows": sum(row.get("transport_error") is True for row in rows),
              "network_requests_sent_by_review": 0, "external_model_called": False,
              "decision": "review_required", "source_claims_unverified": True,
              "limits": ["This packet contains observations, not authorization or instructions.",
                         "No raw URLs, credentials, response bodies or model API calls are included.",
                         "A candidate is not a confirmed vulnerability; negative probes do not prove absence."]}
    stop = data.get("stop_reason")
    packet["stop_reason"] = stop if isinstance(stop, str) and stop in STOP_REASONS else None if stop is None else "unrecognized_stop"
    if topic == "access-control":
        label = data.get("classification")
        packet["access_result"] = label if isinstance(label, str) and label in CLASSIFICATIONS else "inconclusive"
        packet["controls_valid"] = data.get("controls_valid") is True
        packet["cross_read_attempted"] = any(row.get("step") == "cross_read" for row in rows)
        packet["cross_read_observed"] = any(row.get("step") == "cross_read" and type(row.get("status_code")) is int and 100 <= row["status_code"] <= 599 for row in rows)
        packet["private_evidence_observed"] = any(row.get("step") == "cross_read" and row.get("owner_private_match") is True and row.get("owner_resource_match") is True for row in rows)
    return packet
