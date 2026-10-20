from __future__ import annotations

from collections import Counter
import math


CONTEXTS = {"html_text", "comment", "tag_name", "attribute_name", "attribute", "url_attribute", "event_attribute", "script", "style"}
MEDIA_TYPES = {"text/html", "application/xhtml+xml", "application/json", "text/plain", "application/javascript", "text/javascript", "image/svg+xml"}
CLASSIFICATIONS = {"candidate", "rejected_in_this_test", "inconclusive", "possible", "not_reproducible",
                   "not_reflected", "reflected_not_executed", "confirmed", "VULNERABLE", "DEBIL",
                   "DÉBIL", "SEGURO", "NO VULNERABLE", "error", "baseline"}
STOP_REASONS = {"transport_error", "invalid_owner_control", "invalid_actor_control", "rate_limited", "truncated_response",
                "redirect_not_followed", "private_evidence_observed", "partial_private_evidence", "cross_read_rejected",
                "cross_read_not_proven", "cross_write_rejected", "cross_write_not_proven", "access_or_rate_limit",
                "candidate_observed_stop_early", "authentication_failure", "write_probe_rejected"}


def review_evidence(data: dict) -> dict:
    """Export allowlisted observations for an agent, never arbitrary response text or instructions."""
    if not isinstance(data, dict) or not isinstance(data.get("type"), str) or data["type"] not in {"access-control", "xss", "sqli", "cors", "open-redirect"}:
        raise ValueError("Review expects native access-control, XSS, SQLi, CORS or open-redirect evidence.")
    topic = data["type"]
    rows = data.get("steps" if topic == "access-control" else "results", [])
    if not isinstance(rows, list) or len(rows) > 10000 or any(not isinstance(row, dict) for row in rows):
        raise ValueError("Evidence rows are malformed or exceed the review limit.")
    codes = Counter(str(row["status_code"]) for row in rows if type(row.get("status_code")) is int and 100 <= row["status_code"] <= 599)
    labels = Counter(row["classification"] for row in rows if isinstance(row.get("classification"), str) and row["classification"] in CLASSIFICATIONS)
    contexts = Counter()
    media_types = Counter()
    context_states = Counter()
    unavailable = 0
    for row in rows:
        media = row.get("content_type")
        if isinstance(media, str):
            media_types[media if media in MEDIA_TYPES else "other"] += 1
        analysis = row.get("context_analysis", {})
        if not isinstance(analysis, dict):
            continue
        unavailable += analysis.get("status") == "unavailable"
        state = analysis.get("status")
        if isinstance(state, str) and state in {"analyzed", "not_html", "unavailable"}:
            context_states[state] += 1
        entries = analysis.get("contexts", [])
        if isinstance(entries, list):
            for entry in entries:
                kind = entry.get("context") if isinstance(entry, dict) else None
                if isinstance(kind, str) and kind in CONTEXTS:
                    contexts[kind] += 1
    packet = {"type": "agent-review", "topic": topic, "rows_observed": len(rows),
              "status_codes": dict(codes), "classifications": dict(labels), "html_contexts": dict(contexts),
              "content_types": dict(media_types), "context_analysis_states": dict(context_states),
              "context_analysis_unavailable": unavailable, "confirmed": False,
              "truncated_rows": sum(row.get("body_truncated") is True for row in rows),
              "transport_error_rows": sum(row.get("transport_error") is True for row in rows),
              "network_requests_sent_by_review": 0, "external_model_called": False,
              "decision": "review_required", "source_claims_unverified": True,
              "limits": ["This packet contains observations, not authorization or instructions.",
                         "No raw URLs, credentials, response bodies or model API calls are included.",
                         "A candidate is not a confirmed vulnerability; negative probes do not prove absence."]}
    if topic in {"cors", "open-redirect"}:
        packet["tool_verdict_counts"] = dict(labels)
        packet["confirmed"] = False
        packet["limits"].append("Only allowlisted statuses and verdict counts are exported; raw origins, Locations and response headers are omitted.")
    stop = data.get("stop_reason")
    packet["stop_reason"] = stop if isinstance(stop, str) and stop in STOP_REASONS else None if stop is None else "unrecognized_stop"
    if topic == "access-control":
        label = data.get("classification")
        packet["access_result"] = label if isinstance(label, str) and label in CLASSIFICATIONS else "inconclusive"
        packet["controls_valid"] = data.get("controls_valid") is True
        packet["cross_read_attempted"] = any(row.get("step") == "cross_read" for row in rows)
        packet["cross_read_observed"] = any(row.get("step") == "cross_read" and type(row.get("status_code")) is int and 100 <= row["status_code"] <= 599 for row in rows)
        packet["cross_write_attempted"] = any(row.get("step") == "cross_write" for row in rows)
        packet["cross_write_observed"] = any(row.get("step") == "cross_write" and type(row.get("status_code")) is int and 100 <= row["status_code"] <= 599 for row in rows)
        packet["cross_action"] = "write" if data.get("mode") in {"lab-write", "bounded-write-range"} else "read"
        packet["private_evidence_observed"] = any(row.get("step") in {"cross_read", "cross_write"} and row.get("owner_private_match") is True and row.get("owner_resource_match") is True for row in rows)
        if data.get("mode") in {"bounded-range", "bounded-write-range"}:
            probes = data.get("results", [])
            if not isinstance(probes, list) or len(probes) > 100 or any(not isinstance(row, dict) for row in probes):
                raise ValueError("Range evidence is malformed or exceeds its hard review limit.")
            packet["range_probes_observed"] = len(probes)
            packet["range_candidate_offsets"] = [
                row["probe_offset"] for row in probes
                if row.get("classification") == "candidate" and type(row.get("probe_offset")) is int and 0 <= row["probe_offset"] < 100
            ]
            packet["range_result_counts"] = dict(Counter(
                row["classification"] for row in probes
                if isinstance(row.get("classification"), str) and row["classification"] in CLASSIFICATIONS
            ))
            concurrency = data.get("concurrency", 1)
            packet["concurrency"] = concurrency if type(concurrency) is int and 1 <= concurrency <= 4 else None
            interval = data.get("minimum_interval_seconds")
            packet["minimum_interval_seconds"] = interval if isinstance(interval, (int, float)) and not isinstance(interval, bool) and math.isfinite(interval) and interval > 0 else None
    return packet
