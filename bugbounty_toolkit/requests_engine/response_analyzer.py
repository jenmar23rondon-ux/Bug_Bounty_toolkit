from __future__ import annotations

from ..core.http_client import ResponseRecord


def analyze_response(record: ResponseRecord, markers: list[str] | None = None) -> dict[str, object]:
    body = record.body_text
    marker_hits = [marker for marker in markers or [] if marker and marker in body]
    return {
        "status_code": record.status_code,
        "duration_ms": record.duration_ms,
        "body_size": record.body_size,
        "content_type": record.headers.get("content-type", ""),
        "server": record.headers.get("server", ""),
        "marker_hits": marker_hits,
        "looks_like_html": "<html" in body[:1000].lower() or "text/html" in record.headers.get("content-type", ""),
    }
