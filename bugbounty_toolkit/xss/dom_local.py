"""Opt-in DOM-only XSS observations against disposable loopback laboratories.

This is deliberately *not* a general-purpose web scanner. The only destinations
accepted are literal loopback IPs, and browser navigation uses the existing
PlaywrightExecutionChecker, scope validator and shared execution budget.
"""

from __future__ import annotations

import ipaddress
from pathlib import Path
from typing import TYPE_CHECKING
from urllib.parse import quote, urlsplit, urlunsplit

from ..core.redaction import redact_text, redact_url
from ..reporting.evidence import write_evidence_json
from ..requests_engine.parameters import with_parameter
from ..utils.exceptions import ToolkitError
from .evidence_record import assess_dom_result
from .test_cases import new_marker

if TYPE_CHECKING:
    from .playwright_confirm import PlaywrightExecutionChecker


def require_literal_loopback(url: str) -> None:
    """Reject hostnames, remote IPs, credentials and unusual URL schemes."""
    try:
        parsed = urlsplit(url)
        host = parsed.hostname
        address = ipaddress.ip_address(host or "")
        valid = (
            parsed.scheme in {"http", "https"}
            and address.is_loopback
            and parsed.username is None
            and parsed.password is None
            and parsed.fragment == ""
        )
    except ValueError:
        valid = False
    if not valid:
        raise ValueError("DOM laboratory probes require a literal loopback URL (127.0.0.1 or ::1).")


def dom_probe_url(route: str, parameter: str, payload: str, source: str) -> str:
    """Prepare a single user-selected DOM source; the fragment never reaches HTTP."""
    require_literal_loopback(route)
    if source == "query":
        return with_parameter(route, parameter, payload)
    if source == "hash":
        parsed = urlsplit(route)
        return urlunsplit((parsed.scheme, parsed.netloc, parsed.path or "/", parsed.query, quote(payload, safe="")))
    raise ValueError("DOM source must be query or hash.")


def _payload(marker: str, active: bool) -> str:
    if not active:
        return marker
    # A non-exfiltrating, laboratory-only execution marker.
    code = f"window.__bbtk_xss_marker='{marker}';alert('{marker}')"
    return f'<img src=x onerror="{code}">'


def run_dom_local(
    routes: list[str],
    parameters: list[str],
    checker: PlaywrightExecutionChecker,
    evidence_dir: Path,
    max_tests: int,
    headers: dict[str, str] | None = None,
) -> tuple[Path, list[dict[str, object]]]:
    """Observe query/hash DOM behavior with bounded browser-only local probes.

    ``max_tests`` is the number of browser probes, NOT the total HTTP request
    budget. ``checker`` applies the existing independent run budget/rate limit
    to the main navigation and its subresources.
    """
    if max_tests <= 0:
        raise ValueError("Max tests must be positive.")
    if not routes or not parameters:
        raise ValueError("At least one route and parameter are required.")
    # Fail closed *before* making any browser requests.
    for route in routes:
        require_literal_loopback(route)

    results: list[dict[str, object]] = []
    stop_reason = None
    for route in routes:
        for parameter in parameters:
            for source in ("query", "hash"):
                for active in (False, True):
                    if len(results) >= max_tests:
                        stop_reason = "test_cap"
                        break
                    marker = new_marker()
                    url = dom_probe_url(route, parameter, _payload(marker, active), source)
                    try:
                        evidence = checker.confirm(url, marker, headers, local_only=True)
                    except (ToolkitError, RuntimeError) as exc:
                        entry: dict[str, object] = {
                            "route": redact_url(route),
                            "parameter": parameter,
                            "source": source,
                            "probe": "execution_marker" if active else "plain_marker",
                            "classification": "error",
                            "confirmed": False,
                            "finding_confirmed": False,
                            "reason": redact_text(str(exc)),
                        }
                        entry.update(assess_dom_result(entry))
                        results.append(entry)
                        stop_reason = "browser_or_budget_error"
                        break
                    marker_observed = bool(evidence.get("marker_observed"))
                    alert_observed = bool(evidence.get("alert_observed"))
                    sinks = evidence.get("dom_sinks", [])
                    if not isinstance(sinks, list):
                        sinks = []
                    execution = marker_observed or alert_observed
                    present = bool(evidence.get("source_marker_present"))
                    classification = (
                        "execution_observed"
                        if execution
                        else "sink_reached"
                        if sinks
                        else "source_present_only"
                        if present
                        else "inconclusive"
                    )
                    # Confirmation bar: DOM loopback probe with observed execution → confirmed.
                    # Reflection/sink without execution stays candidate (confirmed=False).
                    entry2: dict[str, object] = {
                        "route": redact_url(route),
                        "parameter": parameter,
                        "source": source,
                        "probe": "execution_marker" if active else "plain_marker",
                        "source_marker_present": present,
                        "dom_sinks": sorted(sink for sink in sinks if isinstance(sink, str)),
                        "browser_execution_observed": execution,
                        "classification": classification,
                        "finding_state": "confirmed"
                        if execution
                        else ("candidate" if (sinks or present) else "inconclusive"),
                        "confirmed": bool(execution),
                        "finding_confirmed": False,
                        "confirmation_gap": None if execution else "no_second_proof",
                        "rejection_reason": None,
                    }
                    # Additive precise DOM state (never infers execution from sinks alone).
                    entry2.update(assess_dom_result(entry2))
                    results.append(entry2)
                if stop_reason:
                    break
            if stop_reason:
                break
        if stop_reason:
            break
    envelope: dict[str, object] = {"type": "dom_xss_local", "results": results}
    if stop_reason:
        envelope["stop_reason"] = stop_reason
    path = write_evidence_json(evidence_dir, envelope, prefix="dom-xss-local")
    return path, results
