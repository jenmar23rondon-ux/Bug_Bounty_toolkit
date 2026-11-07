"""In-scope DOM XSS probes that reuse the Playwright validator and run budget.

``--dom`` navigates only the operator-supplied route on that route's origin.
``--dom-local`` is the same probe with the existing literal-loopback restriction.
Confirmation requires two independent observations: an instrumented DOM sink
received the marker, and the marker variable or a matching alert fired.
Reflection into the DOM without execution stays ``reflected_not_executed``.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING
from urllib.parse import quote, urlsplit, urlunsplit

from ..core.redaction import redact_text, redact_url
from ..reporting.evidence import write_evidence_json
from ..requests_engine.parameters import with_parameter
from ..utils.exceptions import ToolkitError
from .dom_local import require_literal_loopback
from .evidence_record import assess_dom_result
from .test_cases import new_marker

if TYPE_CHECKING:
    from .playwright_confirm import PlaywrightExecutionChecker


def validate_dom_route(route: str, *, loopback_only: bool) -> None:
    """Reject schemes, credentials, and fragments before any browser navigation."""
    if loopback_only:
        require_literal_loopback(route)
        return
    parsed = urlsplit(route)
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
    ):
        raise ValueError(
            "DOM probes require an absolute http(s) URL on the target origin, without credentials or a fragment."
        )


def _origin_key(url: str) -> tuple[str, str, int | None]:
    parsed = urlsplit(url)
    scheme = parsed.scheme.lower()
    port = parsed.port or (443 if scheme == "https" else 80 if scheme == "http" else None)
    return scheme, (parsed.hostname or "").lower(), port


def dom_scope_probe_url(
    route: str,
    parameter: str,
    payload: str,
    source: str,
    *,
    loopback_only: bool = False,
) -> str:
    """Build one query or hash probe that stays on the route origin."""
    validate_dom_route(route, loopback_only=loopback_only)
    if source == "query":
        url = with_parameter(route, parameter, payload)
    elif source == "hash":
        parsed = urlsplit(route)
        url = urlunsplit((parsed.scheme, parsed.netloc, parsed.path or "/", parsed.query, quote(payload, safe="")))
    else:
        raise ValueError("DOM source must be query or hash.")
    if _origin_key(url) != _origin_key(route):
        raise ValueError("DOM probe URL must stay on the target origin.")
    return url


def _payload(marker: str, active: bool) -> str:
    if not active:
        return marker
    # Same non-exfiltrating laboratory marker as the loopback DOM probes.
    code = f"window.__bbtk_xss_marker='{marker}';alert('{marker}')"
    return f'<img src=x onerror="{code}">'


def classify_dom_confirmation(
    *,
    sink_reached: bool,
    marker_observed: bool,
    alert_observed: bool,
    reflected_in_dom: bool,
) -> str:
    """Confirm only with two independent proofs.

    Attributed execution is ``window.__bbtk_xss_marker`` equaling this probe's
    marker, or an alert whose message is exactly that marker. An unrelated
    alert or a different marker string is not execution. An instrumented sink
    receiving the marker is corroboration that the value flowed into the DOM
    API; it is not execution by itself. Either proof alone stays unconfirmed.
    """
    execution = marker_observed or alert_observed
    if sink_reached and execution:
        return "confirmed"
    if (reflected_in_dom or sink_reached) and not execution:
        return "reflected_not_executed"
    if execution:
        return "inconclusive"
    return "not_reflected"


def _finding_state(classification: str) -> str:
    if classification == "confirmed":
        return "confirmed"
    if classification == "reflected_not_executed":
        return "candidate"
    if classification == "not_reflected":
        return "not_observed"
    return "inconclusive"


def _observation(
    route: str,
    parameter: str,
    source: str,
    active: bool,
    evidence: dict[str, object],
) -> dict[str, object]:
    raw_sinks = evidence.get("dom_sinks", [])
    sinks = [sink for sink in raw_sinks if isinstance(sink, str)] if isinstance(raw_sinks, list) else []
    marker_observed = bool(evidence.get("marker_observed"))
    alert_observed = bool(evidence.get("alert_observed"))
    reflected_in_dom = bool(evidence.get("dom_marker_present"))
    # The hook records that the marker string was passed to a DOM API.
    # That observation does not mean JavaScript from the probe ran.
    sink_reached = bool(sinks)
    execution = marker_observed or alert_observed
    classification = classify_dom_confirmation(
        sink_reached=sink_reached,
        marker_observed=marker_observed,
        alert_observed=alert_observed,
        reflected_in_dom=reflected_in_dom,
    )
    confirmed = classification == "confirmed"
    gap = None if classification in {"confirmed", "not_reflected"} else "no_second_proof"
    entry: dict[str, object] = {
        "route": redact_url(route),
        "parameter": parameter,
        "source": source,
        "probe": "execution_marker" if active else "plain_marker",
        "source_marker_present": bool(evidence.get("source_marker_present")),
        "dom_marker_present": reflected_in_dom,
        "dom_sinks": sorted(sinks),
        "sink_reached": sink_reached,
        "execution_attributed": execution,
        "marker_observed": marker_observed,
        "alert_observed": alert_observed,
        "browser_execution_observed": execution,
        "classification": classification,
        "finding_state": _finding_state(classification),
        "confirmed": confirmed,
        "finding_confirmed": False,
        "confirmation_gap": gap,
        "rejection_reason": gap,
    }
    entry.update(assess_dom_result(entry))
    # assess_dom_result always restates finding_confirmed=False. Keep the bar on `confirmed`.
    entry["finding_confirmed"] = False
    entry["confirmed"] = confirmed
    return entry


def run_dom(
    routes: list[str],
    parameters: list[str],
    checker: PlaywrightExecutionChecker,
    evidence_dir: Path,
    max_tests: int,
    headers: dict[str, str] | None = None,
    *,
    loopback_only: bool = False,
) -> tuple[Path, list[dict[str, object]]]:
    """Probe query and hash DOM sources with the shared Playwright checker.

    ``checker`` must carry the same scope validator, rate limiter, and
    execution budget as native HTTP. Each browser navigation acquires that
    budget. Requests to any other origin are aborted inside the checker.
    ``max_tests`` caps probes, not individual subresources.
    """
    if max_tests <= 0:
        raise ValueError("Max tests must be positive.")
    if not routes or not parameters:
        raise ValueError("At least one route and parameter are required.")
    if any(not parameter for parameter in parameters):
        raise ValueError("DOM parameter name cannot be empty.")
    # Fail closed before the browser starts.
    for route in routes:
        validate_dom_route(route, loopback_only=loopback_only)
        checker.scope.require(route)

    results: list[dict[str, object]] = []
    stop_reason: str | None = None
    for route in routes:
        for parameter in parameters:
            for source in ("query", "hash"):
                for active in (False, True):
                    if len(results) >= max_tests:
                        stop_reason = "test_cap"
                        break
                    marker = new_marker()
                    url = dom_scope_probe_url(
                        route,
                        parameter,
                        _payload(marker, active),
                        source,
                        loopback_only=loopback_only,
                    )
                    if loopback_only:
                        require_literal_loopback(url.split("#", 1)[0])
                    try:
                        evidence = checker.confirm(url, marker, headers, dom=True)
                    except (ToolkitError, RuntimeError) as exc:
                        entry: dict[str, object] = {
                            "route": redact_url(route),
                            "parameter": parameter,
                            "source": source,
                            "probe": "execution_marker" if active else "plain_marker",
                            "classification": "error",
                            "finding_state": "inconclusive",
                            "confirmed": False,
                            "finding_confirmed": False,
                            "confirmation_gap": "no_second_proof",
                            "rejection_reason": "no_second_proof",
                            "reason": redact_text(str(exc)) or "browser error",
                        }
                        entry.update(assess_dom_result(entry))
                        entry["finding_confirmed"] = False
                        entry["confirmed"] = False
                        results.append(entry)
                        stop_reason = "browser_or_budget_error"
                        break
                    if not isinstance(evidence, dict):
                        raise TypeError("Playwright DOM observation must be a dictionary.")
                    results.append(_observation(route, parameter, source, active, evidence))
                if stop_reason:
                    break
            if stop_reason:
                break
        if stop_reason:
            break
    envelope: dict[str, object] = {
        "type": "dom_xss",
        "loopback_only": loopback_only,
        "results": results,
    }
    if stop_reason:
        envelope["stop_reason"] = stop_reason
    path = write_evidence_json(evidence_dir, envelope, prefix="dom-xss")
    return path, results
