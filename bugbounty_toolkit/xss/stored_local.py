"""Synthetic Stored-XSS laboratory: write → store → render → marker check.

Restricted to disposable loopback applications. Never creates content on third-
party hosts and never implements Blind XSS via public callbacks. Reuses
``require_literal_loopback`` and ``PlaywrightExecutionChecker`` from the
already-merged DOM local probes. Observed marker execution keeps
``finding_confirmed=False``.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING
from urllib.parse import quote, urljoin

from ..core.http_client import HttpClient, RequestSpec
from ..core.redaction import redact_text, redact_url
from ..reporting.evidence import write_evidence_json
from ..utils.exceptions import ToolkitError
from .dom_local import require_literal_loopback
from .evidence_record import DomObservation, classify_dom_state
from .test_cases import new_marker

if TYPE_CHECKING:
    from .playwright_confirm import PlaywrightExecutionChecker


@dataclass(frozen=True)
class StoredLocalOptions:
    write_url: str
    render_url: str
    parameter: str = "content"
    method: str = "POST"
    max_tests: int = 2
    headers: dict[str, str] | None = None
    active_marker: bool = True


def _payload(marker: str, active: bool) -> str:
    if not active:
        return marker
    # Non-exfiltrating laboratory-only execution marker. No callbacks, no Blind XSS.
    code = f"window.__bbtk_xss_marker='{marker}';alert('{marker}')"
    return f'<img src=x onerror="{code}">'


def run_stored_local(
    options: StoredLocalOptions,
    client: HttpClient,
    checker: PlaywrightExecutionChecker,
    evidence_dir: Path,
) -> tuple[Path, list[dict[str, object]]]:
    """Exercise a disposable local write→store→render→browser loop.

    Both URLs must be literal loopback. The write request uses the shared
    ``HttpClient`` (scope + budgets). Browser confirmation uses
    ``PlaywrightExecutionChecker`` with ``local_only=True``.
    """
    if options.max_tests <= 0:
        raise ValueError("Max tests must be positive.")
    require_literal_loopback(options.write_url)
    require_literal_loopback(options.render_url)
    client.scope.require(options.write_url)
    client.scope.require(options.render_url)

    results: list[dict[str, object]] = []
    for active in (False, True) if options.active_marker else (False,):
        if len(results) >= options.max_tests:
            break
        marker = new_marker()
        payload = _payload(marker, active)
        write_body = f"{options.parameter}={quote(payload)}"
        headers = dict(options.headers or {})
        if options.method.upper() == "POST" and "content-type" not in {k.lower() for k in headers}:
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        try:
            write_response = client.send(
                RequestSpec(
                    method=options.method.upper(),
                    url=options.write_url,
                    headers=headers,
                    body=write_body,
                )
            )
        except ToolkitError as exc:
            results.append(
                {
                    "phase": "write",
                    "classification": "error",
                    "confirmed": False,
                    "finding_confirmed": False,
                    "reason": redact_text(str(exc)),
                    "write_url": redact_url(options.write_url),
                    "render_url": redact_url(options.render_url),
                }
            )
            break
        # Prefer a Location header for the render view; otherwise use the configured render URL.
        location = write_response.headers.get("location") or write_response.headers.get("Location")
        render = urljoin(options.write_url, location) if location else options.render_url
        require_literal_loopback(render)
        try:
            evidence = checker.confirm(render, marker, options.headers, local_only=True)
        except (ToolkitError, RuntimeError) as exc:
            results.append(
                {
                    "phase": "render",
                    "classification": "error",
                    "confirmed": False,
                    "finding_confirmed": False,
                    "reason": redact_text(str(exc)),
                    "write_url": redact_url(options.write_url),
                    "render_url": redact_url(render),
                    "write_status": write_response.status_code,
                }
            )
            break
        sinks_raw = evidence.get("dom_sinks", [])
        sink_list = [s for s in sinks_raw if isinstance(s, str)] if isinstance(sinks_raw, list) else []
        observation = DomObservation(
            source_observed=bool(evidence.get("source_marker_present")) or marker in (write_response.body_text or ""),
            sinks=tuple(sink_list),
            marker_executed=bool(evidence.get("marker_observed")) or bool(evidence.get("alert_observed")),
        )
        state = classify_dom_state(observation)
        results.append(
            {
                "phase": "write_store_render",
                "probe": "execution_marker" if active else "plain_marker",
                "write_url": redact_url(options.write_url),
                "render_url": redact_url(render),
                "write_status": write_response.status_code,
                "parameter": options.parameter,
                "source_marker_present": observation.source_observed,
                "dom_sinks": list(observation.sinks),
                "browser_execution_observed": observation.marker_executed,
                "dom_state": state,
                "classification": state,
                "confirmed": False,
                "finding_confirmed": False,
                "reason": (
                    "Innocuous marker executed after a local write→store→render cycle. "
                    "This is a laboratory observation, not a vulnerability confirmation."
                    if observation.marker_executed
                    else "Stored marker did not execute in the headless browser under known lab conditions."
                ),
            }
        )
    envelope: dict[str, object] = {
        "type": "stored_xss_local",
        "results": results,
        "finding_confirmed": False,
        "note": "Synthetic local stored-XSS lab only. No third-party writes. No Blind XSS callbacks.",
    }
    path = write_evidence_json(evidence_dir, envelope, prefix="stored-xss-local")
    return path, results
