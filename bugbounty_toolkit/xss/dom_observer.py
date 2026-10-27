"""Live loopback DOM observability. Hooks are installed before page scripts.

Child frames are read only through the page's own ``contentDocument`` access.
Sandboxed and cross-origin frames are recorded as ``unsupported`` and are not
opened with the debugger protocol. Non-loopback requests are aborted.
``finding_confirmed`` stays false. Inert markers are not forced to execute.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Any, Mapping, Sequence
from urllib.parse import urlsplit

from ..core.redaction import redact_text
from ..core.scope_validator import ScopeValidator
from .dom_local import require_literal_loopback
from .dom_observability import (
    V3_ASYNC_BUDGET_MS,
    artifact_hash,
    assemble_record,
    assert_observation_integrity,
    decide_outcome,
    early_hook_script,
    frame_policy,
    validate_marker,
)

_CLICK_RE = re.compile(r"^#[A-Za-z][\w-]{0,40}$")
_HASH_RE = re.compile(r"^#[A-Za-z0-9_%.-]{0,128}$")
_LOOPBACK_HOSTS = frozenset({"127.0.0.1", "::1"})

_FRAME_INVENTORY = """() => [...document.querySelectorAll('iframe')].map((node) => ({
  id: node.id || '',
  src: node.getAttribute('src') || '',
  sandbox: node.getAttribute('sandbox'),
}))"""

# Reads child state only when the page itself can. Sandbox without
# allow-same-origin never touches contentDocument.
_FRAME_COLLECT = """(marker) => {
  const frames = [];
  for (const node of document.querySelectorAll('iframe')) {
    const sandbox = node.getAttribute('sandbox');
    const entry = {
      id: node.id || '',
      src: node.getAttribute('src') || '',
      sandbox: sandbox,
      accessible: false,
      sop_blocked: false,
      child: null,
      executed: false,
    };
    if (sandbox !== null && sandbox.split(/\\s+/).indexOf('allow-same-origin') === -1) {
      entry.sop_blocked = true;
      frames.push(entry);
      continue;
    }
    try {
      const doc = node.contentDocument;
      const view = doc && doc.defaultView;
      if (view) {
        entry.accessible = true;
        entry.child = view.__bbtk_obs_v3 || null;
        entry.executed = view.__bbtk_xss_marker === marker;
      } else {
        entry.sop_blocked = true;
      }
    } catch (e) {
      entry.sop_blocked = true;
    }
    frames.push(entry);
  }
  return { main: window.__bbtk_obs_v3 || null, frames };
}"""


def _host_is_loopback(url: str) -> bool:
    host = urlsplit(url).hostname
    if host is None:
        return False
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return host in _LOOPBACK_HOSTS


class LoopbackGuard:
    """Abort anything that is not a literal loopback HTTP request."""

    def __init__(self) -> None:
        self.external_requests = 0
        self.loopback_requests = 0

    def handle(self, route: Any) -> None:
        url = str(route.request.url)
        if _host_is_loopback(url) and urlsplit(url).scheme in {"http", "https"}:
            self.loopback_requests += 1
            route.continue_()
            return
        self.external_requests += 1
        route.abort()


def _external_attempts(hook: object) -> int:
    if isinstance(hook, Mapping) and isinstance(hook.get("external_attempts"), int):
        return int(hook["external_attempts"])
    return 0


def _relation_for(entry: Mapping[str, Any], *, swapped: bool, unmounted: bool) -> str:
    if unmounted:
        return "unmounted"
    sandbox = entry.get("sandbox")
    if entry.get("sop_blocked") or (isinstance(sandbox, str) and "allow-same-origin" not in sandbox.split()):
        if isinstance(sandbox, str):
            return "isolated"
        return "no_access"
    if swapped:
        return "swapped"
    return "same_origin"


def _signals_from_hook(state: Mapping[str, Any] | None) -> dict[str, Any]:
    if not isinstance(state, Mapping):
        return {
            "status": "failed",
            "source_refs": [],
            "property_reads": [],
            "sink_refs": [],
            "sanitized": False,
            "csp_blocked": False,
            "errors": ["missing_hook_state"],
            "source_read_ms": None,
            "sink_ms": None,
        }
    reads_raw = state.get("reads")
    sinks_raw = state.get("sinks")
    props_raw = state.get("property_reads")
    reads: list[Any] = reads_raw if isinstance(reads_raw, list) else []
    sinks: list[Any] = sinks_raw if isinstance(sinks_raw, list) else []
    prop_reads: list[Any] = props_raw if isinstance(props_raw, list) else []
    source_apis = {"document.URL", "document.documentURI"}
    source_refs = sorted(
        {str(item) for item in prop_reads if str(item).startswith("location.") or str(item) in source_apis}
    )
    sink_refs: list[str] = []
    sink_ms: int | None = None
    for sink in sinks:
        if not isinstance(sink, Mapping):
            continue
        name = str(sink.get("sink") or "")
        if not name:
            continue
        sink_refs.append(name)
        stamp = sink.get("t_ms")
        if isinstance(stamp, (int, float)) and (sink_ms is None or stamp < sink_ms):
            sink_ms = int(stamp)
    read_ms: int | None = None
    for read in reads:
        if not isinstance(read, Mapping):
            continue
        stamp = read.get("t_ms")
        if isinstance(stamp, (int, float)) and (read_ms is None or stamp < read_ms):
            read_ms = int(stamp)
    errors = [str(item)[:200] for item in list(state.get("errors") or [])[:5] if isinstance(item, str)]
    status = str(state.get("status") or "installed_before_page")
    if status not in {"installed_before_page", "installed_late", "partial", "failed", "unsupported"}:
        status = "partial"
    return {
        "status": status,
        "source_refs": source_refs,
        "property_reads": sorted({str(item) for item in prop_reads}),
        "sink_refs": sorted(set(sink_refs)),
        "sanitized": bool(state.get("sanitized")),
        "csp_blocked": bool(state.get("csp")),
        "errors": errors,
        "source_read_ms": read_ms,
        "sink_ms": sink_ms,
    }


def _frame_record(
    *,
    case_id: str,
    navigation_id: str,
    frame_id: str,
    relation: str,
    accessible: bool,
    sandbox: str | None,
    source_available: bool,
    executed: bool,
    execution_mechanism: str | None,
    hook: Mapping[str, Any] | None,
    external_requests: int,
    extra_limitations: Sequence[str] = (),
) -> dict[str, Any]:
    policy_frame: dict[str, Any] = {"relation": relation, "accessible": accessible, "sandbox": sandbox}
    policy = frame_policy(policy_frame)
    signals = _signals_from_hook(hook if policy == "observe" else None)
    limitations = list(extra_limitations)
    if policy == "unsupported":
        limitations.append("sop_not_bypassed")
        signals = _signals_from_hook(None)
        signals["status"] = "unsupported"
        signals["errors"] = []
        executed = False
        execution_mechanism = None
        source_available = False
    status = "unsupported" if policy != "observe" else str(signals["status"])
    if policy == "inconclusive":
        limitations.append("frame_unmounted" if relation == "unmounted" else "frame_missing")
        executed = False
        execution_mechanism = None
        signals = _signals_from_hook(None)
        signals["status"] = "unsupported"
        signals["errors"] = []
    if source_available and not signals["source_refs"] and policy == "observe":
        limitations.append("source_in_url_is_not_a_read")
    if "innerHTML" in signals["sink_refs"] and not executed:
        limitations.append("execution_not_inferred_from_innerhtml")
    outcome = decide_outcome(
        policy=policy,
        instrumentation_status=status if policy == "observe" else "unsupported",
        source_refs=signals["source_refs"] if policy == "observe" else [],
        sink_refs=signals["sink_refs"] if policy == "observe" else [],
        executed=executed and policy == "observe",
        sanitized=bool(signals["sanitized"]) and policy == "observe",
        csp_blocked=bool(signals["csp_blocked"]) and policy == "observe",
        partial_navigation_unreliable=False,
        dropped_sink_without_signal=False,
    )
    return assemble_record(
        case_id=case_id,
        navigation_id=navigation_id,
        frame_id=frame_id,
        frame_relation=relation,
        instrumentation_status=status if policy == "observe" else "unsupported",
        source_available=source_available if policy == "observe" else False,
        source_refs=signals["source_refs"] if policy == "observe" else [],
        property_reads=signals["property_reads"] if policy == "observe" else [],
        sink_refs=signals["sink_refs"] if policy == "observe" else [],
        executed=executed and policy == "observe",
        execution_mechanism=execution_mechanism if policy == "observe" else None,
        sanitized=bool(signals["sanitized"]) and policy == "observe",
        csp_blocked=bool(signals["csp_blocked"]) and policy == "observe",
        t_rel_ms={
            "navigation_start": 0,
            "instrumentation_installed": 0 if policy == "observe" and status == "installed_before_page" else None,
            "source_read": signals["source_read_ms"] if policy == "observe" else None,
            "sink_call": signals["sink_ms"] if policy == "observe" else None,
            "execution": None,
            "observation_end": V3_ASYNC_BUDGET_MS if policy == "observe" else 0,
        },
        limitations=limitations,
        outcome=outcome,
        external_requests=external_requests,
        technical_errors=[redact_text(item) or "" for item in signals["errors"]],
    )


def _apply_interaction(page: Any, interaction: Mapping[str, Any]) -> None:
    op = str(interaction.get("op") or "")
    if op == "click":
        selector = str(interaction.get("selector") or "")
        if _CLICK_RE.fullmatch(selector) is None:
            raise ValueError("Refusing a non-local click selector.")
        page.click(selector)
        return
    if op == "hash":
        value = str(interaction.get("value") or "")
        if _HASH_RE.fullmatch(value) is None or "javascript" in value.lower():
            raise ValueError("Refusing an unsafe hash assignment.")
        page.evaluate("(value) => { location.hash = value; }", value)
        return
    if op == "popstate":
        page.evaluate("() => history.back()")
        return
    if op == "wait":
        ms = int(interaction.get("ms") or 0)
        if ms < 0 or ms > 500:
            raise ValueError("Interaction wait must be between 0 and 500 ms.")
        page.wait_for_timeout(ms)
        return
    raise ValueError(f"Unknown interaction: {op}")


def observe_loopback(
    url: str,
    marker: str,
    *,
    case_id: str,
    navigation_id: str,
    interactions: Sequence[Mapping[str, Any]] | None = None,
    async_budget_ms: int = V3_ASYNC_BUDGET_MS,
    scope: ScopeValidator | None = None,
    channel: str | None = None,
    executable_path: str | None = None,
    launch_args: Sequence[str] | None = None,
    expected_frame_ids: Sequence[str] = (),
) -> dict[str, Any]:
    """Navigate one literal loopback URL with early hooks and return a v3 record.

    ``async_budget_ms`` bounds how long async sinks are given to run. It does
    not inject payloads. Execution is whatever the page itself does with the
    marker already on the URL.
    """
    if async_budget_ms <= 0 or async_budget_ms > 5000:
        raise ValueError("async_budget_ms must be between 1 and 5000.")
    token = validate_marker(marker)
    bare = url.split("#", 1)[0]
    require_literal_loopback(bare)
    if scope is not None:
        scope.require(bare)
    source_available = token in url

    from playwright.sync_api import sync_playwright

    guard = LoopbackGuard()
    page_attempts = 0
    launch_kwargs: dict[str, Any] = {"headless": True}
    if channel:
        launch_kwargs["channel"] = channel
    if executable_path:
        launch_kwargs["executable_path"] = executable_path
    if launch_args:
        launch_kwargs["args"] = list(launch_args)

    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(**launch_kwargs)
        try:
            context = browser.new_context(service_workers="block")
            context.add_init_script(early_hook_script(token))
            context.route("**/*", guard.handle)
            context.route_web_socket("**/*", lambda websocket: websocket.close())
            page = context.new_page()
            dialogs: list[str] = []

            def on_dialog(dialog: Any) -> None:
                dialogs.append(redact_text(dialog.message) or "")
                dialog.accept()

            page.on("dialog", on_dialog)
            page.goto(bare if "#" not in url else url, wait_until="domcontentloaded", timeout=5000)
            early_frames = page.evaluate(_FRAME_INVENTORY)
            for interaction in interactions or []:
                _apply_interaction(page, interaction)
            page.wait_for_timeout(async_budget_ms)
            executed = bool(page.evaluate("(marker) => window.__bbtk_xss_marker === marker", token))
            mechanism: str | None = None
            if any(token in text for text in dialogs):
                mechanism = "dialog"
                executed = True
            elif executed:
                mechanism = "marker_assignment"
            collected = page.evaluate(_FRAME_COLLECT, token)
            late_frames = collected.get("frames") if isinstance(collected, Mapping) else []
            main_hook = collected.get("main") if isinstance(collected, Mapping) else None
            page_attempts = _external_attempts(main_hook)
        finally:
            browser.close()

    if not isinstance(early_frames, list):
        early_frames = []
    if not isinstance(late_frames, list):
        late_frames = []
    early_by_id = {str(item.get("id") or ""): item for item in early_frames if isinstance(item, Mapping)}
    late_by_id = {str(item.get("id") or ""): item for item in late_frames if isinstance(item, Mapping)}

    main = _frame_record(
        case_id=case_id,
        navigation_id=navigation_id,
        frame_id="main",
        relation="main",
        accessible=True,
        sandbox=None,
        source_available=source_available,
        executed=executed,
        execution_mechanism=mechanism,
        hook=main_hook if isinstance(main_hook, Mapping) else None,
        external_requests=0,
    )
    frames = [main]
    seen: set[str] = set()
    for frame_id, early in early_by_id.items():
        if not frame_id:
            continue
        seen.add(frame_id)
        late = late_by_id.get(frame_id)
        unmounted = not isinstance(late, Mapping)
        early_src = str(early.get("src") or "") if isinstance(early, Mapping) else ""
        late_src = str(late.get("src") or "") if isinstance(late, Mapping) else ""
        swapped = isinstance(late, Mapping) and early_src != late_src
        current: Mapping[str, Any] = late if isinstance(late, Mapping) else early
        sandbox = current.get("sandbox")
        sandbox_text = sandbox if isinstance(sandbox, str) else None
        relation = _relation_for(current, swapped=swapped and not unmounted, unmounted=unmounted)
        child_hook = current.get("child") if isinstance(current, Mapping) else None
        if relation in {"same_origin", "swapped"} and not unmounted:
            page_attempts += _external_attempts(child_hook)
        child_executed = bool(current.get("executed")) and not unmounted and relation in {"same_origin", "swapped"}
        frames.append(
            _frame_record(
                case_id=case_id,
                navigation_id=navigation_id,
                frame_id=frame_id,
                relation=relation,
                accessible=bool(current.get("accessible")) and not unmounted,
                sandbox=sandbox_text,
                source_available=False,
                executed=child_executed,
                execution_mechanism="marker_assignment" if child_executed else None,
                hook=child_hook if isinstance(child_hook, Mapping) else None,
                external_requests=0,
                extra_limitations=["frame_swapped"] if swapped and not unmounted else [],
            )
        )
    for frame_id in expected_frame_ids:
        if frame_id in seen or frame_id == "main":
            continue
        frames.append(
            _frame_record(
                case_id=case_id,
                navigation_id=navigation_id,
                frame_id=frame_id,
                relation="missing",
                accessible=False,
                sandbox=None,
                source_available=False,
                executed=False,
                execution_mechanism=None,
                hook=None,
                external_requests=0,
            )
        )
    focus = frames[0]
    parent: dict[str, Any] = {
        "schema": focus["schema"],
        "case_id": case_id,
        "navigation_id": navigation_id,
        "frame_id": focus["frame_id"],
        "frame_relation": focus["frame_relation"],
        "t_rel_ms": focus["t_rel_ms"],
        "instrumentation_status": focus["instrumentation_status"],
        "source_available": focus["source_available"],
        "source_observed": focus["source_observed"],
        "source_refs": focus["source_refs"],
        "sink_refs": focus["sink_refs"],
        "property_reads": focus["property_reads"],
        "execution_evidence": focus["execution_evidence"],
        "csp_flags": focus["csp_flags"],
        "sanitized": focus["sanitized"],
        "outcome": focus["outcome"],
        "dom_state": focus["dom_state"],
        "limitations": sorted({item for record in frames for item in record["limitations"]}),
        "technical_errors": focus["technical_errors"],
        "external_requests": guard.external_requests + page_attempts,
        "network_attempts": guard.external_requests + page_attempts,
        "loopback_requests": guard.loopback_requests,
        "finding_confirmed": False,
        "human_review_required": True,
        "generation": "v3",
        "frames": frames,
        "legacy_v2": None,
    }
    parent["artifact_hash"] = artifact_hash(parent)
    assert_observation_integrity(parent)
    return parent
