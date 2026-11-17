"""Resumable recon pipeline: passive, optional active, correlation, scoring, and reports."""

from __future__ import annotations

from dataclasses import dataclass, field
import json
from pathlib import Path
from typing import Protocol

from .config import FORMATS, LOG_LEVELS
from .exports import render_dashboard_html, render_sarif, write_text
from .leads import AssetGroup, Lead, build_leads, group_assets
from .models import Observation, ReconReport, SourcePlan
from .pipeline import PassiveTransport, RateLimit, ToolRunner, authorize_recon_target, correlate, run_recon
from .reporting import write_recon_reports
from .tools import parse_severity

_STATE_KIND = "bbtk-run-state"
_SNAPSHOT_KIND = "bbtk-run-snapshot"
_LEVEL_RANK = {"debug": 10, "info": 20, "warning": 30, "error": 40}


@dataclass(frozen=True)
class Progress:
    level: str
    text: str
    always: bool = False


@dataclass(frozen=True)
class RunDiff:
    baseline_present: bool
    new_hosts: tuple[str, ...] = ()
    removed_hosts: tuple[str, ...] = ()
    new_urls: tuple[str, ...] = ()
    removed_urls: tuple[str, ...] = ()
    new_leads: tuple[Lead, ...] = ()
    resolved_leads: tuple[Lead, ...] = ()

    def to_dict(self) -> dict[str, object]:
        return {
            "baseline_present": self.baseline_present,
            "new_hosts": list(self.new_hosts),
            "removed_hosts": list(self.removed_hosts),
            "new_urls": list(self.new_urls),
            "removed_urls": list(self.removed_urls),
            "new_leads": [lead.to_dict() for lead in self.new_leads],
            "resolved_leads": [lead.to_dict() for lead in self.resolved_leads],
            "new_lead_ids": [lead.lead_id for lead in self.new_leads],
            "resolved_lead_ids": [lead.lead_id for lead in self.resolved_leads],
        }


@dataclass
class RunOutcome:
    target: str
    report: ReconReport
    leads: list[Lead]
    groups: list[AssetGroup]
    diff: RunDiff
    stages: dict[str, str]
    progress: list[Progress] = field(default_factory=list)
    wrote: dict[str, Path] = field(default_factory=dict)
    resumed: bool = False


def progress_visible(event: Progress, configured: str) -> bool:
    if event.always:
        return True
    return _LEVEL_RANK[event.level] >= _LEVEL_RANK[configured]


def execute_run(
    target: str,
    scope_file: Path,
    reports_dir: Path,
    *,
    transport: PassiveTransport | None = None,
    rate_limiter: RateLimit | None = None,
    tool_runner: ToolRunner | None = None,
    hosts_path: Path | None = None,
    active: bool = False,
    nuclei: bool = False,
    confirm: bool = False,
    dry_run: bool = False,
    resume: bool = False,
    refresh: bool = False,
    show_diff: bool = False,
    severity: str = "medium,high,critical",
    rate: int = 1,
    timeout: int = 10,
    concurrency: int = 2,
    api_keys: dict[str, str] | None = None,
    formats: tuple[str, ...] = FORMATS,
    log_level: str = "info",
    run_tools: bool | None = None,
) -> RunOutcome:
    """Run the pipeline. Provider calls happen only for stages that are not already saved."""
    if log_level not in LOG_LEVELS:
        names = ", ".join(LOG_LEVELS)
        raise ValueError(f"log_level must be one of {names}.")
    selected = _formats(formats)
    severity = parse_severity(severity)
    if nuclei and not active:
        raise ValueError("Nuclei probes the target. Pass --active --confirm --nuclei.")
    if active and not dry_run and not confirm:
        raise ValueError("Active scanning is opt-in. Re-run with --active --confirm. Add --nuclei to include Nuclei.")
    progress: list[Progress] = []

    def emit(level: str, text: str, always: bool = False) -> None:
        progress.append(Progress(level, text, always))

    reports_dir.mkdir(parents=True, exist_ok=True)
    state_path = reports_dir / "run-state.json"
    normalized = authorize_recon_target(target, scope_file)
    saved = _load_state(state_path) if resume and not refresh else None
    if saved is not None and str(saved.get("target") or "") != normalized:
        raise ValueError(
            f"Saved run is for {saved.get('target')}, not {normalized}. "
            "Use another program directory, delete reports/run-state.json, or pass --refresh."
        )
    tools = (not dry_run) if run_tools is None else run_tools
    signature = _active_signature(active, nuclei, severity)

    passive_observations: list[Observation] = []
    observations: list[Observation] = []
    requests_sent = 0
    dropped = 0
    errors: list[str] = []
    tool_argv: list[list[str]] = []
    plans: list[SourcePlan] = []
    stages = {name: "pending" for name in ("passive", "active", "correlate", "score", "report")}
    resumed = False

    if saved is not None:
        if str(saved.get("target") or "") == "":
            raise ValueError("Saved run state has no target. Start again with --refresh.")
        passive_observations = _observations(saved.get("passive_observations"), "passive_observations")
        observations = _observations(saved.get("observations"), "observations")
        requests_sent = _count(saved.get("requests_sent"), "requests_sent")
        dropped = _count(saved.get("dropped"), "dropped")
        errors = _strings(saved.get("errors"), "errors")
        tool_argv = _argv(saved.get("tool_argv"))
        plans = _plans(saved.get("plans"))
        saved_stages = saved.get("stages")
        if isinstance(saved_stages, dict):
            for name in stages:
                value = saved_stages.get(name)
                if isinstance(value, str):
                    stages[name] = value

    need_passive = saved is None or stages.get("passive") != "complete"
    report: ReconReport | None = None
    if need_passive:
        if dry_run:
            report = run_recon(
                normalized,
                scope_file,
                dry_run=True,
                active=active,
                nuclei=nuclei,
                severity=severity,
                rate=rate,
                timeout=timeout,
                concurrency=concurrency,
                api_keys=api_keys,
                hosts_path=hosts_path,
            )
            plans = list(report.plans)
            tool_argv = [list(argv) for argv in report.tool_argv]
            observations = list(report.observations)
            passive_observations = list(report.observations)
            stages["passive"] = "planned"
            stages["active"] = "planned" if active else "skipped"
            emit("info", f"[1/5] passive: planned for {report.target} (no requests sent)")
            for plan in report.plans:
                emit("debug", f"[debug] {plan.source}: {plan.skipped or 'ready'} {plan.url}")
            if active:
                emit(
                    "info",
                    "[2/5] active: planned (not executed). dnsx, httpx, and nuclei stay off without a live --confirm run.",
                )
                for argv in report.tool_argv:
                    emit("debug", "[debug] tool: " + " ".join(argv))
            else:
                emit("info", "[2/5] active: skipped (pass --active --confirm to opt in)")
        else:
            report = run_recon(
                normalized,
                scope_file,
                transport=transport,
                rate_limiter=rate_limiter,
                tool_runner=tool_runner,
                active=False,
                confirm=False,
                dry_run=False,
                run_tools=tools,
                api_keys=api_keys,
                severity=severity,
                rate=rate,
                timeout=timeout,
                concurrency=concurrency,
                hosts_path=hosts_path,
            )
            observations = list(report.observations)
            passive_observations = list(report.observations)
            requests_sent = report.requests_sent
            dropped = report.dropped
            errors = list(report.errors)
            tool_argv = list(report.tool_argv)
            plans = list(report.plans)
            stages["passive"] = "complete"
            stages["active"] = "pending" if active else "skipped"
            _write_state(
                state_path,
                _state_payload(
                    report.target,
                    stages,
                    signature,
                    requests_sent,
                    dropped,
                    errors,
                    tool_argv,
                    plans,
                    passive_observations,
                    observations,
                ),
            )
            emit(
                "info",
                f"[1/5] passive: complete ({len(observations)} observations, {requests_sent} provider requests)",
            )
            for error in errors:
                emit("warning", f"[!] {error}")
    else:
        assert saved is not None
        saved_target = str(saved.get("target"))
        resumed = True
        stages["passive"] = "complete"
        emit("info", f"[1/5] passive: resumed for {saved_target} (no provider requests)")
        report = _report_from_parts(
            saved_target,
            active=False,
            nuclei=False,
            observations=observations,
            requests_sent=requests_sent,
            dropped=dropped,
            errors=errors,
            tool_argv=tool_argv,
            plans=plans,
        )

    host = report.target if report is not None else normalized
    saved_signature = str(saved.get("active_signature")) if saved else ""
    active_reusable = resumed and stages.get("active") == "complete" and saved_signature == signature and not dry_run
    if dry_run and need_passive:
        pass
    elif not active:
        if stages.get("active") != "complete":
            stages["active"] = "skipped"
        if not (dry_run and need_passive):
            if stages.get("active") == "complete":
                emit("info", "[2/5] active: kept from the saved run (this invocation did not opt in again)")
            else:
                emit("info", "[2/5] active: skipped (pass --active --confirm to opt in)")
    elif dry_run and resumed:
        stages["active"] = "planned"
        emit("info", "[2/5] active: planned from the saved run (not executed)")
    elif active_reusable:
        emit("info", "[2/5] active: resumed from saved state (tools were not run again)")
    else:
        if hosts_path is None:
            raise ValueError("Active probing needs a hosts file path inside the program directory.")
        active_report = run_recon(
            host,
            scope_file,
            transport=transport,
            rate_limiter=rate_limiter,
            tool_runner=tool_runner,
            active=True,
            nuclei=nuclei,
            confirm=True,
            dry_run=False,
            run_tools=True,
            skip_providers=True,
            skip_passive_tools=True,
            seed=passive_observations,
            api_keys=api_keys,
            severity=severity,
            rate=rate,
            timeout=timeout,
            concurrency=concurrency,
            hosts_path=hosts_path,
        )
        observations = list(active_report.observations)
        requests_sent += active_report.requests_sent
        dropped += active_report.dropped
        errors.extend(error for error in active_report.errors if error not in errors)
        tool_argv.extend(active_report.tool_argv)
        stages["active"] = "complete"
        report = active_report
        report.requests_sent = requests_sent
        report.dropped = dropped
        report.errors = list(errors)
        report.tool_argv = list(tool_argv)
        report.plans = list(plans)
        _write_state(
            state_path,
            _state_payload(
                host,
                stages,
                signature,
                requests_sent,
                dropped,
                errors,
                tool_argv,
                plans,
                passive_observations,
                observations,
            ),
        )
        emit("info", f"[2/5] active: complete ({len(active_report.tool_argv)} tool commands)")
        for error in active_report.errors:
            emit("warning", f"[!] {error}")

    if report is None or report.observations != observations or report.assets == [] and observations:
        report = _report_from_parts(
            host,
            active=active and stages.get("active") == "complete",
            nuclei=nuclei and stages.get("active") == "complete",
            observations=observations,
            requests_sent=requests_sent,
            dropped=dropped,
            errors=errors,
            tool_argv=tool_argv,
            plans=plans,
        )
    else:
        report.observations = list(observations)
        report.assets = correlate(observations)
        report.active = stages.get("active") in {"complete", "planned"}
        report.nuclei = bool(report.active and (nuclei or saved_signature.startswith("active:1:")))
        report.requests_sent = requests_sent
        report.dropped = dropped
        report.errors = list(errors)
    report.dry_run = dry_run
    leads = build_leads(report)
    groups = group_assets(report)
    stages["correlate"] = "complete" if not dry_run else "planned"
    stages["score"] = "complete" if not dry_run else "planned"
    emit("info", f"[3/5] correlate: {len(report.assets)} hosts, {len(groups)} groups")
    emit("info", f"[4/5] score: {len(leads)} unconfirmed leads")

    baseline = _load_snapshot(reports_dir / "run-latest.json")
    diff = _diff(baseline, report, leads)
    _emit_diff(emit, diff, show_diff)
    wrote: dict[str, Path] = {}
    if dry_run:
        stages["report"] = "planned"
        emit("info", "[5/5] report: planned (nothing written)", always=True)
        emit("info", "[+] Dry run. No provider requests and no external tools were executed.", always=True)
    else:
        wrote = _write_reports(reports_dir, report, leads, groups, stages, diff, selected)
        stages["report"] = "complete"
        _write_state(
            state_path,
            _state_payload(
                report.target,
                stages,
                signature,
                requests_sent,
                dropped,
                errors,
                tool_argv,
                plans,
                passive_observations,
                observations,
            ),
        )
        _write_snapshot(reports_dir, report, leads)
        names = ", ".join(path.name for path in wrote.values())
        emit("info", f"[5/5] report: wrote {names}", always=True)
        emit("info", "[+] Nothing was submitted. Leads are not confirmed vulnerabilities.", always=True)
    return RunOutcome(
        target=report.target,
        report=report,
        leads=leads,
        groups=groups,
        diff=diff,
        stages=dict(stages),
        progress=progress,
        wrote=wrote,
        resumed=resumed,
    )


def _formats(formats: tuple[str, ...]) -> tuple[str, ...]:
    if not formats:
        raise ValueError(f"formats must include at least one of {', '.join(FORMATS)}.")
    chosen: list[str] = []
    for item in formats:
        if item not in FORMATS:
            raise ValueError(f"Unknown format {item!r}. Choose from {', '.join(FORMATS)}.")
        if item not in chosen:
            chosen.append(item)
    return tuple(chosen)


def _active_signature(active: bool, nuclei: bool, severity: str) -> str:
    if not active:
        return "passive"
    return f"active:{int(nuclei)}:{severity}"


def _report_from_parts(
    target: str,
    *,
    active: bool,
    nuclei: bool,
    observations: list[Observation],
    requests_sent: int,
    dropped: int,
    errors: list[str],
    tool_argv: list[list[str]],
    plans: list[SourcePlan],
) -> ReconReport:
    report = ReconReport(target=target, dry_run=False, active=active, nuclei=nuclei, plans=list(plans))
    report.observations = list(observations)
    report.assets = correlate(observations)
    report.requests_sent = requests_sent
    report.dropped = dropped
    report.errors = list(errors)
    report.tool_argv = [list(argv) for argv in tool_argv]
    return report


class _Emit(Protocol):
    def __call__(self, level: str, text: str, always: bool = ...) -> None: ...


def _emit_diff(emit: _Emit, diff: RunDiff, show_diff: bool) -> None:
    if not diff.baseline_present:
        emit("info", "[i] No previous run to diff. This run is the baseline.", always=True)
        return
    emit(
        "info",
        "[+] Since the previous run: "
        f"{len(diff.new_hosts)} new hosts, {len(diff.removed_hosts)} removed hosts, "
        f"{len(diff.new_urls)} new URLs, {len(diff.new_leads)} new leads, "
        f"{len(diff.resolved_leads)} leads no longer present.",
        always=True,
    )
    if not show_diff:
        return
    if not (diff.new_hosts or diff.removed_hosts or diff.new_urls or diff.new_leads or diff.resolved_leads):
        emit("info", "[diff] No new hosts, URLs, or leads since the previous run.")
    for host in diff.new_hosts[:20]:
        emit("info", f"[diff] new host {host}")
    for host in diff.removed_hosts[:20]:
        emit("info", f"[diff] removed host {host}")
    for url in diff.new_urls[:20]:
        emit("info", f"[diff] new url {url}")
    for lead in diff.new_leads[:20]:
        emit("info", f"[diff] new lead {lead.category} {lead.host}")
    for lead in diff.resolved_leads[:20]:
        emit("info", f"[diff] lead no longer present {lead.category} {lead.host}")


def _diff(baseline: dict[str, object] | None, report: ReconReport, leads: list[Lead]) -> RunDiff:
    if baseline is None:
        return RunDiff(False)
    previous_hosts = set(_strings(baseline.get("hosts"), "hosts"))
    previous_urls = set(_strings(baseline.get("urls"), "urls"))
    previous_leads = _lead_map(baseline.get("leads"))
    current_hosts = {asset.host for asset in report.assets}
    current_urls = {url for asset in report.assets for url in asset.urls}
    current = {lead.lead_id: lead for lead in leads}
    return RunDiff(
        True,
        tuple(sorted(current_hosts - previous_hosts)),
        tuple(sorted(previous_hosts - current_hosts)),
        tuple(sorted(current_urls - previous_urls)),
        tuple(sorted(previous_urls - current_urls)),
        tuple(current[key] for key in sorted(set(current) - set(previous_leads))),
        tuple(previous_leads[key] for key in sorted(set(previous_leads) - set(current))),
    )


def _write_reports(
    reports_dir: Path,
    report: ReconReport,
    leads: list[Lead],
    groups: list[AssetGroup],
    stages: dict[str, str],
    diff: RunDiff,
    formats: tuple[str, ...],
) -> dict[str, Path]:
    wrote = write_recon_reports(report, reports_dir, formats=formats)
    summary = _summary(report, leads, groups, stages, diff)
    if "json" in formats:
        path = reports_dir / "run.json"
        write_text(path, json.dumps(summary, indent=2, sort_keys=True) + "\n")
        wrote["run_json"] = path
    if "sarif" in formats:
        path = reports_dir / "recon.sarif.json"
        write_text(path, render_sarif(report, leads))
        wrote["sarif"] = path
    if "dashboard" in formats:
        path = reports_dir / "dashboard.html"
        write_text(path, render_dashboard_html(report, leads, groups, stages, diff.to_dict()))
        wrote["dashboard"] = path
    return wrote


def _summary(
    report: ReconReport,
    leads: list[Lead],
    groups: list[AssetGroup],
    stages: dict[str, str],
    diff: RunDiff,
) -> dict[str, object]:
    by_category: dict[str, int] = {}
    for lead in leads:
        by_category[lead.category] = by_category.get(lead.category, 0) + 1
    return {
        "kind": "bbtk-run",
        "version": 1,
        "confirmed": False,
        "target": report.target,
        "stages": dict(stages),
        "stats": {
            "assets": len(report.assets),
            "observations": len(report.observations),
            "leads": len(leads),
            "leads_by_category": by_category,
            "requests_sent": report.requests_sent,
            "dropped_out_of_scope": report.dropped,
            "errors": len(report.errors),
            "confirmed": 0,
        },
        "leads": [lead.to_dict() for lead in leads],
        "groups": [group.to_dict() for group in groups],
        "diff": diff.to_dict(),
        "inventory": report.to_dict(),
    }


def _write_snapshot(reports_dir: Path, report: ReconReport, leads: list[Lead]) -> None:
    latest = reports_dir / "run-latest.json"
    previous = reports_dir / "run-previous.json"
    if latest.is_file():
        write_text(previous, latest.read_text(encoding="utf-8"))
    payload = {
        "kind": _SNAPSHOT_KIND,
        "version": 1,
        "target": report.target,
        "hosts": sorted(asset.host for asset in report.assets),
        "urls": sorted({url for asset in report.assets for url in asset.urls}),
        "leads": [lead.to_dict() for lead in leads],
    }
    write_text(latest, json.dumps(payload, indent=2, sort_keys=True) + "\n")


def _load_snapshot(path: Path) -> dict[str, object] | None:
    if not path.is_file():
        return None
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(payload, dict) or payload.get("kind") != _SNAPSHOT_KIND or payload.get("version") != 1:
        return None
    return payload


def _state_payload(
    target: str,
    stages: dict[str, str],
    signature: str,
    requests_sent: int,
    dropped: int,
    errors: list[str],
    tool_argv: list[list[str]],
    plans: list[SourcePlan],
    passive_observations: list[Observation],
    observations: list[Observation],
) -> dict[str, object]:
    return {
        "kind": _STATE_KIND,
        "version": 1,
        "target": target,
        "stages": dict(stages),
        "active_signature": signature,
        "requests_sent": requests_sent,
        "dropped": dropped,
        "errors": list(errors),
        "tool_argv": [list(argv) for argv in tool_argv],
        "plans": [{"source": plan.source, "url": plan.url, "skipped": plan.skipped} for plan in plans],
        "passive_observations": [_observation_dict(item) for item in passive_observations],
        "observations": [_observation_dict(item) for item in observations],
        "confirmed": False,
    }


def _observation_dict(item: Observation) -> dict[str, str]:
    return {"host": item.host, "source": item.source, "kind": item.kind, "value": item.value, "detail": item.detail}


def _write_state(path: Path, payload: dict[str, object]) -> None:
    write_text(path, json.dumps(payload, indent=2, sort_keys=True) + "\n")


def _load_state(path: Path) -> dict[str, object]:
    if not path.is_file():
        raise ValueError("No saved run state. Run bbtk run once before --resume.")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"{path.name} is not valid JSON. Remove it or start again with --refresh.") from exc
    except OSError as exc:
        raise ValueError(f"{path.name} could not be read.") from exc
    if not isinstance(payload, dict) or payload.get("kind") != _STATE_KIND or payload.get("version") != 1:
        raise ValueError(f"{path.name} is not a bbtk run state file (expected kind {_STATE_KIND} version 1).")
    return payload


def _observations(value: object, label: str) -> list[Observation]:
    if not isinstance(value, list):
        raise ValueError(f"Saved run state is missing {label}. Start again with --refresh.")
    found: list[Observation] = []
    for item in value[:2000]:
        if not isinstance(item, dict):
            raise ValueError(f"Saved {label} are unusable. Start again with --refresh.")
        host = item.get("host")
        source = item.get("source")
        kind = item.get("kind")
        observed = item.get("value")
        detail = item.get("detail", "")
        if not all(isinstance(part, str) for part in (host, source, kind, observed, detail)):
            raise ValueError(f"Saved {label} are unusable. Start again with --refresh.")
        found.append(Observation(str(host), str(source), str(kind), str(observed), str(detail)))
    return found


def _strings(value: object, label: str) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ValueError(f"Saved run state field {label} is unusable. Start again with --refresh.")
    return [str(item) for item in value]


def _count(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"Saved run state field {label} is unusable. Start again with --refresh.")
    return value


def _argv(value: object) -> list[list[str]]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise ValueError("Saved tool arguments are unusable. Start again with --refresh.")
    argv: list[list[str]] = []
    for item in value:
        if not isinstance(item, list) or not all(isinstance(token, str) for token in item):
            raise ValueError("Saved tool arguments are unusable. Start again with --refresh.")
        argv.append([str(token) for token in item])
    return argv


def _plans(value: object) -> list[SourcePlan]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise ValueError("Saved provider plan is unusable. Start again with --refresh.")
    plans: list[SourcePlan] = []
    for item in value:
        if not isinstance(item, dict):
            raise ValueError("Saved provider plan is unusable. Start again with --refresh.")
        source = item.get("source")
        url = item.get("url")
        skipped = item.get("skipped", "")
        if not isinstance(source, str) or not isinstance(url, str) or not isinstance(skipped, str):
            raise ValueError("Saved provider plan is unusable. Start again with --refresh.")
        plans.append(SourcePlan(source, url, skipped=skipped))
    return plans


def _lead_map(value: object) -> dict[str, Lead]:
    if not isinstance(value, list):
        return {}
    found: dict[str, Lead] = {}
    for item in value:
        if not isinstance(item, dict):
            continue
        lead_id = item.get("id")
        host = item.get("host")
        category = item.get("category")
        title = item.get("title")
        detail = item.get("detail")
        if not all(isinstance(part, str) for part in (lead_id, host, category, title, detail)):
            continue
        found[str(lead_id)] = Lead(str(lead_id), str(host), str(category), str(title), str(detail), confirmed=False)
    return found
