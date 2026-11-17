"""Shared recon records. Scores never mark a vulnerability as confirmed."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class Observation:
    host: str
    source: str
    kind: str
    value: str
    detail: str = ""

    def identity(self) -> tuple[str, str, str, str]:
        return (self.host, self.source, self.kind, self.value)


@dataclass(frozen=True)
class SourcePlan:
    source: str
    url: str
    headers: tuple[tuple[str, str], ...] = ()
    skipped: str = ""


@dataclass
class Asset:
    host: str
    sources: set[str] = field(default_factory=set)
    urls: list[str] = field(default_factory=list)
    ports: set[int] = field(default_factory=set)
    cves: list[str] = field(default_factory=list)
    nuclei: list[str] = field(default_factory=list)
    score: int = 0
    severity: str = "informational"
    reasons: list[str] = field(default_factory=list)
    confirmed: bool = False


@dataclass
class ReconReport:
    target: str
    dry_run: bool
    active: bool
    nuclei: bool
    observations: list[Observation] = field(default_factory=list)
    assets: list[Asset] = field(default_factory=list)
    plans: list[SourcePlan] = field(default_factory=list)
    tool_argv: list[list[str]] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    dropped: int = 0
    requests_sent: int = 0

    def to_dict(self) -> dict[str, object]:
        return {
            "target": self.target,
            "dry_run": self.dry_run,
            "active": self.active,
            "nuclei": self.nuclei,
            "requests_sent": self.requests_sent,
            "dropped_out_of_scope": self.dropped,
            "confirmed": False,
            "errors": list(self.errors),
            "provider_requests": [
                {"source": plan.source, "url": plan.url, "skipped": plan.skipped} for plan in self.plans
            ],
            "tool_argv": [list(argv) for argv in self.tool_argv],
            "observations": [
                {
                    "host": item.host,
                    "source": item.source,
                    "kind": item.kind,
                    "value": item.value,
                    "detail": item.detail,
                }
                for item in self.observations
            ],
            "assets": [
                {
                    "host": asset.host,
                    "sources": sorted(asset.sources),
                    "urls": list(asset.urls),
                    "ports": sorted(asset.ports),
                    "cves": list(asset.cves),
                    "nuclei": list(asset.nuclei),
                    "score": asset.score,
                    "severity": asset.severity,
                    "reasons": list(asset.reasons),
                    "confirmed": False,
                }
                for asset in self.assets
            ],
        }
