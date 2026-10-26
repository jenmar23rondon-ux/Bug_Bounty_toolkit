"""Offline context-aware discovery planning from local HAR captures.

Connects resilient HAR import, local wordlist collections, Object Discovery
candidates and the existing ffuf runner into one investigation plan. Planning
never opens a network socket, downloads wordlists, or starts fuzzing. Approved
execution reuses ``FfufRunner`` and the CLI confirmation gate.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
import hashlib
import hmac
import json
import re
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence
from urllib.parse import parse_qsl, urlsplit

from ..analysis.evidence_engine import CaptureSource
from ..analysis.har_import import HarImportError, HarImportResult, import_har
from ..analysis.investigation_memory import InvestigationMemory
from ..burp_import import MAX_EXCHANGE_BYTES, MAX_ITEM_BYTES
from ..core.private_files import read_private_input
from ..core.records import RecordStore
from ..core.redaction import redact_data, redact_url
from ..core.scope_validator import ScopeValidator
from ..core.target import normalize_url
from ..reporting.evidence import write_evidence_json
from .content_ranking import CONTENT_PROFILE_VERSION, RANKING_MODES, collect_profiles, rank_content_aware
from .wordlist_manager import (
    WORDLIST_CATEGORIES,
    WordlistCollection,
    WordlistFile,
    _is_credential_wordlist,
    _walk_wordlists,
    classify_wordlist,
    list_wordlists,
    load_collections,
    recommend_wordlists,
)

PLAN_VERSION = "1.0"
DISCOVERY_CATEGORIES = ("api", "endpoints", "directories", "files", "parameters", "extensions", "technology")
EXCLUDED_AUTO_CATEGORIES = frozenset({"xss", "sqli", "other"})
MAX_PLAN_TARGETS = 40
MAX_OBSERVED_PATHS = 256
MAX_PARAMETERS = 128
MAX_TECHNOLOGIES = 32
_ID_SEGMENT = re.compile(r"^(?:[0-9]+|[a-f0-9]{8}-[a-f0-9-]{27,}|[a-f0-9]{24,})$", re.IGNORECASE)
_TECH_PATH_MARKERS: tuple[tuple[str, str], ...] = (
    ("/graphql", "graphql"),
    ("/wp-", "wordpress"),
    ("/wp-json", "wordpress"),
    ("/actuator", "spring"),
    ("/.git", "git"),
    ("/swagger", "openapi"),
    ("/openapi", "openapi"),
    ("/v1/", "versioned-api"),
    ("/v2/", "versioned-api"),
    ("/api/", "api"),
    ("/rest/", "rest"),
    ("/json", "json-api"),
)
_TECH_HEADER_MARKERS: tuple[tuple[str, str, str], ...] = (
    ("server", "nginx", "nginx"),
    ("server", "apache", "apache"),
    ("server", "cloudflare", "cloudflare"),
    ("x-powered-by", "express", "express"),
    ("x-powered-by", "php", "php"),
    ("x-powered-by", "asp.net", "aspnet"),
    ("x-aspnet-version", "", "aspnet"),
    ("x-drupal-", "", "drupal"),
)


@dataclass(frozen=True)
class CaptureContext:
    """Minimized, secret-free view of what a local capture showed."""

    hosts: tuple[str, ...]
    schemes: tuple[str, ...]
    route_prefixes: tuple[str, ...]
    observed_paths: tuple[str, ...]
    parameters: tuple[str, ...]
    technologies: tuple[str, ...]
    content_types: tuple[str, ...]
    methods: tuple[str, ...]
    categories_needed: tuple[str, ...]
    entry_count: int
    capture_import: dict[str, Any]


@dataclass(frozen=True)
class WordlistRecommendation:
    category: str
    path: str
    collection: str
    size_bytes: int
    reason: str
    evidence: tuple[str, ...]
    sha256: str | None = None


@dataclass(frozen=True)
class PlanTarget:
    """One bounded discovery target ready for human review then ``bbtk fuzz``."""

    url_template: str
    host: str
    base_path: str
    category: str
    wordlist: str
    collection: str
    max_entries: int
    estimated_requests: int
    reason: str
    provenance: dict[str, Any]


@dataclass(frozen=True)
class ObjectAssociation:
    """Structural link between a planned route and an Object Discovery candidate.

    Never confirms ownership. Uses the same HMAC discipline as object-handoff for
    any value that leaves the local process: path templates stay literal; resource
    identifiers are never copied into the plan.
    """

    path_template: str
    object_ref: str | None
    resource_type: str | None
    basis: str
    confirmed: bool = False


@dataclass
class FuzzPlan:
    """Offline discovery plan. Creating it never sends HTTP or starts ffuf."""

    program: str
    plan_version: str = PLAN_VERSION
    context: CaptureContext | None = None
    recommendations: list[WordlistRecommendation] = field(default_factory=list)
    targets: list[PlanTarget] = field(default_factory=list)
    discarded: list[dict[str, Any]] = field(default_factory=list)
    budget: dict[str, Any] = field(default_factory=dict)
    scope_hosts: list[str] = field(default_factory=list)
    object_associations: list[ObjectAssociation] = field(default_factory=list)
    network_requests_sent: int = 0
    auto_execute: bool = False
    vulnerabilities_confirmed: int = 0
    notes: list[str] = field(default_factory=list)
    content_ranking: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        payload = {
            "type": "context-aware-fuzz-plan",
            "plan_version": self.plan_version,
            "program": self.program,
            "context": asdict(self.context) if self.context else None,
            "recommendations": [asdict(item) for item in self.recommendations],
            "targets": [asdict(item) for item in self.targets],
            "discarded": list(self.discarded),
            "budget": dict(self.budget),
            "scope_hosts": list(self.scope_hosts),
            "object_associations": [asdict(item) for item in self.object_associations],
            "network_requests_sent": 0,
            "auto_execute": False,
            "vulnerabilities_confirmed": 0,
            "notes": list(self.notes),
            "execution": {
                "status": "plan_only",
                "reuse": "bbtk fuzz <program> --url <url_template> --wordlist <path> --dry-run then --confirm",
                "gates": ["scope", "authorization", "--confirm"],
                "ffuf_runner_duplicated": False,
            },
        }
        if self.content_ranking is not None:
            # Only present when the opt-in content ranking ran; filename-mode plans are unchanged.
            payload["content_ranking"] = self.content_ranking
        redacted = redact_data(payload)
        assert isinstance(redacted, dict)
        return redacted


def _validated_discovery_category(category: str | None) -> str | None:
    if category is None:
        return None
    normalized = category.strip().lower().replace("-", "_")
    aliases = {
        "route": "endpoints",
        "routes": "endpoints",
        "params": "parameters",
        "file": "files",
        "extension": "extensions",
        "tech": "technology",
        "api_endpoints": "api",
    }
    normalized = aliases.get(normalized, normalized)
    if normalized not in DISCOVERY_CATEGORIES:
        raise ValueError(f"Unknown discovery category {category!r}; choose from {', '.join(DISCOVERY_CATEGORIES)}.")
    return normalized


def _path_template(path: str) -> str:
    parts = [part for part in path.split("/") if part != ""]
    templated = ["{id}" if _ID_SEGMENT.fullmatch(part) else part for part in parts]
    return "/" + "/".join(templated) if templated else "/"


def _parent_prefixes(path: str) -> list[str]:
    parts = [part for part in path.split("/") if part and not _ID_SEGMENT.fullmatch(part)]
    prefixes: list[str] = []
    for depth in range(1, min(len(parts), 4) + 1):
        prefixes.append("/" + "/".join(parts[:depth]))
    if path.startswith("/api") and "/api" not in prefixes:
        prefixes.insert(0, "/api")
    return prefixes


def _header_value(headers: Mapping[str, str] | None, name: str) -> str:
    if not headers:
        return ""
    for key, value in headers.items():
        if key.lower() == name.lower() and isinstance(value, str):
            return value
    return ""


def _detect_technologies(sources: Sequence[CaptureSource]) -> tuple[str, ...]:
    found: set[str] = set()
    for source in sources:
        path = urlsplit(source.url or "").path.casefold()
        for marker, label in _TECH_PATH_MARKERS:
            if marker in path:
                found.add(label)
        for header_name, needle, label in _TECH_HEADER_MARKERS:
            value = _header_value(source.response_headers, header_name).casefold()
            value += " " + _header_value(source.request_headers, header_name).casefold()
            if needle:
                if needle in value:
                    found.add(label)
            elif value.strip():
                found.add(label)
        content_type = _header_value(source.response_headers, "content-type").casefold()
        if "json" in content_type:
            found.add("json-api")
        if "graphql" in content_type:
            found.add("graphql")
    return tuple(sorted(found)[:MAX_TECHNOLOGIES])


def _categories_from_context(
    prefixes: Sequence[str],
    parameters: Sequence[str],
    technologies: Sequence[str],
    content_types: Sequence[str],
) -> tuple[str, ...]:
    needed: list[str] = ["directories", "files"]
    joined = " ".join(prefixes).casefold()
    if any(token in joined for token in ("/api", "/v1", "/v2", "/rest", "/graphql")):
        needed.insert(0, "api")
        needed.append("endpoints")
    else:
        needed.append("endpoints")
    if parameters:
        needed.append("parameters")
    if any("json" in item.casefold() for item in content_types) or "json-api" in technologies:
        if "api" not in needed:
            needed.insert(0, "api")
    if technologies:
        needed.append("technology")
    needed.append("extensions")
    ordered = [item for item in DISCOVERY_CATEGORIES if item in needed]
    return tuple(ordered)


def analyze_capture_context(result: HarImportResult) -> CaptureContext:
    """Derive discovery context from accepted HAR entries without echoing secrets."""
    hosts: set[str] = set()
    schemes: set[str] = set()
    paths: list[str] = []
    prefixes: set[str] = set()
    parameters: set[str] = set()
    content_types: set[str] = set()
    methods: set[str] = set()
    for source in result.accepted:
        if not source.url:
            continue
        parsed = urlsplit(source.url)
        host = (parsed.hostname or "").lower()
        if not host:
            continue
        # Keep non-default ports so scope rules like http://127.0.0.1:8191 match.
        netloc = parsed.netloc.rsplit("@", 1)[-1].lower()
        hosts.add(netloc or host)
        if parsed.scheme in {"http", "https"}:
            schemes.add(parsed.scheme)
        path = parsed.path or "/"
        template = _path_template(path)
        if template not in paths and len(paths) < MAX_OBSERVED_PATHS:
            paths.append(template)
        prefixes.update(_parent_prefixes(path))
        for name in source.parameters:
            if isinstance(name, str) and name and not _ID_SEGMENT.fullmatch(name):
                parameters.add(name[:100])
        for key, value in parse_qsl(parsed.query, keep_blank_values=True):
            if key and not _ID_SEGMENT.fullmatch(key):
                parameters.add(key[:100])
        if source.method:
            methods.add(source.method.upper())
        ctype = _header_value(source.response_headers, "content-type")
        if ctype:
            content_types.add(ctype.split(";", 1)[0].strip().lower()[:80])
    technologies = _detect_technologies(result.accepted)
    prefix_list = tuple(sorted(prefixes)[:64])
    param_list = tuple(sorted(parameters)[:MAX_PARAMETERS])
    categories = _categories_from_context(prefix_list, param_list, technologies, tuple(content_types))
    summary = result.summary()
    # Drop per-entry index detail from the plan surface; keep aggregate codes only.
    capture_import = {
        "format": summary["format"],
        "mode": summary["mode"],
        "entries_total": summary["entries_total"],
        "accepted": summary["accepted"],
        "rejected": summary["rejected"],
        "reasons": summary["reasons"],
        "truncated": summary["truncated"],
        "duplicate_entries": summary["duplicate_entries"],
        "network_validation": "none",
    }
    return CaptureContext(
        hosts=tuple(sorted(hosts)),
        schemes=tuple(sorted(schemes)) or ("https",),
        route_prefixes=prefix_list,
        observed_paths=tuple(paths),
        parameters=param_list,
        technologies=technologies,
        content_types=tuple(sorted(content_types)[:32]),
        methods=tuple(sorted(methods)),
        categories_needed=categories,
        entry_count=len(result.accepted),
        capture_import=capture_import,
    )


def _recommendation_reason(category: str, context: CaptureContext) -> tuple[str, tuple[str, ...]]:
    evidence: list[str] = []
    if category == "api":
        evidence = [
            prefix for prefix in context.route_prefixes if "/api" in prefix or "/v1" in prefix or "/v2" in prefix
        ][:5]
        if "json-api" in context.technologies:
            evidence.append("content-type:json")
        return "Capture shows API-shaped routes; prefer API endpoint lists.", tuple(evidence) or ("api-shaped paths",)
    if category == "endpoints":
        return "Observed route templates suggest complementary endpoint names.", tuple(context.observed_paths[:5]) or (
            "observed routes",
        )
    if category == "directories":
        return "Directory lists help expand under observed prefixes without guessing credentials.", tuple(
            context.route_prefixes[:5]
        ) or ("route prefixes",)
    if category == "files":
        return "Common file names complement directory discovery under the same prefixes.", tuple(
            context.route_prefixes[:3]
        ) or ("prefixes",)
    if category == "parameters":
        return "Parameter names already seen in the capture guide param discovery.", tuple(context.parameters[:8]) or (
            "observed parameters",
        )
    if category == "extensions":
        return "Extension lists are useful after directory discovery on the same hosts.", tuple(context.hosts[:3]) or (
            "in-scope hosts",
        )
    if category == "technology":
        return "Technology markers from paths/headers select tech-specific path lists.", tuple(
            context.technologies
        ) or ("technology markers",)
    return "Category matched capture evidence.", ()


def recommend_for_context(
    collections: Iterable[WordlistCollection],
    context: CaptureContext,
    *,
    category: str | None = None,
    max_per_category: int = 3,
    ranking: str = "filename",
    explanations: list[dict[str, Any]] | None = None,
) -> tuple[list[WordlistRecommendation], list[dict[str, Any]]]:
    """Recommend local discovery lists from capture evidence; never downloads.

    ``ranking="filename"`` (default) is the historical behaviour. ``ranking="content"``
    is opt-in and delegates ordering to :mod:`content_ranking`; per-list explanations
    are appended to ``explanations`` when a list is supplied.
    """
    if ranking not in RANKING_MODES:
        raise ValueError(f"Unknown ranking mode {ranking!r}; choose from {', '.join(RANKING_MODES)}.")
    if ranking == "content":
        return _recommend_by_content(
            collections, context, category=category, max_per_category=max_per_category, explanations=explanations
        )
    requested = _validated_discovery_category(category)
    categories = (requested,) if requested else context.categories_needed
    collection_list = list(collections)
    recommendations: list[WordlistRecommendation] = []
    discarded: list[dict[str, Any]] = []
    seen_paths: set[str] = set()

    # Explicitly record credential lists (filtered by the manager) and exploit-oriented categories.
    for collection in collection_list:
        if not collection.path.is_dir():
            continue
        for path in _walk_wordlists(collection.path):
            relative = path.relative_to(collection.path)
            if _is_credential_wordlist(relative) or _is_credential_wordlist(Path(collection.path.name)):
                discarded.append(
                    {
                        "path": str(path),
                        "category": "other",
                        "reason": "Excluded from generic discovery (credential or exploit-oriented list).",
                    }
                )
    for item in list_wordlists(collection_list):
        if item.category in EXCLUDED_AUTO_CATEGORIES or item.category in {"xss", "sqli"}:
            discarded.append(
                {
                    "path": str(item.path),
                    "category": item.category,
                    "reason": "Excluded from generic discovery (credential or exploit-oriented list).",
                }
            )

    for cat in categories:
        reason, evidence = _recommendation_reason(cat, context)
        try:
            matches = recommend_wordlists(collection_list, cat)
        except ValueError:
            discarded.append({"category": cat, "reason": "No local lists registered for this category."})
            continue
        if not matches:
            discarded.append({"category": cat, "reason": "No local lists registered for this category."})
            continue
        # Prefer lists whose names overlap observed routes, params or technologies.
        tokens = {
            part.casefold()
            for path in list(context.observed_paths) + list(context.route_prefixes)
            for part in path.split("/")
            if part and part != "{id}"
        }
        tokens.update(param.casefold() for param in context.parameters)
        tokens.update(marker.casefold() for marker in context.technologies)

        def score(row: WordlistFile) -> tuple[int, int, int, str]:
            # Score the filename only so shared category directories (…/api/…) do not tie every list.
            filename = row.path.name.casefold()
            stem_parts = set(Path(filename).stem.replace("-", " ").replace("_", " ").split())
            overlap = len(tokens.intersection(stem_parts))
            tech_hit = 1 if cat == "technology" and any(marker in filename for marker in context.technologies) else 0
            return (-overlap, -tech_hit, row.size_bytes, str(row.path).casefold())

        ranked = sorted(matches, key=score)
        for item in ranked[:max_per_category]:
            path_key = str(item.path.resolve(strict=False))
            if path_key in seen_paths:
                discarded.append({"path": path_key, "category": cat, "reason": "Duplicate path already recommended."})
                continue
            seen_paths.add(path_key)
            recommendations.append(
                WordlistRecommendation(
                    category=cat,
                    path=path_key,
                    collection=item.collection,
                    size_bytes=item.size_bytes,
                    reason=reason,
                    evidence=evidence,
                )
            )
    return recommendations, discarded


def _recommend_by_content(
    collections: Iterable[WordlistCollection],
    context: CaptureContext,
    *,
    category: str | None,
    max_per_category: int,
    explanations: list[dict[str, Any]] | None,
) -> tuple[list[WordlistRecommendation], list[dict[str, Any]]]:
    """Narrow adapter from content-aware ranking to the planner's recommendation type."""
    requested = _validated_discovery_category(category)
    categories = (requested,) if requested else context.categories_needed
    profiles, excluded = collect_profiles(list(collections))
    discarded: list[dict[str, Any]] = [
        {
            "path": item["path"],
            "category": "other",
            "reason": "Excluded from generic discovery (credential or exploit-oriented list).",
        }
        for item in excluded
    ]
    for profile in profiles:
        if profile.name_category in {"xss", "sqli"}:
            discarded.append(
                {
                    "path": profile.path,
                    "category": profile.name_category,
                    "reason": "Excluded from generic discovery (credential or exploit-oriented list).",
                }
            )
    recommendations: list[WordlistRecommendation] = []
    seen_paths: set[str] = set()
    for cat in categories:
        reason, evidence = _recommendation_reason(cat, context)
        ranked, dropped = rank_content_aware(profiles, cat, context)
        discarded.extend(dropped)
        if not ranked:
            discarded.append({"category": cat, "reason": "No local lists registered for this category."})
            continue
        for item in ranked[:max_per_category]:
            path_key = str(Path(item.path).resolve(strict=False))
            if path_key in seen_paths:
                discarded.append({"path": path_key, "category": cat, "reason": "Duplicate path already recommended."})
                continue
            seen_paths.add(path_key)
            recommendations.append(
                WordlistRecommendation(
                    category=cat,
                    path=path_key,
                    collection=item.collection,
                    size_bytes=item.size_bytes,
                    reason=reason,
                    evidence=evidence,
                    sha256=item.explanation.get("sample_sha256"),
                )
            )
            if explanations is not None:
                explanations.append({"path": path_key, "score": item.score, **item.explanation})
    return recommendations, discarded


def _fuzz_url(scheme: str, host: str, prefix: str) -> str:
    base = prefix.rstrip("/") if prefix != "/" else ""
    return f"{scheme}://{host}{base}/FUZZ"


def _select_prefix(context: CaptureContext) -> str:
    preferred = [
        item for item in context.route_prefixes if item in {"/api", "/api/v1", "/api/v2", "/v1", "/v2", "/graphql"}
    ]
    if preferred:
        return sorted(preferred, key=len)[-1]
    if context.route_prefixes:
        return sorted(context.route_prefixes, key=len)[0]
    return ""


def build_plan_targets(
    context: CaptureContext,
    recommendations: Sequence[WordlistRecommendation],
    *,
    scope: ScopeValidator | None,
    max_tests: int,
    max_targets: int = MAX_PLAN_TARGETS,
    category: str | None = None,
) -> tuple[list[PlanTarget], list[dict[str, Any]]]:
    """Build scoped FUZZ URL templates. Every destination is scope-checked when a validator is given."""
    if max_tests < 2:
        raise ValueError("Planning needs a budget for one baseline request and at least one wordlist entry.")
    if max_targets <= 0 or max_targets > MAX_PLAN_TARGETS:
        raise ValueError(f"max_targets must be between 1 and {MAX_PLAN_TARGETS}.")
    requested = _validated_discovery_category(category)
    discarded: list[dict[str, Any]] = []
    targets: list[PlanTarget] = []
    hosts = list(context.hosts)
    if not hosts:
        raise ValueError("Capture produced no usable hosts for planning.")
    prefix = _select_prefix(context)
    entries_cap = max_tests - 1
    for recommendation in recommendations:
        if requested and recommendation.category != requested:
            continue
        if recommendation.category in EXCLUDED_AUTO_CATEGORIES:
            discarded.append(
                {
                    "path": recommendation.path,
                    "reason": "Category is incompatible with generic discovery planning.",
                }
            )
            continue
        for host in hosts:
            if len(targets) >= max_targets:
                discarded.append({"path": recommendation.path, "reason": "Plan target cap reached."})
                break
            # Parameter discovery places FUZZ in a query value of a known path template.
            scheme = context.schemes[0] if context.schemes else "https"
            if recommendation.category == "parameters" and context.parameters:
                path = context.observed_paths[0] if context.observed_paths else "/"
                # Drop id placeholders from the path used for param FUZZ templates.
                path = path.replace("/{id}", "").rstrip("/") or "/"
                param = context.parameters[0]
                url = f"{scheme}://{host}{path}?{param}=FUZZ"
            else:
                url = _fuzz_url(scheme, host, prefix)
            try:
                normalized = normalize_url(url)
            except ValueError as exc:
                discarded.append({"url": url, "reason": f"Invalid URL template: {exc}"})
                continue
            parsed = urlsplit(normalized)
            if "FUZZ" in parsed.netloc or "FUZZ" not in parsed.path + parsed.query:
                discarded.append({"url": normalized, "reason": "FUZZ must stay in the path or query of a fixed host."})
                continue
            if scope is not None:
                try:
                    # Validate the template host via a placeholder substitution that stays structural.
                    probe = normalize_url(normalized.replace("FUZZ", "__bbtk_plan_probe__"))
                    scope.require(probe)
                except Exception as exc:  # noqa: BLE001 - surface scope failures as discarded rows
                    discarded.append(
                        {
                            "url": redact_url(normalized),
                            "reason": f"Out of scope or rejected by scope validator: {exc}",
                        }
                    )
                    continue
            targets.append(
                PlanTarget(
                    url_template=redact_url(normalized),
                    host=host,
                    base_path=prefix or "/",
                    category=recommendation.category,
                    wordlist=recommendation.path,
                    collection=recommendation.collection,
                    max_entries=entries_cap,
                    estimated_requests=entries_cap + 1,
                    reason=recommendation.reason,
                    provenance={
                        "capture_hosts": list(context.hosts),
                        "route_prefixes": list(context.route_prefixes[:8]),
                        "technologies": list(context.technologies),
                        "evidence": list(recommendation.evidence),
                        "wordlist_category": recommendation.category,
                        "collection": recommendation.collection,
                    },
                )
            )
    return targets, discarded


def associate_object_candidates(
    context: CaptureContext,
    candidates: Sequence[Mapping[str, Any]] | None,
    *,
    hmac_key: bytes | None = None,
) -> list[ObjectAssociation]:
    """Link planned path templates to Object Discovery candidates when structure matches.

    Never confirms ownership. Resource identifiers are not copied; ``object_ref`` is taken
    only when already present as an HMAC-style ref from the graph.
    """
    if not candidates:
        return []
    associations: list[ObjectAssociation] = []
    observed = set(context.observed_paths)
    for row in candidates:
        if not isinstance(row, Mapping):
            continue
        endpoint = row.get("endpoint") or row.get("path_template") or row.get("route_template")
        if not isinstance(endpoint, str) or not endpoint:
            continue
        template = _path_template(urlsplit(endpoint).path if "://" in endpoint else endpoint)
        if template not in observed and not any(
            template.startswith(prefix.rstrip("/") + "/") or template == prefix for prefix in context.route_prefixes
        ):
            continue
        object_ref = row.get("object_ref")
        if object_ref is not None and not isinstance(object_ref, str):
            object_ref = None
        resource_type = row.get("resource_type")
        if resource_type is not None and not isinstance(resource_type, str):
            resource_type = None
        # Optional integrity tag over the template so later consumers can detect tampering.
        basis = "structural_path_match"
        if hmac_key is not None:
            digest = hmac.new(hmac_key, template.encode("utf-8"), hashlib.sha256).hexdigest()[:16]
            basis = f"structural_path_match;template_mac={digest}"
        associations.append(
            ObjectAssociation(
                path_template=template,
                object_ref=object_ref,
                resource_type=resource_type,
                basis=basis,
                confirmed=False,
            )
        )
        if len(associations) >= 50:
            break
    return associations


def load_har_for_planning(
    path: Path,
    *,
    strict: bool = False,
    allow_truncate: bool = False,
) -> HarImportResult:
    """Read a local HAR through the resilient importer; no network."""
    data = read_private_input(path, MAX_ITEM_BYTES)
    return import_har(
        data,
        strict=strict,
        max_bytes=MAX_ITEM_BYTES,
        max_message_bytes=MAX_EXCHANGE_BYTES,
        allow_truncate=allow_truncate,
    )


def build_fuzz_plan(
    program: str,
    har_path: Path,
    *,
    collections: Sequence[WordlistCollection],
    scope: ScopeValidator | None = None,
    category: str | None = None,
    max_tests: int = 40,
    max_targets: int = MAX_PLAN_TARGETS,
    object_candidates: Sequence[Mapping[str, Any]] | None = None,
    object_key: bytes | None = None,
    strict: bool = False,
    allow_truncate: bool = False,
    ranking: str = "filename",
) -> FuzzPlan:
    """Create a fully offline discovery plan from a local HAR and registered wordlists."""
    if max_tests < 2 or max_tests > 1_000_000:
        raise ValueError("max_tests must be between 2 and 1,000,000.")
    result = load_har_for_planning(har_path, strict=strict, allow_truncate=allow_truncate)
    context = analyze_capture_context(result)
    explanations: list[dict[str, Any]] | None = [] if ranking == "content" else None
    recommendations, discarded_lists = recommend_for_context(
        collections, context, category=category, ranking=ranking, explanations=explanations
    )
    targets, discarded_targets = build_plan_targets(
        context,
        recommendations,
        scope=scope,
        max_tests=max_tests,
        max_targets=max_targets,
        category=category,
    )
    associations = associate_object_candidates(context, object_candidates, hmac_key=object_key)
    scope_hosts: list[str] = []
    if scope is not None:
        summary = scope.summary()
        scope_hosts = [str(item) for item in summary.get("allowed", [])][:64]
    notes = [
        "Planning is offline: zero network sockets, no wordlist downloads, no ffuf execution.",
        "Review each target, then run `bbtk fuzz` with --dry-run and --confirm; do not bypass those gates.",
        "No finding is confirmed by plan generation. Object associations never assert ownership.",
    ]
    if not recommendations:
        notes.append("No local discovery wordlists matched; register SecLists/Assetnote/fuzzdb/custom collections.")
    if context.capture_import.get("rejected"):
        notes.append(
            f"Partial HAR recovery isolated {context.capture_import['rejected']} entries; see capture_import.reasons."
        )
    return FuzzPlan(
        program=program,
        context=context,
        recommendations=recommendations,
        targets=targets,
        discarded=[*discarded_lists, *discarded_targets],
        budget={
            "max_tests": max_tests,
            "max_entries_per_target": max_tests - 1,
            "max_targets": max_targets,
            "estimated_requests_total": sum(item.estimated_requests for item in targets),
            "baseline_per_target": 1,
            "rate_guidance": "Use program requests_per_second; stop on HTTP 429; no redirects/recursion/retries.",
        },
        scope_hosts=scope_hosts,
        object_associations=associations,
        notes=notes,
        content_ranking=(
            {"mode": "content", "profile_version": CONTENT_PROFILE_VERSION, "explanations": explanations}
            if explanations is not None
            else None
        ),
    )


def save_plan(
    store: RecordStore,
    plan: FuzzPlan,
    *,
    output: Path | None = None,
    record_memory: bool = True,
) -> dict[str, Any]:
    """Persist a redacted plan into evidence storage and optionally Investigation Memory."""
    document = plan.to_dict()
    evidence_path = write_evidence_json(store.paths.evidence_dir / "fuzzing", document, "fuzz-plan")
    output_path = evidence_path
    if output is not None:
        output = output.expanduser()
        output.parent.mkdir(parents=True, exist_ok=True)
        if output.exists():
            raise FileExistsError(f"Plan output already exists: {output}")
        output.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        output_path = output
    memory_id = None
    if record_memory:
        # Bundle id is a content fingerprint of the plan, not a network artifact.
        digest = hashlib.sha256(json.dumps(document, sort_keys=True).encode("utf-8")).hexdigest()[:24]
        snapshot_ref = evidence_path.relative_to(store.paths.program_dir).as_posix()
        memory = InvestigationMemory(store).save_snapshot(
            f"fuzz-plan-{digest}",
            digest,
            snapshot_ref,
            {
                "planning": {"status": "completed; offline capture analysis only"},
                "discovery": {"status": "pending human review of plan targets"},
                "authorization": {"status": "not started; no ownership claims"},
            },
        )
        memory_id = memory.get("investigation_id")
    return {
        "evidence": str(evidence_path),
        "output": str(output_path),
        "investigation_id": memory_id,
        "targets": len(plan.targets),
        "recommendations": len(plan.recommendations),
        "network_requests_sent": 0,
        "plan_executed": False,
    }


def baseline_generic_recommendations(
    collections: Iterable[WordlistCollection],
    category: str = "api",
) -> list[WordlistRecommendation]:
    """Pre-context baseline: category-only recommendation without capture analysis."""
    matches = recommend_wordlists(collections, category)
    return [
        WordlistRecommendation(
            category=category,
            path=str(item.path),
            collection=item.collection,
            size_bytes=item.size_bytes,
            reason="Generic category recommendation without capture context.",
            evidence=("category-only",),
        )
        for item in matches[:3]
    ]


def compare_recommendation_precision(
    *,
    recommended: Sequence[WordlistRecommendation],
    relevant_paths: set[str],
) -> dict[str, float | int]:
    """Precision of recommended paths against a lab ground-truth relevant set."""
    if not recommended:
        return {"recommended": 0, "relevant_hits": 0, "precision": 0.0}
    hits = sum(1 for item in recommended if item.path in relevant_paths or Path(item.path).name in relevant_paths)
    return {
        "recommended": len(recommended),
        "relevant_hits": hits,
        "precision": hits / len(recommended),
    }


# Re-export helpers tests may want without inventing alternate download paths.
__all__ = [
    "PLAN_VERSION",
    "DISCOVERY_CATEGORIES",
    "CaptureContext",
    "WordlistRecommendation",
    "PlanTarget",
    "ObjectAssociation",
    "FuzzPlan",
    "analyze_capture_context",
    "recommend_for_context",
    "build_plan_targets",
    "associate_object_candidates",
    "load_har_for_planning",
    "build_fuzz_plan",
    "save_plan",
    "baseline_generic_recommendations",
    "compare_recommendation_precision",
    "classify_wordlist",
    "WORDLIST_CATEGORIES",
    "load_collections",
    "HarImportError",
]
