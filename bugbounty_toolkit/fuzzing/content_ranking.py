"""Opt-in, content-aware wordlist ranking (bounded, deterministic, offline).

Three separate stages:

1. ``profile_wordlist`` -- classify a list from a bounded head sample of its
   real entries (never executes, requests or follows anything in it).
2. ``rank_content_aware`` -- score profiles against a minimized capture
   context and explain each recommendation.
3. Plan generation stays in ``context_planner.build_plan_targets``.

Entries are treated purely as data: text inside a wordlist that looks like an
instruction is just another token. Reports expose aggregate counts, a SHA-256
of the inspected bytes and at most a few short matched tokens -- never full
payloads.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import math
import os
import re
import time
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

from .wordlist_manager import (
    MAX_ENTRY_BYTES,
    WordlistCollection,
    _is_credential_wordlist,
    _walk_wordlists,
    classify_wordlist,
)

RANKING_MODES = ("filename", "content")
CONTENT_PROFILE_VERSION = "1.0"
DEFAULT_MAX_SAMPLE_BYTES = 256 * 1024
DEFAULT_MAX_SAMPLE_ENTRIES = 2_000
DEFAULT_MAX_SECONDS = 0.5
MAX_TOKEN_CHARS = 128
MAX_EXPLAINED_TOKENS = 5
INCLUDE_FIT_THRESHOLD = 0.6
PAYLOAD_EXCLUDE_RATIO = 0.2
CREDENTIAL_EXCLUDE_RATIO = 0.3

_FORBIDDEN_NAME_CATEGORIES = frozenset({"xss", "sqli", "other"})
_SPLIT = re.compile(r"[/._\-?=&:]+")
_IDENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,63}$")
_PATHLIKE = re.compile(r"^/?[A-Za-z0-9_~%@+\-][A-Za-z0-9_~%@+\-./]*/?$")
_EXT_ONLY = re.compile(r"^\.?[A-Za-z0-9]{1,6}$")
_FILE = re.compile(r"(?:^|/)[^/]+\.[A-Za-z0-9]{1,6}$")
_PAYLOAD_MARKERS = (
    "<",
    ">",
    "'",
    '"',
    "javascript:",
    "onerror",
    "alert(",
    " or ",
    "1=1",
    "--",
    "union select",
    "sleep(",
    "${",
    "{{",
    "%27",
    "%3c",
)
_API_MARKERS = ("api", "v1", "v2", "v3", "rest", "graphql", "json", "oauth", "swagger", "openapi")
_TECH_TOKENS: Mapping[str, tuple[str, ...]] = {
    "wordpress": ("wp-admin", "wp-content", "wp-json", "wp-includes", "xmlrpc"),
    "drupal": ("sites/default", "node/add", "user/login", "core/misc"),
    "spring": ("actuator", "heapdump", "env", "mappings", "jolokia"),
    "aspnet": (".aspx", ".asmx", "web.config", ".axd", "_vti_bin"),
    "php": (".php", "phpinfo", "composer.json", "vendor/"),
    "graphql": ("graphql", "graphiql", "__schema", "altair"),
    "openapi": ("swagger", "openapi", "api-docs", "redoc"),
    "git": (".git/", ".git/head", ".gitignore"),
    "express": ("node_modules", "package.json", ".env"),
    "nginx": ("nginx_status", "nginx.conf"),
    "apache": ("server-status", ".htaccess", "server-info"),
}
_COMMON_PASSWORD_HINTS = frozenset(
    {
        "123456",
        "password",
        "12345678",
        "qwerty",
        "letmein",
        "welcome",
        "admin123",
        "iloveyou",
        "monkey",
        "dragon",
        "abc123",
        "passw0rd",
        "changeme",
        "secret",
        "111111",
        "sunshine",
        "princess",
        "football",
    }
)
_CATEGORY_KINDS: Mapping[str, tuple[str, ...]] = {
    "api": ("api",),
    "endpoints": ("api", "endpoint", "directory"),
    "directories": ("directory",),
    "files": ("file",),
    "parameters": ("parameter",),
    "extensions": ("extension",),
    "technology": ("technology",),
}


@dataclass(frozen=True)
class ContentProfile:
    """Bounded features of one list. Never contains full entries."""

    path: str
    collection: str
    name_category: str
    size_bytes: int
    inspected: bool
    entries_inspected: int
    bytes_inspected: int
    sample_truncated: bool
    unique_ratio: float
    kind_ratios: dict[str, float]
    technologies: tuple[str, ...]
    tokens: frozenset[str]
    estimated_entries: int
    sample_sha256: str | None
    fallback_reason: str | None = None

    @property
    def content_category(self) -> str:
        """Dominant discovery kind inferred from the sample (or ``unknown``)."""
        if not self.inspected or not self.kind_ratios:
            return "unknown"
        best = max(sorted(self.kind_ratios), key=lambda key: self.kind_ratios[key])
        return best if self.kind_ratios[best] > 0 else "unknown"


@dataclass(frozen=True)
class ContentRecommendation:
    """One ranked list with a full, payload-free explanation."""

    category: str
    path: str
    collection: str
    size_bytes: int
    score: float
    explanation: dict[str, Any] = field(default_factory=dict)


def _entry_kinds(value: str) -> set[str]:
    lowered = value.casefold()
    kinds: set[str] = set()
    if any(marker in lowered for marker in _PAYLOAD_MARKERS) or " " in value.strip():
        kinds.add("payload")
        return kinds
    if not _PATHLIKE.fullmatch(value):
        if lowered in _COMMON_PASSWORD_HINTS or (
            any(c.isdigit() for c in value) and any(not c.isalnum() for c in value)
        ):
            kinds.add("credential")
        else:
            kinds.add("invalid")
        return kinds
    if lowered in _COMMON_PASSWORD_HINTS:
        kinds.add("credential")
        return kinds
    parts = [part for part in lowered.strip("/").split("/") if part]
    if not parts:
        kinds.add("invalid")
        return kinds
    for tokens in _TECH_TOKENS.values():
        if any(token in lowered for token in tokens):
            kinds.add("technology")
            break
    if any(part in _API_MARKERS or re.fullmatch(r"v[0-9]{1,2}", part) for part in parts):
        kinds.add("api")
    if _EXT_ONLY.fullmatch(value) and (value.startswith(".") or len(value) <= 4) and "/" not in value:
        if value.startswith("."):
            kinds.add("extension")
            return kinds
    if _FILE.search(lowered) and not value.endswith("/"):
        kinds.add("file")
    elif len(parts) >= 2:
        kinds.add("endpoint")
    elif _IDENT.fullmatch(value) and (("_" in value) or any(c.isupper() for c in value[1:])):
        kinds.add("parameter")
    else:
        kinds.add("directory")
        if _IDENT.fullmatch(value):
            kinds.add("parameter_weak")
    return kinds


def _tokens(value: str) -> set[str]:
    result: set[str] = set()
    for part in _SPLIT.split(value.casefold()):
        if 2 <= len(part) <= 40:
            result.add(part)
    camel = re.findall(r"[a-z]+|[A-Z][a-z]*", value)
    result.update(item.casefold() for item in camel if len(item) >= 2)
    return result


def _within(root: Path, candidate: Path) -> bool:
    try:
        resolved = candidate.resolve(strict=True)
        return resolved.is_relative_to(root.resolve(strict=True)) and not candidate.is_symlink()
    except (OSError, RuntimeError):
        return False


def profile_wordlist(
    path: Path,
    *,
    collection: WordlistCollection,
    max_sample_bytes: int = DEFAULT_MAX_SAMPLE_BYTES,
    max_sample_entries: int = DEFAULT_MAX_SAMPLE_ENTRIES,
    max_seconds: float = DEFAULT_MAX_SECONDS,
) -> ContentProfile:
    """Read a deterministic head sample (first N bytes / entries) of one registered list."""
    relative = path.relative_to(collection.path) if path.is_relative_to(collection.path) else Path(path.name)
    name_category = collection.category or classify_wordlist(relative)
    try:
        size = path.lstat().st_size
    except OSError:
        size = 0

    def fallback(reason: str) -> ContentProfile:
        return ContentProfile(
            path=str(path),
            collection=collection.name,
            name_category=name_category,
            size_bytes=size,
            inspected=False,
            entries_inspected=0,
            bytes_inspected=0,
            sample_truncated=False,
            unique_ratio=1.0,
            kind_ratios={},
            technologies=(),
            tokens=frozenset(),
            estimated_entries=0,
            sample_sha256=None,
            fallback_reason=reason,
        )

    if path.is_symlink() or not _within(collection.path, path):
        return fallback("outside-collection-or-symlink")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError:
        return fallback("unreadable")
    counts: dict[str, int] = {}
    tokens: set[str] = set()
    seen: set[str] = set()
    techs: set[str] = set()
    entries = 0
    consumed = 0
    truncated = False
    digest = hashlib.sha256()
    started = time.monotonic()
    with os.fdopen(descriptor, "rb") as handle:
        while True:
            if entries >= max_sample_entries or consumed >= max_sample_bytes:
                truncated = bool(handle.read(1))
                break
            if time.monotonic() - started > max_seconds:
                truncated = True
                break
            raw = handle.readline(min(MAX_ENTRY_BYTES + 2, max_sample_bytes - consumed + 1))
            if not raw:
                break
            consumed += len(raw)
            digest.update(raw)
            if not raw.endswith(b"\n") and len(raw) > MAX_TOKEN_CHARS * 4:
                counts["invalid"] = counts.get("invalid", 0) + 1
                while raw and not raw.endswith(b"\n") and consumed < max_sample_bytes:
                    raw = handle.readline(4096)
                    consumed += len(raw)
                    digest.update(raw)
                entries += 1
                continue
            stripped = raw.rstrip(b"\r\n")
            if entries == 0 and stripped.startswith(b"\xef\xbb\xbf"):
                stripped = stripped[3:]
            if b"\x00" in stripped:
                counts["invalid"] = counts.get("invalid", 0) + 1
                entries += 1
                continue
            try:
                value = stripped.decode("utf-8").strip()
            except UnicodeDecodeError:
                counts["invalid"] = counts.get("invalid", 0) + 1
                entries += 1
                continue
            if not value or value.startswith("#"):
                continue
            entries += 1
            if len(value) > MAX_TOKEN_CHARS:
                counts["invalid"] = counts.get("invalid", 0) + 1
                continue
            seen.add(value)
            for kind in _entry_kinds(value):
                counts[kind] = counts.get(kind, 0) + 1
            lowered = value.casefold()
            for label, markers in _TECH_TOKENS.items():
                if any(marker in lowered for marker in markers):
                    techs.add(label)
            if len(tokens) < 20_000:
                tokens.update(_tokens(value))
    if entries == 0:
        return fallback("empty-sample")
    weak = counts.pop("parameter_weak", 0)
    ratios = {kind: counts.get(kind, 0) / entries for kind in sorted({*counts, "parameter"})}
    # A list of plain single identifiers is ambiguous between directory and parameter names.
    ratios["parameter"] = ratios.get("parameter", 0.0) + 0.5 * weak / entries
    if "api" in ratios:
        ratios["endpoint"] = ratios.get("endpoint", 0.0)
    estimated = entries if not truncated or consumed == 0 else int(entries * (size / max(consumed, 1)))
    return ContentProfile(
        path=str(path),
        collection=collection.name,
        name_category=name_category,
        size_bytes=size,
        inspected=True,
        entries_inspected=entries,
        bytes_inspected=consumed,
        sample_truncated=truncated,
        unique_ratio=len(seen) / entries,
        kind_ratios=ratios,
        technologies=tuple(sorted(techs)),
        tokens=frozenset(tokens),
        estimated_entries=max(estimated, entries),
        sample_sha256=digest.hexdigest(),
    )


def _category_fit(profile: ContentProfile, category: str) -> float:
    kinds = _CATEGORY_KINDS.get(category, ())
    return min(1.0, sum(profile.kind_ratios.get(kind, 0.0) for kind in kinds))


def _context_tokens(context: Any) -> tuple[set[str], set[str], set[str]]:
    route: set[str] = set()
    for path in [*getattr(context, "observed_paths", ()), *getattr(context, "route_prefixes", ())]:
        route.update(token for token in _tokens(str(path)) if token != "id")
    params = {str(item).casefold() for item in getattr(context, "parameters", ())}
    techs = {str(item).casefold() for item in getattr(context, "technologies", ())}
    return route, params, techs


def exclusion_reason(profile: ContentProfile) -> str | None:
    """Content-level safety exclusions on top of the filename rules."""
    if not profile.inspected:
        return None
    if profile.kind_ratios.get("credential", 0.0) >= CREDENTIAL_EXCLUDE_RATIO:
        return "content-looks-like-credential-list"
    if profile.kind_ratios.get("payload", 0.0) >= PAYLOAD_EXCLUDE_RATIO:
        return "content-looks-like-injection-payloads"
    return None


def score_profile(profile: ContentProfile, category: str, context: Any) -> tuple[float, dict[str, Any]]:
    """Return (score, explanation). Pure function of the profile and minimized context."""
    route, params, techs = _context_tokens(context)
    if not profile.inspected:
        name_fit = 1.0 if profile.name_category == category else 0.5
        size_term = 1.0 / (1.0 + math.log10(1 + profile.size_bytes))
        score = 0.3 * name_fit + 0.05 * size_term
        return score, {
            "category": category,
            "mode": "filename-fallback",
            "fallback_reason": profile.fallback_reason,
            "uncertainty": "high",
            "content_signals": {},
            "context_signals": {},
        }
    fit = _category_fit(profile, category)
    route_hits = sorted(route & profile.tokens)
    param_hits = sorted(params & profile.tokens)
    tech_hits = sorted(techs & set(profile.technologies))
    if category == "parameters":
        overlap = len(param_hits) / max(len(params), 1) if params else 0.0
        hits = param_hits
    elif category == "technology":
        overlap = len(tech_hits) / max(len(techs), 1) if techs else 0.0
        hits = tech_hits
    else:
        overlap = len(route_hits) / max(len(route), 1) if route else 0.0
        hits = route_hits
    duplication = 1.0 - profile.unique_ratio
    name_bonus = 0.05 if profile.name_category == category else 0.0
    cost = profile.estimated_entries
    cost_term = 1.0 / (1.0 + math.log10(1 + cost))
    score = 0.45 * fit + 0.4 * overlap + 0.05 * (1.0 - duplication) + 0.05 * cost_term + name_bonus
    noise = profile.kind_ratios.get("invalid", 0.0)
    score -= 0.2 * noise
    uncertainty = "low" if profile.entries_inspected >= 200 and not profile.sample_truncated else "medium"
    if profile.entries_inspected < 20:
        uncertainty = "high"
    explanation = {
        "category": category,
        "mode": "content",
        "name_category": profile.name_category,
        "content_category": profile.content_category,
        "context_signals": {
            "matched_tokens": hits[:MAX_EXPLAINED_TOKENS],
            "matched_count": len(hits),
            "technologies": tech_hits[:MAX_EXPLAINED_TOKENS],
        },
        "content_signals": {key: round(value, 3) for key, value in profile.kind_ratios.items() if value},
        "estimated_coverage": round(overlap, 3),
        "estimated_duplication": round(duplication, 3),
        "estimated_requests": cost,
        "entries_inspected": profile.entries_inspected,
        "bytes_inspected": profile.bytes_inspected,
        "sample_truncated": profile.sample_truncated,
        "uncertainty": uncertainty,
        "sample_sha256": profile.sample_sha256,
        "profile_version": CONTENT_PROFILE_VERSION,
    }
    return round(score, 6), explanation


def collect_profiles(
    collections: Iterable[WordlistCollection],
    *,
    max_sample_bytes: int = DEFAULT_MAX_SAMPLE_BYTES,
    max_sample_entries: int = DEFAULT_MAX_SAMPLE_ENTRIES,
) -> tuple[list[ContentProfile], list[dict[str, Any]]]:
    """Profile every registered list; filename credential rules apply before any read."""
    profiles: list[ContentProfile] = []
    excluded: list[dict[str, Any]] = []
    for collection in sorted(collections, key=lambda item: item.name.casefold()):
        if not collection.path.is_dir():
            continue
        for path in _walk_wordlists(collection.path):
            relative = path.relative_to(collection.path)
            if _is_credential_wordlist(relative) or _is_credential_wordlist(Path(collection.path.name)):
                excluded.append({"path": str(path), "reason": "credential-list-by-name"})
                continue
            profiles.append(
                profile_wordlist(
                    path,
                    collection=collection,
                    max_sample_bytes=max_sample_bytes,
                    max_sample_entries=max_sample_entries,
                )
            )
    return profiles, excluded


def rank_content_aware(
    profiles: Sequence[ContentProfile],
    category: str,
    context: Any,
) -> tuple[list[ContentRecommendation], list[dict[str, Any]]]:
    """Rank profiles for one discovery category; deterministic total order."""
    ranked: list[ContentRecommendation] = []
    discarded: list[dict[str, Any]] = []
    for profile in profiles:
        if profile.name_category in {"xss", "sqli"}:
            continue
        reason = exclusion_reason(profile)
        if reason:
            discarded.append({"path": profile.path, "category": category, "reason": reason})
            continue
        name_match = profile.name_category == category or (
            category == "endpoints" and profile.name_category in {"api", "endpoints"}
        )
        content_match = profile.inspected and _category_fit(profile, category) >= INCLUDE_FIT_THRESHOLD
        if not name_match and not content_match:
            continue
        if profile.name_category in _FORBIDDEN_NAME_CATEGORIES and not content_match:
            continue
        score, explanation = score_profile(profile, category, context)
        explanation["selected_by"] = "content" if content_match and not name_match else "name+content"
        ranked.append(
            ContentRecommendation(
                category=category,
                path=profile.path,
                collection=profile.collection,
                size_bytes=profile.size_bytes,
                score=score,
                explanation=explanation,
            )
        )
    ranked.sort(key=lambda item: (-item.score, item.size_bytes, item.path.casefold()))
    return ranked, discarded


__all__ = [
    "CONTENT_PROFILE_VERSION",
    "ContentProfile",
    "ContentRecommendation",
    "RANKING_MODES",
    "collect_profiles",
    "exclusion_reason",
    "profile_wordlist",
    "rank_content_aware",
    "score_profile",
]
