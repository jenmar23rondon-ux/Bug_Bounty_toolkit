"""Local, offline management for user-owned wordlist collections."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import tempfile
from contextlib import ExitStack
from typing import Iterable, Iterator, Mapping

WORDLIST_EXTENSIONS = {".txt", ".lst", ".list", ".wordlist"}
WORDLIST_CATEGORIES = (
    "api",
    "endpoints",
    "directories",
    "files",
    "parameters",
    "extensions",
    "technology",
    "xss",
    "sqli",
    "custom",
    "other",
)
MAX_ENTRY_BYTES = 64 * 1024
MAX_PREPARED_ENTRIES = 1_000_000
DEFAULT_LARGE_FILE_WARNING_BYTES = 1024 * 1024 * 1024
REGISTRY_VERSION = 1
_NAME_PATTERN = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}$")
_SKIP_DIRS = {".git", ".svn", "node_modules", "__pycache__", ".venv", "venv"}
_CREDENTIAL_MARKERS = {"password", "passwords", "credential", "credentials", "bruteforce", "brute-force"}


@dataclass(frozen=True)
class WordlistCollection:
    """A named local directory containing wordlist files."""

    name: str
    path: Path
    category: str | None = None


@dataclass(frozen=True)
class WordlistFile:
    """A local wordlist candidate and its inferred use category."""

    collection: str
    path: Path
    category: str
    size_bytes: int


@dataclass(frozen=True)
class WordlistInspection:
    """Streaming counts and format observations for one wordlist."""

    path: Path
    size_bytes: int
    entry_count: int
    unique_entries: int
    duplicate_entries: int
    blank_lines: int
    comment_lines: int
    invalid_lines: int
    preview: tuple[str, ...]
    requests_estimate: int
    minimum_seconds: float
    large_file_warning: bool
    sha256: str


@dataclass(frozen=True)
class PreparationResult:
    """Summary for a capped and deduplicated output wordlist."""

    output: Path
    category: str
    source_files: tuple[Path, ...]
    unique_entries: int
    duplicate_entries: int
    invalid_lines: int
    limit_reached: bool
    requests_estimate: int
    minimum_seconds: float
    source_hashes: tuple[tuple[str, str], ...]
    output_sha256: str | None


@dataclass(frozen=True)
class _ParsedLine:
    line_number: int
    value: str | None = None
    invalid: bool = False
    blank: bool = False
    comment: bool = False


def default_registry_path(environ: Mapping[str, str] | None = None, home: Path | None = None) -> Path:
    """Return the platform-local registry path without creating it."""
    environment = os.environ if environ is None else environ
    user_home = home or Path.home()
    if os.name == "nt":
        local_app_data = Path(environment.get("LOCALAPPDATA", str(user_home / "AppData" / "Local")))
        return local_app_data / "BugBountyToolkit" / "wordlists.json"
    config_home = Path(environment.get("XDG_CONFIG_HOME", str(user_home / ".config")))
    return config_home / "bug-bounty-toolkit" / "wordlists.json"


def default_prepared_root(environ: Mapping[str, str] | None = None, home: Path | None = None) -> Path:
    """Return a user cache path for prepared lists, outside the repository."""
    environment = os.environ if environ is None else environ
    user_home = home or Path.home()
    if os.name == "nt":
        cache_root = Path(environment.get("LOCALAPPDATA", str(user_home / "AppData" / "Local")))
    else:
        cache_root = Path(environment.get("XDG_CACHE_HOME", str(user_home / ".cache")))
    return cache_root / "bug-bounty-toolkit" / "prepared"


def _validated_category(category: str | None) -> str | None:
    if category is None:
        return None
    normalized = category.strip().lower().replace("-", "_")
    aliases = {
        "route": "endpoints",
        "routes": "endpoints",
        "params": "parameters",
        "sql": "sqli",
        "file": "files",
        "extension": "extensions",
        "tech": "technology",
        "technology_specific_paths": "technology",
        "technology_paths": "technology",
        "api_endpoints": "api",
    }
    normalized = aliases.get(normalized, normalized)
    if normalized not in WORDLIST_CATEGORIES:
        raise ValueError(f"Unknown wordlist category {category!r}; choose from {', '.join(WORDLIST_CATEGORIES)}.")
    return normalized


def _validate_name(name: str) -> str:
    clean = name.strip()
    if not _NAME_PATTERN.fullmatch(clean):
        raise ValueError("Collection name must be 1-64 letters, digits, dots, underscores or hyphens.")
    return clean


def sha256_file(path: Path) -> str:
    """Hash a local file in bounded-memory chunks."""
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _is_credential_wordlist(path: Path) -> bool:
    """Keep password and credential guessing lists out of discovery recommendations."""
    parts = {part.casefold().replace("_", "-") for part in path.parts}
    return any(marker in part for marker in ("password", "credential", "bruteforce", "brute-force") for part in parts)


def load_collections(registry_path: Path) -> list[WordlistCollection]:
    """Load and validate the local collection registry; a missing registry is empty."""
    if not registry_path.exists():
        return []
    try:
        payload = json.loads(registry_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"Cannot read wordlist registry {registry_path}: {exc}") from exc
    if not isinstance(payload, dict) or payload.get("version") != REGISTRY_VERSION:
        raise ValueError(f"Unsupported or malformed wordlist registry: {registry_path}")
    raw_collections = payload.get("collections")
    if not isinstance(raw_collections, list):
        raise ValueError(f"Malformed wordlist registry collections: {registry_path}")
    collections: list[WordlistCollection] = []
    names: set[str] = set()
    for item in raw_collections:
        if not isinstance(item, dict) or not isinstance(item.get("path"), str) or not isinstance(item.get("name"), str):
            raise ValueError(f"Malformed collection entry in registry: {registry_path}")
        name = _validate_name(item["name"])
        if name in names:
            raise ValueError(f"Duplicate collection name in registry: {name}")
        category_value = item.get("category")
        if category_value is not None and not isinstance(category_value, str):
            raise ValueError(f"Malformed category for collection {name}.")
        category = _validated_category(category_value)
        names.add(name)
        collections.append(WordlistCollection(name=name, path=Path(item["path"]).expanduser(), category=category))
    return sorted(collections, key=lambda collection: collection.name.casefold())


def save_collections(registry_path: Path, collections: Iterable[WordlistCollection]) -> None:
    """Atomically write the local wordlist registry."""
    registry_path.parent.mkdir(parents=True, exist_ok=True)
    ordered = sorted(collections, key=lambda collection: collection.name.casefold())
    payload = {
        "version": REGISTRY_VERSION,
        "collections": [{"name": item.name, "path": str(item.path), "category": item.category} for item in ordered],
    }
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            newline="\n",
            dir=registry_path.parent,
            prefix=".wordlists-",
            suffix=".tmp",
            delete=False,
        ) as handle:
            temporary = Path(handle.name)
            json.dump(payload, handle, ensure_ascii=False, indent=2)
            handle.write("\n")
        os.replace(temporary, registry_path)
    finally:
        if temporary is not None and temporary.exists():
            temporary.unlink()


def detect_local_collections(
    environ: Mapping[str, str] | None = None, home: Path | None = None
) -> list[tuple[str, Path]]:
    """Find common Kali/Linux, Windows, and user-configured wordlist roots without walking them."""
    environment = os.environ if environ is None else environ
    user_home = home or Path.home()
    candidates: list[tuple[str, Path]] = []
    for variable, name in (
        ("SECLISTS_DIR", "seclists"),
        ("ASSETNOTE_WORDLISTS_DIR", "assetnote"),
        ("FUZZDB_DIR", "fuzzdb"),
        ("BBTK_WORDLISTS_DIR", "custom-wordlists"),
    ):
        value = environment.get(variable)
        if value:
            candidates.append((name, Path(value).expanduser()))
    candidates.extend(
        [
            ("seclists", Path("/usr/share/seclists")),
            ("seclists", Path("/usr/share/SecLists")),
            ("seclists", Path("/usr/share/wordlists/seclists")),
            ("fuzzdb", Path("/usr/share/fuzzdb")),
            ("fuzzdb", Path("/usr/share/wordlists/fuzzdb")),
            ("assetnote", Path("/usr/share/wordlists/assetnote")),
            ("assetnote", Path("/opt/assetnote-wordlists")),
            ("system-wordlists", Path("/usr/share/wordlists")),
            ("seclists", user_home / "SecLists"),
            ("seclists", user_home / "seclists"),
            ("fuzzdb", user_home / "fuzzdb"),
            ("assetnote", user_home / "assetnote-wordlists"),
            ("user-wordlists", user_home / "wordlists"),
            ("seclists", Path("C:/SecLists")),
            ("fuzzdb", Path("C:/fuzzdb")),
            ("assetnote", Path("C:/assetnote-wordlists")),
        ]
    )
    found: dict[Path, str] = {}
    for name, candidate in candidates:
        try:
            resolved = candidate.resolve(strict=True)
        except (OSError, RuntimeError):
            continue
        if resolved.is_dir() and resolved not in found:
            found[resolved] = name
    return sorted(((name, path) for path, name in found.items()), key=lambda item: (item[0], str(item[1]).casefold()))


def scan_collections(
    registry_path: Path,
    candidates: Iterable[tuple[str, Path]] | None = None,
    *,
    dry_run: bool = False,
) -> list[WordlistCollection]:
    """Add detected local roots to the registry; never downloads or reads list contents."""
    existing = load_collections(registry_path)
    registered_paths = {collection.path.resolve(strict=False) for collection in existing}
    registered_names = {collection.name.casefold() for collection in existing}
    added: list[WordlistCollection] = []
    sources = detect_local_collections() if candidates is None else list(candidates)
    for suggested_name, path in sources:
        try:
            resolved = path.expanduser().resolve(strict=True)
        except (OSError, RuntimeError):
            continue
        if not resolved.is_dir() or resolved in registered_paths:
            continue
        name = _validate_name(suggested_name)
        base_name = name
        suffix = 2
        while name.casefold() in registered_names:
            name = f"{base_name}-{suffix}"
            suffix += 1
        collection = WordlistCollection(name, resolved)
        added.append(collection)
        registered_paths.add(resolved)
        registered_names.add(name.casefold())
    if added and not dry_run:
        save_collections(registry_path, [*existing, *added])
    return added


def register_collection(registry_path: Path, name: str, path: Path, category: str | None = None) -> WordlistCollection:
    """Register a user-supplied local collection directory."""
    clean_name = _validate_name(name)
    clean_category = _validated_category(category)
    try:
        resolved = path.expanduser().resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise FileNotFoundError(f"Collection path not found: {path}") from exc
    if not resolved.is_dir():
        raise ValueError(f"Collection path is not a directory: {path}")
    collections = load_collections(registry_path)
    if any(item.name.casefold() == clean_name.casefold() for item in collections):
        raise ValueError(f"A collection named {clean_name!r} is already registered.")
    if any(item.path.resolve(strict=False) == resolved for item in collections):
        raise ValueError(f"This path is already registered as a collection: {resolved}")
    collection = WordlistCollection(clean_name, resolved, clean_category)
    save_collections(registry_path, [*collections, collection])
    return collection


def _walk_wordlists(root: Path) -> Iterator[Path]:
    """Yield supported text lists without following directory or file symlinks."""
    if root.is_file() and root.suffix.lower() in WORDLIST_EXTENSIONS and not root.is_symlink():
        yield root
        return
    if not root.is_dir():
        return
    for directory, subdirectories, filenames in os.walk(root, followlinks=False):
        current = Path(directory)
        subdirectories[:] = sorted(
            name for name in subdirectories if name.casefold() not in _SKIP_DIRS and not (current / name).is_symlink()
        )
        for filename in sorted(filenames, key=str.casefold):
            candidate = current / filename
            if candidate.suffix.lower() in WORDLIST_EXTENSIONS and not candidate.is_symlink():
                yield candidate


def classify_wordlist(path: Path, fallback: str | None = None) -> str:
    """Infer a broad purpose from the relative path and filename."""
    normalized = str(path).casefold().replace("_", "-").replace("\\", "/")
    parts = set(normalized.split("/"))
    if any(part in _CREDENTIAL_MARKERS for part in parts):
        return "other"
    if any(part in normalized for part in ("xss", "cross-site-scripting")):
        return "xss"
    if any(part in normalized for part in ("sqli", "sql-injection", "databases")):
        return "sqli"
    if any(part in normalized for part in ("parameter", "param-name", "param_names")):
        return "parameters"
    if any(part in normalized for part in ("extension", "extensions", "file-ext")):
        return "extensions"
    if any(part in normalized for part in ("technology", "technologies", "tech-specific", "wordpress", "drupal")):
        return "technology"
    if any(part in normalized for part in ("common-files", "raft-files", "file-names", "filenames", "/files/")):
        return "files"
    filename_tokens = normalized.split("/")[-1].split(".")[0].split("-")
    if any(token in {"file", "files", "filename", "filenames"} for token in filename_tokens):
        return "files"
    if any(part in normalized for part in ("api", "api-endpoint", "graphql")):
        return "api"
    if any(part in normalized for part in ("directory", "directories", "raft", "common.txt")):
        return "directories"
    if any(part in normalized for part in ("endpoint", "route", "web-content")):
        return "endpoints"
    return fallback or "other"


def list_wordlists(collections: Iterable[WordlistCollection]) -> list[WordlistFile]:
    """List supported files and categories without reading file contents."""
    items: list[WordlistFile] = []
    for collection in collections:
        if not collection.path.is_dir():
            continue
        for path in _walk_wordlists(collection.path):
            if _is_credential_wordlist(path.relative_to(collection.path)) or _is_credential_wordlist(
                Path(collection.path.name)
            ):
                continue
            relative = path.relative_to(collection.path)
            category = collection.category or classify_wordlist(relative)
            try:
                size = path.stat().st_size
            except OSError:
                continue
            items.append(WordlistFile(collection.name, path, category, size))
    return sorted(items, key=lambda item: (item.category, item.collection.casefold(), str(item.path).casefold()))


def _parsed_lines(path: Path) -> Iterator[_ParsedLine]:
    """Read a text wordlist with bounded per-line memory and report malformed lines."""
    line_number = 0
    with path.open("rb") as handle:
        while True:
            raw = handle.readline(MAX_ENTRY_BYTES + 2)
            if not raw:
                return
            line_number += 1
            if len(raw) > MAX_ENTRY_BYTES + 1 and not raw.endswith(b"\n"):
                while raw and not raw.endswith(b"\n"):
                    raw = handle.readline(MAX_ENTRY_BYTES + 2)
                yield _ParsedLine(line_number, invalid=True)
                continue
            value_bytes = raw.rstrip(b"\r\n")
            if len(value_bytes) > MAX_ENTRY_BYTES or b"\x00" in value_bytes:
                yield _ParsedLine(line_number, invalid=True)
                continue
            if line_number == 1 and value_bytes.startswith(b"\xef\xbb\xbf"):
                value_bytes = value_bytes[3:]
            try:
                value = value_bytes.decode("utf-8").strip()
            except UnicodeDecodeError:
                yield _ParsedLine(line_number, invalid=True)
                continue
            if not value:
                yield _ParsedLine(line_number, blank=True)
            elif value.startswith("#"):
                yield _ParsedLine(line_number, comment=True)
            else:
                yield _ParsedLine(line_number, value=value)


def _new_seen_db(directory: str) -> sqlite3.Connection:
    connection = sqlite3.connect(Path(directory) / "seen.sqlite3")
    connection.execute("PRAGMA journal_mode=OFF")
    connection.execute("PRAGMA synchronous=OFF")
    connection.execute("PRAGMA temp_store=FILE")
    connection.execute("PRAGMA cache_size=-2048")
    connection.execute("CREATE TABLE seen (value TEXT PRIMARY KEY) WITHOUT ROWID")
    return connection


def inspect_wordlist(
    path: Path,
    *,
    rate: float = 1.0,
    large_file_warning_bytes: int = DEFAULT_LARGE_FILE_WARNING_BYTES,
    preview_limit: int = 5,
) -> WordlistInspection:
    """Count entries and duplicates in a streaming pass; uniqueness state lives on disk."""
    require_wordlist(path)
    if rate <= 0:
        raise ValueError("Rate must be positive.")
    if large_file_warning_bytes <= 0:
        raise ValueError("Large-file warning threshold must be positive.")
    if preview_limit < 0:
        raise ValueError("Preview limit cannot be negative.")
    size = path.stat().st_size
    entries = duplicates = blanks = comments = invalid = unique = 0
    preview: list[str] = []
    with tempfile.TemporaryDirectory(prefix="bbtk-wordlist-inspect-") as directory:
        connection = _new_seen_db(directory)
        try:
            for parsed in _parsed_lines(path):
                if parsed.invalid:
                    invalid += 1
                    continue
                if parsed.blank:
                    blanks += 1
                    continue
                if parsed.comment:
                    comments += 1
                    continue
                if parsed.value is None:
                    continue
                entries += 1
                cursor = connection.execute("INSERT OR IGNORE INTO seen(value) VALUES (?)", (parsed.value,))
                if cursor.rowcount == 1:
                    unique += 1
                    if len(preview) < preview_limit:
                        preview.append(parsed.value)
                else:
                    duplicates += 1
        finally:
            connection.close()
    return WordlistInspection(
        path=path.resolve(),
        size_bytes=size,
        entry_count=entries,
        unique_entries=unique,
        duplicate_entries=duplicates,
        blank_lines=blanks,
        comment_lines=comments,
        invalid_lines=invalid,
        preview=tuple(preview),
        requests_estimate=unique,
        minimum_seconds=unique / rate,
        large_file_warning=size >= large_file_warning_bytes,
        sha256=sha256_file(path),
    )


def _category_matches(actual: str, requested: str) -> bool:
    if requested == "endpoints":
        return actual in {"endpoints", "api"}
    return actual == requested


def recommend_wordlists(collections: Iterable[WordlistCollection], category: str) -> list[WordlistFile]:
    """Select local lists for a category, ordered by smaller files first."""
    requested = _validated_category(category)
    if requested is None or requested == "other":
        raise ValueError(
            "Choose a specific category from the discovery set: api, endpoints, directories, files, parameters, "
            "extensions or technology."
        )
    matches = [item for item in list_wordlists(collections) if _category_matches(item.category, requested)]
    return sorted(matches, key=lambda item: (item.size_bytes, item.collection.casefold(), str(item.path).casefold()))


def prepare_wordlist(
    collections: Iterable[WordlistCollection],
    category: str,
    output: Path,
    *,
    max_entries: int,
    rate: float = 1.0,
    force: bool = False,
    dry_run: bool = False,
) -> PreparationResult:
    """Combine matching lists into a capped, deduplicated file using disk-backed uniqueness.

    With ``dry_run=True`` the complete selection and estimate are computed without
    creating the output directory or file.
    """
    requested = _validated_category(category)
    if requested is None or requested == "other":
        raise ValueError(
            "Choose a specific category: api, endpoints, directories, files, parameters, extensions, "
            "technology, xss or sqli."
        )
    if max_entries <= 0 or max_entries > MAX_PREPARED_ENTRIES:
        raise ValueError(f"--max-entries must be between 1 and {MAX_PREPARED_ENTRIES:,}.")
    if rate <= 0:
        raise ValueError("Rate must be positive.")
    collection_list = list(collections)
    files = [item for item in list_wordlists(collection_list) if _category_matches(item.category, requested)]
    if not files:
        raise ValueError(f"No local wordlists found for category {requested!r}.")
    output_path = output.expanduser().resolve(strict=False)
    for collection in collection_list:
        root = collection.path.resolve(strict=False)
        if output_path == root or output_path.is_relative_to(root):
            raise ValueError("Prepared output must be outside registered source collections.")
    if output_path.exists() and not force:
        raise FileExistsError(f"Output already exists; use --force to replace it: {output_path}")
    if not dry_run:
        output_path.parent.mkdir(parents=True, exist_ok=True)

    source_hashes = tuple((str(item.path), sha256_file(item.path)) for item in files)

    temporary: Path | None = None
    unique = duplicates = invalid = 0
    limit_reached = False
    try:
        with ExitStack() as stack:
            output_handle = None
            if not dry_run:
                output_handle = stack.enter_context(
                    tempfile.NamedTemporaryFile(
                        mode="w",
                        encoding="utf-8",
                        newline="\n",
                        dir=output_path.parent,
                        prefix=f".{output_path.name}.",
                        suffix=".tmp",
                        delete=False,
                    )
                )
                temporary = Path(output_handle.name)
            with tempfile.TemporaryDirectory(prefix="bbtk-wordlist-prepare-") as directory:
                connection = _new_seen_db(directory)
                try:
                    for wordlist in files:
                        for parsed in _parsed_lines(wordlist.path):
                            if parsed.invalid:
                                invalid += 1
                                continue
                            if parsed.value is None:
                                continue
                            cursor = connection.execute("INSERT OR IGNORE INTO seen(value) VALUES (?)", (parsed.value,))
                            if cursor.rowcount == 0:
                                duplicates += 1
                                continue
                            if unique >= max_entries:
                                limit_reached = True
                                break
                            if output_handle is not None:
                                output_handle.write(parsed.value + "\n")
                            unique += 1
                        if limit_reached:
                            break
                finally:
                    connection.close()
        if not dry_run:
            if temporary is None:
                raise RuntimeError("Prepared wordlist temporary file was not created.")
            if force:
                os.replace(temporary, output_path)
            else:
                os.link(temporary, output_path)
                temporary.unlink()
            temporary = None
    finally:
        if temporary is not None and temporary.exists():
            temporary.unlink()
    return PreparationResult(
        output=output_path,
        category=requested,
        source_files=tuple(item.path for item in files),
        unique_entries=unique,
        duplicate_entries=duplicates,
        invalid_lines=invalid,
        limit_reached=limit_reached,
        requests_estimate=unique,
        minimum_seconds=unique / rate,
        source_hashes=source_hashes,
        output_sha256=sha256_file(output_path) if not dry_run else None,
    )


def collection_file_counts(collections: Iterable[WordlistCollection]) -> dict[str, int]:
    """Count list files by directory walk without reading their contents."""
    return {item.name: sum(1 for _ in _walk_wordlists(item.path)) for item in collections}


def require_wordlist(path: Path) -> Path:
    """Validate that a path names an existing regular file."""
    if not path.exists():
        raise FileNotFoundError(f"Wordlist not found: {path}")
    if not path.is_file():
        raise ValueError(f"Wordlist path is not a file: {path}")
    return path


def preview_wordlist(path: Path, limit: int = 5) -> list[str]:
    """Return a bounded preview without loading the complete file into memory."""
    require_wordlist(path)
    if limit < 0:
        raise ValueError("Preview limit cannot be negative.")
    if limit == 0:
        return []
    values: list[str] = []
    for parsed in _parsed_lines(path):
        if parsed.value is not None:
            values.append(parsed.value)
            if len(values) >= limit:
                break
    return values
