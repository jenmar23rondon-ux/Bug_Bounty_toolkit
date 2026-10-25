"""Build access-check case files from local Burp request captures."""

from __future__ import annotations

from dataclasses import dataclass
import json
import os
from pathlib import Path
import re
from urllib.parse import parse_qsl, urlsplit

from .core.http_client import RequestSpec
from .core.redaction import REDACTED, redact_headers
from .core.request_builder import parse_raw_http_request
from .core.target import normalize_url
from .utils.exceptions import ToolkitError


MAX_CAPTURE_BYTES = 1_000_000
SESSION_HEADER = re.compile(r"auth|cookie|token|sess|credential|csrf|signature|api[-_]?key|anti[-_]?content", re.I)
MARKER = re.compile(r"[A-Za-z0-9_-]{12,128}\Z")
HEADER_NAME = re.compile(r"[A-Za-z0-9-]{1,80}\Z")


@dataclass(frozen=True)
class CaseGenerationOptions:
    """Inputs and explicit researcher declarations needed for a read case."""

    owner: Path
    actor: Path
    output: Path
    resource_pointer: str
    private_pointer: str
    success_pointer: str
    success_value: object
    private_marker: str
    actor_marker: str
    accounts_authorized: bool
    resource_private: bool
    base_url: str | None = None
    force: bool = False
    dry_run: bool = False


@dataclass(frozen=True)
class CaseGenerationResult:
    """Safe summary of a generated case; never contains session values."""

    output: Path
    method: str
    origin: str
    resource_kind: str
    resource_name: str
    session_headers: tuple[str, ...]
    session_summary: tuple[str, ...]
    existing_output: bool
    dry_run: bool


@dataclass(frozen=True)
class _Capture:
    path: Path
    request: RequestSpec


def _pointer_parts(pointer: str) -> list[str]:
    if (
        not isinstance(pointer, str)
        or not pointer.startswith("/")
        or len(pointer) > 256
        or re.search(r"~(?![01])", pointer)
    ):
        raise ValueError("JSON pointers must start with '/' and use valid RFC 6901 escapes.")
    return [part.replace("~1", "/").replace("~0", "~") for part in pointer[1:].split("/")]


def _read_capture(path: Path, base_url: str | None) -> _Capture:
    try:
        with path.open("rb") as source:
            raw = source.read(MAX_CAPTURE_BYTES + 1)
    except OSError as exc:
        raise ValueError(f"Cannot read Burp request capture: {path}") from exc
    if len(raw) > MAX_CAPTURE_BYTES:
        raise ValueError(f"Burp request capture exceeds the {MAX_CAPTURE_BYTES}-byte limit: {path}")
    try:
        text = raw.decode("utf-8")
        captured_request = parse_raw_http_request(text)
        request = parse_raw_http_request(text, base_url)
    except (UnicodeDecodeError, ValueError, ToolkitError) as exc:
        raise ValueError(f"Unsupported raw HTTP request in {path}; inspect the capture locally.") from exc
    captured_host = next((value for key, value in captured_request.headers.items() if key.lower() == "host"), None)
    if captured_host is not None and captured_host.lower() != urlsplit(request.prepared_url()).netloc.lower():
        raise ValueError(f"The Host header in {path} conflicts with its target or --base-url.")
    return _Capture(path.resolve(), request)


def _origin(url: str) -> tuple[str, str, int]:
    try:
        parsed = urlsplit(normalize_url(url))
        host = parsed.hostname
        port = parsed.port
    except ValueError as exc:
        raise ValueError("Both captures must use a valid HTTP(S) origin.") from exc
    if not host or parsed.username is not None or parsed.password is not None:
        raise ValueError("Both captures must use a valid HTTP(S) origin without embedded credentials.")
    scheme = parsed.scheme.lower()
    effective_port = port if port is not None else (443 if scheme == "https" else 80)
    return scheme, host.rstrip(".").lower(), effective_port


def _origin_url(url: str) -> str:
    parsed = urlsplit(normalize_url(url))
    return f"{parsed.scheme}://{parsed.netloc}"


def _header_map(request: RequestSpec) -> dict[str, tuple[str, str]]:
    return {name.lower(): (name, value) for name, value in request.headers.items()}


def _session_header_names(owner: RequestSpec, actor: RequestSpec) -> tuple[str, ...]:
    owner_headers, actor_headers = _header_map(owner), _header_map(actor)
    names = sorted(name for name in owner_headers if SESSION_HEADER.search(name))
    actor_names = sorted(name for name in actor_headers if SESSION_HEADER.search(name))
    if names != actor_names:
        owner_only = sorted(set(names) - set(actor_names))
        actor_only = sorted(set(actor_names) - set(names))
        details = []
        if owner_only:
            details.append(f"only in owner capture: {', '.join(owner_only)}")
        if actor_only:
            details.append(f"only in actor capture: {', '.join(actor_only)}")
        raise ValueError("Captured session header names must match in both requests (" + "; ".join(details) + ").")
    if not names or len(names) > 16:
        raise ValueError(
            "Captures must contain 1-16 recognizable session headers (Cookie/Authorization/token/session)."
        )
    if any(not HEADER_NAME.fullmatch(owner_headers[name][0]) for name in names):
        raise ValueError("A detected session header name is not valid for an access-check case.")
    if any(not owner_headers[name][1] or not actor_headers[name][1] for name in names):
        raise ValueError("Every declared session header must have a nonempty value in both captures.")

    if all(owner_headers[name][1] == actor_headers[name][1] for name in names):
        display_names = ", ".join(owner_headers[name][0] for name in names)
        raise ValueError(
            f"Sesión detectada: {display_names} (valores redactados). Los valores son idénticos; "
            "probablemente ambas capturas son de la misma cuenta. Vuelve a capturar A y B con sesiones distintas."
        )
    return tuple(owner_headers[name][0] for name in names)


def _redacted_session_summary(request: RequestSpec, names: tuple[str, ...]) -> tuple[str, ...]:
    header_map = _header_map(request)
    captured = {header_map[name.lower()][0]: header_map[name.lower()][1] for name in names}
    redacted = redact_headers(captured)
    # SESSION_HEADER intentionally catches a wider set than the shared redactor;
    # never expose a value for an unfamiliar session header.
    return tuple(
        f"{name}={redacted.get(name, REDACTED) if redacted.get(name) == REDACTED else REDACTED}" for name in captured
    )


def _validate_other_headers(owner: RequestSpec, actor: RequestSpec) -> None:
    owner_headers, actor_headers = _header_map(owner), _header_map(actor)
    ignored = {"host", "content-length", "transfer-encoding"}
    ignored |= {name for name in owner_headers if SESSION_HEADER.search(name)}
    ignored |= {name for name in actor_headers if SESSION_HEADER.search(name)}
    left = {name: value for name, (_, value) in owner_headers.items() if name not in ignored}
    right = {name: value for name, (_, value) in actor_headers.items() if name not in ignored}
    differences = sorted(name for name in left.keys() | right.keys() if left.get(name) != right.get(name))
    if differences:
        details = []
        for name in differences:
            if name not in left:
                details.append(f"{name} (missing from owner)")
            elif name not in right:
                details.append(f"{name} (missing from actor)")
            else:
                details.append(f"{name} (values differ)")
        raise ValueError("Captures differ outside the resource and session headers: " + ", ".join(details) + ".")


def _resource_selector(owner_url: str, actor_url: str) -> tuple[dict[str, object], str, str, str, str]:
    owner, actor = urlsplit(owner_url), urlsplit(actor_url)
    owner_segments, actor_segments = owner.path.lstrip("/").split("/"), actor.path.lstrip("/").split("/")
    changed_segments = [
        index
        for index in range(max(len(owner_segments), len(actor_segments)))
        if index >= len(owner_segments)
        or index >= len(actor_segments)
        or owner_segments[index] != actor_segments[index]
    ]
    owner_pairs = parse_qsl(owner.query, keep_blank_values=True)
    actor_pairs = parse_qsl(actor.query, keep_blank_values=True)
    owner_query, actor_query = dict(owner_pairs), dict(actor_pairs)
    if len(owner_query) != len(owner_pairs) or len(actor_query) != len(actor_pairs):
        raise ValueError("Duplicate query parameters are ambiguous; capture requests with unique parameter names.")
    if any(SESSION_HEADER.search(name) for name in owner_query.keys() | actor_query.keys()):
        raise ValueError("Session-bearing query parameters are unsupported; keep sessions in headers.")
    changed_query = sorted(
        name for name in owner_query.keys() | actor_query.keys() if owner_query.get(name) != actor_query.get(name)
    )
    if len(changed_segments) == 1 and not changed_query and len(owner_segments) == len(actor_segments):
        index = changed_segments[0]
        owner_id, actor_id = owner_segments[index], actor_segments[index]
        if not owner_id or not actor_id:
            raise ValueError(f"Changed path segment {index} is empty and cannot identify a resource.")
        return {"path_segment": index}, "path segment", str(index), owner_id, actor_id
    if not changed_segments and len(changed_query) == 1:
        name = changed_query[0]
        if name not in owner_query or name not in actor_query:
            raise ValueError(f"Query parameter {name!r} must exist in both captures to identify the resource.")
        owner_id, actor_id = owner_query[name], actor_query[name]
        if not owner_id or not actor_id:
            raise ValueError(f"Changed query parameter {name!r} must have a nonempty value in both captures.")
        return {"query_parameter": name}, "query parameter", name, owner_id, actor_id

    differences: list[str] = []
    differences.extend(f"path segment {index}" for index in changed_segments)
    differences.extend(f"query parameter {name!r}" for name in changed_query)
    if not differences:
        differences.append("no resource reference (the captured targets are identical)")
    raise ValueError(
        "Captures must differ only in one resource path segment or one query parameter; "
        "differences found at: " + ", ".join(differences) + "."
    )


def _request_reference(source: Path, output: Path) -> str:
    try:
        relative = os.path.relpath(source, start=output.parent.resolve())
    except ValueError:
        return str(source)
    return relative.replace(os.sep, "/")


def _validate_marker(marker: str, argument: str) -> None:
    if not MARKER.fullmatch(marker):
        raise ValueError(f"{argument} must be a 12-128 character ASCII identifier (letters, digits, '_' or '-').")


def generate_case(options: CaseGenerationOptions) -> CaseGenerationResult:
    """Validate two local captures and create a compatible, private read case."""
    if not options.accounts_authorized:
        raise ValueError("Pass --attest-authorized-accounts to declare that both accounts are yours or authorized.")
    if not options.resource_private:
        raise ValueError("Pass --attest-private-resource to declare that the owner resource is private.")
    pointers = {
        "resource-pointer": options.resource_pointer,
        "private-pointer": options.private_pointer,
        "success-pointer": options.success_pointer,
    }
    for name, pointer in pointers.items():
        try:
            _pointer_parts(pointer)
        except ValueError as exc:
            raise ValueError(f"Invalid --{name}: {exc}") from exc
    if len(set(pointers.values())) != len(pointers):
        raise ValueError("--resource-pointer, --private-pointer and --success-pointer must be distinct.")
    if type(options.success_value) not in {bool, str, int}:
        raise ValueError("--success-value must be a JSON string, integer or boolean.")
    _validate_marker(options.private_marker, "--private-marker")
    _validate_marker(options.actor_marker, "--actor-marker")
    if (
        options.private_marker == options.actor_marker
        or options.private_marker in options.actor_marker
        or options.actor_marker in options.private_marker
    ):
        raise ValueError("--private-marker and --actor-marker must be distinct and must not contain one another.")

    if options.base_url:
        try:
            normalized_base = normalize_url(options.base_url)
            base_parts = urlsplit(normalized_base)
        except ValueError as exc:
            raise ValueError("--base-url must be a valid HTTP(S) origin.") from exc
        if base_parts.path not in {"", "/"} or base_parts.query:
            raise ValueError("--base-url must contain only the scheme, host and optional port.")
    owner_capture = _read_capture(options.owner, options.base_url)
    actor_capture = _read_capture(options.actor, options.base_url)
    owner, actor = owner_capture.request, actor_capture.request
    owner_url, actor_url = owner.prepared_url(), actor.prepared_url()
    owner_origin, actor_origin = _origin(owner_url), _origin(actor_url)
    if owner_origin != actor_origin:
        raise ValueError("The owner and actor captures must use the same origin (scheme, host and port).")
    # The existing access-check loader compares normalized netloc strings; keep
    # generated cases acceptable to that validator even for explicit default ports.
    if urlsplit(owner_url).netloc != urlsplit(actor_url).netloc:
        raise ValueError(
            "The captures use the same effective origin but serialize the host/port differently; recapture consistently."
        )
    origin_url = _origin_url(owner_url)
    if options.base_url and _origin(normalized_base) != owner_origin:
        raise ValueError("--base-url must match the origin in both Burp captures.")
    if owner.method != actor.method:
        raise ValueError(
            f"Request methods differ: owner={owner.method}, actor={actor.method}. "
            "They must match; state-changing comparisons require --lab-write."
        )
    if owner.method != "GET":
        raise ValueError(
            f"This generator creates read cases and requires GET (both captures use {owner.method}). "
            "Use the separate --lab-write case format for authorized JSON writes."
        )
    if owner.body is not None or actor.body is not None:
        raise ValueError("GET captures with request bodies are unsupported; export clean GET requests from Burp.")

    session_headers = _session_header_names(owner, actor)
    _validate_other_headers(owner, actor)
    selector, resource_kind, resource_name, owner_resource, actor_resource = _resource_selector(owner_url, actor_url)
    if owner_resource == actor_resource:
        raise ValueError("The owner and actor captures must reference distinct resources.")
    for marker in (options.private_marker, options.actor_marker):
        if any(
            marker in owner_url or marker in actor_url or any(marker in value for value in request.headers.values())
            for request in (owner, actor)
        ):
            raise ValueError("Private markers must be observed in responses, not supplied in either request.")

    output = options.output.expanduser()
    case: dict[str, object] = {
        "owner_request": _request_reference(owner_capture.path, output),
        "actor_request": _request_reference(actor_capture.path, output),
        "base_url": origin_url,
        "session_headers": list(session_headers),
        "resource": selector,
        "checks": {
            "success_pointer": options.success_pointer,
            "success_value": options.success_value,
            "resource_pointer": options.resource_pointer,
            "owner_resource": owner_resource,
            "actor_resource": actor_resource,
            "private_pointer": options.private_pointer,
            "owner_marker": options.private_marker,
            "actor_marker": options.actor_marker,
        },
        "accounts_authorized": True,
        "resource_private": True,
        "expected_cross_access": "deny",
    }
    existing = output.exists()
    if existing and not options.force and not options.dry_run:
        raise ValueError(f"Output already exists: {output}. Pass --force to replace it.")
    if not options.dry_run:
        rendered = json.dumps(case, indent=2, sort_keys=True, ensure_ascii=True) + "\n"
        output.parent.mkdir(parents=True, exist_ok=True)
        if options.force:
            output.write_text(rendered, encoding="utf-8")
        else:
            try:
                with output.open("x", encoding="utf-8", newline="") as destination:
                    destination.write(rendered)
            except FileExistsError as exc:
                raise ValueError(f"Output already exists: {output}. Pass --force to replace it.") from exc

    return CaseGenerationResult(
        output=output,
        method=owner.method,
        origin=origin_url,
        resource_kind=resource_kind,
        resource_name=resource_name,
        session_headers=session_headers,
        session_summary=_redacted_session_summary(owner, session_headers),
        existing_output=existing,
        dry_run=options.dry_run,
    )
