from __future__ import annotations

import copy
from dataclasses import dataclass
import json
from pathlib import Path
import re
from typing import Any
from urllib.parse import SplitResult, parse_qsl, unquote, urlsplit

from ..analysis.authorization_denial import assess_response
from ..core.http_client import HttpClient, RequestSpec, ResponseRecord
from ..core.request_builder import parse_raw_http_request
from ..core.scope_validator import ScopeValidator
from ..core.target import normalize_url
from ..reporting.evidence import write_evidence_json
from ..utils.exceptions import ToolkitError


MISSING = object()
SESSION_KEY = re.compile(r"auth|cookie|token|sess|credential|csrf|signature|api[-_]?key|anti[-_]?content", re.I)
CASE_FIELDS = {
    "owner_request",
    "actor_request",
    "base_url",
    "session_headers",
    "resource",
    "checks",
    "accounts_authorized",
    "resource_private",
    "expected_cross_access",
}
CHECK_FIELDS = {
    "success_pointer",
    "success_value",
    "resource_pointer",
    "owner_resource",
    "actor_resource",
    "private_pointer",
    "owner_marker",
    "actor_marker",
}
ACCOUNT_NAME = re.compile(r"[A-Za-z][A-Za-z0-9_-]{0,31}")


def parse_json(text: str) -> Any:
    """Parse JSON while rejecting duplicate keys and excessive nesting."""

    def unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("Ambiguous duplicate JSON keys are not supported.")
            result[key] = value
        return result

    try:
        return json.loads(text, object_pairs_hook=unique)
    except RecursionError as exc:
        raise ValueError("JSON input nesting exceeds the supported limit.") from exc


def read_local(path: Path, limit: int) -> str:
    with path.open("rb") as handle:
        data = handle.read(limit + 1)
    if len(data) > limit:
        raise ValueError("Access-check input exceeds its size limit.")
    return data.decode("utf-8")


def pointer_parts(pointer: str) -> list[str]:
    if (
        not isinstance(pointer, str)
        or not pointer.startswith("/")
        or len(pointer) > 256
        or re.search(r"~(?![01])", pointer)
    ):
        raise ValueError("Checks require valid non-root JSON pointers.")
    return [part.replace("~1", "/").replace("~0", "~") for part in pointer[1:].split("/")]


def lookup(document: Any, pointer: str) -> Any:
    value = document
    for part in pointer_parts(pointer):
        if isinstance(value, dict):
            value = value.get(part, MISSING)
        elif isinstance(value, list) and re.fullmatch(r"0|[1-9][0-9]*", part):
            value = value[int(part)] if int(part) < len(value) else MISSING
        else:
            return MISSING
    return value


def replace_pointer(document: Any, pointer: str, replacement: Any) -> Any:
    parts = pointer_parts(pointer)
    result = copy.deepcopy(document)
    parent = result
    for part in parts[:-1]:
        if isinstance(parent, dict) and part in parent:
            parent = parent[part]
        elif isinstance(parent, list) and re.fullmatch(r"0|[1-9][0-9]*", part) and int(part) < len(parent):
            parent = parent[int(part)]
        else:
            raise ValueError("The declared JSON body pointer does not exist.")
    final = parts[-1]
    if isinstance(parent, dict) and final in parent:
        parent[final] = replacement
    elif isinstance(parent, list) and re.fullmatch(r"0|[1-9][0-9]*", final) and int(final) < len(parent):
        parent[int(final)] = replacement
    else:
        raise ValueError("The declared JSON body pointer does not exist.")
    return result


def exact(value: Any, expected: Any) -> bool:
    return type(value) is type(expected) and value == expected


@dataclass(frozen=True)
class AccessAccount:
    name: str
    request: RequestSpec
    resource: str | int
    marker: str


@dataclass(frozen=True)
class AccessCase:
    owner: RequestSpec
    actor: RequestSpec
    cross: RequestSpec
    checks: dict[str, Any]
    resource: dict[str, Any]
    identity_check: dict[str, Any] | None
    mode: str = "read"
    accounts: tuple[AccessAccount, ...] = ()
    session_headers: tuple[str, ...] = ()
    body_pointer: str | None = None
    owner_body: object | None = None
    actor_body: object | None = None
    persistence_request: RequestSpec | None = None
    persistence_body_pointer: str | None = None
    persistence_response_pointer: str | None = None
    persistence_value: object | None = None
    cleanup_request: RequestSpec | None = None
    cleanup_actor_request: RequestSpec | None = None
    cleanup_body_pointer: str | None = None
    cleanup_response_pointer: str | None = None
    cleanup_original_value: object = MISSING
    cleanup_actor_original_value: object = MISSING
    resource_private: bool = True
    expected_anonymous: str | None = None


def load_owner_get(
    case_dir: Path,
    request_path: str,
    base_url: str,
    base: SplitResult,
    session_headers: list[str],
    expected_headers: dict[str, str],
    scope: ScopeValidator,
    label: str,
) -> RequestSpec:
    """Load a captured, in-scope GET using one account's complete session context."""
    raw = read_local(case_dir / request_path, 1_000_000)
    try:
        captured = parse_raw_http_request(raw)
        request = parse_raw_http_request(raw, base_url)
    except (ValueError, ToolkitError) as exc:
        raise ValueError(f"The {label} GET capture is not a supported HTTP/1.x request.") from exc
    parsed = urlsplit(request.prepared_url())
    captured_host = next((value for key, value in captured.headers.items() if key.lower() == "host"), None)
    if (
        request.method != "GET"
        or request.body is not None
        or (parsed.scheme, parsed.netloc) != (base.scheme, base.netloc)
        or urlsplit(captured.prepared_url()).netloc != base.netloc
        or (captured_host is not None and captured_host.lower() != base.netloc.lower())
    ):
        raise ValueError(f"{label.capitalize()} verification requires an in-scope GET capture on the same origin.")
    request.headers = {key: value for key, value in request.headers.items() if key.lower() != "accept-encoding"}
    request.headers["Accept-Encoding"] = "identity"
    actual_headers = {key.lower(): value for key, value in request.headers.items()}
    if any(actual_headers.get(name) != expected_headers.get(name) for name in session_headers):
        raise ValueError(f"The {label} GET must use its account's captured session context.")
    scope.require(request.prepared_url())
    return request


def load_case(
    path: Path,
    scope: ScopeValidator,
    allow_lab_writes: bool = False,
    allow_multi_accounts: bool = False,
    verify_persistence: bool = False,
    cleanup: bool = False,
    inverse_write: bool = False,
    allow_public_anonymous: bool = False,
) -> AccessCase:
    """Validate private account captures and build a scope-checked comparison case."""
    data = parse_json(read_local(path, 131072))
    optional = {"identity_check", "identifier_enumeration_authorized", "disposable_test_resources"}
    optional |= {"additional_accounts", "persistence_check", "cleanup_check", "expected_anonymous"}
    if not isinstance(data, dict) or not CASE_FIELDS <= set(data) or set(data) - CASE_FIELDS - optional:
        raise ValueError("Access case has missing or unsupported fields.")
    additional = data.get("additional_accounts", {})
    if "additional_accounts" in data and not allow_multi_accounts:
        raise ValueError("additional_accounts requires --multi-account.")
    if not isinstance(additional, dict) or len(additional) > 8:
        raise ValueError("Multi-account cases support at most eight additional accounts.")
    if additional and (not allow_multi_accounts or allow_lab_writes):
        raise ValueError("additional_accounts is available only in read-mode --multi-account checks.")
    if allow_multi_accounts and len(additional) < 1:
        raise ValueError("--multi-account requires at least one additional account (three accounts total).")
    extra_profiles = {}
    for name, profile in additional.items():
        if (
            not isinstance(name, str)
            or not ACCOUNT_NAME.fullmatch(name)
            or name in {"owner", "actor"}
            or not isinstance(profile, dict)
            or set(profile) != {"request", "resource", "marker"}
            or not isinstance(profile["request"], str)
            or not profile["request"]
        ):
            raise ValueError("Each additional account needs a safe label, request path, resource and private marker.")
        extra_profiles[name] = profile
    persistence_check = data.get("persistence_check")
    cleanup_check = data.get("cleanup_check")
    if persistence_check is not None and not allow_lab_writes:
        raise ValueError("persistence_check is available only in --lab-write mode.")
    if verify_persistence and persistence_check is None:
        raise ValueError("--verify-persistence requires persistence_check with a captured owner GET.")
    if cleanup_check is not None and not allow_lab_writes:
        raise ValueError("cleanup_check is available only in --lab-write mode.")
    if cleanup and cleanup_check is None:
        raise ValueError("--cleanup requires cleanup_check with captured GET readbacks for the restored value.")
    for key in ("identifier_enumeration_authorized", "disposable_test_resources"):
        if key in data and type(data[key]) is not bool:
            raise ValueError(f"{key} must be a boolean.")
    if data["accounts_authorized"] is not True or type(data["resource_private"]) is not bool:
        raise ValueError("An access case requires authorized test accounts and a boolean resource_private declaration.")
    if data["expected_cross_access"] != "deny":
        raise ValueError("An access case requires an explicitly denied cross-account read.")
    expected_anonymous = data.get("expected_anonymous")
    if expected_anonymous is not None and (
        not isinstance(expected_anonymous, str) or expected_anonymous not in {"deny", "allow"}
    ):
        raise ValueError('expected_anonymous must be "deny" or "allow".')
    if not data["resource_private"] and not allow_public_anonymous:
        raise ValueError("A non-private resource is accepted only for an explicit --anonymous-check.")
    if not isinstance(data["base_url"], str):
        raise ValueError("The captured base URL is required.")
    try:
        base = urlsplit(normalize_url(data["base_url"]))
    except ValueError as exc:
        raise ValueError("A valid captured HTTP(S) origin is required.") from exc
    if base.path not in {"", "/"} or base.query:
        raise ValueError("Base URL must be the captured origin without a path or query.")
    requests: list[RequestSpec] = []
    body_documents: list[Any] = []
    request_entries = [("owner", data.get("owner_request")), ("actor", data.get("actor_request"))]
    request_entries.extend((name, profile["request"]) for name, profile in extra_profiles.items())
    for account_name, request_path in request_entries:
        if not isinstance(request_path, str) or not request_path:
            raise ValueError("Provide two local raw-request file paths.")
        raw = read_local(path.parent / request_path, 1_000_000)
        try:
            captured = parse_raw_http_request(raw)
            spec = parse_raw_http_request(raw, data["base_url"])
        except (ValueError, ToolkitError) as exc:
            raise ValueError("The raw capture is not a supported HTTP/1.x request; inspect it locally.") from exc
        if urlsplit(captured.prepared_url()).netloc != base.netloc:
            raise ValueError("The raw capture Host must match the declared origin; host overrides are not supported.")
        captured_host = next((value for key, value in captured.headers.items() if key.lower() == "host"), None)
        if captured_host is not None and captured_host.lower() != base.netloc.lower():
            raise ValueError("The captured Host conflicts with the absolute target or declared origin.")
        if spec.method != "GET" or spec.body is not None:
            content_type = next((value for key, value in spec.headers.items() if key.lower() == "content-type"), "")
            if (
                not allow_lab_writes
                or spec.method not in {"POST", "PUT", "PATCH"}
                or spec.body is None
                or account_name not in {"owner", "actor"}
                or content_type.split(";", 1)[0].strip().lower() != "application/json"
            ):
                raise ValueError("Access-check supports GET reads; JSON writes are available only in local lab mode.")
            try:
                body_text = spec.body.decode("utf-8") if isinstance(spec.body, bytes) else spec.body
                body_documents.append(parse_json(body_text))
            except (UnicodeDecodeError, ValueError) as exc:
                raise ValueError("Local write checks require valid UTF-8 JSON request bodies.") from exc
        else:
            body_documents.append(None)
        for key, value in spec.headers.items():
            if not re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+", key) or any(
                (ord(char) < 32 and char != "\t") or ord(char) > 255 for char in value
            ):
                raise ValueError("A captured HTTP header cannot be safely encoded.")
        # The standard client does not decompress captures; request identity encoding for all three steps.
        spec.headers = {key: value for key, value in spec.headers.items() if key.lower() != "accept-encoding"}
        spec.headers["Accept-Encoding"] = "identity"
        try:
            scope.require(spec.prepared_url())
        except ValueError as exc:
            raise ValueError("A control destination is outside the authorized scope.") from exc
        requests.append(spec)
    owner, actor = requests[:2]
    owner_url, actor_url = urlsplit(owner.prepared_url()), urlsplit(actor.prepared_url())
    if (owner_url.scheme, owner_url.netloc) != (actor_url.scheme, actor_url.netloc):
        raise ValueError("Both controls must use the same captured origin.")
    if (owner_url.scheme, owner_url.netloc) != (base.scheme, base.netloc):
        raise ValueError("Control destinations must match the declared captured origin.")
    for extra_spec in requests[2:]:
        extra_url = urlsplit(extra_spec.prepared_url())
        if (extra_url.scheme, extra_url.netloc) != (base.scheme, base.netloc):
            raise ValueError("Every account capture must use the declared origin.")
        if extra_spec.method != "GET" or extra_spec.body is not None:
            raise ValueError("Multi-account matrix checks support GET captures only.")
    owner_query, actor_query = [parse_qsl(url.query, keep_blank_values=True) for url in (owner_url, actor_url)]
    for query in (owner_query, actor_query):
        if len(dict(query)) != len(query) or any(SESSION_KEY.search(key) for key, _ in query):
            raise ValueError("Duplicate or session-bearing query parameters are not supported.")
    resource = data["resource"]
    if not isinstance(resource, dict) or len(resource) != 1:
        raise ValueError("Declare exactly one resource query parameter or path segment.")
    body_pointer = None
    if set(resource) == {"json_body_pointer"}:
        body_pointer = resource["json_body_pointer"]
        if (
            not allow_lab_writes
            or data.get("disposable_test_resources") is not True
            or owner.method not in {"POST", "PUT", "PATCH"}
            or actor.method != owner.method
            or owner.body is None
            or actor.body is None
            or owner.prepared_url() != actor.prepared_url()
        ):
            raise ValueError(
                "JSON body ID checks require matching POST/PUT/PATCH captures and declared disposable lab resources."
            )
        pointer_parts(body_pointer)
        owner_body, actor_body = body_documents
        sentinel = object()
        if replace_pointer(owner_body, body_pointer, sentinel) != replace_pointer(actor_body, body_pointer, sentinel):
            raise ValueError("Controls must differ only at the declared JSON body resource pointer.")
    elif set(resource) == {"query_parameter"}:
        key = resource["query_parameter"]
        if not isinstance(key, str) or key not in dict(owner_query) or key not in dict(actor_query):
            raise ValueError("The declared resource query parameter must exist in both controls.")
        left, right = dict(owner_query), dict(actor_query)
        if (
            not left[key]
            or not right[key]
            or left.pop(key) == right.pop(key)
            or left != right
            or owner_url.path != actor_url.path
        ):
            raise ValueError("Controls must differ only in the declared resource reference.")
        resource_values = [
            dict(parse_qsl(urlsplit(spec.prepared_url()).query, keep_blank_values=True))[key] for spec in requests
        ]
        if len(set(resource_values)) != len(resource_values):
            raise ValueError("Every multi-account resource identifier must be distinct.")
        for spec in requests[2:]:
            current = urlsplit(spec.prepared_url())
            pairs = parse_qsl(current.query, keep_blank_values=True)
            if len(dict(pairs)) != len(pairs) or any(SESSION_KEY.search(k) for k, _ in pairs):
                raise ValueError("Duplicate or session-bearing query parameters are not supported.")
            extra = dict(pairs)
            selected = extra.pop(key, None)
            if (
                selected in {None, ""}
                or extra != left
                or current.path != owner_url.path
                or (current.scheme, current.netloc) != (base.scheme, base.netloc)
            ):
                raise ValueError("Multi-account captures must differ only in the declared resource reference.")
    elif set(resource) == {"path_segment"}:
        index = resource["path_segment"]
        left_segments, right_segments = owner_url.path[1:].split("/"), actor_url.path[1:].split("/")
        if type(index) is not int or index < 0 or index >= min(len(left_segments), len(right_segments)):
            raise ValueError("Invalid zero-based resource path segment.")
        if not left_segments[index] or not right_segments[index] or left_segments[index] == right_segments[index]:
            raise ValueError("Control resource identifiers must be distinct.")
        left_segments[index] = right_segments[index] = "RESOURCE"
        if left_segments != right_segments or dict(owner_query) != dict(actor_query):
            raise ValueError("Controls must differ only in the declared resource reference.")
        normalized_paths = []
        resource_values = []
        for spec in requests:
            parsed = urlsplit(spec.prepared_url())
            segments = parsed.path[1:].split("/")
            if len(segments) != len(left_segments) or index >= len(segments) or not segments[index]:
                raise ValueError("Multi-account captures must share the declared resource path shape.")
            resource_values.append(segments[index])
            segments[index] = "RESOURCE"
            normalized_paths.append((segments, parse_qsl(parsed.query, keep_blank_values=True)))
        if len(set(resource_values)) != len(resource_values) or any(
            shape != normalized_paths[0] for shape in normalized_paths[1:]
        ):
            raise ValueError("Multi-account captures must differ only in the declared resource reference.")
    else:
        raise ValueError("Unsupported resource selector.")
    names = data["session_headers"]
    if (
        not isinstance(names, list)
        or not 1 <= len(names) <= 16
        or not all(isinstance(name, str) and re.fullmatch(r"[A-Za-z0-9-]{1,80}", name) for name in names)
    ):
        raise ValueError("Declare the complete session header names.")
    names = [name.lower() for name in names]
    if len(set(names)) != len(names) or set(names) & {"host", "content-length", "transfer-encoding", "connection"}:
        raise ValueError("Invalid session header selection.")
    account_headers: list[dict[str, str]] = [
        {key.lower(): value for key, value in spec.headers.items()} for spec in requests
    ]
    for headers in account_headers:
        if any(not headers.get(name) for name in names) or any(
            SESSION_KEY.search(name) and name not in names for name in headers
        ):
            raise ValueError("Session header declarations must cover both complete captured contexts.")
    for index, left_headers in enumerate(account_headers):
        for right_headers in account_headers[index + 1 :]:
            if all(left_headers[name] == right_headers[name] for name in names):
                raise ValueError("Every account must have a distinct captured session context.")
    checks: dict[str, Any] = data["checks"]
    if not isinstance(checks, dict) or set(checks) != CHECK_FIELDS:
        raise ValueError("The access case requires explicit application, resource and private-marker checks.")
    for key in ("success_pointer", "resource_pointer", "private_pointer"):
        pointer_parts(checks[key])
    if len({checks[key] for key in ("success_pointer", "resource_pointer", "private_pointer")}) != 3 or type(
        checks["success_value"]
    ) not in {bool, str, int}:
        raise ValueError("Check pointers must be distinct and success must be a scalar.")
    for key in ("owner_resource", "actor_resource"):
        if type(checks[key]) not in {str, int} or checks[key] == "":
            raise ValueError("Expected resources must be nonempty strings or integers.")
    for key in ("owner_marker", "actor_marker"):
        if not isinstance(checks[key], str) or not re.fullmatch(r"[A-Za-z0-9_-]{12,128}", checks[key]):
            raise ValueError("Use distinct controlled private markers of 12-128 ASCII identifier characters.")
    account_values: list[tuple[str, RequestSpec, str | int, str]] = [
        ("owner", owner, checks["owner_resource"], checks["owner_marker"]),
        ("actor", actor, checks["actor_resource"], checks["actor_marker"]),
    ]
    for name, profile in extra_profiles.items():
        if type(profile["resource"]) not in {str, int} or profile["resource"] == "":
            raise ValueError("Expected multi-account resources must be nonempty strings or integers.")
        if type(profile["resource"]) is not type(checks["owner_resource"]):
            raise ValueError("All multi-account resource identifiers must use the same JSON type.")
        marker = profile["marker"]
        if not isinstance(marker, str) or not re.fullmatch(r"[A-Za-z0-9_-]{12,128}", marker):
            raise ValueError("Use distinct controlled private markers of 12-128 ASCII identifier characters.")
        account_values.append(
            (name, requests[[item[0] for item in request_entries].index(name)], profile["resource"], marker)
        )
    resources = [item[2] for item in account_values]
    markers = [item[3] for item in account_values]
    if len({(type(value), value) for value in resources}) != len(resources):
        raise ValueError("Known account resource identifiers must be distinct.")
    if len(set(markers)) != len(markers):
        raise ValueError("Known private proof markers must be distinct.")
    if any(left in right or right in left for index, left in enumerate(markers) for right in markers[index + 1 :]):
        raise ValueError("Known private proof markers must not contain one another.")
    if set(resource) == {"query_parameter"}:
        key = resource["query_parameter"]
        actual_resources = [
            dict(parse_qsl(urlsplit(spec.prepared_url()).query, keep_blank_values=True))[key] for spec in requests
        ]
    elif set(resource) == {"path_segment"}:
        index = resource["path_segment"]
        actual_resources = [urlsplit(spec.prepared_url()).path[1:].split("/")[index] for spec in requests]
    else:
        assert body_pointer is not None
        actual_resources = [lookup(body, body_pointer) for body in body_documents[:2]]

    def resource_reference_matches(actual: Any, expected: str | int) -> bool:
        return actual == str(expected) if type(expected) is int else exact(actual, expected)

    if len(actual_resources) != len(account_values) or any(
        not resource_reference_matches(actual, expected)
        for actual, (_, _, expected, _) in zip(actual_resources, account_values)
    ):
        raise ValueError("Captured resource references must match every declared account resource.")
    if body_pointer is not None:
        owner_value = lookup(body_documents[0], body_pointer)
        actor_value = lookup(body_documents[1], body_pointer)
        if not exact(owner_value, checks["owner_resource"]) or not exact(actor_value, checks["actor_resource"]):
            raise ValueError("Captured JSON body resource values must match the declared owner and actor resources.")
    for marker in markers:
        if any(
            marker in unquote(spec.prepared_url())
            or any(marker in unquote(value) for value in spec.headers.values())
            or (
                spec.body is not None
                and marker
                in (spec.body.decode("utf-8", errors="replace") if isinstance(spec.body, bytes) else spec.body)
            )
            for spec in requests
        ):
            raise ValueError("Private proof markers must not be supplied by any request.")
    identity = data.get("identity_check")
    if identity is not None:
        if (
            not isinstance(identity, dict)
            or set(identity) != {"pointer", "actor_value"}
            or not isinstance(identity["actor_value"], str)
            or not identity["actor_value"]
        ):
            raise ValueError("Identity differential requires a pointer and known actor string value.")
        pointer_parts(identity["pointer"])
    accounts = tuple(
        AccessAccount(name, spec, resource_value, marker) for (name, spec, resource_value, marker) in account_values
    )
    persistence_request = None
    persistence_body_pointer = persistence_response_pointer = None
    persistence_value = None
    if persistence_check is not None:
        if (
            not isinstance(persistence_check, dict)
            or set(persistence_check) != {"request", "body_pointer", "response_pointer", "value"}
            or not isinstance(persistence_check["request"], str)
            or not persistence_check["request"]
        ):
            raise ValueError("persistence_check requires request, body_pointer, response_pointer and value fields.")
        if body_pointer is None or data.get("disposable_test_resources") is not True:
            raise ValueError("Persistence verification requires a disposable JSON write case.")
        persistence_body_pointer = persistence_check["body_pointer"]
        persistence_response_pointer = persistence_check["response_pointer"]
        persistence_value = persistence_check["value"]
        pointer_parts(persistence_body_pointer)
        pointer_parts(persistence_response_pointer)
        if persistence_body_pointer == body_pointer:
            raise ValueError("Persistence body_pointer must identify a changed value, not the resource ID.")
        owner_value = lookup(body_documents[0], persistence_body_pointer)
        if (
            owner_value is MISSING
            or type(persistence_value) not in {str, int, bool}
            or (isinstance(persistence_value, str) and not 1 <= len(persistence_value) <= 128)
            or type(owner_value) is not type(persistence_value)
            or exact(owner_value, persistence_value)
        ):
            raise ValueError("Persistence verification needs a new short scalar value at a captured disposable field.")
        persistence_request = load_owner_get(
            path.parent,
            persistence_check["request"],
            data["base_url"],
            base,
            names,
            account_headers[0],
            scope,
            "persistence",
        )
    cleanup_request = cleanup_actor_request = None
    cleanup_body_pointer = cleanup_response_pointer = None
    cleanup_original_value: Any = MISSING
    cleanup_actor_original_value: Any = MISSING
    if cleanup_check is not None:
        required_cleanup_fields = {"owner_request", "body_pointer", "response_pointer"}
        if (
            not isinstance(cleanup_check, dict)
            or not required_cleanup_fields <= set(cleanup_check)
            or set(cleanup_check) - required_cleanup_fields - {"actor_request"}
            or not all(isinstance(cleanup_check[key], str) and cleanup_check[key] for key in required_cleanup_fields)
            or (
                "actor_request" in cleanup_check
                and (not isinstance(cleanup_check["actor_request"], str) or not cleanup_check["actor_request"])
            )
        ):
            raise ValueError(
                "cleanup_check requires owner_request, body_pointer and response_pointer; actor_request is optional."
            )
        if body_pointer is None or data.get("disposable_test_resources") is not True:
            raise ValueError("Cleanup verification requires a disposable JSON write case.")
        cleanup_body_pointer = cleanup_check["body_pointer"]
        cleanup_response_pointer = cleanup_check["response_pointer"]
        pointer_parts(cleanup_body_pointer)
        pointer_parts(cleanup_response_pointer)
        if cleanup_body_pointer == body_pointer:
            raise ValueError("cleanup_check.body_pointer must identify the original value, not the resource ID.")
        cleanup_original_value = lookup(body_documents[0], cleanup_body_pointer)
        if cleanup_original_value is MISSING:
            raise ValueError("cleanup_check body_pointer must exist in the captured original owner JSON body.")
        cleanup_request = load_owner_get(
            path.parent,
            cleanup_check["owner_request"],
            data["base_url"],
            base,
            names,
            account_headers[0],
            scope,
            "cleanup owner",
        )
        actor_readback = cleanup_check.get("actor_request")
        if cleanup and inverse_write and not actor_readback:
            raise ValueError("--inverse-write --cleanup requires cleanup_check.actor_request for the actor resource.")
        if actor_readback:
            cleanup_actor_request = load_owner_get(
                path.parent,
                actor_readback,
                data["base_url"],
                base,
                names,
                account_headers[1],
                scope,
                "cleanup actor",
            )
            cleanup_actor_original_value = lookup(body_documents[1], cleanup_body_pointer)
            if cleanup and inverse_write and cleanup_actor_original_value is MISSING:
                raise ValueError("cleanup_check.body_pointer must exist in the captured original actor JSON body.")
    # Keep the owner's resource and use the actor's complete captured context.
    if body_pointer is None:
        cross = RequestSpec("GET", owner.prepared_url(), dict(actor.headers))
    else:
        crossed_body = replace_pointer(body_documents[1], body_pointer, checks["owner_resource"])
        cross = RequestSpec(
            owner.method,
            owner.prepared_url(),
            dict(actor.headers),
            body=json.dumps(crossed_body, ensure_ascii=False, separators=(",", ":")),
        )
    scope.require(cross.prepared_url())
    return AccessCase(
        owner,
        actor,
        cross,
        checks,
        resource,
        identity,
        "lab-write" if body_pointer is not None else "read",
        accounts,
        tuple(names),
        body_pointer,
        body_documents[0],
        body_documents[1],
        persistence_request,
        persistence_body_pointer,
        persistence_response_pointer,
        persistence_value,
        cleanup_request,
        cleanup_actor_request,
        cleanup_body_pointer,
        cleanup_response_pointer,
        cleanup_original_value,
        cleanup_actor_original_value,
        data["resource_private"],
        expected_anonymous,
    )


def authorization_denial_observed(response: ResponseRecord) -> bool:
    """Preserve a denial signal even when its envelope also contains resource data."""
    assessment = assess_response(response.status_code, response.body_text, response.headers)
    return assessment.denial_demonstrated or "contradictory_denial_status_with_resource_body" in assessment.reasons


def observations(response: ResponseRecord, checks: dict[str, Any]) -> dict[str, Any]:
    try:
        body = parse_json(response.body_text)
    except ValueError:
        body = None
    success = lookup(body, checks["success_pointer"])
    application_success = (
        None if type(success) is not type(checks["success_value"]) else exact(success, checks["success_value"])
    )
    resource = lookup(body, checks["resource_pointer"])
    private = lookup(body, checks["private_pointer"])
    return {
        "status_code": response.status_code,
        "duration_ms": response.duration_ms,
        "body_size": response.body_size,
        "body_truncated": response.body_truncated,
        "application_success": application_success,
        "authorization_denial_observed": authorization_denial_observed(response),
        **{
            f"{account}_resource_match": exact(resource, checks[f"{account}_resource"])
            for account in ("owner", "actor")
        },
        **{f"{account}_private_match": exact(private, checks[f"{account}_marker"]) for account in ("owner", "actor")},
        **{
            f"{account}_marker_seen": checks[f"{account}_marker"] in response.body_text
            for account in ("owner", "actor")
        },
    }


def account_observations(
    response: ResponseRecord, checks: dict[str, Any], resource_value: str | int, marker: str
) -> dict[str, Any]:
    try:
        body = parse_json(response.body_text)
    except ValueError:
        body = None
    success = lookup(body, checks["success_pointer"])
    success_ok = None if type(success) is not type(checks["success_value"]) else exact(success, checks["success_value"])
    observed_resource = lookup(body, checks["resource_pointer"])
    observed_private = lookup(body, checks["private_pointer"])
    return {
        "status_code": response.status_code,
        "duration_ms": response.duration_ms,
        "body_size": response.body_size,
        "body_truncated": response.body_truncated,
        "application_success": success_ok,
        "authorization_denial_observed": authorization_denial_observed(response),
        "resource_match": exact(observed_resource, resource_value),
        "private_match": exact(observed_private, marker),
        "private_marker_seen": marker in response.body_text,
    }


class AccessControlTester:
    """Run bounded read comparisons using a shared scope-aware HTTP client."""

    def __init__(self, scope: ScopeValidator, client: HttpClient):
        self.scope, self.client = scope, client

    @staticmethod
    def request_count(
        case: AccessCase, anonymous_check: bool = False, inverse_cross: bool = False, multi_account: bool = False
    ) -> int:
        count = len(case.accounts) ** 2 if multi_account else 3
        return count + int(anonymous_check) + int(inverse_cross)

    def validate(
        self,
        case_file: Path,
        max_tests: int = 3,
        anonymous_check: bool = False,
        inverse_cross: bool = False,
        multi_account: bool = False,
    ) -> AccessCase:
        """Preflight the selected read workflow and its complete request budget."""
        if any(type(flag) is not bool for flag in (anonymous_check, inverse_cross, multi_account)):
            raise ValueError("Access-check mode flags must be booleans.")
        case = load_case(
            case_file,
            self.scope,
            allow_multi_accounts=multi_account,
            allow_public_anonymous=anonymous_check,
        )
        if case.mode != "read":
            raise ValueError("Read-mode options cannot be used with a JSON write case.")
        if multi_account and not case.resource_private:
            raise ValueError("Multi-account checks require resources explicitly declared private.")
        if multi_account and not 3 <= len(case.accounts) <= 10:
            raise ValueError("Multi-account mode requires three to ten total accounts.")
        required = self.request_count(case, anonymous_check, inverse_cross, multi_account)
        if type(max_tests) is not int or max_tests < required:
            if multi_account:
                raise ValueError(f"The complete account matrix requires a budget of at least {required} requests.")
            raise ValueError(f"This access-check mode requires a budget of at least {required} requests.")
        return case

    def run(
        self,
        case_file: Path,
        evidence_dir: Path,
        max_tests: int = 3,
        anonymous_check: bool = False,
        inverse_cross: bool = False,
        multi_account: bool = False,
    ) -> tuple[Path, dict[str, Any]]:
        """Execute the selected reads and save predicate-only evidence."""
        case = self.validate(case_file, max_tests, anonymous_check, inverse_cross, multi_account)
        required = self.request_count(case, anonymous_check, inverse_cross, multi_account)
        result: dict[str, Any] = {
            "type": "access-control",
            "mode": "account-matrix" if multi_account else case.mode,
            "classification": "inconclusive",
            "finding_state": "inconclusive",
            "confirmed": False,
            "confirmation_gap": None,
            "rejection_reason": None,
            "controls_valid": False,
            "requests_attempted": 0,
            "request_budget": required,
            "steps": [],
            "stop_reason": None,
            "inverse_sent": False,
            "anonymous_sent": False,
            "anonymous_finding": False,
            "anonymous_expectation_mismatch": False,
        }
        accounts = list(case.accounts if multi_account else case.accounts[:2])

        def send(label: str, request: RequestSpec) -> ResponseRecord | None:
            result["requests_attempted"] += 1
            try:
                return self.client.send(request)
            except (ToolkitError, ValueError):
                result["steps"].append({"step": label, "transport_error": True})
                result["stop_reason"] = "transport_error"
                return None

        def blocked(response: ResponseRecord) -> str | None:
            if response.status_code == 429:
                return "rate_limited"
            if response.body_truncated:
                return "truncated_response"
            if 300 <= response.status_code < 400:
                return "redirect_not_followed"
            return None

        controls_ok = True
        matrix_controls: list[dict[str, Any]] = []
        for account in accounts:
            label = account.name + "_control"
            response = send(label, account.request)
            if response is None:
                controls_ok = False
                break
            facts = account_observations(response, case.checks, account.resource, account.marker)
            result["steps"].append({"step": label, **facts})
            stop_reason = blocked(response)
            if stop_reason:
                result["stop_reason"] = stop_reason
                controls_ok = False
                break
            other_markers_seen = any(
                other.name != account.name and other.marker in response.body_text for other in accounts
            )
            valid = (
                response.status_code == 200
                and facts["application_success"] is True
                and not facts["authorization_denial_observed"]
                and facts["resource_match"]
                and facts["private_match"]
                and not other_markers_seen
            )
            if multi_account:
                matrix_controls.append(
                    {
                        "session_account": account.name,
                        "resource_owner": account.name,
                        "access_type": "control",
                        "status_code": response.status_code,
                        "classification": "control_valid" if valid else "inconclusive",
                        "private_resource_match": bool(facts["resource_match"] and facts["private_match"]),
                        "confirmed": False,
                    }
                )
            if not valid:
                result["stop_reason"] = "invalid_" + label
                controls_ok = False
                break
        result["controls_valid"] = controls_ok
        if not controls_ok:
            return write_evidence_json(evidence_dir, result, prefix="access-control"), result

        pair_results: list[dict[str, Any]] = list(matrix_controls)
        overall_candidate = False
        all_rejected = True
        if multi_account:
            for source in accounts:
                for target in accounts:
                    if source.name == target.name:
                        continue
                    request = RequestSpec("GET", target.request.prepared_url(), dict(source.request.headers))
                    self.scope.require(request.prepared_url())
                    label = f"cross_{source.name}_to_{target.name}"
                    response = send(label, request)
                    if response is None:
                        all_rejected = False
                        break
                    facts = account_observations(response, case.checks, target.resource, target.marker)
                    stop_reason = blocked(response)
                    candidate = (
                        case.resource_private
                        and not stop_reason
                        and 200 <= response.status_code < 300
                        and facts["application_success"] is True
                        and not facts["authorization_denial_observed"]
                        and facts["resource_match"]
                        and facts["private_match"]
                    )
                    denied = (facts["authorization_denial_observed"] or facts["application_success"] is False) and not (
                        facts["resource_match"] and facts["private_match"]
                    )
                    classification = "candidate" if candidate else "rejected_in_this_test" if denied else "inconclusive"
                    pair_results.append(
                        {
                            "session_account": source.name,
                            "resource_owner": target.name,
                            "access_type": "cross",
                            "status_code": response.status_code,
                            "classification": classification,
                            "private_resource_match": bool(facts["resource_match"] and facts["private_match"]),
                            "confirmed": False,
                        }
                    )
                    result["steps"].append({"step": label, **facts})
                    overall_candidate |= candidate
                    all_rejected &= denied
                    if stop_reason:
                        result["stop_reason"] = stop_reason
                        all_rejected = False
                        break
                if result["stop_reason"]:
                    break
            result["matrix"] = pair_results
            result["matrix_crosses"] = sum(cell["access_type"] == "cross" for cell in pair_results)
            result["matrix_accounts"] = [account.name for account in accounts]
            if overall_candidate:
                step_names = {str(step.get("step")) for step in result["steps"] if isinstance(step, dict)}
                controls_present = all(f"{account.name}_control" in step_names for account in accounts)
                cross_present = any(
                    str(step.get("step", "")).startswith("cross_") for step in result["steps"] if isinstance(step, dict)
                )
                if result["controls_valid"] and controls_present and cross_present:
                    result["classification"] = "confirmed"
                    result["finding_state"] = "confirmed"
                    result["confirmed"] = True
                    result["stop_reason"] = result["stop_reason"] or "private_evidence_observed"
                else:
                    result["classification"] = "candidate"
                    result["finding_state"] = "candidate"
                    result["confirmed"] = False
                    result["confirmation_gap"] = "no_second_proof"
                    result["stop_reason"] = result["stop_reason"] or "private_evidence_observed"
            elif len(pair_results) == len(accounts) ** 2 and all_rejected:
                result["classification"] = "rejected_in_this_test"
                result["finding_state"] = "not_observed"
                result["stop_reason"] = "cross_matrix_rejected"
        else:
            actor, owner = accounts[1], accounts[0]
            request = RequestSpec("GET", owner.request.prepared_url(), dict(actor.request.headers))
            response = send("cross_read", request)
            if response is not None:
                facts = observations(response, case.checks)
                result["steps"].append({"step": "cross_read", **facts})
                stop_reason = blocked(response)
                if stop_reason:
                    result["stop_reason"] = stop_reason
                    result["cross_result"] = "inconclusive"
                elif not case.resource_private:
                    result["cross_result"] = "public_endpoint"
                    result["classification"] = "public_endpoint"
                    result["finding_state"] = "not_observed"
                    result["stop_reason"] = "public_endpoint"
                else:
                    contradictory = (
                        facts["authorization_denial_observed"] or facts["application_success"] is False
                    ) and (facts["owner_resource_match"] and facts["owner_private_match"])
                    result["cross_result"] = (
                        "inconclusive"
                        if contradictory
                        else "candidate"
                        if 200 <= response.status_code < 300
                        and facts["application_success"] is True
                        and not facts["authorization_denial_observed"]
                        and facts["owner_resource_match"]
                        and facts["owner_private_match"]
                        else "rejected_in_this_test"
                        if facts["authorization_denial_observed"] or facts["application_success"] is False
                        else "inconclusive"
                    )
                    if result["cross_result"] == "candidate":
                        step_names = {str(step.get("step")) for step in result["steps"] if isinstance(step, dict)}
                        # Session B reads A's resource; both controls + cross response in evidence.
                        if (
                            result["controls_valid"]
                            and "owner_control" in step_names
                            and "actor_control" in step_names
                            and "cross_read" in step_names
                        ):
                            result["classification"] = "confirmed"
                            result["finding_state"] = "confirmed"
                            result["confirmed"] = True
                        else:
                            result["classification"] = "candidate"
                            result["finding_state"] = "candidate"
                            result["confirmed"] = False
                            result["confirmation_gap"] = "no_second_proof"
                        result["stop_reason"] = "private_evidence_observed"
                    elif result["cross_result"] == "rejected_in_this_test":
                        result["classification"] = "rejected_in_this_test"
                        result["finding_state"] = "not_observed"
                        result["stop_reason"] = "cross_read_rejected"
                    elif contradictory:
                        result["stop_reason"] = "contradictory_authorization_evidence"
                    elif facts["owner_marker_seen"] or facts["owner_resource_match"]:
                        result["stop_reason"] = "partial_private_evidence"
                    else:
                        result["stop_reason"] = "cross_read_not_proven"

        can_continue = result["stop_reason"] not in {
            "rate_limited",
            "truncated_response",
            "redirect_not_followed",
            "transport_error",
        }
        if inverse_cross and can_continue:
            inverse_request = RequestSpec("GET", actor.request.prepared_url(), dict(owner.request.headers))
            self.scope.require(inverse_request.prepared_url())
            inverse_response = send("inverse_cross", inverse_request)
            result["inverse_sent"] = True
            if inverse_response is not None:
                facts = account_observations(inverse_response, case.checks, actor.resource, actor.marker)
                candidate = (
                    case.resource_private
                    and not blocked(inverse_response)
                    and 200 <= inverse_response.status_code < 300
                    and facts["application_success"] is True
                    and not facts["authorization_denial_observed"]
                    and facts["resource_match"]
                    and facts["private_match"]
                )
                denied = (facts["authorization_denial_observed"] or facts["application_success"] is False) and not (
                    facts["resource_match"] and facts["private_match"]
                )
                result["inverse_result"] = (
                    "candidate" if candidate else "rejected_in_this_test" if denied else "inconclusive"
                )
                result["steps"].append({"step": "inverse_cross", **facts})
                result["bidirectional_access"] = result.get("cross_result") in {"candidate", "confirmed"} and candidate
                if candidate and result["classification"] not in {"candidate", "confirmed"}:
                    result["classification"] = "candidate"
                    result["finding_state"] = "candidate"
                result["stop_reason"] = blocked(inverse_response) or result["stop_reason"]

        can_continue = result["stop_reason"] not in {
            "rate_limited",
            "truncated_response",
            "redirect_not_followed",
            "transport_error",
        }
        if anonymous_check and can_continue:
            anonymous_headers = {
                key: value for key, value in case.cross.headers.items() if key.lower() not in set(case.session_headers)
            }
            anonymous_request = RequestSpec("GET", case.cross.prepared_url(), anonymous_headers)
            self.scope.require(anonymous_request.prepared_url())
            anonymous_response = send("anonymous_check", anonymous_request)
            result["anonymous_sent"] = True
            if anonymous_response is not None:
                facts = account_observations(anonymous_response, case.checks, owner.resource, owner.marker)
                private_data_observed = bool(facts["resource_match"] and facts["private_match"])
                contradictory = private_data_observed and (
                    facts["authorization_denial_observed"] or facts["application_success"] is False
                )
                anonymous_allowed = bool(
                    not blocked(anonymous_response)
                    and 200 <= anonymous_response.status_code < 300
                    and facts["application_success"] is True
                    and not facts["authorization_denial_observed"]
                )
                anonymous_denied = bool(
                    not contradictory
                    and (facts["authorization_denial_observed"] or facts["application_success"] is False)
                )
                expected = case.expected_anonymous
                if expected is None and case.resource_private:
                    expected = "deny"
                mismatch = (expected == "deny" and anonymous_allowed) or (expected == "allow" and anonymous_denied)
                result["anonymous_expected"] = expected
                result["anonymous_access_observed"] = private_data_observed
                result["anonymous_request_allowed"] = anonymous_allowed
                result["anonymous_expectation_mismatch"] = bool(mismatch)
                result["anonymous_finding"] = bool(
                    not contradictory
                    and (
                        mismatch
                        or (
                            case.resource_private
                            and private_data_observed
                            and anonymous_allowed
                            and expected != "allow"
                        )
                    )
                )
                if contradictory:
                    result["anonymous_classification"] = "inconclusive"
                elif not case.resource_private:
                    result["anonymous_classification"] = "public_endpoint"
                    result["classification"] = "public_endpoint"
                elif private_data_observed and anonymous_allowed and expected != "allow":
                    result["anonymous_classification"] = "anonymous_access"
                    if result["classification"] != "candidate":
                        result["classification"] = "anonymous_access"
                elif mismatch:
                    result["anonymous_classification"] = "anonymous_expectation_mismatch"
                    if result["classification"] != "candidate":
                        result["classification"] = "anonymous_expectation_mismatch"
                elif private_data_observed:
                    result["anonymous_classification"] = "expected_anonymous_access"
                else:
                    result["anonymous_classification"] = "rejected_in_this_test" if anonymous_denied else "inconclusive"
                result["steps"].append({"step": "anonymous_check", **facts})
                result["stop_reason"] = blocked(anonymous_response) or result["stop_reason"]

        path = write_evidence_json(evidence_dir, result, prefix="access-control")
        return path, result
