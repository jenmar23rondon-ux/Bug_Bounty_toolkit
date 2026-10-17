from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
import re
from urllib.parse import parse_qsl, unquote, urlsplit

from ..core.http_client import HttpClient, RequestSpec, ResponseRecord
from ..core.request_builder import parse_raw_http_request
from ..core.scope_validator import ScopeValidator
from ..core.target import normalize_url
from ..reporting.evidence import write_evidence_json
from ..utils.exceptions import ToolkitError


MISSING = object()
SESSION_KEY = re.compile(r"auth|cookie|token|sess|credential|csrf|signature|api[-_]?key|anti[-_]?content", re.I)
CASE_FIELDS = {"owner_request", "actor_request", "base_url", "session_headers", "resource", "checks",
               "accounts_authorized", "resource_private", "expected_cross_access"}
CHECK_FIELDS = {"success_pointer", "success_value", "resource_pointer", "owner_resource", "actor_resource",
                "private_pointer", "owner_marker", "actor_marker"}


def parse_json(text: str):
    def unique(pairs):
        result = {}
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
    if not isinstance(pointer, str) or not pointer.startswith("/") or len(pointer) > 256 or re.search(r"~(?![01])", pointer):
        raise ValueError("Checks require valid non-root JSON pointers.")
    return [part.replace("~1", "/").replace("~0", "~") for part in pointer[1:].split("/")]


def lookup(document, pointer: str):
    value = document
    for part in pointer_parts(pointer):
        if isinstance(value, dict):
            value = value.get(part, MISSING)
        elif isinstance(value, list) and re.fullmatch(r"0|[1-9][0-9]*", part):
            value = value[int(part)] if int(part) < len(value) else MISSING
        else:
            return MISSING
    return value


def exact(value, expected) -> bool:
    return type(value) is type(expected) and value == expected


@dataclass(frozen=True)
class AccessCase:
    owner: RequestSpec
    actor: RequestSpec
    cross: RequestSpec
    checks: dict


def load_case(path: Path, scope: ScopeValidator) -> AccessCase:
    data = parse_json(read_local(path, 131072))
    if not isinstance(data, dict) or set(data) != CASE_FIELDS:
        raise ValueError("Access case has missing or unsupported fields.")
    if data["accounts_authorized"] is not True or data["resource_private"] is not True or data["expected_cross_access"] != "deny":
        raise ValueError("An access case requires authorized test accounts and a known private resource with expected denial.")
    if not isinstance(data["base_url"], str):
        raise ValueError("The captured base URL is required.")
    try:
        base = urlsplit(normalize_url(data["base_url"]))
    except ValueError as exc:
        raise ValueError("A valid captured HTTP(S) origin is required.") from exc
    if base.path not in {"", "/"} or base.query:
        raise ValueError("Base URL must be the captured origin without a path or query.")
    requests = []
    for field in ("owner_request", "actor_request"):
        if not isinstance(data[field], str) or not data[field]:
            raise ValueError("Provide two local raw-request file paths.")
        raw = read_local(path.parent / data[field], 1_000_000)
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
            raise ValueError("Access-check supports reviewed GET reads without bodies only.")
        for key, value in spec.headers.items():
            if not re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+", key) or any((ord(char) < 32 and char != "\t") or ord(char) > 255 for char in value):
                raise ValueError("A captured HTTP header cannot be safely encoded.")
        # The standard client does not decompress captures; request identity encoding for all three steps.
        spec.headers = {key: value for key, value in spec.headers.items() if key.lower() != "accept-encoding"}
        spec.headers["Accept-Encoding"] = "identity"
        try:
            scope.require(spec.prepared_url())
        except ValueError as exc:
            raise ValueError("A control destination is outside the authorized scope.") from exc
        requests.append(spec)
    owner, actor = requests
    owner_url, actor_url = urlsplit(owner.prepared_url()), urlsplit(actor.prepared_url())
    if (owner_url.scheme, owner_url.netloc) != (actor_url.scheme, actor_url.netloc):
        raise ValueError("Both controls must use the same captured origin.")
    if (owner_url.scheme, owner_url.netloc) != (base.scheme, base.netloc):
        raise ValueError("Control destinations must match the declared captured origin.")
    owner_query, actor_query = [parse_qsl(url.query, keep_blank_values=True) for url in (owner_url, actor_url)]
    for query in (owner_query, actor_query):
        if len(dict(query)) != len(query) or any(SESSION_KEY.search(key) for key, _ in query):
            raise ValueError("Duplicate or session-bearing query parameters are not supported.")
    resource = data["resource"]
    if not isinstance(resource, dict) or len(resource) != 1:
        raise ValueError("Declare exactly one resource query parameter or path segment.")
    if set(resource) == {"query_parameter"}:
        key = resource["query_parameter"]
        if not isinstance(key, str) or key not in dict(owner_query) or key not in dict(actor_query):
            raise ValueError("The declared resource query parameter must exist in both controls.")
        left, right = dict(owner_query), dict(actor_query)
        if not left[key] or not right[key] or left.pop(key) == right.pop(key) or left != right or owner_url.path != actor_url.path:
            raise ValueError("Controls must differ only in the declared resource reference.")
    elif set(resource) == {"path_segment"}:
        index = resource["path_segment"]
        left, right = owner_url.path[1:].split("/"), actor_url.path[1:].split("/")
        if type(index) is not int or index < 0 or index >= min(len(left), len(right)):
            raise ValueError("Invalid zero-based resource path segment.")
        if not left[index] or not right[index] or left[index] == right[index]:
            raise ValueError("Control resource identifiers must be distinct.")
        left[index] = right[index] = "RESOURCE"
        if left != right or dict(owner_query) != dict(actor_query):
            raise ValueError("Controls must differ only in the declared resource reference.")
    else:
        raise ValueError("Unsupported resource selector.")
    names = data["session_headers"]
    if not isinstance(names, list) or not 1 <= len(names) <= 16 or not all(isinstance(name, str) and re.fullmatch(r"[A-Za-z0-9-]{1,80}", name) for name in names):
        raise ValueError("Declare the complete session header names.")
    names = [name.lower() for name in names]
    if len(set(names)) != len(names) or set(names) & {"host", "content-length", "transfer-encoding", "connection"}:
        raise ValueError("Invalid session header selection.")
    owner_headers, actor_headers = [{key.lower(): value for key, value in spec.headers.items()} for spec in requests]
    for headers in (owner_headers, actor_headers):
        if any(not headers.get(name) for name in names) or any(SESSION_KEY.search(name) and name not in names for name in headers):
            raise ValueError("Session header declarations must cover both complete captured contexts.")
    if all(owner_headers[name] == actor_headers[name] for name in names):
        raise ValueError("Owner and actor session contexts must be distinct.")
    checks = data["checks"]
    if not isinstance(checks, dict) or set(checks) != CHECK_FIELDS:
        raise ValueError("The access case requires explicit application, resource and private-marker checks.")
    for key in ("success_pointer", "resource_pointer", "private_pointer"):
        pointer_parts(checks[key])
    if len({checks[key] for key in ("success_pointer", "resource_pointer", "private_pointer")}) != 3 or type(checks["success_value"]) not in {bool, str, int}:
        raise ValueError("Check pointers must be distinct and success must be a scalar.")
    for key in ("owner_resource", "actor_resource"):
        if type(checks[key]) not in {str, int} or checks[key] == "":
            raise ValueError("Expected resources must be nonempty strings or integers.")
    if exact(checks["owner_resource"], checks["actor_resource"]):
        raise ValueError("Known owner and actor resources must be distinct.")
    for key in ("owner_marker", "actor_marker"):
        marker = checks[key]
        if not isinstance(marker, str) or not re.fullmatch(r"[A-Za-z0-9_-]{12,128}", marker):
            raise ValueError("Use distinct controlled private markers of 12-128 ASCII identifier characters.")
        if any(marker in unquote(spec.prepared_url()) or any(marker in unquote(value) for value in spec.headers.values()) for spec in requests):
            raise ValueError("Private proof markers must not be supplied by either request.")
    if checks["owner_marker"] in checks["actor_marker"] or checks["actor_marker"] in checks["owner_marker"]:
        raise ValueError("Private proof markers must be distinct.")
    # Keep the owner's destination but use the actor's ENTIRE header context, never a merged owner session.
    cross = RequestSpec("GET", owner.prepared_url(), dict(actor.headers))
    scope.require(cross.prepared_url())
    return AccessCase(owner, actor, cross, checks)


def observations(response: ResponseRecord, checks: dict) -> dict:
    try:
        body = parse_json(response.body_text)
    except ValueError:
        body = None
    success = lookup(body, checks["success_pointer"])
    application_success = None if type(success) is not type(checks["success_value"]) else exact(success, checks["success_value"])
    resource = lookup(body, checks["resource_pointer"])
    private = lookup(body, checks["private_pointer"])
    return {"status_code": response.status_code, "duration_ms": response.duration_ms,
            "body_size": response.body_size, "body_truncated": response.body_truncated,
            "application_success": application_success,
            **{f"{account}_resource_match": exact(resource, checks[f"{account}_resource"]) for account in ("owner", "actor")},
            **{f"{account}_private_match": exact(private, checks[f"{account}_marker"]) for account in ("owner", "actor")},
            **{f"{account}_marker_seen": checks[f"{account}_marker"] in response.body_text for account in ("owner", "actor")}}


class AccessControlTester:
    def __init__(self, scope: ScopeValidator, client: HttpClient):
        self.scope, self.client = scope, client

    def validate(self, case_file: Path, max_tests: int = 3) -> AccessCase:
        if type(max_tests) is not int or max_tests < 3:
            raise ValueError("Three requests must fit: owner control, actor control, then one crossed read.")
        return load_case(case_file, self.scope)

    def run(self, case_file: Path, evidence_dir: Path, max_tests: int = 3) -> tuple[Path, dict]:
        case = self.validate(case_file, max_tests)
        result = {"type": "access-control", "classification": "inconclusive", "confirmed": False,
                  "controls_valid": False, "requests_attempted": 0, "request_budget": 3, "steps": [],
                  "stop_reason": None, "inverse_sent": False, "anonymous_sent": False}
        for label, spec in (("owner_control", case.owner), ("actor_control", case.actor), ("cross_read", case.cross)):
            result["requests_attempted"] += 1
            try:
                response = self.client.send(spec)
            except (ToolkitError, ValueError):
                result["steps"].append({"step": label, "transport_error": True})
                result["stop_reason"] = "transport_error"
                break
            observed = observations(response, case.checks)
            result["steps"].append({"step": label, **observed})
            if response.status_code == 429 or response.body_truncated or 300 <= response.status_code < 400:
                result["stop_reason"] = "rate_limited" if response.status_code == 429 else "truncated_response" if response.body_truncated else "redirect_not_followed"
                break
            if label != "cross_read":
                account = "owner" if label == "owner_control" else "actor"
                other = "actor" if account == "owner" else "owner"
                valid = (response.status_code == 200 and observed["application_success"] is True and
                         observed[f"{account}_resource_match"] and observed[f"{account}_private_match"] and not observed[f"{other}_marker_seen"])
                if not valid:
                    result["stop_reason"] = "invalid_" + label
                    break
                result["controls_valid"] = label == "actor_control"
                continue
            if observed["owner_resource_match"] and observed["owner_private_match"]:
                result["classification"] = "candidate"
                result["stop_reason"] = "private_evidence_observed"
            elif observed["owner_marker_seen"] or observed["owner_resource_match"]:
                result["stop_reason"] = "partial_private_evidence"
            elif response.status_code in {401, 403} or observed["application_success"] is False:
                result["classification"] = "rejected_in_this_test"
                result["stop_reason"] = "cross_read_rejected"
            else:
                result["stop_reason"] = "cross_read_not_proven"
        path = write_evidence_json(evidence_dir, result, prefix="access-control")
        return path, result
