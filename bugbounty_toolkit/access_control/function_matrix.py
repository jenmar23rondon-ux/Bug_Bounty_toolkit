from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import re
from typing import Any
from urllib.parse import parse_qsl, urlsplit

from ..core.http_client import HttpClient, RequestSpec, ResponseRecord
from ..core.request_builder import parse_raw_http_request
from ..core.scope_validator import ScopeValidator
from ..core.target import normalize_url
from ..reporting.evidence import write_evidence_json
from ..utils.exceptions import ToolkitError
from .comparison import exact, lookup, parse_json, pointer_parts, read_local

MAX_FUNCTION_CASE_BYTES = 131_072
MAX_FUNCTION_MATRIX_REQUESTS = 100
_ACCOUNT_NAME = re.compile(r"^[A-Za-z][A-Za-z0-9_-]{0,31}$")
_HEADER_NAME = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]{1,80}$")
_SENSITIVE_QUERY = re.compile(r"auth|cookie|token|sess|credential|csrf|signature|api[-_]?key", re.I)


@dataclass(frozen=True)
class FunctionAccount:
    name: str
    role: str
    request: RequestSpec


@dataclass(frozen=True)
class FunctionCheck:
    name: str
    allowed_roles: tuple[str, ...]
    success_pointer: str
    success_value: object
    denial_value: object
    marker_pointer: str
    marker: str
    accounts: tuple[FunctionAccount, ...]


@dataclass(frozen=True)
class FunctionMatrixCase:
    accounts_authorized: bool
    base_url: str
    session_headers: tuple[str, ...]
    functions: tuple[FunctionCheck, ...]

    @property
    def request_count(self) -> int:
        return sum(len(function.accounts) for function in self.functions)


def _read_case(path: Path) -> object:
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise ValueError(f"Cannot read function-access case: {path.name}.") from exc
    if len(raw) > MAX_FUNCTION_CASE_BYTES:
        raise ValueError(f"Function-access case exceeds the {MAX_FUNCTION_CASE_BYTES}-byte limit.")
    try:
        return parse_json(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise ValueError("Function-access case must be valid UTF-8 JSON.") from exc


def _safe_capture(case_path: Path, relative: object) -> Path:
    if not isinstance(relative, str) or not relative or len(relative) > 512:
        raise ValueError("Each role needs a local raw GET capture path.")
    root = case_path.parent.resolve()
    candidate = (root / relative).resolve()
    if not candidate.is_relative_to(root):
        raise ValueError("Function capture paths must remain inside the case directory.")
    return candidate


def _origin(url: str) -> tuple[str, str, int | None]:
    parsed = urlsplit(url)
    scheme = parsed.scheme.lower()
    port = parsed.port or (443 if scheme == "https" else 80 if scheme == "http" else None)
    return scheme, (parsed.hostname or "").lower(), port


def load_function_matrix_case(path: Path, scope: ScopeValidator) -> FunctionMatrixCase:
    """Validate a supplied, read-only role/function matrix and scope-check every capture."""
    data = _read_case(path)
    required = {"type", "base_url", "accounts_authorized", "session_headers", "accounts", "functions"}
    if not isinstance(data, dict) or set(data) != required or data.get("type") != "function-access-case":
        raise ValueError("Function-access case has missing or unsupported fields.")
    if data["accounts_authorized"] is not True:
        raise ValueError("Function-matrix checks require an explicit authorized test-account declaration.")
    if not isinstance(data["base_url"], str):
        raise ValueError("Function-matrix case requires a captured HTTP(S) origin.")
    try:
        base_url = normalize_url(data["base_url"])
        base = urlsplit(base_url)
    except ValueError as exc:
        raise ValueError("Function-matrix base URL must be a valid HTTP(S) origin.") from exc
    if base.path not in {"", "/"} or base.query or base.fragment:
        raise ValueError("Function-matrix base URL must be an origin without path, query or fragment.")

    headers = data["session_headers"]
    if (
        not isinstance(headers, list)
        or not 1 <= len(headers) <= 5
        or any(not isinstance(name, str) or not _HEADER_NAME.fullmatch(name) for name in headers)
        or len({name.casefold() for name in headers}) != len(headers)
        or any(name.casefold() in {"host", "content-length", "transfer-encoding"} for name in headers)
    ):
        raise ValueError("Declare one to five distinct session header names (not Host or framing headers).")
    session_names = tuple(name.casefold() for name in headers)

    account_data = data["accounts"]
    if not isinstance(account_data, dict) or not 2 <= len(account_data) <= 10:
        raise ValueError("Function matrices require two to ten authorized accounts.")
    account_roles: dict[str, str] = {}
    for name, role in account_data.items():
        if (
            not isinstance(name, str)
            or not _ACCOUNT_NAME.fullmatch(name)
            or not isinstance(role, str)
            or not _ACCOUNT_NAME.fullmatch(role)
        ):
            raise ValueError("Account labels and role labels must use letters, digits, underscores or hyphens.")
        account_roles[name] = role

    function_data = data["functions"]
    if not isinstance(function_data, list) or not 1 <= len(function_data) <= 20:
        raise ValueError("Provide one to twenty function checks.")
    functions: list[FunctionCheck] = []
    account_session_values: dict[str, tuple[tuple[str, str], ...]] = {}
    session_owner: dict[tuple[tuple[str, str], ...], str] = {}
    seen_function_names: set[str] = set()
    seen_markers: set[str] = set()
    for row in function_data:
        expected_fields = {
            "name",
            "allowed_roles",
            "requests",
            "success_pointer",
            "success_value",
            "denial_value",
            "marker_pointer",
            "marker",
            "restricted",
            "read_only_attested",
        }
        if not isinstance(row, dict) or set(row) != expected_fields:
            raise ValueError(
                "Each function needs a name, allowed roles, captures, success/denial/marker predicates and restricted=true."
            )
        name = row["name"]
        if not isinstance(name, str) or not _ACCOUNT_NAME.fullmatch(name) or name in seen_function_names:
            raise ValueError("Function names must be unique safe labels.")
        seen_function_names.add(name)
        if row["restricted"] is not True:
            raise ValueError("Function-matrix checks require restricted=true for every function under review.")
        if row["read_only_attested"] is not True:
            raise ValueError("Function-matrix checks require an explicit read_only_attested=true declaration.")
        allowed_roles = row["allowed_roles"]
        if (
            not isinstance(allowed_roles, list)
            or not allowed_roles
            or any(not isinstance(role, str) or role not in set(account_roles.values()) for role in allowed_roles)
            or len(set(allowed_roles)) != len(allowed_roles)
        ):
            raise ValueError(f"Function {name} must declare known, unique allowed_roles.")
        account_requests = row["requests"]
        if not isinstance(account_requests, dict) or set(account_requests) != set(account_roles):
            raise ValueError(f"Function {name} needs exactly one request capture for every declared account.")
        success_pointer, marker_pointer, marker = row["success_pointer"], row["marker_pointer"], row["marker"]
        if not isinstance(success_pointer, str) or not isinstance(marker_pointer, str):
            raise ValueError(f"Function {name} requires JSON pointers for success and function evidence.")
        pointer_parts(success_pointer)
        pointer_parts(marker_pointer)
        if (
            not isinstance(marker, str)
            or len(marker) < 8
            or len(marker) > 256
            or any(ord(char) < 32 for char in marker)
        ):
            raise ValueError(
                f"Function {name} requires a unique, pre-existing marker of 8 to 256 printable characters."
            )
        if marker in seen_markers:
            raise ValueError("Each function must use a distinct private marker to avoid ambiguous control matches.")
        seen_markers.add(marker)
        success_value = row["success_value"]
        denial_value = row["denial_value"]
        scalar_types = {bool, int, float, str}
        if type(success_value) not in scalar_types or type(denial_value) not in scalar_types:
            raise ValueError(f"Function {name} success_value and denial_value must be JSON scalars.")
        if exact(success_value, denial_value):
            raise ValueError(f"Function {name} success and denial values must be different.")

        requests: list[FunctionAccount] = []
        captured_url: str | None = None
        for account_name, role in account_roles.items():
            capture_path = _safe_capture(path, account_requests[account_name])
            try:
                raw = read_local(capture_path, 1_000_000)
                captured = parse_raw_http_request(raw)
                request = parse_raw_http_request(raw, base_url)
            except (OSError, ValueError, ToolkitError) as exc:
                raise ValueError(
                    f"Capture for account {account_name} in function {name} is not a supported raw request."
                ) from exc
            if request.method != "GET" or request.body is not None:
                raise ValueError("Automated function-matrix checks are GET-only; write methods are not supported.")
            request_url = request.prepared_url()
            parsed = urlsplit(request_url)
            if _origin(request_url) != _origin(base_url):
                raise ValueError("All function captures must share the declared origin.")
            raw_parsed = urlsplit(captured.prepared_url())
            default_port = 443 if base.scheme == "https" else 80
            raw_authority = (raw_parsed.hostname, raw_parsed.port or default_port)
            base_authority = (base.hostname, base.port or default_port)
            if raw_authority != base_authority:
                raise ValueError("Captured Host must match the declared function-matrix origin.")
            if captured_url is None:
                captured_url = request_url
            elif request_url != captured_url:
                raise ValueError(f"Function {name} captures must use the exact same endpoint and query for each role.")
            if any(_SENSITIVE_QUERY.search(key) for key, _ in parse_qsl(parsed.query, keep_blank_values=True)):
                raise ValueError("Session-bearing query parameters are not supported in function-matrix captures.")
            scope.require(request_url)
            request_headers = {key.casefold(): value for key, value in request.headers.items()}
            session_values = tuple(
                sorted((header, request_headers[header]) for header in session_names if request_headers.get(header))
            )
            if len(session_values) != len(session_names):
                raise ValueError(f"Capture for account {account_name} is missing a declared session header.")
            previous_session = account_session_values.get(account_name)
            if previous_session is not None and previous_session != session_values:
                raise ValueError(
                    f"Account {account_name} must use the same session headers across its function captures."
                )
            account_session_values[account_name] = session_values
            previous_owner = session_owner.get(session_values)
            if previous_owner is not None and previous_owner != account_name:
                raise ValueError("Each declared account must use a distinct captured session.")
            session_owner[session_values] = account_name
            for key, value in request.headers.items():
                if not _HEADER_NAME.fullmatch(key) or any(
                    (ord(char) < 32 and char != "\t") or ord(char) > 255 for char in value
                ):
                    raise ValueError("A captured HTTP header cannot be safely encoded.")
            request.headers = {
                key: value for key, value in request.headers.items() if key.casefold() != "accept-encoding"
            }
            request.headers["Accept-Encoding"] = "identity"
            requests.append(FunctionAccount(account_name, role, request))

        roles_present = set(account_roles.values())
        if not set(allowed_roles) < roles_present:
            raise ValueError(f"Function {name} needs at least one declared allowed and one restricted role.")
        functions.append(
            FunctionCheck(
                name,
                tuple(allowed_roles),
                success_pointer,
                success_value,
                denial_value,
                marker_pointer,
                marker,
                tuple(requests),
            )
        )

    case = FunctionMatrixCase(True, base_url, session_names, tuple(functions))
    if case.request_count > MAX_FUNCTION_MATRIX_REQUESTS:
        raise ValueError(f"Function matrix exceeds the {MAX_FUNCTION_MATRIX_REQUESTS}-request hard limit.")
    return case


class AccessFunctionMatrixTester:
    """Run bounded read-only BFLA controls using exact, supplied role captures."""

    def __init__(self, scope: ScopeValidator, client: HttpClient):
        self.scope = scope
        self.client = client

    def validate(self, case_file: Path, max_tests: int) -> FunctionMatrixCase:
        if type(max_tests) is not int or max_tests < 1:
            raise ValueError("Function-matrix request budget must be a positive integer.")
        case = load_function_matrix_case(case_file, self.scope)
        if case.request_count > max_tests:
            raise ValueError(
                f"Function matrix requires {case.request_count} requests, exceeding --max-tests {max_tests}."
            )
        return case

    def run(self, case_file: Path, evidence_dir: Path, max_tests: int) -> tuple[Path, dict[str, Any]]:
        case = self.validate(case_file, max_tests)
        result: dict[str, Any] = {
            "type": "access-control",
            "mode": "function-matrix",
            "classification": "insufficient_evidence",
            "confirmed": False,
            "status_code_used": False,
            "model_opinion_used": False,
            "accounts_authorized_attested": case.accounts_authorized,
            "functions": [],
            "requests_attempted": 0,
            "request_budget": max_tests,
            "stop_reason": None,
            "network_requests_sent": 0,
        }
        global_candidate = False
        all_complete_and_denied = True

        def blocked(response: ResponseRecord) -> str | None:
            if response.status_code == 429:
                return "rate_limited"
            if response.body_truncated:
                return "truncated_response"
            if 300 <= response.status_code < 400:
                return "redirect_not_followed"
            return None

        for function in case.functions:
            function_result: dict[str, Any] = {
                "function": function.name,
                "required_roles": list(function.allowed_roles),
                "read_only_attested": True,
                "controls_valid": False,
                "classification": "insufficient_evidence",
                "results": [],
            }
            rows: list[dict[str, Any]] = function_result["results"]
            positives_valid = True
            function_candidate = False
            function_denied = True
            stop = False
            for account in (item for item in function.accounts if item.role in function.allowed_roles):
                response = self._send(account.request, result)
                if response is None:
                    positives_valid = False
                    function_denied = False
                    stop = True
                    break
                facts = self._facts(response, function)
                stop_reason = blocked(response)
                valid = stop_reason is None and facts["success_match"] and facts["marker_match"]
                rows.append(
                    {
                        "account": account.name,
                        "role": account.role,
                        "expected_access": "allow",
                        "classification": "legitimate_access" if valid else "inconclusive",
                        "status_code": response.status_code,
                        **facts,
                        "confirmed": False,
                    }
                )
                if stop_reason:
                    result["stop_reason"] = stop_reason
                    positives_valid = False
                    function_denied = False
                    stop = True
                    break
                if not valid:
                    positives_valid = False
                    function_denied = False
            function_result["controls_valid"] = positives_valid
            if positives_valid and not stop:
                for account in (item for item in function.accounts if item.role not in function.allowed_roles):
                    response = self._send(account.request, result)
                    if response is None:
                        function_denied = False
                        stop = True
                        break
                    facts = self._facts(response, function)
                    stop_reason = blocked(response)
                    if stop_reason:
                        classification = "inconclusive"
                        result["stop_reason"] = stop_reason
                        function_denied = False
                        stop = True
                    elif facts["success_match"] and facts["marker_match"]:
                        classification = "possible_bfla"
                        function_candidate = True
                        function_denied = False
                    elif facts["denial_match"] and not facts["marker_seen"]:
                        classification = "denied"
                    else:
                        classification = "inconclusive"
                        function_denied = False
                    rows.append(
                        {
                            "account": account.name,
                            "role": account.role,
                            "expected_access": "deny",
                            "classification": classification,
                            "status_code": response.status_code,
                            **facts,
                            "confirmed": False,
                        }
                    )
                    if stop:
                        break
            else:
                function_denied = False
                for account in (item for item in function.accounts if item.role not in function.allowed_roles):
                    rows.append(
                        {
                            "account": account.name,
                            "role": account.role,
                            "expected_access": "deny",
                            "classification": "inconclusive",
                            "request_sent": False,
                            "confirmed": False,
                        }
                    )
            if function_candidate:
                function_result["classification"] = "possible_bfla"
                global_candidate = True
            elif function_denied and positives_valid:
                function_result["classification"] = "denied"
            else:
                function_result["classification"] = "insufficient_evidence"
                all_complete_and_denied = False
            result["functions"].append(function_result)
            if stop:
                for remaining in case.functions[len(result["functions"]) :]:
                    result["functions"].append(
                        {
                            "function": remaining.name,
                            "required_roles": list(remaining.allowed_roles),
                            "controls_valid": False,
                            "classification": "inconclusive",
                            "results": [],
                            "request_sent": False,
                        }
                    )
                all_complete_and_denied = False
                break

        if global_candidate:
            result["classification"] = "possible_bfla"
            result["stop_reason"] = result["stop_reason"] or "restricted_function_marker_observed"
        elif all_complete_and_denied:
            result["classification"] = "denied"
            result["stop_reason"] = "restricted_roles_denied_in_test"
        path = write_evidence_json(evidence_dir, result, prefix="access-function-matrix")
        return path, result

    @staticmethod
    def _facts(response: ResponseRecord, function: FunctionCheck) -> dict[str, object]:
        try:
            body = parse_json(response.body_text)
        except ValueError:
            body = None
        success = lookup(body, function.success_pointer)
        marker = lookup(body, function.marker_pointer)
        success_match = exact(success, function.success_value)
        denial_match = exact(success, function.denial_value)
        marker_match = exact(marker, function.marker)
        return {
            "success_match": success_match,
            "denial_match": denial_match,
            "marker_match": marker_match,
            "marker_seen": function.marker in response.body_text,
            "body_truncated": response.body_truncated,
        }

    def _send(self, request: RequestSpec, result: dict[str, Any]) -> ResponseRecord | None:
        result["requests_attempted"] += 1
        try:
            response = self.client.send(request)
        except (ToolkitError, ValueError):
            result["stop_reason"] = "transport_error"
            return None
        result["network_requests_sent"] += 1
        return response
