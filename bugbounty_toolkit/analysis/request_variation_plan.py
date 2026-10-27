"""Offline, declaration-driven GET resource diffs, never execution or approval.

Plans retain only typed resource diffs and capture digests, never HTTP headers,
cookies, full URLs or raw messages. The unchanged private capture is required
for review. A plan is deliberately not an IDOR case or capture evidence.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
from pathlib import Path
import re
from typing import Any
from urllib.parse import parse_qsl, quote, unquote, unquote_plus, urlsplit

from ..access_control.comparison import exact, parse_json, pointer_parts
from ..burp_import import MAX_EXCHANGE_BYTES, parse_captured_exchanges
from ..case_generator import SESSION_HEADER
from ..core.private_files import atomic_private_write, local_path, read_private_input
from ..core.scope_validator import ScopeValidator
from ..core.target import normalize_url

DECLARATION_SCHEMA = "bbtk-lab-resources/1"
PLAN_SCHEMA = "bbtk-request-variation-plan/1"
MAX_RESOURCES = 64
MAX_DECLARATION_BYTES = 128_000
_NAME = re.compile(r"[A-Za-z][A-Za-z0-9_-]{0,31}\Z")
_VALUE = re.compile(r"[A-Za-z0-9_-]{1,128}\Z")
_PROTECTED = re.compile(
    r"auth|cookie|token|sess|credential|csrf|sign|api[-_]?key|anti[-_]?content|secret|password|"
    r"policy|expires|x-amz|x-goog|key-pair|digest|hmac|nonce|jwt|(?:^|[-_])sig(?:$|[-_])",
    re.I,
)


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _json_bytes(document: object) -> bytes:
    return json.dumps(document, sort_keys=True, indent=2, allow_nan=False).encode() + b"\n"


def _name(value: object) -> bool:
    return isinstance(value, str) and _NAME.fullmatch(value) is not None


def _identifier(value: object) -> bool:
    return (type(value) is int and 0 <= value < 2**63) or (
        isinstance(value, str) and _VALUE.fullmatch(value) is not None
    )


def _lab_origin(origin: object) -> str:
    try:
        canonical = normalize_url(origin).rstrip("/") if isinstance(origin, str) else None
    except ValueError:
        canonical = None
    if not isinstance(origin, str) or origin != canonical:
        raise ValueError("Declaration requires a canonical HTTP(S) lab origin.")
    parsed = urlsplit(origin)
    if parsed.path or parsed.query or parsed.fragment:
        raise ValueError("Declaration origin cannot include a path, query or fragment.")
    host = parsed.hostname or ""
    try:
        local = ipaddress.ip_address(host).is_loopback
    except ValueError:
        local = host == "localhost" or host.endswith((".localhost", ".test", ".invalid"))
    if not local:
        raise ValueError("Only loopback or reserved synthetic lab origins are supported.")
    return origin


def load_declaration(path: Path) -> dict[str, Any]:
    """Read bounded explicit account/ownership facts; infer nothing from sessions."""
    try:
        document = parse_json(read_private_input(path, MAX_DECLARATION_BYTES).decode("utf-8"))
    except (ValueError, UnicodeError) as exc:
        raise ValueError("Invalid local resource declaration.") from exc
    fields = {"schema_version", "lab_authorized", "origin", "accounts", "resources", "source", "targets", "selector"}
    if not isinstance(document, dict) or set(document) != fields:
        raise ValueError("Resource declaration has unsupported fields.")
    if document["schema_version"] != DECLARATION_SCHEMA or document["lab_authorized"] is not True:
        raise ValueError("An explicit authorized lab declaration is required.")
    _lab_origin(document["origin"])
    accounts, resources, targets = document["accounts"], document["resources"], document["targets"]
    if not isinstance(accounts, list) or not 1 <= len(accounts) <= MAX_RESOURCES:
        raise ValueError("Declare a bounded nonempty account list.")
    names: set[str] = set()
    for account in accounts:
        if (
            not isinstance(account, dict)
            or set(account) != {"name", "authorized"}
            or not _name(account["name"])
            or account["authorized"] is not True
            or account["name"] in names
        ):
            raise ValueError("Every lab account must be named, unique and explicitly authorized.")
        names.add(account["name"])
    if not isinstance(resources, list) or not 1 <= len(resources) <= MAX_RESOURCES:
        raise ValueError("Declare a bounded nonempty resource list.")
    resource_names: set[str] = set()
    for resource in resources:
        if (
            not isinstance(resource, dict)
            or set(resource) != {"name", "account", "value", "synthetic"}
            or not _name(resource["name"])
            or not isinstance(resource["account"], str)
            or resource["account"] not in names
            or resource["synthetic"] is not True
            or not _identifier(resource["value"])
            or resource["name"] in resource_names
        ):
            raise ValueError("Resources require explicit ownership, unique names and known synthetic scalar IDs.")
        resource_names.add(resource["name"])
    if not isinstance(document["source"], str) or document["source"] not in resource_names:
        raise ValueError("Source resource must be declared.")
    if not isinstance(targets, list) or not 1 <= len(targets) <= MAX_RESOURCES or any(not _name(t) for t in targets):
        raise ValueError("Targets must be a bounded explicit list of resource references.")
    selector = document["selector"]
    if (
        not isinstance(selector, dict)
        or not selector
        or not set(selector) <= {"path_segment", "query_parameter", "json_body_pointer"}
    ):
        raise ValueError("Unsupported resource selector.")
    for key, value in selector.items():
        if key == "path_segment" and (type(value) is not int or not 0 <= value < 256):
            raise ValueError("Path segment index must be a bounded integer.")
        if key == "query_parameter" and (not isinstance(value, str) or not _VALUE.fullmatch(value)):
            raise ValueError("Query selector must be a bounded parameter name.")
        if key == "json_body_pointer":
            pointer_parts(value)
    return document


def _capture(data: bytes, origin: str) -> tuple[str, str]:
    """Use the IDOR parser's origin/Host/provenance and capture consistency checks."""
    exchanges = parse_captured_exchanges(data, origin)
    if len(exchanges) != 1:
        raise ValueError("CAPTURE_COUNT")
    exchange = exchanges[0]
    request = exchange.request
    raw = exchange.raw_request
    head = re.split(r"\r?\n\r?\n", raw, maxsplit=1)[0]
    lines = head.splitlines()
    target = lines[0].split()[1]
    # The shared parser strips framing headers; inspect original framing as well.
    headers = [line.split(":", 1) for line in lines[1:]]
    if request.method != "GET":
        raise ValueError("NON_GET")
    if request.body is not None:
        raise ValueError("GET_BODY_UNSUPPORTED")
    if any(name.lower().strip() == "transfer-encoding" for name, _ in headers) or any(
        name.lower().strip() == "content-length" and value.strip() != "0" for name, value in headers
    ):
        raise ValueError("PARTIAL_OR_AMBIGUOUS_FRAMING")
    if "#" in target or not (target.startswith("/") or target.startswith(("http://", "https://"))):
        raise ValueError("UNSUPPORTED_TARGET")
    parsed = urlsplit(request.prepared_url())
    if f"{parsed.scheme}://{parsed.netloc}" != origin:
        raise ValueError("ORIGIN_MISMATCH")
    pairs = parse_qsl(parsed.query, keep_blank_values=True, strict_parsing=True)
    if len({key for key, _ in pairs}) != len(pairs):
        raise ValueError("DUPLICATE_QUERY")
    if any(_PROTECTED.search(key) or SESSION_HEADER.search(key) for key, _ in pairs):
        raise ValueError("SIGNED_OR_SENSITIVE_QUERY")
    if any(re.search(r"sign|digest|hmac|x-amz|x-goog|(?:^|[-_])sig(?:$|[-_])", name, re.I) for name, _ in headers):
        raise ValueError("SIGNED_REQUEST")
    return raw, target


def _replace_target(target: str, selector: dict[str, Any], old: str, new: str) -> str:
    """Replace exactly one serialized URL field; retain all unrelated bytes."""
    parsed = urlsplit(target)
    if "path_segment" in selector:
        parts = parsed.path.lstrip("/").split("/")
        index = selector["path_segment"]
        if index >= len(parts) or unquote(parts[index], errors="strict") != old:
            raise ValueError("SOURCE_VALUE_MISMATCH")
        # Restrict IDs to safe scalar text; never create separators, dot paths or escapes.
        offset = len(parsed.path) - len(parsed.path.lstrip("/")) + sum(len(p) + 1 for p in parts[:index])
        path_start = len(target.split("?", 1)[0]) - len(parsed.path)
        start = path_start + offset
        return target[:start] + quote(new, safe="") + target[start + len(parts[index]) :]
    name = selector["query_parameter"]
    if _PROTECTED.search(name) or SESSION_HEADER.search(name):
        raise ValueError("SENSITIVE_SELECTOR")
    pairs = parsed.query.split("&")
    matches = [i for i, part in enumerate(pairs) if unquote_plus(part.partition("=")[0]) == name]
    if len(matches) != 1:
        raise ValueError("SOURCE_VALUE_MISMATCH")
    index = matches[0]
    key, separator, value = pairs[index].partition("=")
    if not separator or unquote_plus(value, errors="strict") != old:
        raise ValueError("SOURCE_VALUE_MISMATCH")
    pairs[index] = key + "=" + quote(new, safe="")
    return target[: target.index("?") + 1] + "&".join(pairs)


def build_plan(capture: Path, declaration: Path, scope_file: Path) -> dict[str, Any]:
    """Plan one field per explicit known target; never return a runnable case.

    Input/config errors raise generic ValueError. Capture and per-target
    incompatibilities are stable codes without raw input/error text.
    """
    config = load_declaration(declaration)
    data = read_private_input(capture, MAX_EXCHANGE_BYTES)
    scope = ScopeValidator(local_path(scope_file))
    resources = {r["name"]: r for r in config["resources"]}
    source = resources[config["source"]]
    selector = config["selector"]
    plan: dict[str, Any] = {
        "schema_version": PLAN_SCHEMA,
        "type": "offline-request-variation-diffs",
        "capture_sha256": _digest(data),
        "declaration_sha256": _digest(_json_bytes(config)),
        "state": "requires_human_review",
        "execution_allowed": False,
        "case_eligible": False,
        "finding_confirmed": False,
        "confirmed": False,
        "network_requests_sent": 0,
        "variants": [],
        "incompatible": [],
        "duplicates_skipped": 0,
    }
    global_code = None
    raw = target = ""
    try:
        read_private_input(scope_file, MAX_DECLARATION_BYTES)
        raw, target = _capture(data, config["origin"])
        spec = parse_captured_exchanges(data, config["origin"])[0].request
        scope.require(spec.prepared_url())
    except ValueError as exc:
        known = {
            "CAPTURE_COUNT",
            "NON_GET",
            "GET_BODY_UNSUPPORTED",
            "PARTIAL_OR_AMBIGUOUS_FRAMING",
            "UNSUPPORTED_TARGET",
            "ORIGIN_MISMATCH",
            "DUPLICATE_QUERY",
            "SIGNED_OR_SENSITIVE_QUERY",
            "SIGNED_REQUEST",
        }
        global_code = str(exc) if str(exc) in known else "CAPTURE_OR_SCOPE_INCOMPATIBLE"
    if len(selector) != 1:
        global_code = "MULTIPLE_FIELDS_REQUESTED"
    elif "json_body_pointer" in selector:
        global_code = "JSON_BODY_POINTER_INCOMPATIBLE_WITH_GET"
    seen: set[str] = set()
    for reference in config["targets"]:
        code = global_code
        resource = resources.get(reference)
        if resource is None:
            code = "UNDECLARED_RESOURCE"
        elif type(source["value"]) is not type(resource["value"]):
            code = "JSON_TYPE_INCOMPATIBLE"
        elif exact(source["value"], resource["value"]):
            code = "NO_CHANGE"
        if code:
            plan["incompatible"].append({"resource_ref": reference, "code": code})
            continue
        assert resource is not None
        try:
            changed = _replace_target(target, selector, str(source["value"]), str(resource["value"]))
            # Reparse using the SAME origin checks; session/header/body bytes never change.
            first, tail = raw.split("\n", 1)
            method, _, protocol = first.strip().split()
            ending = "\r" if first.endswith("\r") else ""
            variant_raw = f"{method} {changed} {protocol}{ending}\n{tail}"
            variant = parse_captured_exchanges(variant_raw.encode(), config["origin"])[0].request
            original = parse_captured_exchanges(data, config["origin"])[0].request
            if variant.headers != original.headers or variant.body != original.body or variant.method != "GET":
                raise ValueError("UNRELATED_FIELD_CHANGE")
            scope.require(variant.prepared_url())
        except ValueError as exc:
            code = (
                str(exc)
                if str(exc) in {"SOURCE_VALUE_MISMATCH", "SENSITIVE_SELECTOR", "UNRELATED_FIELD_CHANGE"}
                else "VARIANT_OR_SCOPE_INCOMPATIBLE"
            )
            plan["incompatible"].append({"resource_ref": reference, "code": code})
            continue
        fingerprint = _digest(variant_raw.encode())
        if fingerprint in seen:
            plan["duplicates_skipped"] += 1
            continue
        seen.add(fingerprint)
        plan["variants"].append(
            {
                "id": fingerprint,
                "resource_ref": reference,
                "method": "GET",
                "fields_changed": 1,
                "diff": {"selector": selector.copy(), "before": source["value"], "after": resource["value"]},
                "state": "requires_human_review",
                "execution_allowed": False,
                "case_eligible": False,
            }
        )
    return plan


def validate_plan(plan: object, capture: Path, declaration: Path, scope_file: Path) -> bool:
    """Recompute against local inputs/scope; reject edits, stale captures and forged approvals."""
    try:
        # Canonical JSON also rejects non-JSON values and NaN.
        return _json_bytes(plan) == _json_bytes(build_plan(capture, declaration, scope_file))
    except (TypeError, ValueError, OSError):
        return False


def save_plan(capture: Path, declaration: Path, scope_file: Path, output: Path) -> dict[str, Any]:
    """Build and publish a versioned mode-0600 diff, exclusively and without secrets."""
    output = local_path(output)
    if output in {local_path(p) for p in (capture, declaration, scope_file)}:
        raise ValueError("Plan output must not replace any input.")
    plan = build_plan(capture, declaration, scope_file)
    atomic_private_write(output, _json_bytes(plan))
    return summary(plan)


def summary(plan: dict[str, Any]) -> dict[str, object]:
    """Count-only shareable summary; no identifiers, URLs, paths or captured data."""
    duplicates = plan.get("duplicates_skipped")
    if type(duplicates) is not int or not 0 <= duplicates <= MAX_RESOURCES:
        raise ValueError("Invalid duplicate count in offline plan.")
    return {
        "schema_version": PLAN_SCHEMA,
        "variants": len(plan["variants"]),
        "incompatible": len(plan["incompatible"]),
        "duplicates_skipped": duplicates,
        "network_requests_sent": 0,
        "execution_allowed": False,
        "confirmed": False,
    }
