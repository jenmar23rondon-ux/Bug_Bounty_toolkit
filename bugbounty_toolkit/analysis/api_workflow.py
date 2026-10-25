from __future__ import annotations

from bisect import bisect_right
from datetime import datetime
import hashlib
import importlib
import json
from pathlib import Path
import re
from typing import Any
from urllib.parse import urlsplit

from .evidence_engine import MAX_INPUT_BYTES, MAX_RECORDS

MAX_OPENAPI_BYTES = 8 * 1024 * 1024
MAX_WORKFLOW_RECORDS = 2000
_SAFE_ID = re.compile(r"^[A-Za-z0-9_-]{1,128}$")
_FINGERPRINT = re.compile(r"^hmac-sha256:[0-9a-f]{24}$")
_METHOD = re.compile(r"^[A-Z]{1,16}$")
_SENSITIVE_NAME = re.compile(
    r"password|passwd|secret|token|api.?key|authorization|cookie|session|csrf|credential", re.I
)
_AUTH_SEGMENTS = {"auth", "authenticate", "authentication", "login", "logout", "oauth", "session", "signin", "token"}
_USER_SEGMENTS = {"account", "accounts", "me", "profile", "profiles", "user", "users"}
_WRITE_METHODS = {"DELETE", "PATCH", "POST", "PUT"}
_READ_METHODS = {"GET", "HEAD", "OPTIONS"}
_OPENAPI_METHODS = {"delete", "get", "head", "options", "patch", "post", "put", "trace"}


def _read_json(path: Path, limit: int, description: str) -> object:
    try:
        with path.open("rb") as handle:
            raw = handle.read(limit + 1)
    except OSError as exc:
        raise ValueError(f"Cannot read {description}: {path.name}.") from exc
    if len(raw) > limit:
        raise ValueError(f"{description.capitalize()} exceeds the {limit}-byte limit.")
    try:
        return json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise ValueError(f"{description.capitalize()} must be valid UTF-8 JSON.") from exc


def _safe_text(value: object, limit: int = 512) -> str | None:
    if not isinstance(value, str):
        return None
    cleaned = "".join(character for character in value if character >= " " and character != "\x7f")
    cleaned = cleaned.strip()
    return cleaned[:limit] if cleaned else None


def _fingerprint(value: object) -> str | None:
    if isinstance(value, str) and _FINGERPRINT.fullmatch(value):
        return value
    return None


def _record_time(value: object) -> datetime | None:
    if not isinstance(value, str) or len(value) > 80:
        return None
    try:
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return result if result.tzinfo is not None else None


def _provenance(row: dict[str, object]) -> list[dict[str, str]]:
    value = row.get("provenance")
    if not isinstance(value, list):
        return []
    output: list[dict[str, str]] = []
    for item in value[:20]:
        if not isinstance(item, dict):
            continue
        path = _safe_text(item.get("source_path"), 1024)
        locator = _safe_text(item.get("locator"), 300)
        output.append(
            {
                "source": Path(path).name if path else "unknown",
                "locator": locator or "unknown",
            }
        )
    return output


def _normalize_record(value: object) -> dict[str, object] | None:
    if not isinstance(value, dict):
        return None
    evidence_id = _safe_text(value.get("evidence_id"), 128)
    host = _safe_text(value.get("host"), 255)
    endpoint = _safe_text(value.get("endpoint"), 4096)
    method = _safe_text(value.get("method"), 16)
    if (
        evidence_id is None
        or not _SAFE_ID.fullmatch(evidence_id)
        or host is None
        or any(character.isspace() for character in host)
        or endpoint is None
        or not endpoint.startswith("/")
        or "?" in endpoint
        or "#" in endpoint
        or method is None
        or not _METHOD.fullmatch(method)
    ):
        return None
    status = value.get("status_code")
    if type(status) is not int or not 100 <= status <= 599:
        status = None
    parameters_value = value.get("parameters")
    parameters = (
        sorted(
            {
                name
                for item in parameters_value[:100]
                if isinstance(item, str)
                and (name := _safe_text(item, 100)) is not None
                and not _SENSITIVE_NAME.search(name)
            },
            key=str.casefold,
        )
        if isinstance(parameters_value, list)
        else []
    )
    tools_value = value.get("source_tools")
    tools = (
        sorted({tool for item in tools_value[:20] if isinstance(item, str) and (tool := _safe_text(item, 80))})
        if isinstance(tools_value, list)
        else []
    )
    return {
        "evidence_id": evidence_id,
        "host": host.lower().rstrip("."),
        "endpoint": endpoint,
        "method": method.upper(),
        "status_code": status,
        "captured_at": _safe_text(value.get("captured_at"), 80),
        "parameters": parameters,
        "source_tools": tools,
        "session_fingerprint": _fingerprint(value.get("session_fingerprint")),
        "request_session_fingerprint": _fingerprint(value.get("request_session_fingerprint")),
        "response_session_fingerprint": _fingerprint(value.get("response_session_fingerprint")),
        "resource_fingerprint": _fingerprint(value.get("resource_fingerprint")),
        "response_fingerprint": _fingerprint(value.get("response_fingerprint")),
        "response_shape_fingerprint": _fingerprint(value.get("response_shape_fingerprint")),
        "validation_status": _safe_text(value.get("validation_status"), 40) or "unknown",
        "technical_evidence": value.get("technical_evidence")
        if isinstance(value.get("technical_evidence"), dict)
        else {},
        "provenance": _provenance(value),
    }


def _node_id(kind: str, *parts: str) -> str:
    joined = "\x1f".join(parts)
    digest = hashlib.sha256(joined.encode("utf-8", errors="replace")).hexdigest()[:24]
    return f"{kind.lower()}-{digest}"


def _path_segments(endpoint: str) -> set[str]:
    return {part.casefold() for part in endpoint.split("/") if part and not part.startswith("{")}


def _endpoint_hypotheses(endpoint: str, method: str, evidence_id: str) -> list[dict[str, object]]:
    segments = _path_segments(endpoint)
    hypotheses: list[dict[str, object]] = []
    if segments & _AUTH_SEGMENTS:
        hypotheses.append(
            {
                "kind": "authentication_endpoint",
                "status": "hypothesis",
                "confidence": "low",
                "reason": "A path segment matches a common authentication term; behavior was not inferred from the name.",
                "evidence_refs": [evidence_id],
            }
        )
    if segments & _USER_SEGMENTS:
        hypotheses.append(
            {
                "kind": "user_related_endpoint",
                "status": "hypothesis",
                "confidence": "low",
                "reason": "A path segment matches a common account/profile term; the account relationship is unknown.",
                "evidence_refs": [evidence_id],
            }
        )
    if method in _READ_METHODS:
        operation = "read_like"
    elif method in _WRITE_METHODS:
        operation = "write_like"
    else:
        operation = "unknown_operation"
    hypotheses.append(
        {
            "kind": operation,
            "status": "hypothesis",
            "confidence": "low",
            "reason": f"HTTP {method} is a conventional operation hint, not proof of server-side behavior.",
            "evidence_refs": [evidence_id],
        }
    )
    return hypotheses


def _openapi_operations(path: Path | None) -> list[dict[str, object]]:
    if path is None:
        return []
    try:
        with path.open("rb") as handle:
            raw = handle.read(MAX_OPENAPI_BYTES + 1)
    except OSError as exc:
        raise ValueError(f"Cannot read OpenAPI document: {path.name}.") from exc
    if len(raw) > MAX_OPENAPI_BYTES:
        raise ValueError(f"OpenAPI document exceeds the {MAX_OPENAPI_BYTES}-byte limit.")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("OpenAPI document must be UTF-8.") from exc
    if path.suffix.casefold() == ".json":
        try:
            document = json.loads(text)
        except (json.JSONDecodeError, RecursionError) as exc:
            raise ValueError("OpenAPI JSON is malformed.") from exc
    else:
        try:
            yaml_module: Any = importlib.import_module("yaml")
        except ModuleNotFoundError as exc:
            raise ValueError("YAML OpenAPI requires the project's PyYAML dependency.") from exc
        try:
            document = yaml_module.safe_load(text)
        except Exception as exc:  # Safe parser errors depend on the optional parser implementation.
            raise ValueError("OpenAPI YAML is malformed.") from exc
    if not isinstance(document, dict) or not isinstance(document.get("paths"), dict):
        raise ValueError("OpenAPI document must contain a paths object.")
    if not (isinstance(document.get("openapi"), str) or isinstance(document.get("swagger"), str)):
        raise ValueError("Document is not recognizable as OpenAPI/Swagger.")
    hosts: set[str] = set()
    servers = document.get("servers", [])
    if isinstance(servers, list):
        for server in servers[:50]:
            if not isinstance(server, dict) or not isinstance(server.get("url"), str):
                continue
            try:
                hostname = urlsplit(server["url"]).hostname
            except ValueError:
                hostname = None
            if hostname:
                hosts.add(hostname.lower().rstrip("."))
    operations: list[dict[str, object]] = []
    for spec_path, path_item in list(document["paths"].items())[:MAX_RECORDS]:
        path_name = _safe_text(spec_path, 4096)
        if path_name is None or not path_name.startswith("/") or not isinstance(path_item, dict):
            continue
        normalized_path = re.sub(r"\{[^/{}]{1,128}\}", "{id}", path_name)
        for method, operation in path_item.items():
            if method.casefold() not in _OPENAPI_METHODS or not isinstance(operation, dict):
                continue
            operations.append(
                {
                    "path": normalized_path,
                    "documented_path": path_name,
                    "method": method.upper(),
                    "hosts": sorted(hosts),
                    "operation_id": _safe_text(operation.get("operationId"), 160),
                    "provenance": {"source": path.name, "locator": f"/paths/{path_name}/{method}"[:300]},
                }
            )
            if len(operations) >= MAX_RECORDS:
                return operations
    return operations


def build_api_workflow(bundle_path: Path, openapi_path: Path | None = None) -> dict[str, object]:
    """Build an offline, provenance-bearing API workflow graph from normalized evidence."""
    bundle = _read_json(bundle_path, MAX_INPUT_BYTES, "evidence bundle")
    if (
        not isinstance(bundle, dict)
        or bundle.get("type") != "unified-evidence-bundle"
        or not isinstance(bundle.get("records"), list)
    ):
        raise ValueError("Input is not a unified evidence bundle.")
    source_records = bundle["records"]
    if len(source_records) > MAX_WORKFLOW_RECORDS:
        raise ValueError(f"API workflow input exceeds the {MAX_WORKFLOW_RECORDS}-record graph limit.")
    records: list[dict[str, object]] = []
    seen_record_ids: set[str] = set()
    for item in source_records:
        record = _normalize_record(item)
        if record is None or str(record["evidence_id"]) in seen_record_ids:
            continue
        seen_record_ids.add(str(record["evidence_id"]))
        records.append(record)
    bundle_id = _safe_text(bundle.get("bundle_id"), 64) or "unknown"
    safe_bundle_id = bundle_id if _SAFE_ID.fullmatch(bundle_id) else "unknown"

    nodes: dict[str, dict[str, object]] = {}
    relations: dict[tuple[str, str, str], dict[str, object]] = {}
    investigation_id = _node_id("investigation", safe_bundle_id)
    nodes[investigation_id] = {
        "id": investigation_id,
        "type": "Investigation",
        "bundle_id": safe_bundle_id,
        "source": "unified_evidence_bundle",
    }

    def add_relation(
        relation: str,
        source: str,
        target: str,
        evidence_refs: list[str],
        provenance: list[dict[str, str]],
        *,
        state: str = "observed",
        basis: str,
        limitations: str,
    ) -> None:
        key = (relation, source, target)
        existing = relations.get(key)
        refs = sorted(set(evidence_refs))
        if existing is not None:
            current_refs = existing["evidence_refs"]
            if isinstance(current_refs, list):
                existing["evidence_refs"] = sorted(set(current_refs) | set(refs))
            current_provenance = existing["provenance"]
            if isinstance(current_provenance, list):
                merged = [*current_provenance, *provenance]
                existing["provenance"] = list({json.dumps(item, sort_keys=True): item for item in merged}.values())
            return
        relations[key] = {
            "relation": relation,
            "source": source,
            "target": target,
            "state": state,
            "basis": basis,
            "evidence_refs": refs,
            "provenance": provenance,
            "limitations": limitations,
        }

    for record in records:
        evidence_id = str(record["evidence_id"])
        host = str(record["host"])
        endpoint = str(record["endpoint"])
        method = str(record["method"])
        endpoint_id = _node_id("endpoint", host, endpoint)
        request_id = _node_id("request", evidence_id)
        response_id = _node_id("response", evidence_id)
        provenance = record["provenance"]
        assert isinstance(provenance, list)
        endpoint_node = nodes.setdefault(
            endpoint_id,
            {
                "id": endpoint_id,
                "type": "Endpoint",
                "host": host,
                "path_template": endpoint,
                "observed": True,
                "observed_methods": [],
                "hypotheses": [],
                "documentation": [],
                "authentication_state": "unknown",
                "resource_visibility": "unknown",
            },
        )
        methods = endpoint_node["observed_methods"]
        assert isinstance(methods, list)
        if method not in methods:
            methods.append(method)
            methods.sort()
        nodes[request_id] = {
            "id": request_id,
            "type": "HTTPRequest",
            "evidence_id": evidence_id,
            "method": method,
            "status_code": record["status_code"],
            "parameters": record["parameters"],
            "captured_at": record["captured_at"],
            "source_tools": record["source_tools"],
            "provenance": provenance,
        }
        if record["status_code"] is not None or record["response_fingerprint"] is not None:
            nodes[response_id] = {
                "id": response_id,
                "type": "HTTPResponse",
                "evidence_id": evidence_id,
                "status_code": record["status_code"],
                "response_fingerprint": record["response_fingerprint"],
                "shape_fingerprint": record["response_shape_fingerprint"],
                "validation_status": record["validation_status"],
                "provenance": provenance,
            }
            add_relation(
                "RETURNS",
                request_id,
                response_id,
                [evidence_id],
                provenance,
                basis="Response status and fingerprints belong to this imported request record.",
                limitations="Response bodies are not retained; fingerprints do not establish content or impact.",
            )
        add_relation(
            "REQUESTS",
            request_id,
            endpoint_id,
            [evidence_id],
            provenance,
            basis="The imported record contains this exact host, endpoint template and method.",
            limitations="This describes captured traffic only; it does not establish server behavior beyond the capture.",
        )
        add_relation(
            "RELATED_TO",
            investigation_id,
            request_id,
            [evidence_id],
            provenance,
            basis="This request record is part of the selected unified evidence bundle.",
            limitations="Bundle membership does not establish a causal or business workflow relationship.",
        )
        hypotheses = endpoint_node["hypotheses"]
        assert isinstance(hypotheses, list)
        for hypothesis in _endpoint_hypotheses(endpoint, method, evidence_id):
            existing_hypothesis = next(
                (
                    item
                    for item in hypotheses
                    if isinstance(item, dict)
                    and item.get("kind") == hypothesis["kind"]
                    and item.get("reason") == hypothesis["reason"]
                ),
                None,
            )
            if existing_hypothesis is None:
                hypotheses.append(hypothesis)
            else:
                refs = existing_hypothesis.get("evidence_refs")
                if isinstance(refs, list) and evidence_id not in refs:
                    refs.append(evidence_id)
            hypothesis_kind = str(hypothesis["kind"])
            hypothesis_id = _node_id("hypothesis", endpoint_id, method, hypothesis_kind)
            evidence_refs = [evidence_id]
            hypothesis_node = nodes.get(hypothesis_id)
            if hypothesis_node is None:
                nodes[hypothesis_id] = {
                    "id": hypothesis_id,
                    "type": "Hypothesis",
                    "kind": hypothesis_kind,
                    "status": "hypothesis",
                    "confidence": "low",
                    "reason": hypothesis["reason"],
                }
            add_relation(
                "RELATED_TO",
                endpoint_id,
                hypothesis_id,
                evidence_refs,
                provenance,
                state="inferred",
                basis=str(hypothesis["reason"]),
                limitations="Endpoint role and operation hints are hypotheses and need independent evidence.",
            )

        request_session = record["request_session_fingerprint"]
        if isinstance(request_session, str):
            session_id = _node_id("session", request_session)
            nodes.setdefault(
                session_id,
                {"id": session_id, "type": "Session", "fingerprint": request_session, "identity": "opaque"},
            )
            add_relation(
                "AUTHENTICATED_AS",
                request_id,
                session_id,
                [evidence_id],
                provenance,
                basis="A session-bearing request header was observed and represented by a per-import HMAC.",
                limitations="A session fingerprint is not an account identity and does not prove authentication succeeded.",
            )

        resource_fp = record["resource_fingerprint"]
        if isinstance(resource_fp, str):
            resource_id = _node_id("resource", resource_fp)
            nodes.setdefault(
                resource_id,
                {
                    "id": resource_id,
                    "type": "Resource",
                    "fingerprint": resource_fp,
                    "ownership": "unknown",
                    "privacy": "unknown",
                },
            )
            add_relation(
                "ACCESSES",
                request_id,
                resource_id,
                [evidence_id],
                provenance,
                basis="A resource-like path/query value was represented by a per-import HMAC fingerprint.",
                limitations="The fingerprint does not identify an owner or prove the resource is private/public.",
            )
    # A response-issued cookie linked to a later request is an observed transition only
    # when both directional fingerprints and timestamps are present and ordered. Link
    # to the first following use; the shared opaque Session node represents later uses.
    response_records = [record for record in records if record["response_session_fingerprint"]]
    request_records = [record for record in records if record["request_session_fingerprint"]]
    requests_by_cookie: dict[tuple[str, str], list[tuple[float, dict[str, object]]]] = {}
    for record in request_records:
        request_time = _record_time(record["captured_at"])
        fingerprint = record["request_session_fingerprint"]
        if request_time is None or not isinstance(fingerprint, str):
            continue
        key = (str(record["host"]), fingerprint)
        requests_by_cookie.setdefault(key, []).append((request_time.timestamp(), record))
    for matching_requests in requests_by_cookie.values():
        matching_requests.sort(key=lambda entry: entry[0])
    request_times = {key: [entry[0] for entry in entries] for key, entries in requests_by_cookie.items()}
    for previous in response_records:
        previous_time = _record_time(previous["captured_at"])
        response_fingerprint = previous["response_session_fingerprint"]
        if previous_time is None or not isinstance(response_fingerprint, str):
            continue
        lookup_key = (str(previous["host"]), response_fingerprint)
        matched_times = request_times.get(lookup_key, [])
        matched_requests = requests_by_cookie.get(lookup_key, [])
        next_index = bisect_right(matched_times, previous_time.timestamp())
        while next_index < len(matched_requests):
            following = matched_requests[next_index][1]
            if previous["evidence_id"] != following["evidence_id"]:
                break
            next_index += 1
        if next_index >= len(matched_requests):
            continue
        following = matched_requests[next_index][1]
        if previous["evidence_id"] != following["evidence_id"]:
            previous_provenance = previous["provenance"]
            following_provenance = following["provenance"]
            assert isinstance(previous_provenance, list)
            assert isinstance(following_provenance, list)
            source_id = _node_id("response", str(previous["evidence_id"]))
            target_id = _node_id("request", str(following["evidence_id"]))
            add_relation(
                "RELATED_TO",
                source_id,
                target_id,
                [str(previous["evidence_id"]), str(following["evidence_id"])],
                [*previous_provenance, *following_provenance],
                basis="The response-issued cookie fingerprint matches a later request cookie fingerprint; timestamps are ordered.",
                limitations="This observes cookie continuity only; it does not prove login success, account identity or authorization.",
            )

    observed_index: dict[tuple[str, str], list[tuple[str, str, dict[str, object]]]] = {}
    for observed_id, observed_node in nodes.items():
        if observed_node.get("type") != "Endpoint" or not observed_node.get("observed"):
            continue
        observed_host = observed_node.get("host")
        observed_path = observed_node.get("path_template")
        observed_methods = observed_node.get("observed_methods")
        if (
            not isinstance(observed_host, str)
            or not isinstance(observed_path, str)
            or not isinstance(observed_methods, list)
        ):
            continue
        for observed_method in observed_methods:
            if isinstance(observed_method, str):
                observed_index.setdefault((observed_path, observed_method), []).append(
                    (observed_host, observed_id, observed_node)
                )

    openapi_operations = _openapi_operations(openapi_path)
    for operation in openapi_operations:
        path_name = str(operation["path"])
        method = str(operation["method"])
        hosts_value = operation.get("hosts")
        hosts = (
            [doc_host for item in hosts_value if isinstance(item, str) if (doc_host := _safe_text(item, 255))]
            if isinstance(hosts_value, list)
            else []
        )
        operation_provenance = operation.get("provenance")
        documentation_provenance: list[dict[str, str]] = []
        if isinstance(operation_provenance, dict):
            source = _safe_text(operation_provenance.get("source"), 255)
            locator = _safe_text(operation_provenance.get("locator"), 300)
            documentation_provenance.append({"source": source or "openapi", "locator": locator or "unknown"})
        docs_id = _node_id("endpoint", "openapi", *(hosts or ["host-unknown"]), method, path_name)
        nodes[docs_id] = {
            "id": docs_id,
            "type": "Endpoint",
            "host": hosts or None,
            "path_template": path_name,
            "method": method,
            "observed": False,
            "source": "openapi_documentation_only",
            "operation_id": _safe_text(operation.get("operation_id"), 160),
            "provenance": documentation_provenance,
        }
        for observed_host, observed_id, observed_node in observed_index.get((path_name, method), []):
            if hosts and observed_host not in hosts:
                continue
            add_relation(
                "RELATED_TO",
                docs_id,
                observed_id,
                [],
                documentation_provenance,
                state="documented_only",
                basis="Exact documented path/method match"
                + (" and host" if hosts else "; OpenAPI host is unspecified"),
                limitations="OpenAPI describes intended/documented API shape; it is not evidence that the server implements it.",
            )
            documentation = observed_node.get("documentation")
            if isinstance(documentation, list):
                documentation.append({"operation_node": docs_id, "state": "documented_only"})

    node_rows = sorted(nodes.values(), key=lambda node: str(node["id"]))
    relation_rows = sorted(
        relations.values(), key=lambda edge: (str(edge["relation"]), str(edge["source"]), str(edge["target"]))
    )
    endpoint_count = sum(1 for node in node_rows if node["type"] == "Endpoint")
    hypothesis_count = sum(
        len(hypotheses) for node in node_rows if isinstance((hypotheses := node.get("hypotheses")), list)
    )
    summary = {
        "records_received": len(source_records),
        "records_usable": len(records),
        "records_skipped": len(source_records) - len(records),
        "nodes": len(node_rows),
        "relations": len(relation_rows),
        "endpoint_nodes": endpoint_count,
        "hypotheses": hypothesis_count,
        "documented_operations": len(openapi_operations),
        "confirmed_findings": 0,
    }
    return {
        "type": "api-workflow-model",
        "schema_version": "1.0",
        "bundle_id": safe_bundle_id,
        "generated_at": datetime.now().astimezone().isoformat(timespec="seconds"),
        "nodes": node_rows,
        "relations": relation_rows,
        "summary": summary,
        "limitations": [
            "Session fingerprints are per-import opaque values; they are not account identities.",
            "Resource fingerprints do not prove ownership or whether a resource is private or public.",
            "Authentication and user-related endpoint labels are low-confidence hypotheses based on path terms.",
            "HTTP methods are conventional read/write hints; application behavior may differ.",
            "OpenAPI relationships are documentation-only and do not prove live server behavior.",
            "No requests were sent, no vulnerability was confirmed, and no AI model was consulted.",
        ],
        "network_requests_sent": 0,
        "vulnerabilities_confirmed": 0,
    }
