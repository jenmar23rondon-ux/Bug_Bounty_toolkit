from __future__ import annotations

import hashlib
import hmac
import json
import re
import secrets
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from ..core.redaction import redact_data, redact_text, redact_url
from ..core.records import RecordStore
from .access_assessment import assess_access_control_data
from .api_workflow import MAX_WORKFLOW_RECORDS, build_api_workflow
from .hypotheses import _validate_hypothesis
from .skill_router import SKILL_REGISTRY

MAX_GRAPH_INPUT_BYTES = 8 * 1024 * 1024
MAX_GRAPH_NODES = 10_000
MAX_GRAPH_EDGES = 30_000
MAX_SEARCH_RESULTS = 100
_GRAPH_STATES = {"observed", "inferred", "attested", "documented_only", "hypothesis"}
_RELATIONS = {
    "AUTHENTICATED_AS",
    "REQUESTS",
    "RETURNS",
    "OWNS",
    "ACCESSES",
    "SUPPORTS",
    "CONTRADICTS",
    "VALIDATED_BY",
    "RELATED_TO",
}
_UUID_OR_LONG_ID = re.compile(r"(?i)^(?:[0-9a-f]{8}-[0-9a-f-]{27,}|[0-9]{4,})$")
_EMAIL_SEGMENT = re.compile(r"^[^/@\s]+@[^/@\s]+\.[^/@\s]+$")
_JWT_SEGMENT = re.compile(r"^eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}$")
_LONG_OPAQUE_SEGMENT = re.compile(r"^[A-Za-z0-9._~-]{32,}$")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _read_json(path: Path, description: str, limit: int = MAX_GRAPH_INPUT_BYTES) -> object:
    try:
        with path.open("rb") as source:
            raw = source.read(limit + 1)
    except OSError as exc:
        raise ValueError(f"Cannot read {description}: {path.name}.") from exc
    if len(raw) > limit:
        raise ValueError(f"{description.capitalize()} exceeds the {limit}-byte limit.")
    try:
        return json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise ValueError(f"{description.capitalize()} must be valid UTF-8 JSON.") from exc


def _json(value: object) -> str:
    safe = redact_data(value)
    return json.dumps(safe, sort_keys=True, ensure_ascii=True, separators=(",", ":"))


def _safe_endpoint(value: object) -> str | None:
    if not isinstance(value, str) or not value.startswith("/") or len(value) > 4096:
        return None
    path = value.split("?", 1)[0].split("#", 1)[0]
    parts = [
        "{id}"
        if (
            _UUID_OR_LONG_ID.fullmatch(part)
            or _EMAIL_SEGMENT.fullmatch(part)
            or _JWT_SEGMENT.fullmatch(part)
            or _LONG_OPAQUE_SEGMENT.fullmatch(part)
        )
        else part
        for part in path.split("/")
    ]
    return "/".join(parts)[:4096]


def _safe_host(value: object) -> str | None:
    if not isinstance(value, str) or not value or len(value) > 512:
        return None
    try:
        hostname = urlsplit(f"//{value}").hostname
    except ValueError:
        return None
    if not hostname or any(character.isspace() for character in hostname):
        return None
    return hostname.casefold().rstrip(".")[:255]


def _safe_text(value: object, limit: int = 500) -> str | None:
    if not isinstance(value, str):
        return None
    cleaned = "".join(char for char in value if char >= " " and char != "\x7f").strip()
    if not cleaned:
        return None
    return (redact_text(cleaned) or "")[:limit] or None


def _stable_id(kind: str, value: str) -> str:
    digest = hashlib.sha256(f"{kind}\x1f{value}".encode("utf-8", errors="replace")).hexdigest()[:32]
    return f"{kind.lower()}-{digest}"


def _mapping(value: object) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _list_of_mappings(value: object) -> list[dict[str, Any]]:
    return [item for item in value if isinstance(item, dict)] if isinstance(value, list) else []


def _command_matches_registry(command: str, templates: tuple[str, ...]) -> bool:
    """Accept an exact registered command template with one safe program-name substitution."""
    for template in templates:
        if "{program}" not in template:
            if command == template:
                return True
            continue
        if template.count("{program}") != 1:
            continue
        prefix, suffix = template.split("{program}")
        if not command.startswith(prefix) or not command.endswith(suffix):
            continue
        program = command[len(prefix) : len(command) - len(suffix) if suffix else None]
        if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,79}", program):
            return True
    return False


class EvidenceGraphStore:
    """Persist a minimized evidence graph in the program's existing SQLite database."""

    def __init__(self, records: RecordStore):
        self.records = records
        self.connection = records.connection
        self._migrate()

    def _migrate(self) -> None:
        self.connection.executescript(
            """
            create table if not exists graph_meta (
              key text primary key,
              value text not null
            );
            create table if not exists graph_nodes (
              node_id text primary key,
              node_type text not null,
              epistemic_state text not null,
              host text,
              endpoint text,
              account_key text,
              resource_key text,
              category text,
              finding_id text,
              attributes_json text not null,
              provenance_json text not null,
              observed_at text not null
            );
            create index if not exists graph_nodes_endpoint_idx on graph_nodes(endpoint);
            create index if not exists graph_nodes_account_idx on graph_nodes(account_key);
            create index if not exists graph_nodes_resource_idx on graph_nodes(resource_key);
            create index if not exists graph_nodes_category_idx on graph_nodes(category);
            create index if not exists graph_nodes_finding_idx on graph_nodes(finding_id);
            create table if not exists graph_edges (
              edge_id text primary key,
              relation text not null,
              source_id text not null references graph_nodes(node_id) on delete cascade,
              target_id text not null references graph_nodes(node_id) on delete cascade,
              epistemic_state text not null,
              evidence_refs_json text not null,
              provenance_json text not null,
              basis text not null,
              limitations text not null,
              observed_at text not null,
              unique(relation, source_id, target_id)
            );
            create index if not exists graph_edges_source_idx on graph_edges(source_id);
            create index if not exists graph_edges_target_idx on graph_edges(target_id);
            create table if not exists graph_ingestions (
              id integer primary key autoincrement,
              bundle_id text not null,
              source_name text not null,
              imported_at text not null,
              node_count integer not null,
              edge_count integer not null
            );
            """
        )
        self.connection.execute("pragma foreign_keys = on")
        self.connection.execute(
            "insert or ignore into graph_meta(key, value) values('pseudonym_salt', ?)",
            (secrets.token_hex(32),),
        )
        self.connection.commit()

    def _pseudonym(self, namespace: str, value: object) -> str:
        if not isinstance(value, (str, int, float)):
            raise ValueError(f"{namespace.capitalize()} selector must be a string or number.")
        salt_row = self.connection.execute("select value from graph_meta where key='pseudonym_salt'").fetchone()
        if salt_row is None:
            raise RuntimeError("Evidence graph pseudonym salt is missing.")
        digest = hmac.new(str(salt_row[0]).encode(), str(value).encode("utf-8", errors="replace"), hashlib.sha256)
        return f"{namespace}-{digest.hexdigest()[:32]}"

    def _upsert_node(self, row: dict[str, object]) -> None:
        node_id = row["node_id"]
        node_type = row["node_type"]
        state = row["epistemic_state"]
        if not isinstance(node_id, str) or not isinstance(node_type, str) or state not in _GRAPH_STATES:
            raise ValueError("Graph node has an invalid ID, type or epistemic state.")
        self.connection.execute(
            """
            insert into graph_nodes(
              node_id,node_type,epistemic_state,host,endpoint,account_key,resource_key,category,finding_id,
              attributes_json,provenance_json,observed_at
            ) values(?,?,?,?,?,?,?,?,?,?,?,?)
            on conflict(node_id) do update set
              node_type=excluded.node_type, epistemic_state=excluded.epistemic_state, host=excluded.host,
              endpoint=excluded.endpoint, account_key=excluded.account_key, resource_key=excluded.resource_key,
              category=excluded.category, finding_id=excluded.finding_id, attributes_json=excluded.attributes_json,
              provenance_json=excluded.provenance_json
            """,
            (
                node_id,
                node_type,
                state,
                row.get("host"),
                row.get("endpoint"),
                row.get("account_key"),
                row.get("resource_key"),
                row.get("category"),
                row.get("finding_id"),
                _json(row.get("attributes", {})),
                _json(row.get("provenance", [])),
                str(row.get("observed_at") or _now()),
            ),
        )

    def _upsert_edge(self, row: dict[str, object]) -> None:
        relation = row.get("relation")
        source = row.get("source_id")
        target = row.get("target_id")
        state = row.get("epistemic_state")
        if relation not in _RELATIONS or not isinstance(source, str) or not isinstance(target, str):
            raise ValueError("Graph relation has an invalid type or endpoint.")
        if state not in _GRAPH_STATES:
            raise ValueError("Graph relation has an invalid epistemic state.")
        edge_id = _stable_id("edge", f"{relation}\x1f{source}\x1f{target}")
        refs_value = row.get("evidence_refs")
        refs: list[object] = list(refs_value) if isinstance(refs_value, list) else []
        provenance_value = row.get("provenance")
        provenance: list[object] = list(provenance_value) if isinstance(provenance_value, list) else []
        if not refs:
            refs = [
                f"source:{Path(str(item.get('source', 'unknown'))).name}:{str(item.get('locator', 'unknown'))[:120]}"
                for item in provenance
                if isinstance(item, dict)
            ]
        basis = _safe_text(row.get("basis"), 1000) or "Evidence relationship imported from a local source."
        limitations = (
            _safe_text(row.get("limitations"), 1000) or "Relationship does not independently confirm a vulnerability."
        )
        existing = self.connection.execute(
            "select evidence_refs_json, provenance_json from graph_edges where relation=? and source_id=? and target_id=?",
            (relation, source, target),
        ).fetchone()
        if existing is not None:
            old_refs_value = json.loads(existing[0])
            old_provenance_value = json.loads(existing[1])
            old_refs: list[object] = old_refs_value if isinstance(old_refs_value, list) else []
            old_provenance: list[object] = old_provenance_value if isinstance(old_provenance_value, list) else []
            merged_refs = sorted({str(item) for item in [*old_refs, *refs] if isinstance(item, (str, int))})
            refs.clear()
            refs.extend(merged_refs)
            provenance_rows = [item for item in [*old_provenance, *provenance] if isinstance(item, dict)]
            provenance_map = {json.dumps(item, sort_keys=True): item for item in provenance_rows}
            provenance.clear()
            provenance.extend(list(provenance_map.values())[:50])
        self.connection.execute(
            """
            insert into graph_edges(
              edge_id,relation,source_id,target_id,epistemic_state,evidence_refs_json,provenance_json,basis,
              limitations,observed_at
            ) values(?,?,?,?,?,?,?,?,?,?)
            on conflict(relation,source_id,target_id) do update set
              epistemic_state=excluded.epistemic_state,evidence_refs_json=excluded.evidence_refs_json,
              provenance_json=excluded.provenance_json,basis=excluded.basis,limitations=excluded.limitations
            """,
            (
                edge_id,
                relation,
                source,
                target,
                state,
                _json(refs),
                _json([item for item in provenance[:50] if isinstance(item, dict)]),
                basis,
                limitations,
                _now(),
            ),
        )

    def _workflow_rows(self, model: dict[str, object]) -> tuple[list[dict[str, object]], list[dict[str, object]]]:
        source_nodes = _list_of_mappings(model.get("nodes"))
        source_edges = _list_of_mappings(model.get("relations"))
        if len(source_nodes) > MAX_GRAPH_NODES or len(source_edges) > MAX_GRAPH_EDGES:
            raise ValueError("API workflow graph exceeds the persistent graph size limit.")
        nodes: list[dict[str, object]] = []
        for node in source_nodes:
            node_id = node.get("id")
            node_type = node.get("type")
            if not isinstance(node_id, str) or not isinstance(node_type, str):
                continue
            state = "observed"
            if node_type == "Hypothesis":
                state = "hypothesis"
            elif node.get("source") == "openapi_documentation_only":
                state = "documented_only"
            host_value = node.get("host")
            host = _safe_host(host_value)
            endpoint = _safe_endpoint(node.get("path_template")) if node_type == "Endpoint" else None
            attributes: dict[str, object] = {"id": node_id, "type": node_type}
            allowed_by_type: dict[str, tuple[str, ...]] = {
                "Investigation": ("bundle_id", "source"),
                "Endpoint": (
                    "observed",
                    "observed_methods",
                    "authentication_state",
                    "resource_visibility",
                    "method",
                    "operation_id",
                ),
                "HTTPRequest": ("evidence_id", "method", "status_code", "parameters", "captured_at", "source_tools"),
                "HTTPResponse": (
                    "evidence_id",
                    "status_code",
                    "response_fingerprint",
                    "shape_fingerprint",
                    "validation_status",
                ),
                "Session": ("fingerprint", "identity"),
                "Resource": ("fingerprint", "ownership", "privacy"),
                "Hypothesis": ("kind", "status", "confidence", "reason"),
            }
            for key in allowed_by_type.get(node_type, ()):
                value = node.get(key)
                if isinstance(value, str):
                    attributes[key] = _safe_text(value, 1000) or ""
                elif isinstance(value, (bool, int, float)) or value is None:
                    attributes[key] = value
                elif isinstance(value, list):
                    attributes[key] = [str(item)[:300] for item in value[:100] if isinstance(item, (str, int, float))]
            provenance = node.get("provenance", [])
            if not isinstance(provenance, list):
                provenance = []
            safe_provenance = [
                {
                    "source": Path(str(item.get("source", "unknown"))).name[:255],
                    "locator": _safe_text(item.get("locator"), 300) or "unknown",
                }
                for item in provenance[:20]
                if isinstance(item, dict)
            ]
            category = attributes.get("kind") if node_type == "Hypothesis" else None
            nodes.append(
                {
                    "node_id": node_id,
                    "node_type": node_type,
                    "epistemic_state": state,
                    "host": host,
                    "endpoint": endpoint,
                    "category": category,
                    "attributes": attributes,
                    "provenance": safe_provenance,
                }
            )
        ids = {str(row["node_id"]) for row in nodes}
        edges: list[dict[str, object]] = []
        for edge in source_edges:
            relation, source, target = edge.get("relation"), edge.get("source"), edge.get("target")
            if relation not in _RELATIONS or not isinstance(source, str) or not isinstance(target, str):
                continue
            if source not in ids or target not in ids:
                continue
            edge_state = edge.get("state")
            if not isinstance(edge_state, str) or edge_state not in _GRAPH_STATES:
                edge_state = "inferred"
            edges.append(
                {
                    "relation": relation,
                    "source_id": source,
                    "target_id": target,
                    "epistemic_state": edge_state,
                    "evidence_refs": edge.get("evidence_refs", []),
                    "provenance": edge.get("provenance", []),
                    "basis": edge.get("basis"),
                    "limitations": edge.get("limitations"),
                }
            )
        return nodes, edges

    def _add_hypotheses(
        self,
        path: Path | None,
        evidence_nodes: dict[str, str],
        nodes: list[dict[str, object]],
        edges: list[dict[str, object]],
    ) -> dict[str, int]:
        if path is None:
            return {"hypotheses": 0, "invalid_references": 0}
        data = _read_json(path, "hypotheses file", 2_000_000)
        if (
            not isinstance(data, dict)
            or data.get("type") != "ai-hypotheses"
            or not isinstance(data.get("groups"), list)
        ):
            raise ValueError("Hypotheses input must be an ai-hypotheses JSON result.")
        count = invalid_count = 0
        for group in data["groups"][:MAX_WORKFLOW_RECORDS]:
            if not isinstance(group, dict) or group.get("status") not in {"reviewed", "complete"}:
                continue
            hypothesis = group.get("hypothesis")
            if hypothesis is None and isinstance(group.get("hypothesis"), dict):
                hypothesis = group["hypothesis"]
            # Current output nests the validated object at group.hypothesis when reviewed.
            if hypothesis is None:
                hypothesis = _mapping(group.get("minimized_packet")).get("hypothesis")
            try:
                item = _validate_hypothesis(hypothesis)
            except (ValueError, TypeError):
                continue
            group_id = _safe_text(group.get("group_id"), 100) or str(count)
            hypothesis_id = _stable_id("hypothesis", group_id)
            all_refs = [
                str(entry["record_id"])
                for key in ("evidence_for", "evidence_against")
                for entry in item[key]
                if isinstance(entry, dict) and isinstance(entry.get("record_id"), str)
            ]
            invalid = sorted(set(all_refs) - set(evidence_nodes))
            invalid_count += len(invalid)
            attrs = {
                "category": item["category"],
                "summary": _safe_text(item["summary"], 300) or "",
                "confidence": item["confidence"],
                "status": "hypothesis",
                "invalid_reference_count": len(invalid),
                "invalid_record_ref_hashes": [_stable_id("invalid-ref", value) for value in invalid[:50]],
                "notice": "Second opinion only; never confirmation.",
            }
            nodes.append(
                {
                    "node_id": hypothesis_id,
                    "node_type": "Hypothesis",
                    "epistemic_state": "hypothesis",
                    "category": item["category"],
                    "attributes": attrs,
                    "provenance": [{"source": path.name, "locator": f"groups/{group_id}"}],
                }
            )
            for direction, relation in (("evidence_for", "SUPPORTS"), ("evidence_against", "CONTRADICTS")):
                for entry in item[direction]:
                    evidence_id = entry["record_id"]
                    if evidence_id not in evidence_nodes:
                        continue
                    request_id = evidence_nodes[evidence_id]
                    edges.append(
                        {
                            "relation": relation,
                            "source_id": request_id,
                            "target_id": hypothesis_id,
                            "epistemic_state": "hypothesis",
                            "evidence_refs": [evidence_id],
                            "provenance": [{"source": path.name, "locator": f"groups/{group_id}"}],
                            "basis": _safe_text(entry.get("why"), 400) or "Model-linked evidence reference.",
                            "limitations": "Ollama output is an untrusted second opinion and never a factual validation.",
                        }
                    )
            count += 1
        return {"hypotheses": count, "invalid_references": invalid_count}

    def _add_route(self, path: Path | None, nodes: list[dict[str, object]], edges: list[dict[str, object]]) -> int:
        if path is None:
            return 0
        data = _read_json(path, "skill route", 2_000_000)
        if (
            not isinstance(data, dict)
            or not isinstance(data.get("selected"), list)
            or not isinstance(data.get("plan"), list)
        ):
            raise ValueError("Skill route input must contain selected and plan lists.")
        registry = SKILL_REGISTRY
        plans = _list_of_mappings(data.get("plan"))
        selected = _list_of_mappings(data.get("selected"))
        valid: dict[str, dict[str, object]] = {}
        for row in selected:
            name = row.get("skill")
            if not isinstance(name, str) or name not in registry:
                raise ValueError("Skill route contains an unknown skill; graph import stopped.")
            if name in valid:
                raise ValueError("Skill route contains a duplicate selected skill.")
            valid[name] = row
        for plan in plans:
            plan_skill = plan.get("skill")
            command = plan.get("command")
            if not isinstance(plan_skill, str) or plan_skill not in registry or plan_skill not in valid:
                raise ValueError("Skill route plan references an unknown or unselected skill.")
            if not isinstance(command, str) or not _command_matches_registry(command, registry[plan_skill].commands):
                raise ValueError(f"Skill route command is not registered for {plan_skill}.")
        count = 0
        for name, row in valid.items():
            definition = registry[name]
            skill_id = _stable_id("skill", name)
            nodes.append(
                {
                    "node_id": skill_id,
                    "node_type": "Skill",
                    "epistemic_state": "observed",
                    "category": ",".join(definition.categories),
                    "attributes": {
                        "name": name,
                        "when": definition.when,
                        "requires": list(definition.requires),
                        "produces": list(definition.produces),
                    },
                    "provenance": [{"source": "installed-skill-registry", "locator": name}],
                }
            )
            reason = _safe_text(row.get("reason"), 500) or "Selected by validated skill router output."
            for hypothesis in [node for node in nodes if node.get("node_type") == "Hypothesis"]:
                attrs = _mapping(hypothesis.get("attributes"))
                if attrs.get("category") not in definition.categories:
                    continue
                edges.append(
                    {
                        "relation": "RELATED_TO",
                        "source_id": str(hypothesis["node_id"]),
                        "target_id": skill_id,
                        "epistemic_state": "inferred",
                        "evidence_refs": [],
                        "provenance": [{"source": path.name, "locator": "selected"}],
                        "basis": reason,
                        "limitations": "Routing is advisory; no command was executed and skill selection is not validation.",
                    }
                )
            count += 1
        if len(valid) > len(registry):
            raise ValueError("Skill route exceeds the registered skill limit.")
        return count

    def _add_access_assessment(
        self,
        case_path: Path | None,
        evidence_path: Path | None,
        nodes: list[dict[str, object]],
        edges: list[dict[str, object]],
    ) -> dict[str, object] | None:
        if case_path is None and evidence_path is None:
            return None
        if case_path is None or evidence_path is None:
            raise ValueError("--case-file and --access-evidence must be supplied together.")
        case = _read_json(case_path, "access case", 2_000_000)
        evidence = _read_json(evidence_path, "access evidence", 2_000_000)
        assessment = assess_access_control_data(case, evidence)
        if not isinstance(case, dict):
            return assessment
        classification = assessment.get("classification", "insufficient_evidence")
        evidence_digest = hashlib.sha256(evidence_path.read_bytes()).hexdigest()
        evidence_ref = f"access-{evidence_digest[:24]}"
        validation_id = _stable_id("validation", evidence_digest)
        nodes.append(
            {
                "node_id": validation_id,
                "node_type": "Validation",
                "epistemic_state": "observed",
                "category": str(assessment.get("category", "access_control")),
                "attributes": {
                    "classification": classification,
                    "confirmed": False,
                    "status_code_used": False,
                    "model_opinion_used": False,
                    "reason": _safe_text(assessment.get("reason"), 800) or "Assessment produced no explanation.",
                },
                "provenance": [{"source": evidence_path.name, "locator": "access-control-assessment"}],
            }
        )
        checks = _mapping(case.get("checks"))
        endpoint = _safe_endpoint(_mapping(case.get("resource")).get("path"))
        endpoint_id: str | None = None
        if endpoint is None and isinstance(case.get("base_url"), str):
            try:
                from urllib.parse import urlsplit

                endpoint = _safe_endpoint(urlsplit(case["base_url"]).path or "/")
            except ValueError:
                endpoint = None
        if endpoint:
            endpoint_id = _stable_id("endpoint", f"{case.get('base_url', '')}\x1f{endpoint}")
            nodes.append(
                {
                    "node_id": endpoint_id,
                    "node_type": "Endpoint",
                    "epistemic_state": "attested",
                    "endpoint": endpoint,
                    "host": None,
                    "attributes": {"source": "access-case-attestation", "observed": False},
                    "provenance": [{"source": case_path.name, "locator": "base_url"}],
                }
            )
        steps = _list_of_mappings(_mapping(evidence).get("steps"))
        validation_responses: list[str] = []
        step_request_ids: dict[str, str] = {}
        for index, step in enumerate(steps):
            step_name = _safe_text(step.get("step"), 80) or f"step-{index}"
            request_id = _stable_id("access-request", f"{evidence_digest}:{step_name}")
            response_id = _stable_id("access-response", f"{evidence_digest}:{step_name}")
            step_request_ids[step_name] = request_id
            validation_responses.append(response_id)
            nodes.extend(
                [
                    {
                        "node_id": request_id,
                        "node_type": "HTTPRequest",
                        "epistemic_state": "observed",
                        "endpoint": endpoint,
                        "attributes": {"step": step_name, "method": "GET", "source": "native-access-check"},
                        "provenance": [{"source": evidence_path.name, "locator": f"steps/{step_name}"}],
                    },
                    {
                        "node_id": response_id,
                        "node_type": "HTTPResponse",
                        "epistemic_state": "observed",
                        "attributes": {
                            key: step[key]
                            for key in (
                                "application_success",
                                "resource_match",
                                "private_match",
                                "owner_resource_match",
                                "owner_private_match",
                                "actor_resource_match",
                                "actor_private_match",
                                "status_code",
                                "response_fingerprint",
                                "response_shape_fingerprint",
                            )
                            if key in step and (type(step[key]) in {bool, int} or isinstance(step[key], str))
                        },
                        "provenance": [{"source": evidence_path.name, "locator": f"steps/{step_name}"}],
                    },
                ]
            )
            edges.append(
                {
                    "relation": "RETURNS",
                    "source_id": request_id,
                    "target_id": response_id,
                    "epistemic_state": "observed",
                    "evidence_refs": [evidence_ref],
                    "provenance": [{"source": evidence_path.name, "locator": f"steps/{step_name}"}],
                    "basis": "Native access-check evidence records these minimized response predicates.",
                    "limitations": "Raw response bodies, cookies and private markers are not stored in the graph.",
                }
            )
            if endpoint_id:
                edges.append(
                    {
                        "relation": "REQUESTS",
                        "source_id": request_id,
                        "target_id": endpoint_id,
                        "epistemic_state": "attested",
                        "evidence_refs": [evidence_ref],
                        "provenance": [{"source": evidence_path.name, "locator": f"steps/{step_name}"}],
                        "basis": "The supplied case associates this native test with the declared endpoint.",
                        "limitations": "The case association is researcher supplied; only the recorded predicates are observed.",
                    }
                )
        account_resources: list[tuple[str, object, str]] = []
        account_ids: dict[str, str] = {}
        if isinstance(case.get("type"), str) and case.get("type") == "function-access-case":
            accounts = _mapping(case.get("accounts"))
            roles: dict[str, str] = {}
            for label, role in accounts.items():
                if not isinstance(label, str) or not isinstance(role, str):
                    continue
                account_key = self._pseudonym("account", label)
                account_id = _stable_id("account", account_key)
                account_ids[label] = account_id
                nodes.append(
                    {
                        "node_id": account_id,
                        "node_type": "Account",
                        "epistemic_state": "attested",
                        "account_key": account_key,
                        "attributes": {
                            "label": account_key[-12:],
                            "authorized": case.get("accounts_authorized") is True,
                        },
                        "provenance": [{"source": case_path.name, "locator": "accounts"}],
                    }
                )
                role_name = _safe_text(role, 100) or "unknown"
                role_id = _stable_id("role", role_name)
                nodes.append(
                    {
                        "node_id": role_id,
                        "node_type": "Role",
                        "epistemic_state": "attested",
                        "attributes": {"name": role_name},
                        "provenance": [{"source": case_path.name, "locator": "accounts"}],
                    }
                )
                edges.append(
                    {
                        "relation": "RELATED_TO",
                        "source_id": account_id,
                        "target_id": role_id,
                        "epistemic_state": "attested",
                        "evidence_refs": [],
                        "provenance": [{"source": case_path.name, "locator": "accounts"}],
                        "basis": "Role assignment was declared by the investigator in the function-access case.",
                        "limitations": "The role assignment is an attestation and has not been independently verified.",
                    }
                )
                roles[label] = role_id
        elif isinstance(checks.get("owner_resource"), (str, int)) and isinstance(
            checks.get("actor_resource"), (str, int)
        ):
            account_resources = [
                ("owner", checks["owner_resource"], "owner_resource"),
                ("actor", checks["actor_resource"], "actor_resource"),
            ]
            for label, resource_value, locator in account_resources:
                account_key = self._pseudonym("account", label)
                account_id = _stable_id("account", account_key)
                account_ids[label] = account_id
                resource_key = self._pseudonym("resource", resource_value)
                resource_id = _stable_id("resource", resource_key)
                nodes.append(
                    {
                        "node_id": account_id,
                        "node_type": "Account",
                        "epistemic_state": "attested",
                        "account_key": account_key,
                        "attributes": {"label": label, "authorized": case.get("accounts_authorized") is True},
                        "provenance": [{"source": case_path.name, "locator": "accounts_authorized"}],
                    }
                )
                nodes.append(
                    {
                        "node_id": resource_id,
                        "node_type": "Resource",
                        "epistemic_state": "attested",
                        "resource_key": resource_key,
                        "attributes": {
                            "identifier": resource_key[-12:],
                            "privacy": "private" if case.get("resource_private") is True else "unknown",
                        },
                        "provenance": [{"source": case_path.name, "locator": locator}],
                    }
                )
                edges.append(
                    {
                        "relation": "OWNS",
                        "source_id": account_id,
                        "target_id": resource_id,
                        "epistemic_state": "attested",
                        "evidence_refs": [],
                        "provenance": [{"source": case_path.name, "locator": locator}],
                        "basis": "Resource ownership was explicitly attested in the access case.",
                        "limitations": "Ownership and privacy are investigator declarations, not independent server facts.",
                    }
                )
                if endpoint_id:
                    edges.append(
                        {
                            "relation": "RELATED_TO",
                            "source_id": resource_id,
                            "target_id": endpoint_id,
                            "epistemic_state": "attested",
                            "evidence_refs": [],
                            "provenance": [{"source": case_path.name, "locator": locator}],
                            "basis": "The case associates this resource with the declared endpoint.",
                            "limitations": "The association is based on the researcher-provided case file.",
                        }
                    )
            cross = next((step for step in steps if step.get("step") == "cross_read"), None)
            for step_name, account_label in (
                ("owner_control", "owner"),
                ("actor_control", "actor"),
                ("cross_read", "actor"),
            ):
                linked_request_id = step_request_ids.get(step_name)
                linked_account_id = account_ids.get(account_label)
                if linked_request_id and linked_account_id:
                    edges.append(
                        {
                            "relation": "AUTHENTICATED_AS",
                            "source_id": linked_request_id,
                            "target_id": linked_account_id,
                            "epistemic_state": "attested",
                            "evidence_refs": [evidence_ref],
                            "provenance": [{"source": evidence_path.name, "locator": f"steps/{step_name}"}],
                            "basis": "The access case associates this test step with the named authorized account.",
                            "limitations": "Only the account association is attested; raw session headers are not stored or verified by this graph.",
                        }
                    )
            if cross and cross.get("owner_resource_match") is True:
                owner_resource_key = self._pseudonym("resource", checks["owner_resource"])
                resource_id = _stable_id("resource", owner_resource_key)
                if cross.get("owner_private_match") is True and cross.get("application_success") is True:
                    cross_request_id = step_request_ids.get("cross_read")
                    if cross_request_id:
                        edges.append(
                            {
                                "relation": "ACCESSES",
                                "source_id": cross_request_id,
                                "target_id": resource_id,
                                "epistemic_state": "observed",
                                "evidence_refs": [evidence_ref],
                                "provenance": [{"source": evidence_path.name, "locator": "steps/cross_read"}],
                                "basis": "Native evidence records the configured owner-resource, private-marker and application-success predicates for the crossed read.",
                                "limitations": "This is a possible access-control issue only; it is not confirmation and status is not proof.",
                            }
                        )
        for response_id in validation_responses:
            edges.append(
                {
                    "relation": "VALIDATED_BY",
                    "source_id": validation_id,
                    "target_id": response_id,
                    "epistemic_state": "observed",
                    "evidence_refs": [evidence_ref],
                    "provenance": [{"source": evidence_path.name, "locator": "assessment"}],
                    "basis": "Assessment predicates were evaluated from this native response record.",
                    "limitations": "The assessment never confirms a vulnerability and does not use HTTP status as proof.",
                }
            )
        return assessment

    def _sync_findings(self, nodes: list[dict[str, object]], edges: list[dict[str, object]]) -> int:
        count = 0
        for finding in self.records.findings():
            finding_id = _safe_text(finding.get("id"), 100)
            if not finding_id:
                continue
            target = _safe_text(finding.get("target"), 4096) or ""
            endpoint = _safe_endpoint(target) if target.startswith("/") else None
            if target.startswith(("http://", "https://")):
                target = redact_url(target)[:4096]
                endpoint = _safe_endpoint(urlsplit(target).path)
            category = _safe_text(finding.get("category"), 100) or "unknown"
            nodes.append(
                {
                    "node_id": _stable_id("finding", finding_id),
                    "node_type": "Finding",
                    "epistemic_state": "attested",
                    "endpoint": endpoint,
                    "category": category,
                    "finding_id": finding_id,
                    "attributes": {
                        "title": _safe_text(finding.get("title"), 300) or "Untitled finding",
                        "severity": _safe_text(finding.get("severity"), 40) or "unknown",
                        "status": _safe_text(finding.get("status"), 40) or "unknown",
                        "target": target,
                        "summary": _safe_text(finding.get("summary"), 1000) or "",
                    },
                    "provenance": [{"source": "toolkit-findings", "locator": finding_id}],
                }
            )
            finding_endpoint = endpoint
            finding_host: str | None = None
            if target.startswith(("http://", "https://")):
                parsed_target = urlsplit(target)
                finding_endpoint = _safe_endpoint(parsed_target.path)
                finding_host = _safe_host(parsed_target.hostname)
            if finding_endpoint:
                for endpoint_node in nodes:
                    if (
                        endpoint_node.get("node_type") != "Endpoint"
                        or endpoint_node.get("endpoint") != finding_endpoint
                    ):
                        continue
                    endpoint_host = endpoint_node.get("host")
                    if (
                        finding_host
                        and isinstance(endpoint_host, str)
                        and endpoint_host.casefold() != finding_host.casefold()
                    ):
                        continue
                    edges.append(
                        {
                            "relation": "RELATED_TO",
                            "source_id": _stable_id("finding", finding_id),
                            "target_id": str(endpoint_node["node_id"]),
                            "epistemic_state": "attested",
                            "evidence_refs": [f"finding:{finding_id}"],
                            "provenance": [{"source": "toolkit-findings", "locator": finding_id}],
                            "basis": "The saved toolkit finding identifies a target matching this endpoint path.",
                            "limitations": "This records target association only; the graph does not independently revalidate the finding.",
                        }
                    )
            count += 1
        return count

    def ingest(
        self,
        bundle_path: Path,
        openapi_path: Path | None = None,
        hypotheses_path: Path | None = None,
        route_path: Path | None = None,
        case_path: Path | None = None,
        access_evidence_path: Path | None = None,
    ) -> dict[str, object]:
        """Ingest offline evidence and optional validated opinions/attestations atomically."""
        model = build_api_workflow(bundle_path, openapi_path)
        nodes, edges = self._workflow_rows(model)
        evidence_nodes = {
            str(evidence_id): str(row["node_id"])
            for row in nodes
            if row.get("node_type") == "HTTPRequest"
            if isinstance((evidence_id := _mapping(row.get("attributes")).get("evidence_id")), str)
        }
        hypothesis_stats = self._add_hypotheses(hypotheses_path, evidence_nodes, nodes, edges)
        skills = self._add_route(route_path, nodes, edges)
        access_assessment = self._add_access_assessment(case_path, access_evidence_path, nodes, edges)
        findings = self._sync_findings(nodes, edges)
        if len(nodes) > MAX_GRAPH_NODES or len(edges) > MAX_GRAPH_EDGES:
            raise ValueError("Combined evidence graph exceeds the configured node or relation limit.")
        # Keep only edges whose endpoints exist, then validate references and commit as a unit.
        node_ids = {str(row["node_id"]) for row in nodes}
        edges = [edge for edge in edges if str(edge["source_id"]) in node_ids and str(edge["target_id"]) in node_ids]
        bundle_id = str(model.get("bundle_id", "unknown"))
        try:
            self.connection.execute("begin")
            for row in nodes:
                self._upsert_node(row)
            for edge in edges:
                self._upsert_edge(edge)
            self.connection.execute(
                "insert into graph_ingestions(bundle_id,source_name,imported_at,node_count,edge_count) values(?,?,?,?,?)",
                (bundle_id, bundle_path.name, _now(), len(nodes), len(edges)),
            )
            self.connection.commit()
        except Exception as exc:
            self.connection.rollback()
            if isinstance(exc, sqlite3.Error):
                raise RuntimeError("Evidence graph transaction failed and was rolled back.") from exc
            raise
        return {
            "type": "evidence-graph-ingestion",
            "bundle_id": bundle_id,
            "nodes_written": len(nodes),
            "relations_written": len(edges),
            "hypotheses_written": hypothesis_stats["hypotheses"],
            "invalid_hypothesis_evidence_refs": hypothesis_stats["invalid_references"],
            "skills_linked": skills,
            "findings_synced": findings,
            "access_assessment": access_assessment,
            "network_requests_sent": 0,
            "ollama_calls": 0,
        }

    def search(
        self,
        *,
        endpoint: str | None = None,
        account: str | None = None,
        resource: str | None = None,
        category: str | None = None,
        finding_id: str | None = None,
        limit: int = 50,
    ) -> dict[str, object]:
        """Search graph nodes by exact endpoint, pseudonymous account/resource, category or finding ID."""
        if not any((endpoint, account, resource, category, finding_id)):
            raise ValueError("Provide at least one graph search filter.")
        if not 1 <= limit <= MAX_SEARCH_RESULTS:
            raise ValueError(f"Search limit must be from 1 to {MAX_SEARCH_RESULTS}.")
        clauses: list[str] = []
        params: list[object] = []
        if endpoint:
            safe_endpoint = _safe_endpoint(endpoint)
            if safe_endpoint is None:
                raise ValueError("Endpoint filter must be an absolute API path.")
            clauses.append("endpoint = ?")
            params.append(safe_endpoint)
        if account:
            clauses.append("account_key = ?")
            params.append(self._pseudonym("account", account))
        if resource:
            clauses.append("resource_key in (?, ?)")
            params.extend(
                (self._pseudonym("resource", resource), resource if resource.startswith("hmac-sha256:") else "")
            )
        if category:
            clauses.append("lower(category) = lower(?)")
            params.append(category[:100])
        if finding_id:
            clauses.append("finding_id = ?")
            params.append(finding_id[:100])
        rows = self.connection.execute(
            "select * from graph_nodes where " + " and ".join(clauses) + " order by observed_at desc limit ?",
            (*params, limit),
        ).fetchall()
        matches = [self._render_node(row) for row in rows]
        matched_ids = [str(item["node_id"]) for item in matches]
        neighbors: dict[str, dict[str, object]] = {}
        relations: list[dict[str, object]] = []
        for node_id in matched_ids:
            edge_rows = self.connection.execute(
                """
                select * from graph_edges where source_id=? or target_id=?
                order by relation, edge_id limit 300
                """,
                (node_id, node_id),
            ).fetchall()
            for edge in edge_rows:
                relations.append(
                    {
                        "relation": edge["relation"],
                        "source_id": edge["source_id"],
                        "target_id": edge["target_id"],
                        "epistemic_state": edge["epistemic_state"],
                        "evidence_refs": json.loads(edge["evidence_refs_json"]),
                        "provenance": json.loads(edge["provenance_json"]),
                        "basis": edge["basis"],
                        "limitations": edge["limitations"],
                    }
                )
                for neighbor_id in (str(edge["source_id"]), str(edge["target_id"])):
                    if neighbor_id not in matched_ids:
                        neighbor = self.connection.execute(
                            "select * from graph_nodes where node_id=?", (neighbor_id,)
                        ).fetchone()
                        if neighbor is not None:
                            neighbors[neighbor_id] = self._render_node(neighbor)
        deduplicated_relations = {json.dumps(item, sort_keys=True): item for item in relations}
        return {
            "type": "evidence-graph-search",
            "matches": matches,
            "neighbors": list(neighbors.values()),
            "relations": list(deduplicated_relations.values()),
            "truncated": len(rows) == limit,
            "raw_secrets_included": False,
        }

    @staticmethod
    def _render_node(row: sqlite3.Row) -> dict[str, object]:
        return {
            "node_id": row["node_id"],
            "node_type": row["node_type"],
            "epistemic_state": row["epistemic_state"],
            "host": row["host"],
            "endpoint": row["endpoint"],
            "account_key": row["account_key"],
            "resource_key": row["resource_key"],
            "category": row["category"],
            "finding_id": row["finding_id"],
            "attributes": json.loads(row["attributes_json"]),
            "provenance": json.loads(row["provenance_json"]),
            "observed_at": row["observed_at"],
        }


def preview_graph_ingest(
    bundle_path: Path,
    openapi_path: Path | None = None,
    hypotheses_path: Path | None = None,
    route_path: Path | None = None,
    case_path: Path | None = None,
    access_evidence_path: Path | None = None,
) -> dict[str, object]:
    """Validate and count an ingest without opening or creating the program database."""
    # A temporary in-memory graph store reuses exactly the same sanitizers and validation.
    connection = sqlite3.connect(":memory:")
    try:
        records = type("Records", (), {"connection": connection, "findings": lambda self: []})()
        store = object.__new__(EvidenceGraphStore)
        store.records = records
        store.connection = connection
        store._migrate()
        # Preview intentionally builds the rows using the same pure workflow parsing and validators.
        model = build_api_workflow(bundle_path, openapi_path)
        nodes, edges = store._workflow_rows(model)
        evidence_nodes = {
            str(evidence_id): str(row["node_id"])
            for row in nodes
            if row.get("node_type") == "HTTPRequest"
            if isinstance((evidence_id := _mapping(row.get("attributes")).get("evidence_id")), str)
        }
        stats = store._add_hypotheses(hypotheses_path, evidence_nodes, nodes, edges)
        skills = store._add_route(route_path, nodes, edges)
        assessment = store._add_access_assessment(case_path, access_evidence_path, nodes, edges)
        return {
            "bundle_id": model.get("bundle_id", "unknown"),
            "nodes": len(nodes),
            "relations": len(edges),
            "hypotheses": stats["hypotheses"],
            "invalid_hypothesis_evidence_refs": stats["invalid_references"],
            "skills_linked": skills,
            "access_assessment": assessment,
        }
    finally:
        connection.close()
