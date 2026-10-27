"""Versioned synthetic resources. No captured credentials or secret canaries."""

from __future__ import annotations

import copy
from typing import Any

from bugbounty_toolkit.analysis.request_variation_plan import DECLARATION_SCHEMA

CORPUS_VERSION = "request-variation-eval/1"


def declaration() -> dict[str, Any]:
    return {
        "schema_version": DECLARATION_SCHEMA,
        "lab_authorized": True,
        "origin": "https://lab.test",
        "accounts": [{"name": "alice", "authorized": True}, {"name": "bob", "authorized": True}],
        "resources": [
            {"name": "own", "account": "alice", "value": 101, "synthetic": True},
            {"name": "other", "account": "bob", "value": 202, "synthetic": True},
        ],
        "source": "own",
        "targets": ["other"],
        "selector": {"path_segment": 1},
    }


def request(target: str = "/objects/101", method: str = "GET", body: str = "", extra: str = "") -> str:
    return (
        f"{method} {target} HTTP/1.1\r\nHost: lab.test\r\nAccept: application/json\r\n"
        f"Cookie: [REDACTED]\r\nX-CSRF-Token: [REDACTED]\r\n{extra}\r\n{body}"
    )


def corpus() -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []

    def add(name: str, raw: str, code: str | None = None, config: dict[str, Any] | None = None) -> None:
        rows.append(
            {"name": name, "raw": raw, "expected_code": code, "declaration": copy.deepcopy(config or declaration())}
        )

    add("numeric_path", request())
    add("sensitive_cookie_preserved", request(extra="Authorization: [REDACTED]\r\n"))
    uuid = declaration()
    uuid["resources"][0]["value"] = "00000000-0000-4000-8000-000000000001"
    uuid["resources"][1]["value"] = "00000000-0000-4000-8000-000000000002"
    add("uuid_path", request("/objects/" + uuid["resources"][0]["value"]), config=uuid)
    query = declaration()
    query["selector"] = {"query_parameter": "id"}
    add("query_parameter", request("/objects?view=a%20b&id=101&empty="), config=query)
    pointer = declaration()
    pointer["selector"] = {"json_body_pointer": "/object/id"}
    add(
        "json_pointer",
        request("/objects", body='{"object":{"id":101}}'),
        "JSON_BODY_POINTER_INCOMPATIBLE_WITH_GET",
        pointer,
    )
    multi = declaration()
    multi["selector"]["query_parameter"] = "id"
    add("two_fields", request("/objects/101?id=101"), "MULTIPLE_FIELDS_REQUESTED", multi)
    add("signed_url", request("/objects/101?X-Amz-Signature=[REDACTED]"), "SIGNED_OR_SENSITIVE_QUERY")
    add("signed_header", request(extra="X-Signature: [REDACTED]\r\n"), "SIGNED_REQUEST")
    add("post", request(method="POST"), "NON_GET")
    add("delete", request(method="DELETE"), "NON_GET")
    add("patch", request(method="PATCH"), "NON_GET")
    add("different_origin", request().replace("Host: lab.test", "Host: other.test"), "CAPTURE_OR_SCOPE_INCOMPATIBLE")
    add("partial_capture", "GET /objects/101 HTTP/1.1\r\nHost: lab.test", "CAPTURE_OR_SCOPE_INCOMPATIBLE")
    incompatible = declaration()
    incompatible["resources"][1]["value"] = "202"
    add("json_type", request(), "JSON_TYPE_INCOMPATIBLE", incompatible)
    unknown = declaration()
    unknown["targets"] = ["undeclared"]
    add("undeclared_resource", request(), "UNDECLARED_RESOURCE", unknown)
    duplicate = declaration()
    duplicate["targets"] = ["other", "other"]
    add("duplicate", request(), config=duplicate)
    add("duplicate_query", request("/objects/101?id=101&id=202"), "DUPLICATE_QUERY")
    add("partial_body", request(extra="Content-Length: 8\r\n"), "PARTIAL_OR_AMBIGUOUS_FRAMING")
    add("get_body", request(body='{"id":101}'), "GET_BODY_UNSUPPORTED")
    add("source_mismatch", request("/objects/999"), "SOURCE_VALUE_MISMATCH")
    add("sensitive_selector", request("/objects?csrf=101"), "SIGNED_OR_SENSITIVE_QUERY", query)
    return rows
