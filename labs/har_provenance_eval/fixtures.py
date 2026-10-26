"""Synthetic, offline HAR fixtures for the evidence-import provenance evaluation.

All hosts are reserved ``.test`` names; all credentials are synthetic canaries.
"""

from __future__ import annotations

import json
from typing import Any

CANARY = "CANARY-SYNTHETIC-7f3a9c"


def entry(
    path: str,
    *,
    host: str = "api.example.test",
    method: str = "GET",
    body: str = "",
    status: int = 200,
    response: str = '{"ok":true}',
    cookie: bool = False,
) -> dict[str, Any]:
    request: dict[str, Any] = {"method": method, "url": f"https://{host}{path}", "headers": []}
    if cookie:
        request["headers"] = [{"name": "Authorization", "value": f"Bearer {CANARY}"}]
        request["cookies"] = [{"name": "sid", "value": CANARY}]
    if body:
        request["postData"] = {"mimeType": "application/json", "text": body}
    return {
        "startedDateTime": "2026-01-01T00:00:00Z",
        "request": request,
        "response": {"status": status, "headers": [], "content": {"mimeType": "application/json", "text": response}},
    }


def har(entries: list[Any]) -> bytes:
    return json.dumps({"log": {"version": "1.2", "entries": entries}}).encode()


def fixtures() -> dict[str, dict[str, Any]]:
    """name -> {"data": bytes, "valid": [indices the resilient validator accepts], "expect": {...}}"""
    valid = [entry(f"/users/{n}/orders", response=f'{{"id":{n}}}') for n in range(1, 4)]
    nested = entry("/accounts/7", method="POST", body='{"a":{"b":{"c":[1,{"d":2}]}}}', response='{"x":{"y":[1,2]}}')
    creds = entry("/me", cookie=True, response=f'{{"token":"{CANARY}","mail":"a@example.test"}}')
    out: dict[str, dict[str, Any]] = {
        "valid": {"data": har(valid), "rejected": {}},
        "nested_json": {"data": har([nested, valid[0]]), "rejected": {}},
        "synthetic_credentials": {"data": har([creds, valid[1]]), "rejected": {}},
        "partial": {
            "data": har([valid[0], "not-an-entry", {"request": valid[1]["request"]}, valid[2]]),
            "rejected": {1: "entry_not_object", 2: "response_missing"},
        },
        "incomplete_request": {
            "data": har([{"response": valid[0]["response"]}, valid[1]]),
            "rejected": {0: "request_missing"},
        },
        "incomplete_response": {
            "data": har([valid[0], {"request": valid[1]["request"], "response": "x"}]),
            "rejected": {1: "response_missing"},
        },
        "duplicates": {"data": har([valid[0], valid[0], valid[1]]), "rejected": {}, "duplicates": 1},
        "non_consecutive_locators": {
            "data": har([1, valid[0], 2, 3, valid[1], {"request": {}}, valid[2]]),
            "rejected": {0: "entry_not_object", 2: "entry_not_object", 3: "entry_not_object", 5: "response_missing"},
        },
        "multi_origin": {
            "data": har(
                [
                    entry("/a", host="one.example.test"),
                    entry("/a", host="two.example.test:8443"),
                    entry("/a", host="one.example.test"),
                ]
            ),
            "rejected": {},
            "duplicates": 1,
        },
        "huge_entry": {
            "data": har([valid[0], entry("/big", response='"' + "A" * (2 * 1024 * 1024) + '"')]),
            "rejected": {},  # evidence import has no per-message cap below the file cap
        },
    }
    dup_keys = har([valid[0], {"placeholder": 1}]).replace(
        b'{"placeholder": 1}',
        b'{"request": ' + json.dumps(valid[1]["request"]).encode() + b', "response": {"status": 200}, '
        b'"response": ' + json.dumps(valid[2]["response"]).encode() + b"}",
    )
    out["duplicate_json_keys"] = {"data": dup_keys, "rejected": {1: "duplicate_json_keys"}}
    return out


def over_limit_entries(count: int) -> bytes:
    return har([entry(f"/items/{n}") for n in range(count)])
