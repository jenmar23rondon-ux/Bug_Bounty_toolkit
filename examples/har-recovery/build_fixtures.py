"""Build the synthetic HAR partial-recovery fixtures (synthetic data only, no network).

Run: python examples/har-recovery/build_fixtures.py  (rewrites the *.har files deterministically)
Every secret-looking value contains the marker ``SYNTH-SECRET`` so tests can grep outputs for it.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
ORIGIN = "https://api.example.test"
MARK = "SYNTH-SECRET"


def entry(target: str, body: Any, session: str = "alice", method: str = "GET") -> dict[str, Any]:
    return {
        "startedDateTime": "2026-01-01T00:00:00Z",
        "request": {
            "method": method,
            "url": ORIGIN + target,
            "headers": [
                {"name": "Authorization", "value": f"Bearer {MARK}-token-{session}"},
                {"name": "Cookie", "value": f"sid={MARK}-cookie-{session}"},
            ],
        },
        "response": {
            "status": 200,
            "headers": [{"name": "Set-Cookie", "value": f"sid={MARK}-set-{session}"}],
            "content": {"mimeType": "application/json", "text": json.dumps(body, sort_keys=True)},
        },
    }


def valid(n: int, start: int = 1000, session: str = "alice") -> list[dict[str, Any]]:
    return [entry(f"/v1/orders/{start + i}", {"id": start + i, "user_id": 7}, session) for i in range(n)]


def nested(depth: int) -> Any:
    value: Any = {"id": 1}
    for _ in range(depth):
        value = {"child": value}
    return value


def fixtures() -> dict[str, Any]:
    out: dict[str, Any] = {}
    out["valid"] = valid(5)
    out["malformed_among_valid"] = [*valid(2), "not-an-entry", *valid(2, 2000)]
    no_url = entry("/v1/orders/3001", {"id": 3001})
    del no_url["request"]["url"]
    bad_method = entry("/v1/orders/3002", {"id": 3002}, method="get it")
    no_request = entry("/v1/orders/3003", {"id": 3003})
    del no_request["request"]
    bad_post = entry("/v1/orders/3004", {"id": 3004}, method="POST")
    bad_post["request"]["postData"] = {"text": {"user_id": 1}}
    out["incomplete_requests"] = [valid(1, 3000)[0], no_url, bad_method, no_request, bad_post, valid(1, 3005)[0]]
    no_response = entry("/v1/orders/4001", {"id": 4001})
    del no_response["response"]
    truncated_body = entry("/v1/orders/4002", {"id": 4002})
    truncated_body["response"]["content"]["text"] = '{"id": 4002, "items": [1, 2'
    bad_b64 = entry("/v1/orders/4003", {"id": 4003})
    bad_b64["response"]["content"].update(text="%%%not-base64", encoding="base64")
    gzip = entry("/v1/orders/4004", {"id": 4004})
    gzip["response"]["content"]["encoding"] = "gzip"
    content_obj = entry("/v1/orders/4005", {"id": 4005})
    content_obj["response"]["content"] = ["not", "an", "object"]
    out["incomplete_responses"] = [
        valid(1, 4000)[0],
        no_response,
        truncated_body,
        bad_b64,
        gzip,
        content_obj,
        valid(1, 4006)[0],
    ]
    deep_body = entry("/v1/orders/5001", nested(40))
    deep_struct = entry("/v1/orders/5002", {"id": 5002})
    deep_struct["_extra"] = nested(40)
    out["deep_json"] = [valid(1, 5000)[0], deep_body, deep_struct, valid(1, 5003)[0]]
    dup = valid(1, 6000)[0]
    out["duplicates"] = [dup, dup, valid(1, 6001)[0], dup]
    creds = entry("/v1/orders/7001", {"id": 7001})
    creds["request"]["url"] = f"https://user:{MARK}-pw@api.example.test/v1/orders/7001"
    body_secret = entry(
        "/v1/orders/7002", {"id": 7002, "access_token": f"{MARK}-body-token", "email": "synthetic.person@example.test"}
    )
    query_secret = entry(f"/v1/orders/7003?api_key={MARK}-query", {"id": 7003})
    out["synthetic_secrets"] = [creds, body_secret, query_secret, valid(1, 7004)[0]]
    # adversarial mixing: request-only and response-only neighbours must never be paired
    req_only = entry("/v1/invoices/8001", {"id": 8001}, "mallory")
    del req_only["response"]
    resp_only = entry("/v1/invoices/8002", {"id": 8002, "owner_id": 99}, "alice")
    del resp_only["request"]
    resp_list = entry("/v1/invoices/8003", {"id": 8003})
    resp_list["response"] = [resp_list["response"], resp_only["response"]]
    out["adversarial_mixing"] = [req_only, resp_only, "DUPLICATE_RESPONSE_PLACEHOLDER", resp_list, valid(1, 8005)[0]]
    out["over_count"] = valid(40, 9000)
    return out


def dump(name: str, entries: list[Any]) -> str:
    text = json.dumps({"log": {"version": "1.2", "creator": {"name": "synthetic"}, "entries": entries}}, indent=1)
    if name == "adversarial_mixing":
        # A JSON object with two "response" keys: ambiguous, so the entry must be rejected, not repaired.
        a = entry("/v1/invoices/8004", {"id": 8004}, "alice")
        b = entry("/v1/invoices/8999", {"id": 8999}, "mallory")
        fragment = (
            '{"request": '
            + json.dumps(a["request"])
            + ', "response": '
            + json.dumps(a["response"])
            + ', "response": '
            + json.dumps(b["response"])
            + "}"
        )
        text = text.replace('"DUPLICATE_RESPONSE_PLACEHOLDER"', fragment)
    return text + "\n"


GLOBAL_INVALID = {
    "invalid_truncated_file": '{"log": {"entries": [{"request": {"method": "GET", "url": "https://api.example.test/',
    "invalid_no_entries": '{"log": {"version": "1.2"}}\n',
    "invalid_empty_entries": '{"log": {"entries": []}}\n',
    "invalid_duplicate_log": '{"log": {"entries": []}, "log": {"entries": []}}\n',
    "invalid_all_entries_bad": '{"log": {"entries": [1, "two", null]}}\n',
}


def main() -> None:
    for name, entries in fixtures().items():
        (HERE / f"{name}.har").write_text(dump(name, entries), encoding="utf-8")
    for name, text in GLOBAL_INVALID.items():
        (HERE / f"{name}.har").write_text(text, encoding="utf-8")
    (HERE / "invalid_deep_document.har").write_text('{"log": {"entries": ' + "[" * 300 + "]" * 300 + "}}\n")
    (HERE / "invalid_not_utf8.har").write_bytes(b'{"log": {"entries": ["\xff\xfe"]}}\n')


if __name__ == "__main__":
    main()
