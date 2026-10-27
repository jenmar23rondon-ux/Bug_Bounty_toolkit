"""Measure existing read-pair representation; no planner implementation required."""

from __future__ import annotations

import json

from bugbounty_toolkit.burp_import import parse_captured_exchanges
from bugbounty_toolkit.case_generator import inspect_read_pair

BASE_SHA = "bd289808600d57983f1dcacaa9b68c0d7eea0d18"


def measure() -> dict[str, object]:
    pairs = {
        "numeric_path": ("/objects/101", "/objects/202", "GET", ""),
        "uuid_path": (
            "/objects/00000000-0000-4000-8000-000000000001",
            "/objects/00000000-0000-4000-8000-000000000002",
            "GET",
            "",
        ),
        "query_parameter": ("/objects?id=101&view=small", "/objects?id=202&view=small", "GET", ""),
        "two_fields": ("/objects/101?id=101", "/objects/202?id=202", "GET", ""),
        "json_pointer_get_body": ("/objects", "/objects", "GET", '{"id":101}'),
        "post": ("/objects/101", "/objects/202", "POST", ""),
        "signed_url": ("/objects?id=101&signature=synthetic", "/objects?id=202&signature=synthetic", "GET", ""),
    }
    represented: dict[str, bool] = {}
    for name, (left, right, method, body) in pairs.items():
        requests = []
        for target, session in ((left, "lab-a"), (right, "lab-b")):
            raw = f"{method} {target} HTTP/1.1\r\nHost: lab.test\r\nCookie: session={session}\r\n\r\n{body}"
            requests.append(parse_captured_exchanges(raw.encode())[0].request)
        try:
            inspect_read_pair(requests[0], requests[1])
            represented[name] = True
        except ValueError:
            represented[name] = False
    return {
        "schema_version": "bbtk-request-variation-baseline/1",
        "base_sha": BASE_SHA,
        "measurement": "existing inspect_read_pair representation, not planner efficacy",
        "representable": represented,
        "representable_types": sum(represented.values()),
        "declaration_driven_planner_available": False,
        "network_requests_sent": 0,
        "confirmed": False,
    }


if __name__ == "__main__":
    print(json.dumps(measure(), indent=2, sort_keys=True))
