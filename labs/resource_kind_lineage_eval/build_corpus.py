"""Synthetic local corpus for resource-kind-lineage-v1 evaluation (no network)."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
VERSION = "rkl-1.0"
ORIGIN = "http://127.0.0.1:8191"
PREFIX = "/rk"
PROGRAM = "rkl-lab"
KEY = bytes.fromhex("aa" * 32)


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _entry(
    method: str, path: str, session: str, *, status: int = 200, resp: Any = None, body: Any = None
) -> dict[str, Any]:
    headers = [{"name": "Cookie", "value": f"sess={session}"}]
    req: dict[str, Any] = {
        "method": method,
        "url": ORIGIN + PREFIX + path,
        "headers": headers,
        "httpVersion": "HTTP/1.1",
        "cookies": [],
        "queryString": [],
        "headersSize": -1,
        "bodySize": -1,
    }
    if body is not None:
        text = json.dumps(body)
        req["postData"] = {"mimeType": "application/json", "text": text}
        req["bodySize"] = len(text.encode())
    response: dict[str, Any] = {
        "status": status,
        "statusText": "OK",
        "httpVersion": "HTTP/1.1",
        "headers": [{"name": "Content-Type", "value": "application/json"}],
        "cookies": [],
        "content": {"size": 0, "mimeType": "application/json", "text": ""},
        "redirectURL": "",
        "headersSize": -1,
        "bodySize": 0,
    }
    if resp is not None:
        text = json.dumps(resp)
        response["content"] = {"size": len(text.encode()), "mimeType": "application/json", "text": text}
        response["bodySize"] = len(text.encode())
    return {
        "startedDateTime": "2026-01-01T00:00:00.000Z",
        "time": 1,
        "request": req,
        "response": response,
        "cache": {},
        "timings": {"send": 0, "wait": 1, "receive": 0},
    }


SCENARIOS: list[dict[str, Any]] = [
    {
        "id": "K01",
        "tag": "users-vs-orders-same-id",
        "expect": {
            "kinds": ["user", "order"],
            "no_cross_kind_collision": True,
            "preserve": True,
            "ownership": "unknown",
        },
        "entries": [
            _entry("GET", "/users/7", "A", resp={"id": 7, "name": "a"}),
            _entry("GET", "/orders/7", "A", resp={"id": 7, "total": 1}),
            _entry("GET", "/users/7", "B", resp={"id": 7, "name": "b"}),
            _entry("GET", "/orders/7", "B", resp={"id": 7, "total": 2}),
        ],
    },
    {
        "id": "K02",
        "tag": "identical-id-different-collections",
        "expect": {
            "kinds": ["ticket", "claim"],
            "no_cross_kind_collision": True,
            "preserve": True,
            "ownership": "unknown",
        },
        "entries": [
            _entry("GET", "/tickets/42", "A", resp={"id": 42}),
            _entry("GET", "/claims/42", "A", resp={"id": 42}),
            _entry("GET", "/tickets/42", "B", resp={"id": 42}),
            _entry("GET", "/claims/42", "B", resp={"id": 42}),
        ],
    },
    {
        "id": "K03",
        "tag": "uuid-different-namespace",
        "expect": {
            "kinds": ["dossier", "shipment"],
            "no_cross_kind_collision": True,
            "preserve": True,
            "ownership": "unknown",
        },
        "entries": [
            _entry(
                "GET",
                "/dossiers/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
                "A",
                resp={"id": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"},
            ),
            _entry(
                "GET",
                "/shipments/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
                "A",
                resp={"id": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"},
            ),
            _entry(
                "GET",
                "/dossiers/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
                "B",
                resp={"id": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"},
            ),
            _entry(
                "GET",
                "/shipments/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
                "B",
                resp={"id": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"},
            ),
        ],
    },
    {
        "id": "K04",
        "tag": "singular-plural",
        "expect": {"kinds": ["invoice"], "preserve": True, "ownership": "unknown"},
        "entries": [
            _entry("GET", "/invoices/9", "A", resp={"invoice_id": 9}),
            _entry("GET", "/invoice/9", "B", resp={"invoiceId": 9}),
        ],
    },
    {
        "id": "K05",
        "tag": "unconventional-noun",
        "expect": {"kinds": ["crate"], "preserve": True, "ownership": "unknown"},
        "entries": [
            _entry("GET", "/crates/3", "A", resp={"id": 3}),
            _entry("GET", "/crates/3", "B", resp={"id": 3}),
        ],
    },
    {
        "id": "K06",
        "tag": "nested-resources",
        "expect": {
            "kinds": ["user", "order"],
            "no_cross_kind_collision": True,
            "preserve": True,
            "ownership": "unknown",
        },
        "entries": [
            _entry("GET", "/users/1/orders/7", "A", resp={"id": 7, "user_id": 1}),
            _entry("GET", "/users/2/orders/7", "B", resp={"id": 7, "user_id": 2}),
        ],
    },
    {
        "id": "K07",
        "tag": "arrays",
        "expect": {"kinds": ["ticket"], "preserve": True, "ownership": "unknown"},
        "entries": [
            _entry("GET", "/inbox", "A", resp={"tickets": [{"id": 11}, {"id": 12}]}),
            _entry("GET", "/inbox", "B", resp={"tickets": [{"id": 11}, {"id": 13}]}),
        ],
    },
    {
        "id": "K08",
        "tag": "schema-change-same-kind",
        "expect": {"kinds": ["order"], "preserve": True, "ownership": "unknown"},
        "entries": [
            _entry("GET", "/orders/5", "A", resp={"id": 5}),
            _entry("GET", "/v2/orders/5", "B", resp={"orderId": 5}),
        ],
    },
    {
        "id": "K09",
        "tag": "unknown-generic-id",
        "expect": {"kinds": [], "status": "unknown", "ownership": "unknown"},
        "entries": [
            _entry("GET", "/things?id=99", "A", resp={"ok": True}),
            _entry("GET", "/things?id=99", "B", resp={"ok": True}),
        ],
    },
    {
        "id": "K10",
        "tag": "bare-id-field",
        "expect": {"kinds": [], "status": "unknown", "ownership": "unknown"},
        "entries": [
            _entry("GET", "/payload", "A", resp={"id": 55, "name": "x"}),
            _entry("GET", "/payload", "B", resp={"id": 55, "name": "y"}),
        ],
    },
    {
        "id": "K11",
        "tag": "foreign-id-fields",
        "expect": {
            "kinds": ["order", "user"],
            "no_cross_kind_collision": True,
            "preserve": True,
            "ownership": "unknown",
        },
        "entries": [
            _entry("GET", "/checkout", "A", resp={"order_id": 7, "user_id": 7}),
            _entry("GET", "/checkout", "B", resp={"order_id": 7, "user_id": 8}),
        ],
    },
    {
        "id": "K12",
        "tag": "out-of-order-captures",
        "expect": {"kinds": ["product"], "preserve": True, "ownership": "unknown"},
        "entries": [
            _entry("GET", "/products/4", "B", resp={"id": 4}),
            _entry("GET", "/products/4", "A", resp={"id": 4}),
            _entry("GET", "/products/4", "B", resp={"id": 4}),
        ],
    },
    {
        "id": "K13",
        "tag": "contradictory-kind-evidence",
        "expect": {
            # Same raw value under two typed field names: each keeps its own namespace (no merge).
            "kinds": ["ticket", "claim"],
            "no_cross_kind_collision": True,
            "preserve": True,
            "ownership": "unknown",
        },
        "entries": [
            _entry("GET", "/bundle", "A", resp={"ticket_id": 77, "claim_id": 77}),
            _entry("GET", "/bundle", "B", resp={"ticket_id": 77, "claim_id": 77}),
        ],
    },
]


def write(root: Path) -> dict[str, str]:
    root.mkdir(parents=True, exist_ok=True)
    digests: dict[str, str] = {}
    for scenario in SCENARIOS:
        har = {
            "log": {
                "version": "1.2",
                "creator": {"name": "rkl-lab", "version": VERSION},
                "entries": scenario["entries"],
            }
        }
        path = root / f"{scenario['id']}.har"
        data = json.dumps(har, indent=2, sort_keys=True).encode() + b"\n"
        path.write_bytes(data)
        digests[path.name] = _sha(data)
        meta = {k: scenario[k] for k in ("id", "tag", "expect")}
        mpath = root / f"{scenario['id']}.json"
        mdata = json.dumps(meta, indent=2, sort_keys=True).encode() + b"\n"
        mpath.write_bytes(mdata)
        digests[mpath.name] = _sha(mdata)
    (root / "MANIFEST.sha256").write_text(
        "".join(f"{digest}  {name}\n" for name, digest in sorted(digests.items())), encoding="utf-8"
    )
    return digests


def check(root: Path) -> None:
    manifest = {
        line.split()[1]: line.split()[0]
        for line in (root / "MANIFEST.sha256").read_text(encoding="utf-8").splitlines()
        if line.strip()
    }
    for name, digest in sorted(manifest.items()):
        got = _sha((root / name).read_bytes())
        if got != digest:
            raise SystemExit(f"digest mismatch: {name}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    root = HERE / "corpus"
    if args.check:
        check(root)
        print("ok", len(list(root.glob("*.har"))), "scenarios")
        return
    write(root)
    print("wrote", len(SCENARIOS), "scenarios under", root)


if __name__ == "__main__":
    main()
