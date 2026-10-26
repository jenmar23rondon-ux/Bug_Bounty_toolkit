"""Deterministic synthetic capture fixtures for the batch-ingestion evaluation (offline only).

Hosts use reserved ``.test`` names; credentials are synthetic canaries. Every scenario carries
its ground truth (valid entry locators per file, session label per locator, expected rejects)
derived from how the fixture was *constructed*, never from importer output.
"""

from __future__ import annotations

import base64
import json
from typing import Any

CANARY = "CANARY-BATCH-SYNTHETIC-5e1d"
SPLITS = ("dev", "final")


def entry(
    path: str, *, session: str, host: str = "api.example.test", n: int = 0, method: str = "GET"
) -> dict[str, Any]:
    return {
        "startedDateTime": f"2026-01-01T00:{n // 60 % 60:02d}:{n % 60:02d}Z",
        "request": {
            "method": method,
            "url": f"https://{host}{path}",
            "headers": [
                {"name": "Cookie", "value": f"sid={session}-{CANARY}"},
                {"name": "Authorization", "value": f"Bearer {session}.{CANARY}"},
            ],
        },
        "response": {
            "status": 200,
            "headers": [{"name": "Content-Type", "value": "application/json"}],
            "content": {"mimeType": "application/json", "text": json.dumps({"id": n, "owner": session})},
        },
    }


def har(entries: list[Any]) -> bytes:
    return json.dumps({"log": {"version": "1.2", "entries": entries}}, sort_keys=True).encode()


def burp(items: list[tuple[str, str, bool]], empty_items: int = 0) -> bytes:
    """items: (request text, response text, corrupt_base64); ``empty_items`` have no URL/messages."""
    rows = ["<item><comment>empty</comment></item>"] * empty_items
    for request, response, corrupt in items:
        req = "!!not-base64!!" if corrupt else base64.b64encode(request.encode()).decode()
        res = base64.b64encode(response.encode()).decode()
        rows.append(
            f'<item><url>https://burp.example.test/x</url><request base64="true">{req}</request>'
            f'<response base64="true">{res}</response></item>'
        )
    return ("<items>" + "".join(rows) + "</items>").encode()


class Scenario:
    def __init__(self, name: str, split: str) -> None:
        self.name = name
        self.split = split
        self.files: dict[str, bytes] = {}
        # relpath -> {locator: session label} for entries that must be preserved.
        self.valid: dict[str, dict[str, str]] = {}
        # relpath -> {index: reason} for entries that must be reported rejected.
        self.rejected: dict[str, dict[int, str]] = {}
        self.rejected_files: set[str] = set()
        self.expect: dict[str, Any] = {}

    def add_har(
        self, relpath: str, entries: list[Any], sessions: list[str | None], rejected: dict[int, str] | None = None
    ) -> None:
        self.files[relpath] = har(entries)
        self.valid[relpath] = {f"/log/entries[{i}]": s for i, s in enumerate(sessions) if s is not None}
        self.rejected[relpath] = dict(rejected or {})


def _segment(
    sc: Scenario, files: int, per_file: int, *, offset: int = 0, sessions: tuple[str, ...] = ("alice",)
) -> None:
    for f in range(files):
        labels = [sessions[(f + i) % len(sessions)] for i in range(per_file)]
        n0 = offset + f * per_file
        entries = [entry(f"/items/{n0 + i}", session=labels[i], n=n0 + i) for i in range(per_file)]
        sc.add_har(f"seg/part-{f:04d}.har", entries, list(labels))


def scenarios(split: str) -> list[Scenario]:
    salt = 0 if split == "dev" else 7000  # FINAL uses disjoint ids/paths from DEV
    out: list[Scenario] = []

    def new(name: str) -> Scenario:
        sc = Scenario(name, split)
        out.append(sc)
        return sc

    _segment(new("small"), 1, 5, offset=salt)
    _segment(new("large_segmented"), 24, 30, offset=salt)
    _segment(new("multi_session"), 6, 10, offset=salt, sessions=("alice", "bob", "carol"))
    sc = new("many_duplicates")
    base = [entry(f"/dup/{salt}", session="alice", n=1)] * 8
    sc.add_har("dups.har", base, ["alice"] * 8)
    sc.expect["duplicate_entries_min"] = 7
    sc = new("cross_batch_duplicates")
    same = [entry(f"/shared/{salt + i}", session="alice", n=i) for i in range(4)]
    sc.add_har("a.har", same, ["alice"] * 4)
    sc.add_har("b.har", same + [entry(f"/only-b/{salt}", session="alice", n=9)], ["alice"] * 5)
    sc.expect["cross_file_duplicate_har_entries"] = 4
    sc = new("duplicate_file")
    data = [entry(f"/copy/{salt}", session="alice", n=1)]
    sc.add_har("orig.har", data, ["alice"])
    sc.add_har("zz-copy.har", data, [None])
    sc.expect["duplicate_files"] = 1
    sc = new("incomplete_file")
    sc.add_har("ok.har", [entry(f"/ok/{salt}", session="alice", n=1)], ["alice"])
    sc.files["broken.har"] = har([entry(f"/b/{salt}", session="alice")])[:-17]
    sc.rejected_files.add("broken.har")
    sc = new("request_without_response")
    good = entry(f"/r/{salt}", session="alice", n=1)
    sc.add_har("r.har", [good, {"request": good["request"]}], ["alice", None], {1: "response_missing"})
    sc = new("burp_partial")
    request = f"GET /burp/{salt} HTTP/1.1\r\nHost: burp.example.test\r\nCookie: sid={CANARY}\r\n\r\n"
    response = 'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{"ok":true}'
    sc.files["site.xml"] = burp(
        [(request, response, False), (request, response, True), (request, response, False)], empty_items=1
    )
    # The empty item is skipped by the existing importer; the corrupt-request item is still
    # emitted (response half only) by the existing importer, which this PR does not change.
    sc.expect["burp_items_not_emitted"] = 1
    sc = new("different_origins")
    sc.add_har(
        "o.har",
        [entry(f"/o/{salt}", session="alice", host=h, n=i) for i, h in enumerate(("a.example.test", "b.example.test"))],
        ["alice", "alice"],
    )
    sc = new("out_of_order")
    _segment(sc, 5, 3, offset=salt)
    sc.expect["shuffle"] = True
    sc = new("raw_http")
    sc.files["req.http"] = (
        f"GET /raw/{salt} HTTP/1.1\r\nHost: raw.example.test\r\nCookie: sid={CANARY}\r\n\r\n".encode()
    )
    sc = new("huge_entry")
    big = entry(f"/big/{salt}", session="alice", n=1)
    big["response"]["content"]["text"] = json.dumps({"blob": "x" * (2 * 1024 * 1024)})
    sc.add_har("big.har", [big, entry(f"/small/{salt}", session="alice", n=2)], ["alice", "alice"])
    sc = new("deep_json")
    deep = entry(f"/deep/{salt}", session="alice", n=1)
    deep["response"]["content"]["text"] = "[" * 40 + "]" * 40
    sc.add_har(
        "deep.har", [deep, entry(f"/flat/{salt}", session="alice", n=2)], [None, "alice"], {0: "body_json_too_deep"}
    )
    return out


def oversize_file() -> bytes:
    """One byte above the existing 32 MiB per-file import limit (built on demand, not committed)."""
    from bugbounty_toolkit.analysis.evidence_engine import MAX_INPUT_BYTES

    return b" " * (MAX_INPUT_BYTES + 1)
