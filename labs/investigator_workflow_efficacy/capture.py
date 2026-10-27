"""Fetch one case from the loopback lab. No name resolution and no proxy."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.error import HTTPError
from urllib.parse import quote
from urllib.request import ProxyHandler, Request, build_opener

from .secrets import ACTOR_TOKEN, OWNER_TOKEN
from .server import LabServer


@dataclass
class Exchange:
    role: str
    status: int
    headers: dict[str, str]
    body: str
    path: str

    @property
    def truncated(self) -> bool:
        return self.headers.get("X-BBTK-Truncated") == "1"


@dataclass
class Capture:
    case_id: str
    workflow: str
    exchanges: list[Exchange] = field(default_factory=list)
    request_payload: str = ""
    request_marker: str = ""

    def by_role(self, role: str) -> Exchange | None:
        for item in self.exchanges:
            if item.role == role:
                return item
        return None


def _opener() -> Any:
    return build_opener(ProxyHandler({}))


def fetch(base_url: str, case: dict[str, Any]) -> Capture:
    if not base_url.startswith("http://127.0.0.1:") and not base_url.startswith("http://[::1]:"):
        raise ValueError("captures must use a literal loopback base URL")
    kind = _resolved_type(case)
    roles = ("owner", "actor") if kind == "idor_pair" else ("request",)
    payload = ""
    marker = ""
    if kind == "reflected" and case["behavior"].get("type") != "mirror":
        marker = str(case["behavior"]["marker"])
        payload = f"<{marker}>"
    capture = Capture(
        case_id=str(case["id"]),
        workflow=str(case["workflow"]),
        request_payload=payload,
        request_marker=marker,
    )
    opener = _opener()
    for role in roles:
        path = f"/lab/{case['id']}?role={role}"
        if payload and role == "request":
            path += "&q=" + quote(payload, safe="")
        headers = {"Accept": "*/*", "User-Agent": "bbtk-iwe-lab"}
        if role == "owner":
            headers["Authorization"] = f"Bearer {OWNER_TOKEN}"
        elif role == "actor":
            headers["Authorization"] = f"Bearer {ACTOR_TOKEN}"
        request = Request(base_url + path, headers=headers, method="GET")
        try:
            with opener.open(request, timeout=3) as response:
                status = int(response.status)
                raw_headers = {key: value for key, value in response.headers.items()}
                body = response.read().decode("utf-8")
        except HTTPError as exc:
            status = int(exc.code)
            raw_headers = {key: value for key, value in exc.headers.items()}
            body = exc.read().decode("utf-8")
        capture.exchanges.append(Exchange(role, status, raw_headers, body, path))
    return capture


def _resolved_type(case: dict[str, Any]) -> str:
    behavior = case["behavior"]
    if behavior.get("type") == "mirror":
        return "reflected"
    return str(behavior.get("type"))


def raw_request(base_url: str, exchange: Exchange) -> str:
    """Burp-style request text. The bearer value is the synthetic lab token."""
    host = base_url.split("://", 1)[1]
    lines = [f"GET {exchange.path} HTTP/1.1", f"Host: {host}"]
    for key, value in exchange.headers.items():
        if key.lower() in {"content-length", "date", "server"}:
            continue
    lines.append("Accept: */*")
    lines.append("User-Agent: bbtk-iwe-lab")
    if exchange.role == "owner":
        lines.append(f"Authorization: Bearer {OWNER_TOKEN}")
    elif exchange.role == "actor":
        lines.append(f"Authorization: Bearer {ACTOR_TOKEN}")
    return "\r\n".join(lines) + "\r\n\r\n"


def header(exchange: Exchange, name: str) -> str:
    for key, value in exchange.headers.items():
        if key.lower() == name.lower():
            return value
    return ""


def disclosure_record(base_url: str, case: dict[str, Any], capture: Capture) -> dict[str, Any]:
    exchange = capture.exchanges[0]
    path = header(exchange, "X-BBTK-Path") or "/"
    audience = header(exchange, "X-BBTK-Audience") or "unknown"
    origin = base_url
    return {
        "responses": [
            {
                "id": case["id"],
                "audience": audience,
                "url": origin + path,
                "request": {"query": ""},
                "response": {
                    "status": exchange.status,
                    "headers": {"Content-Type": header(exchange, "Content-Type") or "application/json"},
                    "body": exchange.body,
                    "truncated": exchange.truncated,
                },
            }
        ]
    }


def write_tutorial_files(base_url: str, case: dict[str, Any], capture: Capture, out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "base_url.txt").write_text(base_url + "\n", encoding="utf-8")
    primary = capture.exchanges[0]
    (out_dir / f"{case['id']}.request.txt").write_text(raw_request(base_url, primary), encoding="utf-8")
    if str(case["behavior"].get("type")) == "disclosure" or case["workflow"] == "C":
        record = disclosure_record(base_url, case, capture)
        (out_dir / f"{case['id']}.disclosure.json").write_text(
            json.dumps(record, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )


def main(argv: list[str] | None = None) -> int:
    import argparse

    from .guard import LoopbackGuard

    parser = argparse.ArgumentParser(description="Capture loopback lab exchanges into local files")
    parser.add_argument("--serve", action="store_true")
    parser.add_argument("--case", action="append", required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args(argv)
    lab = Path(__file__).resolve().parent
    cases: list[dict[str, Any]] = []
    for split in ("dev", "final", "stress"):
        payload = json.loads((lab / split / "cases.json").read_text(encoding="utf-8"))
        cases.extend(payload["cases"])
    selected = [case for case in cases if case["id"] in set(args.case)]
    if len(selected) != len(args.case):
        raise SystemExit("unknown case id")
    if not args.serve:
        raise SystemExit("--serve is required so the capture cannot target an arbitrary host")
    with LoopbackGuard() as guard:
        with LabServer(cases) as server:
            for case in selected:
                captured = fetch(server.url, case)
                write_tutorial_files(server.url, case, captured, args.out)
        if guard.external:
            raise SystemExit(f"external connects blocked: {guard.external}")
    print(f"captured {len(selected)} case(s) at {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
