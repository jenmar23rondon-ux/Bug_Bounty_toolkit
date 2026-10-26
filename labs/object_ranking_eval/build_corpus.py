"""Deterministic generators for the object-RANKING corpora.

* ``adv-ranking-1.0`` (``frozen/``): FINAL evaluation only. Authored and hash-frozen
  BEFORE any evidence-based ranking rule existed. Never tune on it.
* ``adv-ranking-dev`` (``dev/``): separate DEV set (different origin, nouns, values) that
  may be used for tuning.

Ground truth is *review relevance* (which candidate a human reviewer should look at first
for an owner/actor comparison), NOT confirmed vulnerabilities. Synthetic, loopback-only,
no real secrets. Regeneration must be byte-identical (test-enforced).
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent


class Corpus:
    def __init__(self, version: str, origin: str, prefix: str, tok: str) -> None:
        self.version, self.origin, self.prefix, self.tok = version, origin, prefix, tok
        self.entries: list[dict] = []
        self.scenarios: list[dict] = []

    def ex(
        self,
        method: str,
        path: str,
        session: str | None,
        body: dict | None = None,
        resp: dict | None = None,
        *,
        cookie: bool = False,
        raw_resp: str | None = None,
        times: int = 1,
        no_response: bool = False,
        status: int = 200,
    ) -> list[int]:
        out: list[int] = []
        for _ in range(times):
            hdr: list[dict] = []
            if session is not None:
                hdr = (
                    [{"name": "Cookie", "value": f"sid={self.tok}-{session}"}]
                    if cookie
                    else [{"name": "Authorization", "value": f"Bearer {self.tok}-{session}"}]
                )
            req: dict = {"method": method, "url": self.origin + self.prefix + path, "headers": hdr}
            if body is not None:
                req["headers"] = hdr + [{"name": "Content-Type", "value": "application/json"}]
                req["postData"] = {"mimeType": "application/json", "text": json.dumps(body, sort_keys=True)}
            entry: dict = {"request": req}
            if not no_response:
                text = (
                    raw_resp
                    if raw_resp is not None
                    else (json.dumps(resp, sort_keys=True) if resp is not None else "")
                )
                entry["response"] = {
                    "status": status,
                    "content": {"mimeType": "application/json", "text": text},
                }
            self.entries.append(entry)
            out.append(len(self.entries) - 1)
        return out

    def scenario(
        self,
        sid: str,
        tag: str,
        desc: str,
        groups: list[list[int]],
        *,
        relevant: tuple[str, ...] | list[str] = (),
        non_relevant: tuple[str, ...] | list[str] = (),
        ambiguous: tuple[str, ...] | list[str] = (),
    ) -> None:
        self.scenarios.append(
            {
                "id": sid,
                "adversarial_tag": tag,
                "class": "positive" if relevant else ("ambiguous" if ambiguous else "negative"),
                "description": desc,
                "entries": [i for g in groups for i in g],
                "expected_pair_types": list(relevant),
                "forbidden_pair_types": list(non_relevant),
                "ambiguous_types": list(ambiguous),
                "relevance_semantics": "review-priority, not a confirmed vulnerability",
                "expected_confirmed": False,
            }
        )

    def write(self, out: Path) -> None:
        out.mkdir(parents=True, exist_ok=True)
        har = {
            "log": {
                "version": "1.2",
                "creator": {"name": "bbtk-ranking-corpus", "version": self.version},
                "entries": self.entries,
            }
        }
        gt = {"corpus_version": self.version, "origin": self.origin, "scenarios": self.scenarios}
        files = {
            "captures.har": json.dumps(har, indent=1, sort_keys=True) + "\n",
            "ground_truth.json": json.dumps(gt, indent=1, sort_keys=True) + "\n",
        }
        lines = []
        for name, text in files.items():
            (out / name).write_text(text, encoding="utf-8")
            lines.append(f"{hashlib.sha256(text.encode()).hexdigest()}  {name}")
        (out / "MANIFEST.sha256").write_text("\n".join(lines) + "\n", encoding="utf-8")


def build_eval() -> Corpus:
    c = Corpus("adv-ranking-1.0", "http://127.0.0.1:8139", "/rk", "rk10")
    s = c.scenario
    s(
        "R01",
        "shared-frequent",
        "Shared org on every call by 3 sessions; one rare private dossier each",
        [
            c.ex("GET", "/orgs/9100/dossiers/9111", "a", resp={"t": 1}),
            c.ex("GET", "/orgs/9100/dossiers/9112", "b", resp={"t": 2}),
            c.ex("GET", "/orgs/9100/dossiers/9113", "c", resp={"t": 3}),
            c.ex("GET", "/orgs/9100/summary", "a", resp={"n": 1}),
            c.ex("GET", "/orgs/9100/summary", "b", resp={"n": 1}),
            c.ex("GET", "/orgs/9100/summary", "c", resp={"n": 1}),
        ],
        relevant=["dossier"],
        non_relevant=["org"],
    )
    s(
        "R02",
        "multi-role",
        "Manager and report both read distinct employee records under shared department",
        [
            c.ex("GET", "/departments/9200/employees/9211", "mgr", resp={"role": "ic"}),
            c.ex("GET", "/departments/9200/employees/9212", "rpt", resp={"role": "ic"}),
        ],
        relevant=["employee"],
        non_relevant=["department"],
    )
    s(
        "R03",
        "id-collision",
        "Same numeric value used as warehouse id and crate id across sessions",
        [
            c.ex("GET", "/warehouses/9300/crates/9301", "a", resp={"w": 1}),
            c.ex("GET", "/warehouses/9301/crates/9300", "b", resp={"w": 2}),
        ],
        relevant=["warehouse", "crate"],
    )
    s(
        "R04",
        "uuid-numeric",
        "UUID path ticket + numeric query export across two sessions",
        [
            c.ex("GET", "/tickets/aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee", "a", resp={"ok": True}),
            c.ex("GET", "/exports?export_id=9401", "b", resp={"ok": True}),
            c.ex("GET", "/tickets/ffffffff-1111-4222-8333-444444444444", "b", resp={"ok": True}),
            c.ex("GET", "/exports?export_id=9402", "a", resp={"ok": True}),
        ],
        relevant=["ticket", "export"],
    )
    s(
        "R05",
        "nested-arrays",
        "Array of shipment ids in JSON body; nested preference under profile",
        [
            c.ex("POST", "/shipments/batch", "a", body={"shipment_ids": [9501, 9502]}, resp={"ok": True}),
            c.ex("POST", "/shipments/batch", "b", body={"shipment_ids": [9503, 9504]}, resp={"ok": True}),
            c.ex("POST", "/profiles/update", "a", body={"profile": {"preference_id": 9511}}, resp={"ok": True}),
            c.ex("POST", "/profiles/update", "b", body={"profile": {"preference_id": 9512}}, resp={"ok": True}),
        ],
        relevant=["shipment", "preference"],
    )
    s(
        "R06",
        "relations",
        "Shared tenant parent with distinct pipeline children",
        [
            c.ex("GET", "/tenants/9600/pipelines/9611", "a", resp={"s": "x"}),
            c.ex("GET", "/tenants/9600/pipelines/9612", "b", resp={"s": "y"}),
        ],
        relevant=["pipeline"],
        non_relevant=["tenant"],
    )
    s(
        "R07",
        "partial-duplicate",
        "Duplicate identical capture of license; second session missing response",
        [
            c.ex("GET", "/licenses/9701", "a", resp={"v": 1}, times=2),
            c.ex("GET", "/licenses/9702", "b", no_response=True),
        ],
        relevant=[],
        non_relevant=["license"],
    )
    s(
        "R08",
        "ambiguous-fields",
        "Opaque generic ref parameter across sessions",
        [
            c.ex("GET", "/lookup?ref=9801", "a", resp={"ok": True}),
            c.ex("GET", "/lookup?ref=9802", "b", resp={"ok": True}),
        ],
        ambiguous=["ref"],
    )
    s(
        "R09",
        "public-protected",
        "Public article catalogue without credentials; protected note with auth",
        [
            c.ex("GET", "/articles/9901", None, resp={"public": True}),
            c.ex("GET", "/articles/9902", None, resp={"public": True}),
            c.ex("GET", "/notes/9911", "a", resp={"private": True}),
            c.ex("GET", "/notes/9912", "b", resp={"private": True}),
        ],
        relevant=["note"],
        non_relevant=["article"],
    )
    s(
        "R10",
        "misleading-shared",
        "Same channel id requested by both sessions on two endpoints (shared resource)",
        [
            c.ex("GET", "/channels/9001", "a", resp={"name": "lobby"}),
            c.ex("GET", "/channels/9001", "b", resp={"name": "lobby"}),
            c.ex("GET", "/channels/9001/meta", "a", resp={"m": 1}),
            c.ex("GET", "/channels/9001/meta", "b", resp={"m": 1}),
        ],
        relevant=[],
        non_relevant=["channel"],
    )
    s(
        "R11",
        "unknown-endpoints",
        "Unknown collection nouns outside built-in vocabulary; distinct ids per session",
        [
            c.ex("GET", "/zephyrs/9011", "a", resp={"z": 1}),
            c.ex("GET", "/zephyrs/9012", "b", resp={"z": 2}),
            c.ex("GET", "/quarrels/9021", "a", resp={"q": 1}),
            c.ex("GET", "/quarrels/9022", "b", resp={"q": 2}),
        ],
        relevant=["zephyr", "quarrel"],
    )
    s(
        "R12",
        "cross-reference",
        "Id in session A listing response, requested by B on path",
        [
            c.ex("GET", "/home", "a", resp={"subscriptions": [{"id": 9031}]}),
            c.ex("GET", "/subscriptions/9032", "b", resp={"plan": "pro"}),
        ],
        relevant=["subscription"],
    )
    return c


def build_dev() -> Corpus:
    c = Corpus("adv-ranking-dev", "http://127.0.0.1:8140", "/rd", "rkdev")
    s = c.scenario
    s(
        "D01",
        "shared-frequent",
        "Shared campus vs rare locker per session",
        [
            c.ex("GET", "/campuses/8100/lockers/8111", "a", resp={"t": 1}),
            c.ex("GET", "/campuses/8100/lockers/8112", "b", resp={"t": 2}),
            c.ex("GET", "/campuses/8100/info", "a", resp={"n": 1}),
            c.ex("GET", "/campuses/8100/info", "b", resp={"n": 1}),
        ],
        relevant=["locker"],
        non_relevant=["campus"],
    )
    s(
        "D02",
        "multi-role",
        "Lead and member under shared squad",
        [
            c.ex("GET", "/squads/8200/members/8211", "lead", resp={"ok": 1}),
            c.ex("GET", "/squads/8200/members/8212", "mem", resp={"ok": 1}),
        ],
        relevant=["member"],
        non_relevant=["squad"],
    )
    s(
        "D03",
        "public-protected",
        "Public brochure vs private memo",
        [
            c.ex("GET", "/brochures/8301", None, resp={"public": True}),
            c.ex("GET", "/memos/8311", "a", resp={"private": True}),
            c.ex("GET", "/memos/8312", "b", resp={"private": True}),
        ],
        relevant=["memo"],
        non_relevant=["brochure"],
    )
    s(
        "D04",
        "misleading-shared",
        "Identical bulletin id across sessions",
        [
            c.ex("GET", "/bulletins/8401", "a", resp={"t": "x"}),
            c.ex("GET", "/bulletins/8401", "b", resp={"t": "x"}),
        ],
        relevant=[],
        non_relevant=["bulletin"],
    )
    s(
        "D05",
        "uuid-numeric",
        "UUID parcel + numeric invoice",
        [
            c.ex("GET", "/parcels/11111111-2222-4333-8444-555555555555", "a", resp={"ok": True}),
            c.ex("GET", "/invoices?invoice_id=8501", "b", resp={"ok": True}),
            c.ex("GET", "/parcels/66666666-7777-4888-8999-aaaaaaaaaaaa", "b", resp={"ok": True}),
            c.ex("GET", "/invoices?invoice_id=8502", "a", resp={"ok": True}),
        ],
        relevant=["parcel", "invoice"],
    )
    return c


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    target = args[0] if args else "all"
    if target in {"all", "eval", "frozen"}:
        build_eval().write(HERE / "frozen")
        print("wrote", HERE / "frozen")
    if target in {"all", "dev"}:
        build_dev().write(HERE / "dev")
        print("wrote", HERE / "dev")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
