"""Deterministic generator for the FROZEN adversarial IDOR/BOLA evaluation corpus.

Synthetic, loopback-only data. This script is kept for provenance/reproducibility;
the committed ``frozen/captures.har`` + ``frozen/ground_truth.json`` are the frozen
artifacts and are hash-pinned in ``frozen/MANIFEST.sha256``. Regenerating must be
byte-identical (checked by tests). Do NOT edit scenarios to make the pipeline score
better: this corpus was authored from the scenario spec before any pipeline run and
must never be used to tune detection rules.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

ORIGIN = "http://127.0.0.1:8137"
CORPUS_VERSION = "adv-1.0"
ENTRIES: list[dict] = []
SCENARIOS: list[dict] = []


def _hdr(session: str | None, *, cookie: bool = False) -> list[dict]:
    if session is None:
        return []
    if cookie:
        return [{"name": "Cookie", "value": f"sid=adv-{session}"}]
    return [{"name": "Authorization", "value": f"Bearer adv-{session}"}]


def ex(method, path, session, body=None, resp=None, *, cookie=False, status=200, raw_resp=None, no_response=False):
    req = {"method": method, "url": ORIGIN + path, "headers": _hdr(session, cookie=cookie)}
    if body is not None:
        req["headers"] = req["headers"] + [{"name": "Content-Type", "value": "application/json"}]
        req["postData"] = {"mimeType": "application/json", "text": json.dumps(body, sort_keys=True)}
    entry = {"request": req}
    if not no_response:
        text = raw_resp if raw_resp is not None else (json.dumps(resp, sort_keys=True) if resp is not None else "")
        entry["response"] = {"status": status, "content": {"mimeType": "application/json", "text": text}}
    ENTRIES.append(entry)
    return len(ENTRIES) - 1


def scenario(sid, tag, cls, desc, entries, *, positives=(), negatives=(), ambiguous=(), vuln_truth="n/a"):
    """positives: resource types that SHOULD reach a review pairing proposal.
    negatives: resource types that must NOT produce a pairing proposal.
    ambiguous: resource types where either outcome is acceptable but a human must decide.
    vuln_truth: designed server behaviour of the synthetic lab (informational; the
    offline pipeline can never confirm it — confirmation needs a human-gated test)."""
    SCENARIOS.append({
        "id": sid, "adversarial_tag": tag, "class": cls, "description": desc,
        "entries": entries, "expected_pair_types": list(positives),
        "forbidden_pair_types": list(negatives), "ambiguous_types": list(ambiguous),
        "vulnerability_truth": vuln_truth, "expected_confirmed": False,
    })


# ---------------- positives ----------------
scenario("S01", "uuid", "positive", "UUID path ids, two sessions, distinct objects",
         [ex("GET", "/adv/receipts/3f2b1c9e-0a4d-4c1e-9b7a-111111111111", "s01a", resp={"receipt": {"total": 9}}),
          ex("GET", "/adv/receipts/7a9d2e4f-5b6c-4d8e-a1f0-222222222222", "s01b", resp={"receipt": {"total": 4}})],
         positives=["receipt"], vuln_truth="vulnerable")
scenario("S02", "nested-objects", "positive", "Child object under per-session parent",
         [ex("GET", "/adv/workspaces/20101/boards/20201", "s02a", resp={"board": {"id": 20201}}),
          ex("GET", "/adv/workspaces/20102/boards/20202", "s02b", resp={"board": {"id": 20202}})],
         positives=["board", "workspace"], vuln_truth="vulnerable")
scenario("S03", "arrays", "positive", "Array of ids in JSON request body",
         [ex("POST", "/adv/shipments/lookup", "s03a", body={"shipment_ids": [20301, 20302]}, resp={"ok": True}),
          ex("POST", "/adv/shipments/lookup", "s03b", body={"shipment_ids": [20311]}, resp={"ok": True})],
         positives=["shipment"], vuln_truth="vulnerable")
scenario("S04", "cross-reference", "positive", "Id observed in session A listing response, requested by B",
         [ex("GET", "/adv/helpdesk", "s04a", resp={"items": [{"ticket_id": 20401, "subject": "x"}]}),
          ex("GET", "/adv/tickets/20402", "s04b", resp={"ticket": {"state": "open"}})],
         positives=["ticket"], vuln_truth="vulnerable")
scenario("S05", "multi-session", "positive", "Three sessions on the same template",
         [ex("GET", "/adv/statements/20501", "s05a", resp={"ok": 1}),
          ex("GET", "/adv/statements/20502", "s05b", resp={"ok": 1}),
          ex("GET", "/adv/statements/20503", "s05c", resp={"ok": 1})],
         positives=["statement"], vuln_truth="vulnerable")
scenario("S06", "hierarchical-permissions", "positive",
         "Manager and report both reach employee records; manager access is LEGITIMATE (hierarchy)",
         [ex("GET", "/adv/departments/20601/employees/20611", "s06mgr", resp={"employee": {"manager": True}}),
          ex("GET", "/adv/departments/20601/employees/20612", "s06emp", resp={"employee": {"manager": False}})],
         positives=["employee"], negatives=["department"], vuln_truth="protected-by-hierarchy")
scenario("S07", "uuid", "positive", "UUID in query parameter",
         [ex("GET", "/adv/exports?export_uuid=0b1c2d3e-4f50-4617-8899-333333333333", "s07a", resp={"ready": True}),
          ex("GET", "/adv/exports?export_uuid=9e8d7c6b-5a49-4382-b1a0-444444444444", "s07b", resp={"ready": True})],
         positives=["export"], vuln_truth="vulnerable")
scenario("S08", "nested-objects", "positive", "Deeply nested typed id in JSON request body",
         [ex("PUT", "/adv/settings", "s08a", body={"profile": {"prefs": {"preference_id": 20801}}}, resp={"ok": True}),
          ex("PUT", "/adv/settings", "s08b", body={"profile": {"prefs": {"preference_id": 20802}}}, resp={"ok": True})],
         positives=["preference"], vuln_truth="protected")
scenario("S09", "multi-session", "positive", "Cookie-based sessions instead of bearer tokens",
         [ex("GET", "/adv/payslips/20901", "s09a", cookie=True, resp={"net": 1}),
          ex("GET", "/adv/payslips/20902", "s09b", cookie=True, resp={"net": 2})],
         positives=["payslip"], vuln_truth="vulnerable")
scenario("S10", "shared-ids", "positive", "Shared parent org, distinct child pipelines",
         [ex("GET", "/adv/orgs/21000/pipelines/21001", "s10a", resp={"ok": 1}),
          ex("GET", "/adv/orgs/21000/pipelines/21002", "s10b", resp={"ok": 1})],
         positives=["pipeline"], negatives=["org"], vuln_truth="vulnerable")
scenario("S11", "cross-reference", "positive", "Nested response object id vs query parameter in another session",
         [ex("GET", "/adv/dashboard", "s11a", resp={"data": {"billing": {"subscription_id": 21101}}}),
          ex("GET", "/adv/subscriptions?subscription_id=21102", "s11b", resp={"ok": True})],
         positives=["subscription"], vuln_truth="vulnerable")

# ---------------- negatives ----------------
scenario("S12", "shared-ids", "negative", "Same object id requested by both sessions (shared resource)",
         [ex("GET", "/adv/channels/21201", "s12a", resp={"ok": 1}),
          ex("GET", "/adv/channels/21201", "s12b", resp={"ok": 1})],
         negatives=["channel"])
scenario("S13", "public-objects", "negative", "Public catalogue, no credentials",
         [ex("GET", "/adv/articles/21301", None, resp={"title": "a"}),
          ex("GET", "/adv/articles/21302", None, resp={"title": "b"})],
         negatives=["article"])
scenario("S14", "multi-session", "negative", "Single session reads two own objects",
         [ex("GET", "/adv/coupons/21401", "s14a", resp={"ok": 1}),
          ex("GET", "/adv/coupons/21402", "s14a", resp={"ok": 1})],
         negatives=["coupon"])
scenario("S15", "partial-responses", "negative", "Truncated JSON responses only; ids never in requests",
         [ex("GET", "/adv/contracts/latest", "s15a", raw_resp='{"contract": {"contract_id": 21501, "par'),
          ex("GET", "/adv/contracts/latest", "s15b", raw_resp='{"contract": {"contract_id": 21502, "pa')],
         negatives=["contract"])
scenario("S16", "incomplete-captures", "negative", "Second capture missing credentials and response",
         [ex("GET", "/adv/licenses/21601", "s16a", resp={"ok": 1}),
          ex("GET", "/adv/licenses/21602", None, no_response=True)],
         negatives=["license"])
scenario("S17", "public-objects", "negative", "Pagination/limit numbers differ across sessions (not object ids)",
         [ex("GET", "/adv/reports?page=2&limit=50", "s17a", resp={"n": 50}),
          ex("GET", "/adv/reports?page=7&limit=25", "s17b", resp={"n": 25})],
         negatives=["report", "page", "limit"])
scenario("S18", "partial-responses", "negative", "Response echoes own id only; request has no id",
         [ex("GET", "/adv/me/locker", "s18a", resp={"locker": {"locker_id": 21801}}),
          ex("GET", "/adv/me/locker", "s18b", resp={"locker": {"locker_id": 21802}})],
         negatives=["locker"])
scenario("S19", "public-objects", "negative", "Public object accessed with and without auth, same id",
         [ex("GET", "/adv/banners/21901", "s19a", resp={"ok": 1}),
          ex("GET", "/adv/banners/21901", None, resp={"ok": 1})],
         negatives=["banner"])
scenario("S20", "incomplete-captures", "negative", "Only one session captured at all for a resource",
         [ex("DELETE", "/adv/vouchers/22001", "s20a", resp={"deleted": True})],
         negatives=["voucher"])

# ---------------- ambiguous ----------------
scenario("S21", "ambiguous", "ambiguous", "Opaque generic `ref` parameter, unclear if object id",
         [ex("GET", "/adv/lookup?ref=k7Qm2", "s21a", resp={"ok": 1}),
          ex("GET", "/adv/lookup?ref=p9Zx4", "s21b", resp={"ok": 1})],
         ambiguous=["ref", "lookup"])
scenario("S22", "hierarchical-permissions", "ambiguous", "Admin vs member reading member records; policy unknown",
         [ex("GET", "/adv/members/22201", "s22admin", resp={"role": "admin-view"}),
          ex("GET", "/adv/members/22202", "s22member", resp={"role": "self"})],
         ambiguous=["member"], vuln_truth="unknown")
scenario("S23", "shared-ids", "ambiguous", "Ids overlap partially in arrays across sessions",
         [ex("POST", "/adv/folders/share", "s23a", body={"folder_ids": [22301, 22302]}, resp={"ok": 1}),
          ex("POST", "/adv/folders/share", "s23b", body={"folder_ids": [22302, 22303]}, resp={"ok": 1})],
         ambiguous=["folder"])
scenario("S24", "cross-reference", "ambiguous", "Bare `id` in response vs typed id in other session path",
         [ex("GET", "/adv/inbox", "s24a", resp={"data": [{"id": 22401}, {"id": 22402}]}),
          ex("GET", "/adv/messages/22403", "s24b", resp={"ok": 1})],
         ambiguous=["message"])


def build(out: Path) -> None:
    out.mkdir(parents=True, exist_ok=True)
    har = {"log": {"version": "1.2", "creator": {"name": "bbtk-adversarial-eval", "version": CORPUS_VERSION},
                   "entries": ENTRIES}}
    gt = {"corpus_version": CORPUS_VERSION, "split": "adversarial-frozen",
          "tuning_policy": "FROZEN. Do not tune detection rules against this corpus. Authored before any pipeline run.",
          "independent_of": ["labs/object_discovery_lab/dev", "labs/object_discovery_lab/eval"],
          "origin": ORIGIN, "scenarios": SCENARIOS}
    files = {"captures.har": json.dumps(har, indent=1, sort_keys=True) + "\n",
             "ground_truth.json": json.dumps(gt, indent=1, sort_keys=True) + "\n"}
    for name, text in files.items():
        (out / name).write_text(text, encoding="utf-8")
    manifest = "".join(f"{hashlib.sha256(t.encode()).hexdigest()}  {n}\n" for n, t in sorted(files.items()))
    (out / "MANIFEST.sha256").write_text(manifest, encoding="utf-8")


if __name__ == "__main__":
    build(Path(__file__).resolve().parent / "frozen")
