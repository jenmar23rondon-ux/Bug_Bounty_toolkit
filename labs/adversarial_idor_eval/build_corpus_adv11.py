"""Deterministic generator for the FROZEN adversarial IDOR/BOLA FINAL-evaluation corpus ``adv-1.1``.

Independent of adv-1.0: different origin port, path prefix, resource nouns and shapes.
Authored and committed BEFORE the open-vocabulary resource-kind logic was run on it.

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

ORIGIN = "http://127.0.0.1:8138"
CORPUS_VERSION = "adv-1.1"
ENTRIES: list[dict] = []
SCENARIOS: list[dict] = []


def _hdr(session: str | None, *, cookie: bool = False) -> list[dict]:
    if session is None:
        return []
    if cookie:
        return [{"name": "Cookie", "value": f"sid=adv11-{session}"}]
    return [{"name": "Authorization", "value": f"Bearer adv11-{session}"}]


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
    SCENARIOS.append(
        {
            "id": sid,
            "adversarial_tag": tag,
            "class": cls,
            "description": desc,
            "entries": entries,
            "expected_pair_types": list(positives),
            "forbidden_pair_types": list(negatives),
            "ambiguous_types": list(ambiguous),
            "vulnerability_truth": vuln_truth,
            "expected_confirmed": False,
        }
    )


# ---------------- positives ----------------
P = "/adv11"
scenario(
    "T01",
    "numeric-path",
    "positive",
    "Numeric path ids, two sessions, distinct parcels",
    [
        ex("GET", P + "/parcels/40101", "t01a", resp={"weight": 3}),
        ex("GET", P + "/parcels/40102", "t01b", resp={"weight": 5}),
    ],
    positives=["parcel"],
    vuln_truth="vulnerable",
)
scenario(
    "T02",
    "nested-objects",
    "positive",
    "Distinct parents and children per session (two kinds, two positions)",
    [
        ex("GET", P + "/fleets/40201/vehicles/40211", "t02a", resp={"plate": "x"}),
        ex("GET", P + "/fleets/40202/vehicles/40212", "t02b", resp={"plate": "y"}),
    ],
    positives=["fleet", "vehicle"],
    vuln_truth="vulnerable",
)
scenario(
    "T03",
    "camel-case",
    "positive",
    "camelCase typed id in JSON request body",
    [
        ex("POST", P + "/claims/submit", "t03a", body={"claimId": 40301, "note": "a"}, resp={"ok": True}),
        ex("POST", P + "/claims/submit", "t03b", body={"claimId": 40302, "note": "b"}, resp={"ok": True}),
    ],
    positives=["claim"],
    vuln_truth="vulnerable",
)
scenario(
    "T04",
    "cross-reference",
    "positive",
    "Bare id inside a named response collection vs path id in another session",
    [
        ex("GET", P + "/home", "t04a", resp={"leases": [{"id": 40401, "rent": 1}]}),
        ex("GET", P + "/leases/40402", "t04b", resp={"rent": 2}),
    ],
    positives=["lease"],
    vuln_truth="vulnerable",
)
scenario(
    "T05",
    "cross-reference",
    "positive",
    "Typed UUID in a nested response vs query UUID in another session",
    [
        ex("GET", P + "/overview", "t05a", resp={"result": {"quote_uuid": "5d1e2f30-4a5b-4c6d-8e7f-555555555555"}}),
        ex("GET", P + "/quotes?quote_uuid=6e2f3041-5b6c-4d7e-9f80-666666666666", "t05b", resp={"ok": True}),
    ],
    positives=["quote"],
    vuln_truth="vulnerable",
)
scenario(
    "T06",
    "numeric-collision",
    "positive",
    "Swapped numeric values across two kinds on one template",
    [
        ex("GET", P + "/datasets/40601/ledgers/40602", "t06a", resp={"ok": 1}),
        ex("GET", P + "/datasets/40602/ledgers/40601", "t06b", resp={"ok": 1}),
    ],
    positives=["dataset", "ledger"],
    vuln_truth="vulnerable",
)
scenario(
    "T07",
    "query",
    "positive",
    "Typed id in query string, two sessions",
    [
        ex("GET", P + "/pharmacy?prescription_id=40701", "t07a", resp={"ok": 1}),
        ex("GET", P + "/pharmacy?prescription_id=40702", "t07b", resp={"ok": 1}),
    ],
    positives=["prescription"],
    vuln_truth="vulnerable",
)
scenario(
    "T08",
    "multi-session",
    "positive",
    "Three cookie sessions on a UUID path template",
    [
        ex("GET", P + "/certificates/a1a1a1a1-0000-4000-8000-777777777771", "t08a", cookie=True, resp={"ok": 1}),
        ex("GET", P + "/certificates/b2b2b2b2-0000-4000-8000-777777777772", "t08b", cookie=True, resp={"ok": 1}),
        ex("GET", P + "/certificates/c3c3c3c3-0000-4000-8000-777777777773", "t08c", cookie=True, resp={"ok": 1}),
    ],
    positives=["certificate"],
    vuln_truth="vulnerable",
)
scenario(
    "T09",
    "mixed-positions",
    "positive",
    "Path child id with a shared typed parent id in the query",
    [
        ex("GET", P + "/wards/40901?hospital_id=40900", "t09a", resp={"beds": 3}),
        ex("GET", P + "/wards/40902?hospital_id=40900", "t09b", resp={"beds": 4}),
    ],
    positives=["ward"],
    negatives=["hospital"],
    vuln_truth="vulnerable",
)
scenario(
    "T10",
    "arrays",
    "positive",
    "Typed id array in JSON body, disjoint across sessions",
    [
        ex("POST", P + "/campaigns/pause", "t10a", body={"campaign_ids": [41001, 41002]}, resp={"ok": 1}),
        ex("POST", P + "/campaigns/pause", "t10b", body={"campaign_ids": [41011]}, resp={"ok": 1}),
    ],
    positives=["campaign"],
    vuln_truth="vulnerable",
)

# ---------------- negatives ----------------
scenario(
    "T11",
    "shared-ids",
    "negative",
    "Both sessions request the same venue id",
    [ex("GET", P + "/venues/41101", "t11a", resp={"ok": 1}), ex("GET", P + "/venues/41101", "t11b", resp={"ok": 1})],
    negatives=["venue"],
)
scenario(
    "T12",
    "multi-session",
    "negative",
    "One session reads two of its own badges",
    [ex("GET", P + "/badges/41201", "t12a", resp={"ok": 1}), ex("GET", P + "/badges/41202", "t12a", resp={"ok": 1})],
    negatives=["badge"],
)
scenario(
    "T13",
    "numeric-collision",
    "negative",
    "Response gift id equals another session's refund path id (different kinds)",
    [
        ex("GET", P + "/wallet", "t13a", resp={"gift": {"gift_id": 41300}}),
        ex("GET", P + "/refunds/41300", "t13b", resp={"ok": 1}),
    ],
    negatives=["gift", "refund"],
)
scenario(
    "T14",
    "partial-responses",
    "negative",
    "Response-only own bundle ids, no request ids",
    [
        ex("GET", P + "/me/bundle", "t14a", resp={"bundle": {"bundle_id": 41401}}),
        ex("GET", P + "/me/bundle", "t14b", resp={"bundle": {"bundle_id": 41402}}),
    ],
    negatives=["bundle"],
)
scenario(
    "T15",
    "incomplete-captures",
    "negative",
    "Second request carries no credentials",
    [ex("GET", P + "/tracks/41501", "t15a", resp={"ok": 1}), ex("GET", P + "/tracks/41502", None, resp={"ok": 1})],
    negatives=["track"],
)
scenario(
    "T16",
    "shared-ids",
    "negative",
    "Region id seen in two sessions' responses (shared context); third session requests another region",
    [
        ex("GET", P + "/profile", "t16a", resp={"location": {"region_id": 41600}}),
        ex("GET", P + "/profile", "t16b", resp={"location": {"region_id": 41600}}),
        ex("GET", P + "/regions/41601", "t16c", resp={"ok": 1}),
    ],
    negatives=["region"],
)
scenario(
    "T17",
    "public-objects",
    "negative",
    "Sort/offset numbers differ across sessions (not object ids)",
    [
        ex("GET", P + "/rankings?offset=20&size=10", "t17a", resp={"n": 10}),
        ex("GET", P + "/rankings?offset=40&size=5", "t17b", resp={"n": 5}),
    ],
    negatives=["ranking", "offset", "size"],
)
scenario(
    "T18",
    "incomplete-captures",
    "negative",
    "Only one session ever captured for kiosks",
    [ex("PATCH", P + "/kiosks/41801", "t18a", body={"label": "x"}, resp={"ok": 1})],
    negatives=["kiosk"],
)
scenario(
    "T19",
    "shared-ids",
    "negative",
    "Same bin id in the same position for both sessions on a two-level path",
    [
        ex("GET", P + "/stores/41900/bins/41901", "t19a", resp={"ok": 1}),
        ex("GET", P + "/stores/41900/bins/41901", "t19b", resp={"ok": 1}),
    ],
    negatives=["store", "bin"],
)
scenario(
    "T20",
    "numeric-collision",
    "positive",
    "Two typed request fields on one endpoint; numeric values collide across kinds",
    [
        ex("POST", P + "/links", "t20a", body={"editor_id": 42001, "topic_id": 42002}, resp={"ok": 1}),
        ex("POST", P + "/links", "t20b", body={"editor_id": 42002, "topic_id": 42001}, resp={"ok": 1}),
    ],
    positives=["editor", "topic"],
    vuln_truth="vulnerable",
)

# ---------------- ambiguous ----------------
scenario(
    "T21",
    "ambiguous",
    "ambiguous",
    "Bare id under generic `data` wrapper vs path id in another session",
    [
        ex("GET", P + "/feed", "t21a", resp={"data": {"id": 42101}}),
        ex("GET", P + "/notes/42102", "t21b", resp={"ok": 1}),
    ],
    ambiguous=["note"],
)
scenario(
    "T22",
    "ambiguous",
    "ambiguous",
    "Generic `entity_id` parameter, kind unknown",
    [
        ex("GET", P + "/resolve?entity_id=42201", "t22a", resp={"ok": 1}),
        ex("GET", P + "/resolve?entity_id=42202", "t22b", resp={"ok": 1}),
    ],
    ambiguous=["entity", "resolve"],
)
scenario(
    "T23",
    "shared-ids",
    "ambiguous",
    "Tag id arrays overlap partially across sessions",
    [
        ex("POST", P + "/tags/apply", "t23a", body={"tag_ids": [42301, 42302]}, resp={"ok": 1}),
        ex("POST", P + "/tags/apply", "t23b", body={"tag_ids": [42302, 42303]}, resp={"ok": 1}),
    ],
    ambiguous=["tag"],
)
scenario(
    "T24",
    "hierarchical-permissions",
    "ambiguous",
    "Clinician vs patient reading patient charts; policy unknown",
    [
        ex("GET", P + "/patients/42401", "t24doc", resp={"view": "clinician"}),
        ex("GET", P + "/patients/42402", "t24pat", resp={"view": "self"}),
    ],
    ambiguous=["patient"],
    vuln_truth="unknown",
)


def build(out: Path) -> None:
    out.mkdir(parents=True, exist_ok=True)
    har = {
        "log": {
            "version": "1.2",
            "creator": {"name": "bbtk-adversarial-eval-adv11", "version": CORPUS_VERSION},
            "entries": ENTRIES,
        }
    }
    gt = {
        "corpus_version": CORPUS_VERSION,
        "split": "adversarial-frozen",
        "tuning_policy": "FROZEN. Do not tune detection rules against this corpus. Authored before the open-vocabulary logic was run on it; final evaluation only.",
        "independent_of": [
            "labs/object_discovery_lab/dev",
            "labs/object_discovery_lab/eval",
            "labs/adversarial_idor_eval/frozen (adv-1.0)",
        ],
        "origin": ORIGIN,
        "scenarios": SCENARIOS,
    }
    files = {
        "captures.har": json.dumps(har, indent=1, sort_keys=True) + "\n",
        "ground_truth.json": json.dumps(gt, indent=1, sort_keys=True) + "\n",
    }
    for name, text in files.items():
        (out / name).write_text(text, encoding="utf-8")
    manifest = "".join(f"{hashlib.sha256(t.encode()).hexdigest()}  {n}\n" for n, t in sorted(files.items()))
    (out / "MANIFEST.sha256").write_text(manifest, encoding="utf-8")


if __name__ == "__main__":
    build(Path(__file__).resolve().parent / "frozen_adv11")
