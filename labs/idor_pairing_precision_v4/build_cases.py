"""Author DEV and FINAL compatibility cases from the behavioural spec.

Labels are the expected decisions for each synthetic pair. They are not copied
from evaluator output. Run this module to rewrite the JSON splits, then refresh
MANIFEST.sha256 before any FINAL measurement.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
MARKER = "SYNTH_PRIVATE_MARKER"
# Dedicated loopback. 8177/8178 belong to the independent-research corpus and
# 8191 belongs to the context-fuzz and kind-lineage labs. Those markers must
# not appear in this lab's JSON or the historical-overlap guard fails.
ORIGIN = "http://127.0.0.1:8194"
ALT_ORIGIN = "http://127.0.0.1:8195"


def _body(kind: str, oid: str, *, extra: dict[str, object] | None = None, note: str | None = None) -> str:
    payload: dict[str, object] = {"id": oid, "owner_label": "SYNTH_OWNER"}
    if note:
        payload["note"] = note
    if extra:
        payload.update(extra)
    return json.dumps({"ok": True, kind: payload}, sort_keys=True)


def _side(role: str, **overrides: object) -> dict[str, object]:
    kind = "order"
    oid = "7"
    base: dict[str, object] = {
        "evidence_ref": f"ev-{role}",
        "method": "GET",
        "url": f"{ORIGIN}/{kind}s/{oid}",
        "origin": ORIGIN,
        "program": "synth-lab",
        "resource_kind": kind,
        "kind_status": "explicit",
        "resource_namespace": f"{ORIGIN}|{kind}",
        "resource_id": oid,
        "parent_ids": [],
        "endpoint_template": f"/{kind}s/{{id}}",
        "account_ref": f"acct:SYNTH_{role.upper()}",
        "session_ref": f"sess:SYNTH_{role.upper()}",
        "batch_id": "batch-1",
        "continuity_declared": True,
        "captured_at": "2026-10-01T00:00:00+00:00",
        "temporal_not_before": "2026-09-01T00:00:00+00:00",
        "temporal_not_after": "2026-11-01T00:00:00+00:00",
        "stale": False,
        "response_present": True,
        "status_code": 200,
        "response_body": _body(kind, oid, note=MARKER if role == "owner" else None),
        "response_headers": {"content-type": "application/json"},
        "request_headers": {"authorization": f"Bearer SYNTH_{role.upper()}"},
        "integrity_sha256": "sha256:intact",
        "artifact_sha256": "sha256:intact",
        "array_object_ids": [],
        "query_id_values": [],
    }
    base.update(overrides)
    return base


def _case(
    case_id: str,
    compatibility: str,
    *,
    valid_pair: bool,
    tags: list[str],
    owner: dict[str, object] | None = None,
    actor: dict[str, object] | None = None,
    alias_rules: list[list[str]] | None = None,
    note: str,
) -> dict[str, object]:
    return {
        "id": case_id,
        "note": note,
        "tags": tags,
        "valid_pair": valid_pair,
        "expected_compatibility": compatibility,
        "expected_pairing_decision": compatibility == "compatible",
        "alias_rules": alias_rules or [],
        "owner": _side("owner", **(owner or {})),
        "actor": _side("actor", **(actor or {})),
    }


def dev_cases() -> list[dict[str, object]]:
    return [
        _case(
            "DEV-same-instance",
            "compatible",
            valid_pair=True,
            tags=["positive"],
            owner={"resource_id": "11", "url": f"{ORIGIN}/orders/11"},
            actor={"resource_id": "11", "url": f"{ORIGIN}/orders/11"},
            note="DEV positive: one order id, two attested accounts.",
        ),
        _case(
            "DEV-cross-kind",
            "incompatible",
            valid_pair=False,
            tags=["cross_kind"],
            owner={
                "resource_kind": "user",
                "resource_id": "42",
                "resource_namespace": f"{ORIGIN}|user",
                "endpoint_template": "/users/{id}",
                "url": f"{ORIGIN}/users/42",
            },
            actor={
                "resource_kind": "order",
                "resource_id": "42",
                "resource_namespace": f"{ORIGIN}|order",
                "endpoint_template": "/orders/{id}",
                "url": f"{ORIGIN}/orders/42",
            },
            note="DEV negative: same digits, different kind.",
        ),
        _case(
            "DEV-missing-response",
            "insufficient_evidence",
            valid_pair=False,
            tags=["abstain"],
            actor={"response_present": False, "response_body": "", "status_code": None},
            note="DEV negative: actor response artifact absent.",
        ),
        _case(
            "DEV-json-equivalent",
            "compatible",
            valid_pair=True,
            tags=["positive", "json"],
            owner={"response_body": '{"ok":true,"order":{"id":"11","owner_label":"SYNTH_OWNER"}}'},
            actor={"response_body": '{"order":{"owner_label":"SYNTH_OWNER","id":"11"},"ok":true}'},
            note="DEV control: reordered JSON must stay compatible.",
        ),
        _case(
            "DEV-shared",
            "incompatible",
            valid_pair=False,
            tags=["shared"],
            owner={"response_body": '{"acl":"shared","ok":true,"order":{"id":"7","shared_with":["a"]}}'},
            actor={"response_body": '{"acl":"shared","ok":true,"order":{"id":"7","shared_with":["a"]}}'},
            note="DEV negative: shared ACL.",
        ),
    ]


def final_cases() -> list[dict[str, object]]:
    denial = '{"error":"not_authorized","ok":false,"order":null}'
    echo = '{"id":"7","ok":true}'
    shared = '{"acl":"shared","ok":true,"order":{"id":"7","shared_with":["owner","actor"]}}'
    return [
        _case("FIN-same-instance", "compatible", valid_pair=True, tags=["positive"], note="Same order id, distinct accounts, private bodies."),
        _case(
            "FIN-json-equivalent",
            "compatible",
            valid_pair=True,
            tags=["positive", "json"],
            owner={"response_body": '{"ok":true,"order":{"id":"7","owner_label":"SYNTH_OWNER"}}'},
            actor={"response_body": '{"order":{"owner_label":"SYNTH_OWNER","id":"7"},"ok":true}'},
            note="Dual JSON serialization of one payload.",
        ),
        _case(
            "FIN-alias-route",
            "compatible",
            valid_pair=True,
            tags=["positive", "alias"],
            owner={"url": f"{ORIGIN}/api/v1/orders/7", "endpoint_template": "/api/v1/orders/{id}"},
            actor={"url": f"{ORIGIN}/orders/7", "endpoint_template": "/orders/{id}"},
            alias_rules=[["/api/v1", ""]],
            note="Declared alias /api/v1/orders/7 and /orders/7.",
        ),
        _case(
            "FIN-nested-same-leaf",
            "compatible",
            valid_pair=True,
            tags=["positive", "nested"],
            owner={
                "resource_kind": "comment",
                "resource_namespace": f"{ORIGIN}|comment",
                "resource_id": "75311",
                "parent_ids": ["75301"],
                "endpoint_template": "/posts/{id}/comments/{id}",
                "url": f"{ORIGIN}/posts/75301/comments/75311",
                "response_body": _body("comment", "75311"),
            },
            actor={
                "resource_kind": "comment",
                "resource_namespace": f"{ORIGIN}|comment",
                "resource_id": "75311",
                "parent_ids": ["75301"],
                "endpoint_template": "/posts/{id}/comments/{id}",
                "url": f"{ORIGIN}/posts/75301/comments/75311",
                "response_body": _body("comment", "75311"),
            },
            note="Same comment id under the same parent post.",
        ),
        _case(
            "FIN-cross-kind",
            "incompatible",
            valid_pair=False,
            tags=["cross_kind", "hard_negative"],
            owner={"resource_kind": "user", "resource_id": "42", "resource_namespace": f"{ORIGIN}|user",
                   "endpoint_template": "/users/{id}", "url": f"{ORIGIN}/users/42",
                   "response_body": _body("user", "42")},
            actor={"resource_kind": "order", "resource_id": "42", "resource_namespace": f"{ORIGIN}|order",
                   "endpoint_template": "/orders/{id}", "url": f"{ORIGIN}/orders/42"},
            note="Hard negative 1: /users/42 vs /orders/42.",
        ),
        _case(
            "FIN-same-account",
            "incompatible",
            valid_pair=False,
            tags=["hard_negative"],
            actor={"account_ref": "acct:SYNTH_OWNER", "session_ref": "sess:SYNTH_OTHER"},
            note="Hard negative 4: same account, two sessions.",
        ),
        _case(
            "FIN-shared",
            "incompatible",
            valid_pair=False,
            tags=["hard_negative", "shared"],
            owner={"response_body": shared},
            actor={"response_body": shared},
            note="Hard negative 5: legitimate shared ACL.",
        ),
        _case(
            "FIN-missing-response",
            "insufficient_evidence",
            valid_pair=False,
            tags=["hard_negative", "abstain"],
            actor={"response_present": False, "response_body": "", "status_code": None},
            note="Hard negative 6: missing response artifact.",
        ),
        _case(
            "FIN-denial-200",
            "incompatible",
            valid_pair=False,
            tags=["hard_negative"],
            owner={"response_body": denial},
            actor={"response_body": denial},
            note="Hard negative 7: HTTP 200 authorization denial.",
        ),
        _case(
            "FIN-id-echo",
            "insufficient_evidence",
            valid_pair=False,
            tags=["hard_negative", "abstain"],
            owner={"response_body": echo},
            actor={"response_body": echo},
            note="Hard negative 8: id echo only.",
        ),
        _case(
            "FIN-temporal",
            "incompatible",
            valid_pair=False,
            tags=["hard_negative"],
            actor={
                "temporal_not_before": "2027-01-01T00:00:00+00:00",
                "temporal_not_after": "2027-02-01T00:00:00+00:00",
                "captured_at": "2027-01-15T00:00:00+00:00",
            },
            note="Hard negative 9: disjoint temporal windows.",
        ),
        _case(
            "FIN-stale",
            "incompatible",
            valid_pair=False,
            tags=["hard_negative"],
            owner={"stale": True},
            note="Hard negative 9: stale evidence.",
        ),
        _case(
            "FIN-ambiguous-kind",
            "insufficient_evidence",
            valid_pair=False,
            tags=["hard_negative", "abstain"],
            owner={"kind_status": "unknown"},
            actor={"kind_status": "ambiguous"},
            note="Hard negative 10: unknown and ambiguous kinds.",
        ),
        _case(
            "FIN-tamper",
            "conflicting_evidence",
            valid_pair=False,
            tags=["hard_negative", "abstain"],
            actor={"artifact_sha256": "sha256:tampered"},
            note="Hard negative 11: integrity hash mismatch.",
        ),
        _case(
            "FIN-mixed-origin",
            "incompatible",
            valid_pair=False,
            tags=["hard_negative", "cross_program"],
            actor={
                "origin": f"{ALT_ORIGIN}",
                "url": f"{ALT_ORIGIN}/orders/7",
                "resource_namespace": f"{ALT_ORIGIN}|order",
            },
            note="Hard negative 12: mixed origins.",
        ),
        _case(
            "FIN-mixed-program",
            "incompatible",
            valid_pair=False,
            tags=["hard_negative", "cross_program"],
            actor={"program": "other-synth-lab"},
            note="Hard negative 12: artifacts from different programs.",
        ),
        _case(
            "FIN-partial-array",
            "incompatible",
            valid_pair=False,
            tags=["hard_negative"],
            owner={"resource_id": "9", "array_object_ids": ["1", "2"], "endpoint_template": "/batches/{id}",
                   "url": f"{ORIGIN}/batches/9", "response_body": _body("batch", "9")},
            actor={"resource_id": "10", "array_object_ids": ["1", "3"], "endpoint_template": "/batches/{id}",
                   "url": f"{ORIGIN}/batches/10", "response_body": _body("batch", "10")},
            note="Hard negative 13: partial object-array overlap.",
        ),
        _case(
            "FIN-batch",
            "insufficient_evidence",
            valid_pair=False,
            tags=["hard_negative", "abstain"],
            owner={"continuity_declared": False},
            actor={"batch_id": "batch-2", "continuity_declared": False},
            note="Hard negative 14: different batches, no continuity.",
        ),
        _case(
            "FIN-contradiction",
            "conflicting_evidence",
            valid_pair=False,
            tags=["hard_negative", "abstain"],
            actor={"response_body": '{"error":"forbidden","ok":false}', "status_code": 200},
            note="Hard negative 15: one side access, the other a denial.",
        ),
        _case(
            "FIN-distinct-instances",
            "incompatible",
            valid_pair=False,
            tags=["distinct_instance"],
            actor={"resource_id": "8", "url": f"{ORIGIN}/orders/8", "response_body": _body("order", "8")},
            note="Different order ids are not the same resource.",
        ),
    ]


def _manifest(split: str, blob: bytes) -> None:
    digest = hashlib.sha256(blob).hexdigest()
    text = f"{digest}  cases.json\n"
    (HERE / split / "MANIFEST.sha256").write_text(text, encoding="utf-8")


def write_splits() -> None:
    for name, cases in (("dev", dev_cases()), ("final", final_cases())):
        folder = HERE / name
        folder.mkdir(parents=True, exist_ok=True)
        blob = (json.dumps({"split": name, "cases": cases}, indent=2, sort_keys=True) + "\n").encode()
        (folder / "cases.json").write_bytes(blob)
        _manifest(name, blob)


def check_splits() -> list[str]:
    """Return mismatches against the committed manifest. Does not rewrite files."""
    bad: list[str] = []
    for name in ("dev", "final"):
        path = HERE / name / "cases.json"
        manifest = HERE / name / "MANIFEST.sha256"
        if not path.is_file() or not manifest.is_file():
            bad.append(f"{name}:missing")
            continue
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        listed = manifest.read_text(encoding="utf-8").split()[0]
        if digest != listed:
            bad.append(f"{name}:hash")
        expected = {"dev": dev_cases(), "final": final_cases()}[name]
        actual = json.loads(path.read_text(encoding="utf-8"))["cases"]
        if actual != expected:
            bad.append(f"{name}:generator")
    return bad


if __name__ == "__main__":
    import sys

    if "--check" in sys.argv:
        mismatches = check_splits()
        if mismatches:
            print("mismatch", ",".join(mismatches))
            raise SystemExit(1)
        print("ok")
    else:
        write_splits()
        print("wrote dev and final")
