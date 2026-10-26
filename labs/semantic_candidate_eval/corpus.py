"""DEV / FINAL synthetic corpora for semantic candidate correlation.

Each scenario is a self-contained synthetic program directory: an Evidence
Ledger plus local evidence JSON files carrying explicit annotations
(``bbtk-candidate-correlation/1`` / ``bbtk-control-annotation/1``). Labels
(``duplicate_pairs``, ``expected_reuse``) are written from the scenario
specification — what the synthetic application *is* — and never from the
output of the correlation engine. Literal object IDs, paths and cookie-like
strings include canaries so that leaks can be detected in the report.

No network traffic and no live captures. Synthetic only.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Callable

CORR = "bbtk-candidate-correlation/1"
CTRL = "bbtk-control-annotation/1"
NOW = "2026-10-26T12:00:00Z"
FP = "fp-v1"
CANARY = "CANARY-SEMDEDUP-7f3a"


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class Program:
    """Tiny builder for one synthetic program ledger."""

    def __init__(self, root: Path, name: str) -> None:
        self.name = name
        self.dir = root / name
        self.surfaces: list[dict[str, Any]] = []
        self.evidence: list[dict[str, Any]] = []
        self.candidates: list[dict[str, Any]] = []
        self._tamper: list[Path] = []

    def surface(self, sid: str, ref: str, *, fingerprint: str = FP) -> None:
        self.surfaces.append(
            {"surface_id": sid, "kind": "endpoint", "ref": ref, "status": "investigated", "fingerprint": fingerprint}
        )

    def ev(
        self,
        eid: str,
        *,
        corr: dict[str, Any] | None = None,
        control: dict[str, Any] | None = None,
        graph: list[str] | None = None,
        investigation: str | None = None,
        body: str = "synthetic",
        stale: bool = False,
        tamper: bool = False,
    ) -> None:
        payload: dict[str, Any] = {"body": body, "cookie": f"session={CANARY}-cookie"}
        if corr is not None:
            payload["correlation"] = {"annotation_version": CORR, **corr}
        if control is not None:
            payload["control"] = {"annotation_version": CTRL, **control}
        rel = f"evidence/{eid}.json"
        path = self.dir / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload, sort_keys=True, indent=2) + "\n", encoding="utf-8")
        prov: dict[str, Any] = {"tool": "synthetic-lab", "captured_at": NOW}
        if graph:
            prov["graph_node_ids"] = graph
        if investigation:
            prov["investigation_id"] = investigation
        self.evidence.append(
            {
                "evidence_id": eid,
                "path": rel,
                "sha256": _sha(path),
                "surface_fingerprint": "fp-v0" if stale else FP,
                "provenance": prov,
            }
        )
        if tamper:
            self._tamper.append(path)

    def cand(
        self, cid: str, sid: str, category: str, refs: list[str], *, state: str = "candidate", **extra: Any
    ) -> None:
        row: dict[str, Any] = {
            "candidate_id": cid,
            "surface_id": sid,
            "category": category,
            "title": cid,
            "state": state,
            "evidence_refs": refs,
            "raised_by": "analyst",
        }
        if state == "rejected":
            row["rejection"] = {"reason": "false_positive", "detail": "synthetic rejection"}
            row.setdefault("review", {"reviewer": "rev", "method": "human_manual", "basis": "lab", "reviewed_at": NOW})
        if state == "requires_validation":
            row["blockers"] = ["awaiting review"]
        row.update(extra)
        self.candidates.append(row)

    def write(self) -> str:
        ledger = {
            "schema_version": "bbtk-evidence-ledger/1",
            "program": self.name,
            "updated_at": NOW,
            "surfaces": self.surfaces,
            "evidence": self.evidence,
            "candidates": self.candidates,
        }
        for path in self._tamper:
            path.write_text(path.read_text(encoding="utf-8").replace("synthetic", "altered!!"), encoding="utf-8")
        path = self.dir / "ledger" / "evidence-ledger.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(ledger, sort_keys=True, indent=2) + "\n", encoding="utf-8")
        return _sha(path)


def obj(ns: str, ident: str) -> dict[str, str]:
    return {"namespace": ns, "id": ident}


def read(path: str, objects: list[dict[str, str]], **kw: Any) -> dict[str, Any]:
    return {"method": "GET", "path_template": path, "objects": objects, "operation": "read", **kw}


Scenario = Callable[[Path, str, str], dict[str, Any]]

# ----------------------------------------------------------------------------------- DEV


def d_true_dup(root: Path, name: str, v: str) -> dict[str, Any]:
    p = Program(root, name)
    p.surface("s1", "GET /api/invoices/{id}")
    o = [obj("invoice", f"{CANARY}-501")]
    p.ev("e1", corr=read("/api/invoices/501", o, root_cause="missing_tenant_check", actor_role="customer"))
    p.ev("e2", corr=read("/api/invoices/{id}", o, root_cause="missing_tenant_check", actor_role="customer"))
    p.cand("c1", "s1", "idor", ["e1"], dedup_key="k-a")
    p.cand("c2", "s1", "bola", ["e2"], dedup_key="k-b")
    return {"programs": [p], "duplicate_pairs": [["c1", "c2"]], "family": "true_duplicate", "adversarial": False}


def d_same_path_diff_vuln(root: Path, name: str, v: str) -> dict[str, Any]:
    p = Program(root, name)
    p.surface("s1", "GET /api/search")
    p.ev("e1", corr={"method": "GET", "path_template": "/api/search", "root_cause": "reflected_param"})
    p.ev("e2", corr={"method": "GET", "path_template": "/api/search", "root_cause": "sql_concat"})
    p.cand("c1", "s1", "xss", ["e1"])
    p.cand("c2", "s1", "sqli", ["e2"])
    return {"programs": [p], "duplicate_pairs": [], "family": "same_path_different_vuln", "adversarial": True}


def d_same_id_ns(root: Path, name: str, v: str) -> dict[str, Any]:
    p = Program(root, name)
    p.surface("s1", "GET /api/files/{id}")
    p.ev("e1", corr=read("/api/files/{id}", [obj("file", f"{CANARY}-42")], root_cause="missing_owner_check"))
    p.ev("e2", corr=read("/api/files/{id}", [obj("folder", f"{CANARY}-42")], root_cause="missing_owner_check"))
    p.cand("c1", "s1", "idor", ["e1"])
    p.cand("c2", "s1", "idor", ["e2"], dedup_key="other")
    return {"programs": [p], "duplicate_pairs": [], "family": "same_id_different_namespace", "adversarial": True}


def d_diff_role(root: Path, name: str, v: str) -> dict[str, Any]:
    p = Program(root, name)
    p.surface("s1", "GET /api/reports/{id}")
    o = [obj("report", "9")]
    p.ev("e1", corr=read("/api/reports/{id}", o, actor_role="viewer", required_permission="reports:read"))
    p.ev("e2", corr=read("/api/reports/{id}", o, actor_role="auditor", required_permission="reports:audit"))
    p.cand("c1", "s1", "idor", ["e1"])
    p.cand("c2", "s1", "idor", ["e2"])
    return {"programs": [p], "duplicate_pairs": [], "family": "different_role_permission", "adversarial": True}


def d_rejected_new(root: Path, name: str, v: str) -> dict[str, Any]:
    p = Program(root, name)
    p.surface("s1", "GET /api/carts/{id}")
    o = [obj("cart", "77")]
    p.ev("e1", corr=read("/api/carts/{id}", o, root_cause="missing_owner_check"))
    p.ev("e2", corr=read("/api/carts/{id}", o, root_cause="missing_owner_check"))
    p.cand("c1", "s1", "idor", ["e1"], state="rejected")
    p.cand("c2", "s1", "idor", ["e2"])
    return {"programs": [p], "duplicate_pairs": [], "family": "rejected_and_new", "adversarial": True}


def d_stale(root: Path, name: str, v: str) -> dict[str, Any]:
    p = Program(root, name)
    p.surface("s1", "GET /api/notes/{id}")
    o = [obj("note", "3")]
    p.ev("e1", corr=read("/api/notes/{id}", o, root_cause="missing_owner_check"), stale=True)
    p.ev("e2", corr=read("/api/notes/{id}", o, root_cause="missing_owner_check"))
    p.cand("c1", "s1", "idor", ["e1"])
    p.cand("c2", "s1", "idor", ["e2"], dedup_key="n2")
    return {"programs": [p], "duplicate_pairs": [], "family": "stale_evidence", "adversarial": True}


def d_group(root: Path, name: str, v: str) -> dict[str, Any]:
    p = Program(root, name)
    p.surface("s1", "GET /api/tickets/{id}")
    o = [obj("ticket", "12")]
    for i in (1, 2, 3):
        p.ev(f"e{i}", corr=read("/api/tickets/{id}", o, control_type="tenant_scope"))
        p.cand(f"c{i}", "s1", "idor", [f"e{i}"], dedup_key=f"t{i}")
    return {
        "programs": [p],
        "duplicate_pairs": [["c1", "c2"], ["c1", "c3"], ["c2", "c3"]],
        "family": "group",
        "adversarial": False,
    }


def d_cross_program(root: Path, name: str, v: str) -> dict[str, Any]:
    out = []
    for suffix in ("a", "b"):
        p = Program(root, f"{name}-{suffix}")
        p.surface("s1", "GET /api/orders/{id}")
        p.ev("e1", corr=read("/api/orders/{id}", [obj("order", "1")], root_cause="missing_owner_check"))
        p.cand("c1", "s1", "idor", ["e1"])
        out.append(p)
    return {
        "programs": out,
        "duplicate_pairs": [],
        "family": "different_programs",
        "adversarial": True,
        "cross_program": True,
    }


DEV: list[tuple[str, Scenario]] = [
    ("true_duplicate", d_true_dup),
    ("same_path_diff_vuln", d_same_path_diff_vuln),
    ("same_id_diff_namespace", d_same_id_ns),
    ("different_role", d_diff_role),
    ("rejected_and_new", d_rejected_new),
    ("stale_evidence", d_stale),
    ("group_of_three", d_group),
    ("cross_program", d_cross_program),
]

# --------------------------------------------------------------------------------- FINAL
# Written from the scenario list in the task spec; different resources, values and
# shapes from DEV. Frozen with SHA-256 before the first FINAL evaluation.


def f_true_dup(root: Path, name: str, v: str) -> dict[str, Any]:
    p = Program(root, name)
    p.surface("s-ship", "GET /v2/shipments/{shipmentId}")
    o = [obj("shipment", "8d1f3c2a-0000-4000-8000-00000000abcd")]
    neg = {"role": "negative_control", "contradicts_hypothesis": False}
    p.ev("e-a", corr=read("/v2/shipments/8d1f3c2a-0000-4000-8000-00000000abcd", o, control_type="tenant_scope"))
    p.ev("e-b", corr=read("/v2/shipments/{shipmentId}", o, control_type="tenant_scope"))
    p.ev("e-neg", control=neg)
    p.cand("dup-1", "s-ship", "BOLA", ["e-a", "e-neg"])
    p.cand("dup-2", "s-ship", "idor", ["e-b"], dedup_key="manual-2")
    return {
        "programs": [p],
        "duplicate_pairs": [["dup-1", "dup-2"]],
        "expected_reuse": [["dup-2", "reuse_negative_control"]],
        "family": "true_duplicate",
        "adversarial": False,
    }


def f_same_path_diff_vuln(root: Path, name: str, v: str) -> dict[str, Any]:
    p = Program(root, name)
    p.surface("s-prof", "PUT /api/profile/{id}")
    o = [obj("profile", "55")]
    p.ev(
        "e1",
        corr={**read("/api/profile/{id}", o), "method": "PUT", "operation": "update", "root_cause": "mass_assignment"},
    )
    p.ev(
        "e2",
        corr={
            **read("/api/profile/{id}", o),
            "method": "PUT",
            "operation": "update",
            "root_cause": "missing_csrf_token",
        },
    )
    p.cand("x1", "s-prof", "mass_assignment", ["e1"])
    p.cand("x2", "s-prof", "csrf", ["e2"])
    return {"programs": [p], "duplicate_pairs": [], "family": "same_path_different_vuln", "adversarial": True}


def f_same_cat_diff_objects(root: Path, name: str, v: str) -> dict[str, Any]:
    p = Program(root, name)
    p.surface("s-doc", "GET /api/documents/{id}")
    p.ev("e1", corr=read("/api/documents/{id}", [obj("document", "1001")], control_type="owner_check"))
    p.ev("e2", corr=read("/api/documents/{id}", [obj("document", "2002")], control_type="owner_check"))
    p.cand("d1", "s-doc", "idor", ["e1"])
    p.cand("d2", "s-doc", "idor", ["e2"], dedup_key="d2")
    return {"programs": [p], "duplicate_pairs": [], "family": "same_category_different_objects", "adversarial": True}


def f_same_id_ns(root: Path, name: str, v: str) -> dict[str, Any]:
    p = Program(root, name)
    p.surface("s-gen", "GET /api/{kind}/{id}")
    p.ev("e1", corr=read("/api/users/{id}", [obj("user", f"{CANARY}-7")], root_cause="missing_owner_check"))
    p.ev("e2", corr=read("/api/users/{id}", [obj("organization", f"{CANARY}-7")], root_cause="missing_owner_check"))
    p.cand("n1", "s-gen", "idor", ["e1"])
    p.cand("n2", "s-gen", "idor", ["e2"], dedup_key="n2")
    return {"programs": [p], "duplicate_pairs": [], "family": "same_id_different_namespace", "adversarial": True}


def f_same_obj_diff_captures(root: Path, name: str, v: str) -> dict[str, Any]:
    p = Program(root, name)
    p.surface("s-har", "GET /api/payslips/{id}")
    p.surface("s-burp", "GET /api/payslips/{id}")
    o = [obj("payslip", "31")]
    p.ev("e-har", corr=read("/api/payslips/31", o, root_cause="missing_owner_check"), graph=["obj-payslip-31"])
    p.ev("e-burp", corr=read("/api/payslips/{id}", o, root_cause="missing_owner_check"), graph=["obj-payslip-31"])
    p.cand("cap-har", "s-har", "idor", ["e-har"])
    p.cand("cap-burp", "s-burp", "idor", ["e-burp"])
    return {
        "programs": [p],
        "duplicate_pairs": [["cap-burp", "cap-har"]],
        "family": "same_object_different_captures",
        "adversarial": False,
    }


def f_same_request_times(root: Path, name: str, v: str) -> dict[str, Any]:
    p = Program(root, name)
    p.surface("s-st", "GET /api/statements/{id}")
    o = [obj("statement", "2026-01")]
    att = {"role": "owner_response", "ownership": "attested"}
    p.ev(
        "e-mon", corr=read("/api/statements/{id}", o, control_type="account_scope"), control=att, investigation="inv-1"
    )
    p.ev("e-tue", corr=read("/api/statements/{id}", o, control_type="account_scope"), body="synthetic tuesday")
    p.cand("t-mon", "s-st", "idor", ["e-mon"])
    p.cand("t-tue", "s-st", "idor", ["e-tue"], dedup_key="tue")
    return {
        "programs": [p],
        "duplicate_pairs": [["t-mon", "t-tue"]],
        "expected_reuse": [["t-tue", "reuse_ownership_attestation"], ["t-tue", "consult_prior_investigation"]],
        "family": "same_request_different_times",
        "adversarial": False,
    }


def f_shared_resource(root: Path, name: str, v: str) -> dict[str, Any]:
    p = Program(root, name)
    p.surface("s-team", "GET /api/team-boards/{id}")
    o = [obj("board", "shared-1")]
    vis = {"role": "actor_response", "resource_visibility": "shared"}
    p.ev("e1", corr=read("/api/team-boards/{id}", o, control_type="membership"), control=vis)
    p.ev("e2", corr=read("/api/team-boards/{id}", o, control_type="membership"))
    p.cand("sh1", "s-team", "idor", ["e1"])
    p.cand("sh2", "s-team", "idor", ["e2"], dedup_key="sh2")
    return {"programs": [p], "duplicate_pairs": [], "family": "legitimately_shared_resource", "adversarial": True}


def f_diff_role_perm(root: Path, name: str, v: str) -> dict[str, Any]:
    p = Program(root, name)
    p.surface("s-adm", "DELETE /api/projects/{id}")
    o = [obj("project", "4")]
    base = {"method": "DELETE", "path_template": "/api/projects/{id}", "objects": o, "operation": "delete"}
    p.ev("e1", corr={**base, "actor_role": "member", "required_permission": "project:delete"})
    p.ev("e2", corr={**base, "actor_role": "guest", "required_permission": "project:read"})
    p.cand("r1", "s-adm", "bfla", ["e1"])
    p.cand("r2", "s-adm", "bfla", ["e2"], dedup_key="r2")
    return {"programs": [p], "duplicate_pairs": [], "family": "different_role_permission", "adversarial": True}


def f_rejected_new(root: Path, name: str, v: str) -> dict[str, Any]:
    p = Program(root, name)
    p.surface("s-coupon", "GET /api/coupons/{code}")
    o = [obj("coupon", "SPRING")]
    p.ev("e-old", corr=read("/api/coupons/{code}", o, control_type="public_catalog"))
    p.ev("e-new", corr=read("/api/coupons/{code}", o, control_type="public_catalog"))
    p.cand("old", "s-coupon", "idor", ["e-old"], state="rejected")
    p.cand("new", "s-coupon", "idor", ["e-new"])
    return {"programs": [p], "duplicate_pairs": [], "family": "rejected_and_new", "adversarial": True}


def f_invalid_evidence(root: Path, name: str, v: str) -> dict[str, Any]:
    p = Program(root, name)
    p.surface("s-msg", "GET /api/messages/{id}", fingerprint="fp-v1")
    o = [obj("message", "88")]
    p.ev("e-stale", corr=read("/api/messages/{id}", o, root_cause="missing_owner_check"), stale=True)
    p.ev("e-tamp", corr=read("/api/messages/{id}", o, root_cause="missing_owner_check"), tamper=True)
    p.ev("e-ok", corr=read("/api/messages/{id}", o, root_cause="missing_owner_check"))
    p.cand("m-stale", "s-msg", "idor", ["e-stale"])
    p.cand("m-tamp", "s-msg", "idor", ["e-tamp"], dedup_key="m2")
    p.cand("m-broken", "s-msg", "idor", ["e-missing"], dedup_key="m3")
    p.cand("m-ok", "s-msg", "idor", ["e-ok"], dedup_key="m4")
    return {"programs": [p], "duplicate_pairs": [], "family": "stale_or_invalid_evidence", "adversarial": True}


def f_ambiguous_sessions(root: Path, name: str, v: str) -> dict[str, Any]:
    p = Program(root, name)
    p.surface("s-acct", "GET /api/accounts/{id}")
    o = [obj("account", "600")]
    p.ev("e1", corr=read("/api/accounts/{id}", o, control_type="account_scope", session_ambiguous=True))
    p.ev("e2", corr=read("/api/accounts/{id}", o, control_type="account_scope", session_ambiguous=True))
    p.cand("a1", "s-acct", "idor", ["e1"])
    p.cand("a2", "s-acct", "idor", ["e2"], dedup_key="a2")
    return {"programs": [p], "duplicate_pairs": [], "family": "ambiguous_sessions", "adversarial": True}


def f_cross_program(root: Path, name: str, v: str) -> dict[str, Any]:
    out = []
    for suffix in ("left", "right"):
        p = Program(root, f"{name}-{suffix}")
        p.surface("s-same", "GET /api/wallets/{id}")
        p.ev("e1", corr=read("/api/wallets/{id}", [obj("wallet", "5")], control_type="owner_check"))
        p.cand("w1", "s-same", "idor", ["e1"])
        out.append(p)
    return {
        "programs": out,
        "duplicate_pairs": [],
        "family": "different_programs",
        "adversarial": True,
        "cross_program": True,
    }


def f_near_identical_cause(root: Path, name: str, v: str) -> dict[str, Any]:
    p = Program(root, name)
    p.surface("s-exp", "GET /api/exports/{id}")
    o = [obj("export", "e-19")]
    p.ev("e1", corr=read("/api/exports/{id}", o, control_type="owner_check", root_cause="cache_key_missing_user"))
    p.ev("e2", corr=read("/api/exports/{id}", o, control_type="owner_check", root_cause="missing_owner_check"))
    p.cand("nx1", "s-exp", "idor", ["e1"])
    p.cand("nx2", "s-exp", "idor", ["e2"], dedup_key="nx2")
    return {"programs": [p], "duplicate_pairs": [], "family": "near_identical_different_cause", "adversarial": True}


def f_noise_dups(root: Path, name: str, v: str) -> dict[str, Any]:
    p = Program(root, name)
    p.surface("s-rx", "GET /api/prescriptions/{id}")
    for i in range(6):
        p.surface(f"s-noise{i}", f"GET /api/noise{i}/{{id}}")
        p.ev(f"e-n{i}", corr=read(f"/api/noise{i}/{{id}}", [obj("noise", str(i))], control_type="owner_check"))
        p.cand(f"noise-{i}", f"s-noise{i}", "idor", [f"e-n{i}"])
    o = [obj("prescription", "rx-1")]
    p.ev("e-x", corr=read("/api/prescriptions/{id}", o, root_cause="missing_owner_check"), graph=["obj-rx-1"])
    p.ev("e-y", corr=read("/api/prescriptions/rx-1", o, root_cause="missing_owner_check"))
    p.cand("aa-rx", "s-rx", "idor", ["e-x"])
    p.cand("zz-rx", "s-rx", "bola", ["e-y"], dedup_key="zz")
    return {
        "programs": [p],
        "duplicate_pairs": [["aa-rx", "zz-rx"]],
        "family": "duplicates_separated_by_noise",
        "adversarial": False,
    }


def f_multi_group(root: Path, name: str, v: str) -> dict[str, Any]:
    p = Program(root, name)
    p.surface("s-ord", "GET /api/orders/{id}")
    o = [obj("order", "300")]
    for i in range(1, 5):
        p.ev(f"e{i}", corr=read("/api/orders/{id}", o, control_type="tenant_scope", actor_role="buyer"))
        p.cand(f"g{i}", "s-ord", "idor", [f"e{i}"], dedup_key=f"g{i}")
    pairs = [[f"g{i}", f"g{j}"] for i in range(1, 5) for j in range(i + 1, 5)]
    return {"programs": [p], "duplicate_pairs": pairs, "family": "multi_candidate_group", "adversarial": False}


def f_separate_groups(root: Path, name: str, v: str) -> dict[str, Any]:
    p = Program(root, name)
    p.surface("s-inv", "GET /api/invoices/{id}")
    for grp, ident in (("a", "111"), ("b", "222")):
        for i in (1, 2):
            p.ev(f"e{grp}{i}", corr=read("/api/invoices/{id}", [obj("invoice", ident)], control_type="tenant_scope"))
            p.cand(f"{grp}{i}", "s-inv", "idor", [f"e{grp}{i}"], dedup_key=f"{grp}{i}")
    return {
        "programs": [p],
        "duplicate_pairs": [["a1", "a2"], ["b1", "b2"]],
        "family": "groups_must_stay_separate",
        "adversarial": True,
    }


FINAL: list[tuple[str, Scenario]] = [
    ("true_duplicate", f_true_dup),
    ("same_path_diff_vuln", f_same_path_diff_vuln),
    ("same_category_diff_objects", f_same_cat_diff_objects),
    ("same_id_diff_namespace", f_same_id_ns),
    ("same_object_diff_captures", f_same_obj_diff_captures),
    ("same_request_diff_times", f_same_request_times),
    ("legitimately_shared", f_shared_resource),
    ("different_role_permission", f_diff_role_perm),
    ("rejected_and_new", f_rejected_new),
    ("stale_or_invalid_evidence", f_invalid_evidence),
    ("ambiguous_sessions", f_ambiguous_sessions),
    ("different_programs", f_cross_program),
    ("near_identical_diff_cause", f_near_identical_cause),
    ("duplicates_separated_by_noise", f_noise_dups),
    ("multi_candidate_group", f_multi_group),
    ("groups_stay_separate", f_separate_groups),
]


def build_split(split: str, root: Path) -> dict[str, Any]:
    """Materialise one split under ``root``; returns the manifest (labels + ledger digests)."""
    builders = {"dev": DEV, "final": FINAL}.get(split)
    if builders is None:
        raise ValueError("split must be 'dev' or 'final'")
    scenarios: list[dict[str, Any]] = []
    for name, builder in builders:
        sname = f"sem-{split}-{name.replace('_', '-')}"
        spec = builder(root, sname, split)
        programs: list[Program] = spec.pop("programs")
        spec["scenario"] = name
        spec["programs"] = [{"program": p.name, "ledger_sha256": p.write()} for p in programs]
        spec.setdefault("expected_reuse", [])
        spec.setdefault("cross_program", False)
        scenarios.append(spec)
    return {
        "schema_version": "bbtk-semantic-candidate-lab/1",
        "split": split,
        "scenario_count": len(scenarios),
        "scenarios": scenarios,
        "canary": CANARY,
        "network_requests_sent": 0,
    }
