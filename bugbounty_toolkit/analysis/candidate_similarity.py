"""Conservative semantic duplicate detection and correlation for ledger candidates.

Offline, deterministic, explainable and **read-only**:

* The Evidence Ledger is the only source of candidate state. It is validated with
  :func:`analysis.evidence_ledger.validate_ledger` (digests, references, stale
  fingerprints) and never written. ``dedup_key``, candidate states, ``duplicate_of``
  and confirmations are never changed; ``merge_performed`` and
  ``finding_confirmed`` are always ``False``.
* Only evidence whose digest verifies and which is not stale contributes facts.
  Broken, tampered or stale references are listed as missing information and
  are never used as supporting evidence.
* Facts are read from explicit structured annotations inside evidence JSON files
  (``bbtk-candidate-correlation/1`` and the planner's ``bbtk-control-annotation/1``)
  plus ledger surface data. Raw bodies, cookies and headers are never read.
  Session/cookie data never supports "same account"; ownership is never inferred.
* Object identifiers, paths and session refs are HMAC-pseudonymised in memory
  (same construction as :mod:`analysis.object_relationships`) and never exported;
  the output only contains ledger candidate/evidence IDs, counts and reason codes.
* Programs are never compared with each other unless explicitly requested, and
  even then such pairs are only reported as ``not_comparable_cross_program``.
* No AI provider is consulted. Weights and rules are fixed in this module.

Bands (most to least similar): ``strong`` (probable duplicate, still needs a
human), ``possible``, ``weak``, ``unrelated``; plus ``distinct`` (an explicit
conflict proves different issues), ``insufficient_evidence`` and
``not_comparable_cross_program``. Only ``strong`` pairs are duplicate hypotheses.
"""

from __future__ import annotations

import copy
import hashlib
import hmac
import json
import re
import secrets
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping

from .evidence_ledger import MAX_LEDGER_BYTES, load_ledger, validate_ledger

SCHEMA_VERSION = "bbtk-candidate-correlation/1"
ANNOTATION_VERSION = "bbtk-candidate-correlation/1"
CONTROL_ANNOTATION_VERSION = "bbtk-control-annotation/1"
PLANNER_CONTEXT_VERSION = "bbtk-candidate-correlation-planner-context/1"
MAX_ANNOTATED_EVIDENCE_BYTES = 2 * 1024 * 1024
MAX_CANDIDATES = 1000
MAX_OBJECTS_PER_EVIDENCE = 200

BAND_ORDER = ("strong", "possible", "weak", "unrelated")
BANDS = (*BAND_ORDER, "distinct", "insufficient_evidence", "not_comparable_cross_program")
# Category families: only aliases that mean the same class of issue.
CATEGORY_FAMILIES: dict[str, str] = {"idor": "object_access", "bola": "object_access"}
# Fixed neighbour-ranking weights (explainability, not a probability).
WEIGHTS: dict[str, int] = {
    "same_category": 2,
    "same_surface": 2,
    "same_endpoint": 3,
    "same_objects": 4,
    "object_overlap": 2,
    "same_operation": 1,
    "same_root_cause": 4,
    "same_control_type": 2,
    "same_actor_role": 1,
    "shared_evidence_digest": 3,
    "shared_graph_nodes": 2,
}
CONFLICT_PENALTY = 10
_DYNAMIC = re.compile(
    r"^(\d+|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|[0-9a-f]{16,}|\{[^}]*\}|:[a-z_]+)$",
    re.IGNORECASE,
)
_METHOD = re.compile(r"^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+", re.IGNORECASE)


def normalize_path(value: str) -> str:
    """Path template: lowercase, no query/fragment, dynamic segments → ``{}``."""
    path = value.split("?", 1)[0].split("#", 1)[0].strip()
    if "://" in path:
        path = "/" + path.split("://", 1)[1].partition("/")[2]
    segments = [s for s in path.split("/") if s]
    return "/" + "/".join("{}" if _DYNAMIC.match(s) else s.lower() for s in segments)


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def _token(key: bytes, kind: str, *values: Any) -> str:
    # Same HMAC construction as analysis.object_relationships._ref (kept private there).
    return kind + "-" + hmac.new(key, _canonical([kind, *values]), hashlib.sha256).hexdigest()[:32]


@dataclass
class Profile:
    candidate_id: str
    program: str
    state: str
    category: str
    surface_id: str
    endpoint: str | None
    usable_refs: list[str] = field(default_factory=list)
    invalid_refs: list[str] = field(default_factory=list)
    stale_refs: list[str] = field(default_factory=list)
    objects: set[str] = field(default_factory=set)
    literal_ids: set[str] = field(default_factory=set)
    object_refs_by_evidence: dict[str, set[str]] = field(default_factory=dict)
    operations: set[str] = field(default_factory=set)
    roles: set[str] = field(default_factory=set)
    permissions: set[str] = field(default_factory=set)
    control_types: set[str] = field(default_factory=set)
    root_causes: set[str] = field(default_factory=set)
    digests: dict[str, str] = field(default_factory=dict)
    graph_nodes: dict[str, set[str]] = field(default_factory=dict)
    investigations: dict[str, str] = field(default_factory=dict)
    control_roles: dict[str, list[str]] = field(default_factory=dict)
    attested: dict[str, list[str]] = field(default_factory=dict)
    visibility: dict[str, str] = field(default_factory=dict)
    session_ambiguous: list[str] = field(default_factory=list)


def _read_json(path: Path) -> dict[str, Any] | None:
    try:
        if not path.is_file() or path.is_symlink() or path.stat().st_size > MAX_ANNOTATED_EVIDENCE_BYTES:
            return None
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, UnicodeDecodeError):
        return None
    return data if isinstance(data, dict) else None


def _norm(value: object) -> str | None:
    if isinstance(value, str) and value.strip():
        return value.strip().lower()[:120]
    return None


def _evidence_states(ledger: Mapping[str, Any], program_dir: Path | None) -> tuple[dict[str, str], dict[str, Any]]:
    validation = validate_ledger(ledger, program_dir=program_dir)
    issues = [i for i in validation.get("issues", []) if isinstance(i, dict)]
    tampered = {
        str(i["ref"])
        for i in issues
        if i.get("code")
        in {"evidence_digest_mismatch", "evidence_missing", "evidence_path_unsafe", "evidence_too_large"}
    }
    stale = set(validation.get("summary", {}).get("stale_evidence") or []) - tampered
    states: dict[str, str] = {}
    rows = [e for e in ledger.get("evidence") or [] if isinstance(e, dict)]
    for row in rows:
        eid = str(row.get("evidence_id"))
        states[eid] = "tampered" if eid in tampered else ("stale" if eid in stale else "ok")
    for issue in issues:
        if issue.get("code") == "evidence_invalidated_by_change":
            msg = str(issue.get("message", ""))
            for eid, state in list(states.items()):
                if f"Evidence {eid} " in msg and state == "ok":
                    states[eid] = "stale"
    if program_dir is None:
        # Without a program directory digests cannot be verified: nothing is trusted.
        states = {k: ("unverified" if v == "ok" else v) for k, v in states.items()}
    return states, validation


def build_profiles(
    ledger: Mapping[str, Any], program_dir: Path | None, key: bytes, *, now: str | None = None
) -> tuple[list[Profile], dict[str, Any]]:
    program = str(ledger.get("program") or "")
    states, validation = _evidence_states(ledger, program_dir)
    rows = {str(e.get("evidence_id")): e for e in ledger.get("evidence") or [] if isinstance(e, dict)}
    surfaces = {str(s.get("surface_id")): s for s in ledger.get("surfaces") or [] if isinstance(s, dict)}
    facts: dict[str, dict[str, Any]] = {}
    if program_dir is not None:
        for eid, row in rows.items():
            if states.get(eid) == "ok":
                data = _read_json(program_dir / str(row.get("path")))
                if data is not None:
                    facts[eid] = data
    profiles: list[Profile] = []
    for cand in sorted(
        (c for c in ledger.get("candidates") or [] if isinstance(c, dict)), key=lambda c: str(c.get("candidate_id"))
    ):
        sid = str(cand.get("surface_id") or "")
        surface_ref = str((surfaces.get(sid) or {}).get("ref") or "")
        method_match = _METHOD.match(surface_ref)
        method = method_match.group(1).upper() if method_match else None
        path_ref = surface_ref[method_match.end() :] if method_match else surface_ref
        raw_cat = str(cand.get("category") or "").strip().lower()
        prof = Profile(
            candidate_id=str(cand.get("candidate_id")),
            program=program,
            state=str(cand.get("state") or ""),
            category=CATEGORY_FAMILIES.get(raw_cat, raw_cat),
            surface_id=_token(key, "surface", program, sid),
            endpoint=None,
        )
        endpoint_parts: set[tuple[str | None, str]] = set()
        if path_ref.startswith("/"):
            endpoint_parts.add((method, normalize_path(path_ref)))
        for ref in sorted({r for r in cand.get("evidence_refs") or [] if isinstance(r, str)}):
            state = states.get(ref, "broken")
            if state in {"broken", "tampered", "unverified"}:
                prof.invalid_refs.append(ref)
                continue
            data = facts.get(ref) or {}
            raw_control = data.get("control")
            control: dict[str, Any] = raw_control if isinstance(raw_control, dict) else {}
            if control.get("annotation_version") != CONTROL_ANNOTATION_VERSION:
                control = {}
            expires = control.get("expires_at")
            if state == "stale" or (isinstance(expires, str) and now is not None and expires <= now):
                prof.stale_refs.append(ref)
                continue
            prof.usable_refs.append(ref)
            prof.digests[ref] = str(rows[ref].get("sha256"))
            prov = rows[ref].get("provenance") or {}
            nodes = {str(n) for n in prov.get("graph_node_ids") or [] if isinstance(n, str)}
            if nodes:
                prof.graph_nodes[ref] = {_token(key, "graph", program, n) for n in nodes}
            if isinstance(prov.get("investigation_id"), str):
                prof.investigations[ref] = _token(key, "inv", program, prov["investigation_id"])
            role = control.get("role")
            if isinstance(role, str):
                prof.control_roles.setdefault(role, []).append(ref)
                if role == "negative_control" and control.get("contradicts_hypothesis") is True:
                    prof.control_roles.setdefault("contradicted_negative_control", []).append(ref)
            for att in ("ownership", "distinct_accounts"):
                if control.get(att) == "attested":
                    prof.attested.setdefault(att, []).append(ref)
            if control.get("resource_visibility") in {"public", "shared"}:
                prof.visibility[ref] = str(control["resource_visibility"])
            corr = data.get("correlation")
            if not isinstance(corr, dict) or corr.get("annotation_version") != ANNOTATION_VERSION:
                continue
            if isinstance(corr.get("path_template"), str) and corr["path_template"].startswith("/"):
                m = _norm(corr.get("method"))
                endpoint_parts.add((m.upper() if m else method, normalize_path(corr["path_template"])))
            ev_objects: set[str] = set()
            for obj in (corr.get("objects") or [])[:MAX_OBJECTS_PER_EVIDENCE]:
                if not isinstance(obj, dict) or obj.get("id") in (None, ""):
                    continue
                ns = _norm(obj.get("namespace")) or "unknown_namespace"
                literal = str(obj.get("id"))
                ev_objects.add(_token(key, "obj", program, ns, literal))
                prof.literal_ids.add(_token(key, "lit", program, literal))
            for node in prof.graph_nodes.get(ref, set()):
                ev_objects.add(node)
            if ev_objects:
                prof.object_refs_by_evidence[ref] = ev_objects
                prof.objects |= ev_objects
            for attr, target in (
                ("operation", prof.operations),
                ("actor_role", prof.roles),
                ("required_permission", prof.permissions),
                ("control_type", prof.control_types),
                ("root_cause", prof.root_causes),
            ):
                val = _norm(corr.get(attr))
                if val:
                    target.add(val)
            if corr.get("session_ambiguous") is True:
                prof.session_ambiguous.append(ref)
        if len(endpoint_parts) == 1:
            m, p = next(iter(endpoint_parts))
            prof.endpoint = _token(key, "endpoint", program, m or "?", p)
        elif len(endpoint_parts) > 1:
            prof.endpoint = "conflicting"
        profiles.append(prof)
    return profiles, validation


def _overlap(a: set[str], b: set[str]) -> bool:
    return bool(a & b)


def _both_disjoint(a: set[str], b: set[str]) -> bool:
    return bool(a) and bool(b) and not (a & b)


def compare(a: Profile, b: Profile) -> dict[str, Any]:
    """Explainable comparison of two candidate profiles (same program)."""
    support: list[str] = []
    conflicts: list[str] = []
    missing: list[str] = []
    s_refs: set[str] = set()
    c_refs: set[str] = set()
    score = 0

    def sup(code: str, refs: set[str] | None = None) -> None:
        nonlocal score
        support.append(code)
        score += WEIGHTS.get(code, 0)
        s_refs.update(refs or set())

    def con(code: str, refs: set[str] | None = None) -> None:
        conflicts.append(code)
        c_refs.update(refs or set())

    ua, ub = set(a.usable_refs), set(b.usable_refs)
    for prof in (a, b):
        for ref in prof.invalid_refs:
            missing.append(f"invalid_evidence_ref:{prof.candidate_id}:{ref}")
        for ref in prof.stale_refs:
            missing.append(f"stale_evidence_ref:{prof.candidate_id}:{ref}")
        for ref in prof.session_ambiguous:
            missing.append(f"session_ambiguous:{prof.candidate_id}:{ref}")
    if a.category == b.category:
        sup("same_category")
    else:
        con("different_category")
    if a.surface_id == b.surface_id:
        sup("same_surface")
    if a.endpoint and b.endpoint and "conflicting" not in (a.endpoint, b.endpoint):
        if a.endpoint == b.endpoint:
            sup("same_endpoint")
        else:
            con("different_endpoint")
    else:
        missing.append("endpoint_unknown_or_conflicting")
    if a.objects and b.objects:
        if a.objects == b.objects:
            sup(
                "same_objects",
                _refs_for(a.object_refs_by_evidence, b.objects) | _refs_for(b.object_refs_by_evidence, a.objects),
            )
        elif a.objects & b.objects:
            sup(
                "object_overlap",
                _refs_for(a.object_refs_by_evidence, b.objects) | _refs_for(b.object_refs_by_evidence, a.objects),
            )
            missing.append("objects_partially_overlap")
        else:
            con("different_objects", set(a.object_refs_by_evidence) | set(b.object_refs_by_evidence))
            if a.literal_ids & b.literal_ids:
                con("same_literal_id_different_namespace")
    else:
        missing.append("object_refs_not_declared")
    for code, x, y in (
        ("operation", a.operations, b.operations),
        ("actor_role", a.roles, b.roles),
        ("required_permission", a.permissions, b.permissions),
        ("control_type", a.control_types, b.control_types),
        ("root_cause", a.root_causes, b.root_causes),
    ):
        if _both_disjoint(x, y):
            con(f"different_{code}")
        elif _overlap(x, y):
            if code == "required_permission":
                continue
            sup(f"same_{code}")
        else:
            missing.append(f"{code}_not_declared")
    shared_digest = {r for r in ua if a.digests[r] in {b.digests[x] for x in ub}} | {
        r for r in ub if b.digests[r] in {a.digests[x] for x in ua}
    }
    if shared_digest:
        sup("shared_evidence_digest", shared_digest)
    na = set().union(*a.graph_nodes.values()) if a.graph_nodes else set()
    nb = set().union(*b.graph_nodes.values()) if b.graph_nodes else set()
    if na & nb:
        sup(
            "shared_graph_nodes",
            {r for r, n in a.graph_nodes.items() if n & nb} | {r for r, n in b.graph_nodes.items() if n & na},
        )
    vis = set(a.visibility) | set(b.visibility)
    if vis:
        con("legitimate_access_documented", vis)
    contradicted = set(a.control_roles.get("contradicted_negative_control", [])) | set(
        b.control_roles.get("contradicted_negative_control", [])
    )
    if contradicted:
        missing.append("negative_control_contradicts_hypothesis")
        c_refs.update(contradicted)
    score -= CONFLICT_PENALTY * len(conflicts)

    discriminator = {"same_root_cause", "same_control_type", "shared_evidence_digest"} & set(support)
    hard_conflicts = [c for c in conflicts if c != "legitimate_access_documented"]
    if not ua or not ub:
        band = "insufficient_evidence"
    elif hard_conflicts:
        band = "distinct"
    elif (
        {"same_category", "same_endpoint", "same_objects", "same_operation"} <= set(support)
        and discriminator
        and not a.session_ambiguous
        and not b.session_ambiguous
        and not contradicted
    ):
        band = "strong"
    elif {"same_category", "same_endpoint"} <= set(support) and (
        "same_objects" in support or "object_overlap" in support or "object_refs_not_declared" in missing
    ):
        band = "possible"
    elif support and set(support) != {"same_category"}:
        band = "weak"
    else:
        band = "unrelated"
    if band in BAND_ORDER:
        cap = "strong"
        if "legitimate_access_documented" in conflicts:
            cap = "weak"
        elif "rejected" in (a.state, b.state):
            cap = "possible"
        if BAND_ORDER.index(band) < BAND_ORDER.index(cap):
            band = cap
    if band == "strong":
        hypothesis = "probable_same_issue"
    elif band == "possible" and "rejected" in (a.state, b.state):
        hypothesis = "may_repeat_rejected_candidate"
    elif band == "possible":
        hypothesis = "possible_same_issue_needs_information"
    elif band == "distinct":
        hypothesis = "different_issues"
    elif band == "insufficient_evidence":
        hypothesis = "undetermined"
    else:
        hypothesis = "not_same_issue_shared_context_only" if support else "unrelated"
    return {
        "candidate_a": a.candidate_id,
        "candidate_b": b.candidate_id,
        "similarity_band": band,
        "score": score,
        "supporting_signals": sorted(support),
        "conflicting_signals": sorted(conflicts),
        "supporting_evidence_refs": sorted(s_refs),
        "conflicting_evidence_refs": sorted(c_refs),
        "duplicate_hypothesis": hypothesis,
        "missing_information": sorted(set(missing)),
        "states": [a.state, b.state],
        "human_review_required": True,
        "merge_performed": False,
        "finding_confirmed": False,
    }


def _refs_for(by_ev: Mapping[str, set[str]], other: set[str]) -> set[str]:
    return {r for r, objs in by_ev.items() if objs & other}


def _groups(ids: list[str], strong: set[tuple[str, str]]) -> tuple[list[list[str]], list[list[str]]]:
    """Connected components of strong edges; only fully-connected (clique) components become groups."""
    adj: dict[str, set[str]] = {i: set() for i in ids}
    for x, y in strong:
        adj[x].add(y)
        adj[y].add(x)
    seen: set[str] = set()
    groups: list[list[str]] = []
    review: list[list[str]] = []
    for node in ids:
        if node in seen or not adj[node]:
            continue
        stack, comp = [node], set()
        while stack:
            cur = stack.pop()
            if cur in comp:
                continue
            comp.add(cur)
            stack.extend(adj[cur] - comp)
        seen |= comp
        members = sorted(comp)
        clique = all((x, y) in strong or (y, x) in strong for i, x in enumerate(members) for y in members[i + 1 :])
        (groups if clique else review).append(members)
    return groups, review


def _reuse(a: Profile, b: Profile, band: str) -> list[dict[str, Any]]:
    """Read-only reuse suggestions from ``b`` (source) to ``a`` (target). Nothing is copied."""
    out: list[dict[str, Any]] = []
    if band not in {"strong", "possible"} or a.endpoint != b.endpoint or not a.endpoint:
        return out

    def rec(kind: str, refs: list[str]) -> None:
        refs = sorted(r for r in refs if r not in a.usable_refs)
        if refs:
            out.append(
                {
                    "target_candidate": a.candidate_id,
                    "source_candidate": b.candidate_id,
                    "reuse_kind": kind,
                    "evidence_refs": refs,
                    "requires_human_review": True,
                    "copy_performed": False,
                    "ledger_modified": False,
                }
            )

    contradicted = set(b.control_roles.get("contradicted_negative_control", []))
    if not a.control_roles.get("negative_control"):
        rec("reuse_negative_control", [r for r in b.control_roles.get("negative_control", []) if r not in contradicted])
    if band == "strong":
        # Object-specific attestations only transfer when objects, roles and operations match.
        for att in ("ownership", "distinct_accounts"):
            if not a.attested.get(att):
                rec(f"reuse_{att}_attestation", b.attested.get(att, []))
        if b.investigations:
            rec("consult_prior_investigation", list(b.investigations))
    na = set().union(*a.graph_nodes.values()) if a.graph_nodes else set()
    rec("reuse_object_relation", [r for r, n in b.graph_nodes.items() if n & na])
    return out


def correlate_ledger(
    ledger: Mapping[str, Any],
    *,
    program_dir: Path | None,
    key: bytes | None = None,
    now: str | None = None,
    extra_ledgers: list[tuple[Mapping[str, Any], Path | None]] | None = None,
    include_cross_program: bool = False,
    top_k: int = 3,
) -> dict[str, Any]:
    """Return the versioned correlation report. Never writes anything."""
    started = time.perf_counter()
    hkey = key if key is not None else secrets.token_bytes(32)
    snapshot = copy.deepcopy(dict(ledger))
    profiles, validation = build_profiles(ledger, program_dir, hkey, now=now)
    others: list[Profile] = []
    for extra, extra_dir in extra_ledgers or []:
        others.extend(build_profiles(extra, extra_dir, hkey, now=now)[0])
    base: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "program": str(ledger.get("program") or ""),
        "deterministic": True,
        "ai_used": False,
        "network_requests_sent": 0,
        "merge_performed": False,
        "finding_confirmed": False,
        "ledger_modified": False,
        "dedup_key_modified": False,
        "ledger_valid": bool(validation.get("valid")),
    }
    if len(profiles) + len(others) > MAX_CANDIDATES:
        return {**base, "status": "too_many_candidates", "limit": MAX_CANDIDATES, "pairs": [], "groups": []}
    pairs: list[dict[str, Any]] = []
    reuse: list[dict[str, Any]] = []
    for i, a in enumerate(profiles):
        for b in profiles[i + 1 :]:
            row = compare(a, b)
            pairs.append(row)
            reuse.extend(_reuse(a, b, row["similarity_band"]))
            reuse.extend(_reuse(b, a, row["similarity_band"]))
    skipped_cross = 0
    for a in profiles:
        for b in others:
            if a.program == b.program:
                continue
            if not include_cross_program:
                skipped_cross += 1
                continue
            pairs.append(
                {
                    "candidate_a": a.candidate_id,
                    "candidate_b": f"{b.program}:{b.candidate_id}",
                    "similarity_band": "not_comparable_cross_program",
                    "score": 0,
                    "supporting_signals": [],
                    "conflicting_signals": ["different_program"],
                    "supporting_evidence_refs": [],
                    "conflicting_evidence_refs": [],
                    "duplicate_hypothesis": "different_programs_not_compared",
                    "missing_information": [],
                    "states": [a.state, b.state],
                    "human_review_required": True,
                    "merge_performed": False,
                    "finding_confirmed": False,
                }
            )
    ids = [p.candidate_id for p in profiles]
    strong = {(p["candidate_a"], p["candidate_b"]) for p in pairs if p["similarity_band"] == "strong"}
    groups, group_review = _groups(ids, strong)
    neighbours: dict[str, list[dict[str, Any]]] = {}
    for cid in ids:
        rows = [
            p for p in pairs if cid in (p["candidate_a"], p["candidate_b"]) and p["similarity_band"] in BAND_ORDER[:3]
        ]
        rows.sort(
            key=lambda p: (BAND_ORDER.index(p["similarity_band"]), -int(p["score"]), p["candidate_a"], p["candidate_b"])
        )
        neighbours[cid] = [
            {
                "candidate": p["candidate_b"] if p["candidate_a"] == cid else p["candidate_a"],
                "similarity_band": p["similarity_band"],
                "score": p["score"],
            }
            for p in rows[:top_k]
        ]
    reuse.sort(key=lambda r: (r["target_candidate"], r["reuse_kind"], r["source_candidate"]))
    if dict(ledger) != snapshot:  # defensive: the input must never be mutated
        raise RuntimeError("candidate correlation mutated the ledger input")
    counts = {band: sum(1 for p in pairs if p["similarity_band"] == band) for band in BANDS}
    return {
        **base,
        "status": "ok",
        "candidate_count": len(profiles),
        "pair_count": len(pairs),
        "cross_program_pairs_skipped": skipped_cross,
        "band_counts": counts,
        "pairs": pairs,
        "groups": [
            {"members": g, "basis": "all_pairs_strong", "human_review_required": True, "merge_performed": False}
            for g in groups
        ],
        "groups_requiring_review": [{"members": g, "basis": "transitive_strong_only"} for g in group_review],
        "neighbours": neighbours,
        "reuse_recommendations": reuse,
        "elapsed_ms": round((time.perf_counter() - started) * 1000, 3),
    }


def correlate_program(program_dir: Path, *, ledger_file: Path | None = None, **kwargs: Any) -> dict[str, Any]:
    """Load ``<program_dir>/ledger/evidence-ledger.json`` read-only and correlate it."""
    path = ledger_file or (program_dir / "ledger" / "evidence-ledger.json")
    if not path.is_file() or path.stat().st_size > MAX_LEDGER_BYTES:
        return {"schema_version": SCHEMA_VERSION, "status": "no_ledger", "pairs": [], "network_requests_sent": 0}
    return correlate_ledger(load_ledger(path), program_dir=program_dir, **kwargs)


def exact_key_duplicates(ledger: Mapping[str, Any], *, use_dedup_key: bool = True) -> set[tuple[str, str]]:
    """Baseline: the ledger's existing key rule (``dedup_key`` or ``surface|category``), active candidates."""
    by_key: dict[str, list[str]] = {}
    for cand in ledger.get("candidates") or []:
        if not isinstance(cand, dict) or cand.get("state") == "rejected":
            continue
        k = str(
            (cand.get("dedup_key") if use_dedup_key else None)
            or f"{cand.get('surface_id')}|{str(cand.get('category', '')).lower()}"
        )
        by_key.setdefault(k, []).append(str(cand.get("candidate_id")))
    out: set[tuple[str, str]] = set()
    for members in by_key.values():
        ms = sorted(members)
        out |= {(x, y) for i, x in enumerate(ms) for y in ms[i + 1 :]}
    return out


def planner_context(plan: Mapping[str, Any], report: Mapping[str, Any]) -> dict[str, Any]:
    """Read-only side-car for an evidence-gap plan. The plan and its scores are not modified."""
    open_ids = {str(c.get("candidate_id")) for c in plan.get("candidates") or [] if isinstance(c, dict)}
    out: dict[str, dict[str, Any]] = {}
    for pair in report.get("pairs") or []:
        if pair.get("similarity_band") not in {"strong", "possible"}:
            continue
        for me, other in ((pair["candidate_a"], pair["candidate_b"]), (pair["candidate_b"], pair["candidate_a"])):
            if open_ids and me not in open_ids:
                continue
            out.setdefault(me, {"possible_duplicates": [], "reuse": []})["possible_duplicates"].append(
                {"candidate": other, "similarity_band": pair["similarity_band"]}
            )
    for rec in report.get("reuse_recommendations") or []:
        me = rec["target_candidate"]
        if open_ids and me not in open_ids:
            continue
        out.setdefault(me, {"possible_duplicates": [], "reuse": []})["reuse"].append(
            {
                "reuse_kind": rec["reuse_kind"],
                "source_candidate": rec["source_candidate"],
                "evidence_refs": rec["evidence_refs"],
            }
        )
    return {
        "schema_version": PLANNER_CONTEXT_VERSION,
        "plan_schema_version": plan.get("schema_version"),
        "correlation_schema_version": report.get("schema_version"),
        "candidates": {k: out[k] for k in sorted(out)},
        "planner_modified": False,
        "scores_modified": False,
        "execution_allowed": False,
        "finding_confirmed": False,
    }


def main(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(description="Read-only semantic candidate correlation for one program")
    parser.add_argument("program_dir", type=Path)
    parser.add_argument("--ledger", type=Path)
    parser.add_argument("--now")
    args = parser.parse_args(argv)
    print(
        json.dumps(correlate_program(args.program_dir, ledger_file=args.ledger, now=args.now), indent=2, sort_keys=True)
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
