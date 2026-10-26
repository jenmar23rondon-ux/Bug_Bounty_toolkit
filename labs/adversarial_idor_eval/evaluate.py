"""Offline measurement harness for the frozen adversarial IDOR/BOLA corpus.

Measurement only: imports the pipeline as-is and never changes detection rules.
Stages are scored separately:
  1. discovery    -> object_candidates()        (object candidates, NOT findings)
  2. pairing      -> propose_object_handoff()   (owner/actor review proposals, NOT findings)
  3. case         -> discover_idor()            (idor-case-proposal needs_review, NOT findings)
  4. confirmation -> requires human approve-idor + authorized access-check; never run here.
Network is hard-blocked for the whole run. Works against older checkouts (stages that
do not exist in that version are reported as null).
"""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
import math
import re
import socket
import sys
import tempfile
from collections.abc import Iterator
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
FROZEN = HERE / "frozen"
# Independent frozen corpora. adv-1.1 is FINAL-evaluation only (never used for tuning).
CORPORA = {"adv-1.0": HERE / "frozen", "adv-1.1": HERE / "frozen_adv11"}
KEY = hashlib.sha256(b"bbtk-adversarial-eval-adv-1.0").digest()
PROGRAM = "adv-eval"


class NetworkBlocked(RuntimeError):
    pass


@contextlib.contextmanager
def no_network() -> Iterator[dict[str, int]]:
    """Hard-fail any socket connect / DNS lookup for the duration; always restores."""
    attempts = {"count": 0}
    saved = (socket.socket.connect, socket.socket.connect_ex, socket.create_connection, socket.getaddrinfo)

    def guard(*_a: Any, **_k: Any) -> Any:
        attempts["count"] += 1
        raise NetworkBlocked("network disabled during offline evaluation")

    socket.socket.connect = guard  # type: ignore[method-assign]
    socket.socket.connect_ex = guard  # type: ignore[method-assign]
    socket.create_connection = guard  # type: ignore[assignment]
    socket.getaddrinfo = guard  # type: ignore[assignment]
    try:
        yield attempts
    finally:
        socket.socket.connect, socket.socket.connect_ex, socket.create_connection, socket.getaddrinfo = saved  # type: ignore[method-assign]


def wilson(k: int, n: int, z: float = 1.96) -> list[float] | None:
    if n == 0:
        return None
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return [round(max(0.0, c - h), 3), round(min(1.0, c + h), 3)]


def _ratio(k: int, n: int) -> float | None:
    return round(k / n, 4) if n else None


def _entry(locator: str) -> int:
    m = re.fullmatch(r"/log/entries\[(\d+)\]", locator)
    return int(m.group(1)) if m else -1


def load_frozen() -> tuple[Path, dict]:
    """Load the selected frozen corpus (adv-1.0 by default; see ``CORPORA``)."""
    return FROZEN / "captures.har", json.loads((FROZEN / "ground_truth.json").read_text(encoding="utf-8"))


def scenario_of_entry(gt: dict) -> dict[int, dict]:
    return {i: s for s in gt["scenarios"] for i in s["entries"]}


SHARD_SIZE = 25  # below the importer's 32-exchange per-file cap


def _importable(entry: dict) -> bool:
    """True unless the entry is one the importer rejects wholesale (no response / unparsable JSON body)."""
    resp = entry.get("response")
    if not isinstance(resp, dict):
        return False
    text = resp.get("content", {}).get("text", "")
    if text:
        try:
            json.loads(text)
        except ValueError:
            return False
    return True


def shard(captures: Path, out: Path) -> tuple[list[Path], dict[tuple[int, int], int], list[int]]:
    """Deterministically split the frozen HAR into importer-sized files.

    Entries lacking a response object are excluded from the primary run (they make the
    importer reject the whole file; that behaviour is measured separately as a probe).
    Returns (files, {(file_index, local_entry): global_entry}, excluded_global_entries).
    """
    doc = json.loads(captures.read_text(encoding="utf-8"))
    entries = doc["log"]["entries"]
    keep = [i for i, e in enumerate(entries) if _importable(e)]
    excluded = [i for i in range(len(entries)) if i not in keep]
    files, mapping = [], {}
    for fi, start in enumerate(range(0, len(keep), SHARD_SIZE)):
        chunk = keep[start : start + SHARD_SIZE]
        part = {"log": {**doc["log"], "entries": [entries[i] for i in chunk]}}
        path = out / f"shard-{fi}.har"
        path.write_text(json.dumps(part, sort_keys=True), encoding="utf-8")
        files.append(path)
        for li, gi in enumerate(chunk):
            mapping[(fi, li)] = gi
    return files, mapping, excluded


def probes(orel, captures: Path, tmp: Path) -> dict:
    """Bounds / fail-closed probes on unmodified or minimally derived inputs."""
    out = {}

    def attempt(name, paths):
        try:
            g = orel.build_object_graph(PROGRAM, paths, KEY, authorized=True)
            out[name] = {"accepted": True, "observations": g["summary"]["observations"]}
        except ValueError as exc:
            out[name] = {"accepted": False, "error": str(exc)[:160]}

    attempt("frozen_har_as_is_49_entries", [captures])
    doc = json.loads(captures.read_text(encoding="utf-8"))
    gt = json.loads((captures.parent / "ground_truth.json").read_text(encoding="utf-8"))
    for sid, name in (
        ("S16", "incomplete_capture_entry_without_response"),
        ("S15", "partial_response_truncated_json"),
    ):
        # adv-1.0 only: these probes replay scenarios that exist in that corpus.
        scen = next((s for s in gt["scenarios"] if s["id"] == sid), None)
        if scen is None:
            continue
        probe_file = tmp / f"{name}.har"
        probe_file.write_text(
            json.dumps({"log": {**doc["log"], "entries": [doc["log"]["entries"][i] for i in scen["entries"]]}}),
            encoding="utf-8",
        )
        attempt(name, [probe_file])
    big = tmp / "oversize.har"
    ok = [e for e in doc["log"]["entries"] if _importable(e)]
    big.write_text(json.dumps({"log": {**doc["log"], "entries": (ok * 2)[:33]}}), encoding="utf-8")
    attempt("33_entries_over_cap", [big])
    many = []
    for i in range(17):
        f = tmp / f"many-{i}.har"
        f.write_text(json.dumps({"log": {**doc["log"], "entries": ok[i : i + 1]}}), encoding="utf-8")
        many.append(f)
    attempt("17_files_over_MAX_FILES", many)
    trunc = tmp / "truncated.har"
    trunc.write_text(captures.read_text(encoding="utf-8")[:4000], encoding="utf-8")
    attempt("truncated_har_file", [trunc])
    return out


def _tokens(doc: dict) -> set[str]:
    out: set[str] = set()

    def walk(v):
        if isinstance(v, dict):
            for k, x in v.items():
                out.add(str(k))
                walk(x)
        elif isinstance(v, list):
            for x in v:
                walk(x)

    for e in doc["log"]["entries"]:
        url = e["request"]["url"]
        path, _, query = url.split("//", 1)[1].partition("/")[2].partition("?")
        out.update(path.split("/"))
        out.update(q.split("=")[0] for q in query.split("&") if q)
        for text in (
            e["request"].get("postData", {}).get("text"),
            e.get("response", {}).get("content", {}).get("text"),
        ):
            try:
                walk(json.loads(text)) if text else None
            except ValueError:
                pass
    out.update(str(i) for i in range(64))  # array indices are keyed-hashed like names
    return out


def _singular(word: str) -> str:
    word = re.sub(r"_?(?:ids|uuid|uid|id)$", "", word.lower())
    return word[:-1] if word.endswith("s") and not word.endswith("ss") else word


class ObjectTyper:
    """Evaluator-side ground-truth typing of an object occurrence from its captured location.

    The pipeline only names 19 built-in nouns and exports everything else as 'unknown'.
    To score pairing/discovery independently of that vocabulary, we resolve the field
    pointer (keyed name hashes are inverted with the synthetic eval key) back to the
    collection/field the identifier was captured in.
    """

    def __init__(self, orel, graph: dict, doc: dict, gentry, by_entry):
        names = {orel._ref(KEY, "name", t): t for t in _tokens(doc)}
        nodes = graph["nodes"] if isinstance(graph["nodes"], list) else list(graph["nodes"].values())
        self.fields = {n["id"]: n for n in nodes if n.get("type") == "Field"}
        self.obs = {o["id"]: o for o in graph["observations"]}
        self.names, self.doc, self.gentry, self.by_entry = names, doc, gentry, by_entry

    def type_of(self, object_ref: str, observation_ref: str) -> str:
        obs = self.obs.get(observation_ref)
        if not obs:
            return "?"
        fact = next((f for f in obs["references"] if f["object_ref"] == object_ref), None)
        if not fact:
            return "?"
        field = self.fields.get(fact["field_ref"], {})
        ptr = [self.names.get(p, p) for p in str(field.get("pointer_template", "")).split("/") if p]
        if fact["location"] == "path" and len(ptr) == 2 and ptr[1].isdigit():
            prov = obs["provenance"][0]
            g = self.gentry(prov["source_ref"], prov["locator"])
            segs = (
                self.doc["log"]["entries"][g]["request"]["url"]
                .split("//", 1)[1]
                .partition("/")[2]
                .split("?")[0]
                .split("/")
            )
            idx = int(ptr[1]) - 1  # pointer index counts the leading empty segment
            return _singular(segs[idx - 1]) if idx >= 1 else "?"
        words = [p for p in ptr if not p.isdigit() and p not in ("query", "path", "data", "items")]
        if not words:
            return "?"
        last = words[-1]
        if last.lower() in ("id", "uid", "uuid", "ids") and len(words) >= 2:
            last = words[-2]
        return _singular(last)


def evaluate(ks: tuple[int, ...] = (1, 3, 5, 10), corpus: str = "adv-1.0") -> dict:
    global FROZEN
    saved, FROZEN = FROZEN, CORPORA[corpus]
    try:
        with no_network() as attempts:
            result = _evaluate(ks)
    finally:
        FROZEN = saved
    result["safety"] = {"network_connect_attempts": attempts["count"]}
    return result


def _evaluate(ks: tuple[int, ...]) -> dict:
    from bugbounty_toolkit.analysis import object_relationships as orel

    captures, gt = load_frozen()
    by_entry = scenario_of_entry(gt)
    work = Path(tempfile.mkdtemp(prefix="bbtk-adv-"))
    probe = probes(orel, captures, work)
    files, mapping, excluded = shard(captures, work)
    src_index = {orel._ref(KEY, "source", PROGRAM, f.read_bytes().hex()): fi for fi, f in enumerate(files)}

    def gentry(source_ref, locator):
        fi = src_index.get(source_ref)
        return mapping.get((fi, _entry(locator)), -1) if fi is not None else -1

    graph = orel.build_object_graph(PROGRAM, files, KEY, authorized=True)
    typer = ObjectTyper(orel, graph, json.loads(load_frozen()[0].read_text(encoding="utf-8")), gentry, by_entry)
    captures = files  # downstream stages consume the importer-sized shards
    cands = orel.object_candidates(graph, PROGRAM, KEY, limit=100)["candidates"]

    # Per-scenario typed universe
    pos = {(s["id"], t) for s in gt["scenarios"] for t in s["expected_pair_types"]}
    neg = {(s["id"], t) for s in gt["scenarios"] for t in s["forbidden_pair_types"]}
    amb = {(s["id"], t) for s in gt["scenarios"] for t in s["ambiguous_types"]}

    # ---------- discovery ----------
    obs_entry = {}
    for node in graph.get("observations", []):
        obs_entry[node.get("id")] = [
            gentry(pv.get("source_ref"), str(pv.get("locator", ""))) for pv in node.get("provenance", [])
        ]

    def cand_scen(c):
        ids = {by_entry.get(e, {}).get("id") for o in c.get("observation_refs", []) for e in obs_entry.get(o, [])}
        ids.discard(None)
        return sorted(ids)

    disc_rows = [
        {
            "resource_type": typer.type_of(c["object_ref"], c["observation_refs"][0])
            if c.get("observation_refs")
            else "?",
            "exported_resource_type": c["resource_type"],
            "scenarios": cand_scen(c),
            "score": c.get("score"),
        }
        for c in cands
    ]
    disc_found = {(s, r["resource_type"]) for r in disc_rows for s in r["scenarios"]}
    disc_rel = [any((s, r["resource_type"]) in pos for s in r["scenarios"]) for r in disc_rows]
    discovery = {
        "candidates": len(disc_rows),
        "expected_objects": len(pos),
        "expected_found": len(pos & disc_found),
        "recall": _ratio(len(pos & disc_found), len(pos)),
        "recall_ci95": wilson(len(pos & disc_found), len(pos)),
        "missed": sorted(f"{s}:{t}" for s, t in pos - disc_found),
        "precision_at_k": {str(k): _ratio(sum(disc_rel[:k]), min(k, len(disc_rel))) for k in ks},
        "negative_objects_surfaced": sorted(f"{s}:{t}" for s, t in neg & disc_found),
        "rows": disc_rows,
        "exported_resource_types": sorted({c["resource_type"] for c in cands}),
        "note": "Discovery candidates are leads for review, not vulnerabilities.",
    }

    result = {
        "corpus_version": gt["corpus_version"],
        "scenarios": len(gt["scenarios"]),
        "entries": len(by_entry),
        "observations": graph["summary"]["observations"],
        "discovery": discovery,
        "pairing": None,
        "case_discovery": None,
    }
    try:
        from bugbounty_toolkit.analysis import object_handoff as oh
    except ImportError:
        oh = None

    if oh is not None:
        with tempfile.TemporaryDirectory() as tmp:
            kwargs = {"verify_inputs": list(captures), "limit": 64, "materialize_dir": Path(tmp) / "pairs"}
            try:
                handoff = oh.propose_object_handoff(graph, PROGRAM, KEY, **kwargs)
            except TypeError:
                kwargs.pop("materialize_dir")
                handoff = oh.propose_object_handoff(graph, PROGRAM, KEY, **kwargs)
            props = handoff["proposals"]
            rows = []
            for p in props:
                oe = gentry(p["owner"]["source_ref"], p["owner"]["locator"])
                ae = gentry(p["actor"]["source_ref"], p["actor"]["locator"])
                so, sa = by_entry.get(oe, {}).get("id"), by_entry.get(ae, {}).get("id")
                rt = typer.type_of(p["owner"]["object_ref"], p["owner"]["observation_ref"])
                at = typer.type_of(p["actor"]["object_ref"], p["actor"]["observation_ref"])
                same_scen = so is not None and so == sa
                key = (so, rt)
                if rt != at:
                    verdict = "FP-type-mismatch"
                elif same_scen and key in pos and p["owner"]["session_ref"] != p["actor"]["session_ref"]:
                    verdict = "TP"
                elif same_scen and key in amb:
                    verdict = "AMBIGUOUS"
                elif same_scen and key in neg:
                    verdict = "FP-forbidden"
                elif not same_scen:
                    verdict = "FP-cross-scenario"
                else:
                    verdict = "FP-unlabeled"
                rows.append(
                    {
                        "rank": len(rows) + 1,
                        "resource_type": rt,
                        "actor_type": at,
                        "exported_resource_type": p["resource_type"],
                        "owner_entry": oe,
                        "actor_entry": ae,
                        "scenario": so if same_scen else f"{so}x{sa}",
                        "pair_kind": p.get("pair_kind", "request_request"),
                        "rule": p.get("relation", {}).get("rule"),
                        "score": p.get("score"),
                        "verdict": verdict,
                        "insufficient_evidence": bool(p.get("insufficient_evidence")),
                        "review_required": bool(p.get("researcher_review_required", True)),
                        "confirmed": bool(p.get("confirmed")),
                        "paths": p.get("paths") or p.get("materialized"),
                    }
                )
            tp_keys = {(r["scenario"], r["resource_type"]) for r in rows if r["verdict"] == "TP"}
            # Dedup TP proposals for precision (duplicate correct pairs are not errors, but are reported)
            rel = [r["verdict"] == "TP" for r in rows]
            scored = [r for r in rows if r["verdict"] != "AMBIGUOUS"]
            fps = [r for r in rows if r["verdict"].startswith("FP")]
            pairing = {
                "proposals": len(rows),
                "tp_proposals": sum(rel),
                "fp_proposals": len(fps),
                "ambiguous_proposals": sum(r["verdict"] == "AMBIGUOUS" for r in rows),
                "expected_pairs": len(pos),
                "pairs_found": len(tp_keys),
                "recall": _ratio(len(tp_keys), len(pos)),
                "recall_ci95": wilson(len(tp_keys), len(pos)),
                "precision": _ratio(sum(rel), len(scored)),
                "precision_ci95": wilson(sum(rel), len(scored)),
                "precision_at_k": {str(k): _ratio(sum(rel[:k]), min(k, len(rel))) for k in ks},
                "false_negatives": sorted(f"{s}:{t}" for s, t in pos - tp_keys),
                "false_positives": [f"{r['scenario']}:{r['resource_type']}#{r['rank']}({r['verdict']})" for r in fps],
                "forbidden_types_proposed": sorted(
                    {f"{r['scenario']}:{r['resource_type']}" for r in fps if r["verdict"] == "FP-forbidden"}
                ),
                "ambiguous_types_proposed": sorted(
                    {f"{r['scenario']}:{r['resource_type']}" for r in rows if r["verdict"] == "AMBIGUOUS"}
                ),
                "ambiguous_types_total": len(amb),
                "manual_review_rate": _ratio(sum(r["review_required"] for r in rows), len(rows)),
                "insufficient_evidence_rate": _ratio(sum(r["insufficient_evidence"] for r in rows), len(rows)),
                "review_burden_non_tp_rate": _ratio(len(rows) - sum(rel), len(rows)),
                "confirmed_flags": sum(r["confirmed"] for r in rows),
                "network_requests_sent_reported": handoff.get("network_requests_sent"),
                "rows": rows,
                "exported_resource_types": sorted({p["resource_type"] for p in props}),
            }
            result["pairing"] = pairing

            # ---------- case discovery (discover_idor) on materialized pairs ----------
            try:
                from bugbounty_toolkit.idor_discovery import discover_idor
            except ImportError:
                discover_idor = None
            pairs_dir = Path(tmp) / "pairs"
            if discover_idor is not None and pairs_dir.is_dir():
                case_rows = []
                for r, p in zip(rows, props):
                    owner = pairs_dir / f"{p['id']}-owner.http"
                    actor = pairs_dir / f"{p['id']}-actor.http"
                    if not owner.is_file() or not actor.is_file():
                        case_rows.append(
                            {"rank": r["rank"], "verdict": r["verdict"], "cases": None, "error": "not materialized"}
                        )
                        continue
                    ores = pairs_dir / f"{p['id']}-owner-response.http"
                    ares = pairs_dir / f"{p['id']}-actor-response.http"
                    try:
                        d = discover_idor(
                            PROGRAM,
                            owner,
                            actor,
                            base_url="http://127.0.0.1:8137",
                            owner_response=ores if ores.is_file() else None,
                            actor_response=ares if ares.is_file() else None,
                            accounts_authorized=False,
                        )
                        prop = d.proposal if hasattr(d, "proposal") else d
                        prop = prop if isinstance(prop, dict) else getattr(d, "__dict__", {})
                        n = len(prop.get("candidates", []))
                        case_rows.append(
                            {
                                "rank": r["rank"],
                                "verdict": r["verdict"],
                                "cases": n,
                                "state": prop.get("state"),
                                "confirmed": bool(prop.get("confirmed")),
                                "session_only_pairs": prop.get("session_only_pairs"),
                                "unsupported_pairs": prop.get("unsupported_pairs"),
                                "error": None,
                            }
                        )
                    except Exception as exc:  # noqa: BLE001 - measured, reported
                        case_rows.append(
                            {
                                "rank": r["rank"],
                                "verdict": r["verdict"],
                                "cases": None,
                                "error": f"{type(exc).__name__}: {str(exc)[:120]}",
                            }
                        )
                tp_rows = [c for c in case_rows if c["verdict"] == "TP"]
                result["case_discovery"] = {
                    "pairs_evaluated": len(case_rows),
                    "tp_pairs_with_case": sum(1 for c in tp_rows if c["cases"]),
                    "tp_pairs": len(tp_rows),
                    "case_yield_on_tp": _ratio(sum(1 for c in tp_rows if c["cases"]), len(tp_rows)),
                    "non_tp_pairs_with_case": sum(1 for c in case_rows if c["verdict"] != "TP" and c["cases"]),
                    "errors": sum(1 for c in case_rows if c["error"]),
                    "confirmed_flags": sum(1 for c in case_rows if c.get("confirmed")),
                    "rows": case_rows,
                    "note": "Case proposals are needs_review; accounts_authorized=False here, so nothing is executable.",
                }

    vt = [s for s in gt["scenarios"] if s["vulnerability_truth"] not in ("n/a",)]
    result["confirmation"] = {
        "designed_vulnerable_scenarios": sum(s["vulnerability_truth"] == "vulnerable" for s in vt),
        "designed_protected_scenarios": sum(s["vulnerability_truth"].startswith("protected") for s in vt),
        "confirmed_by_pipeline": 0,
        "measurable_offline": False,
        "note": "Vulnerability confirmation requires a human-gated, authorized live/lab access test (approve-idor + access-check). "
        "Not executed by this offline evaluation. Candidates and proposals are NOT confirmed findings.",
    }
    result["bounds_probes"] = probe
    result["primary_run_input"] = {"shards": len(files), "shard_size": SHARD_SIZE, "excluded_entries": excluded}
    import shutil

    shutil.rmtree(work, ignore_errors=True)
    return result


def strip_volatile(doc: dict) -> dict:
    d = json.loads(json.dumps(doc))
    for r in (d.get("pairing") or {}).get("rows", []):
        r.pop("paths", None)
    return d


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--json", type=Path)
    ap.add_argument("--corpus", choices=sorted(CORPORA), default="adv-1.0")
    a = ap.parse_args()
    res = strip_volatile(evaluate(corpus=a.corpus))
    text = json.dumps(res, indent=1, sort_keys=True)
    if a.json:
        a.json.write_text(text + "\n", encoding="utf-8")
    print(text)


if __name__ == "__main__":
    sys.exit(main())
