"""Read-only integrity checks for frozen evaluation corpora (measurement quality only).

Every function here is side-effect free with respect to the frozen corpora: regeneration
always happens inside a caller-provided or disposable temporary directory, and manifests
are verified, never rewritten. Nothing contacts the network and nothing tunes detection.
"""

from __future__ import annotations

import hashlib
import json
import re
import tempfile
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

MANIFEST = "MANIFEST.sha256"
_LINE = re.compile(r"^([0-9a-f]{64})  ([A-Za-z0-9._-]+)$")
_IGNORED = {"__pycache__"}
LABEL_KEYS = ("expected_pair_types", "forbidden_pair_types", "ambiguous_types")

Builder = Callable[[Path], None]


@dataclass(frozen=True)
class Issue:
    code: str
    corpus: str
    detail: str

    def as_dict(self) -> dict[str, str]:
        return {"code": self.code, "corpus": self.corpus, "detail": self.detail}


@dataclass(frozen=True)
class CorpusSpec:
    name: str
    root: Path
    builder: Builder


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def parse_manifest(root: Path, corpus: str) -> tuple[dict[str, str], list[Issue]]:
    issues: list[Issue] = []
    path = root / MANIFEST
    if not path.is_file():
        return {}, [Issue("manifest_missing", corpus, MANIFEST)]
    raw = path.read_bytes()
    if not raw.endswith(b"\n") or b"\r" in raw:
        issues.append(Issue("manifest_malformed", corpus, "manifest must be LF-terminated"))
    entries: dict[str, str] = {}
    for number, line in enumerate(raw.decode("utf-8", errors="replace").splitlines(), 1):
        match = _LINE.match(line)
        if match is None:
            issues.append(Issue("manifest_malformed", corpus, f"line {number}"))
            continue
        digest, name = match.groups()
        if name in entries or name == MANIFEST:
            issues.append(Issue("manifest_duplicate_entry", corpus, name))
            continue
        entries[name] = digest
    if not entries:
        issues.append(Issue("manifest_empty", corpus, MANIFEST))
    return entries, issues


def snapshot(root: Path) -> dict[str, str]:
    """Digest of every regular file below ``root`` (ignores bytecode caches)."""
    out: dict[str, str] = {}
    for path in sorted(root.rglob("*")):
        if any(part in _IGNORED for part in path.relative_to(root).parts):
            continue
        if path.is_file():
            out[path.relative_to(root).as_posix()] = sha256_bytes(path.read_bytes())
    return out


def verify_manifest(root: Path, corpus: str, *, pinned_manifest_sha256: str | None = None) -> list[Issue]:
    """Verify bytes against the ORIGINAL manifest without rewriting anything.

    ``pinned_manifest_sha256`` pins the manifest itself so a coordinated edit of a
    capture *and* its manifest line is still detected.
    """
    entries, issues = parse_manifest(root, corpus)
    if pinned_manifest_sha256 is not None and (root / MANIFEST).is_file():
        actual = sha256_bytes((root / MANIFEST).read_bytes())
        if actual != pinned_manifest_sha256:
            issues.append(Issue("manifest_pin_mismatch", corpus, f"{actual[:12]} != {pinned_manifest_sha256[:12]}"))
    present = {name for name in snapshot(root) if name != MANIFEST}
    for name in sorted(present - set(entries)):
        issues.append(Issue("file_added", corpus, name))
    for name, digest in sorted(entries.items()):
        path = root / name
        if not path.is_file():
            issues.append(Issue("file_removed", corpus, name))
        elif sha256_bytes(path.read_bytes()) != digest:
            issues.append(Issue("hash_mismatch", corpus, name))
    return issues


def compare_regeneration(spec: CorpusSpec, workdir: Path | None = None) -> list[Issue]:
    """Rebuild into a disposable directory and byte-compare against the frozen originals."""
    with tempfile.TemporaryDirectory(prefix="bbtk-regen-") as tmp:
        out = (workdir or Path(tmp)) / spec.name
        lab_dir = spec.root.resolve().parent
        if out.exists() or out.resolve() == lab_dir or lab_dir in out.resolve().parents:
            raise ValueError("Regeneration target must be a new directory outside the corpus lab.")
        spec.builder(out)
        fresh = snapshot(out)
    frozen = snapshot(spec.root)
    issues: list[Issue] = []
    for name in sorted(set(frozen) - set(fresh)):
        issues.append(Issue("regenerated_file_missing", spec.name, name))
    for name in sorted(set(fresh) - set(frozen)):
        issues.append(Issue("regenerated_file_extra", spec.name, name))
    for name in sorted(set(fresh) & set(frozen)):
        if fresh[name] != frozen[name]:
            issues.append(Issue("regeneration_drift", spec.name, name))
    return issues


def _load(root: Path, name: str) -> Any:
    return json.loads((root / name).read_text(encoding="utf-8"))


def validate_ground_truth(root: Path, corpus: str) -> list[Issue]:
    """Structural ground-truth checks: references, labels, single ownership of entries."""
    issues: list[Issue] = []
    try:
        gt = _load(root, "ground_truth.json")
        har = _load(root, "captures.har")
    except (OSError, ValueError) as exc:
        return [Issue("corpus_unreadable", corpus, type(exc).__name__)]
    entries = har.get("log", {}).get("entries") if isinstance(har, dict) else None
    if not isinstance(entries, list):
        return [Issue("captures_malformed", corpus, "log.entries")]
    scenarios = gt.get("scenarios") if isinstance(gt, dict) else None
    if not isinstance(scenarios, list) or not scenarios:
        return [Issue("ground_truth_malformed", corpus, "scenarios")]
    owner: dict[int, str] = {}
    seen_ids: set[str] = set()
    for scenario in scenarios:
        sid = str(scenario.get("id"))
        if sid in seen_ids:
            issues.append(Issue("duplicate_scenario_id", corpus, sid))
        seen_ids.add(sid)
        refs = scenario.get("entries")
        if not isinstance(refs, list) or not refs:
            issues.append(Issue("scenario_without_entries", corpus, sid))
            refs = []
        for ref in refs:
            if not isinstance(ref, int) or not 0 <= ref < len(entries):
                issues.append(Issue("missing_entry_ref", corpus, f"{sid}:{ref}"))
            elif ref in owner:
                issues.append(Issue("entry_shared_by_scenarios", corpus, f"{owner[ref]},{sid}:{ref}"))
            else:
                owner[ref] = sid
        labels: dict[str, set[str]] = {}
        for key in LABEL_KEYS:
            value = scenario.get(key)
            if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
                issues.append(Issue("label_malformed", corpus, f"{sid}:{key}"))
                value = []
            labels[key] = set(value)
        if labels["expected_pair_types"] & labels["forbidden_pair_types"]:
            issues.append(Issue("label_contradiction", corpus, sid))
        if scenario.get("expected_confirmed") is not False:
            issues.append(Issue("ground_truth_claims_confirmation", corpus, sid))
    orphans = sorted(set(range(len(entries))) - set(owner))
    if orphans:
        issues.append(Issue("entry_without_scenario", corpus, ",".join(map(str, orphans[:10]))))
    return issues


def _request_fingerprints(root: Path) -> set[str]:
    har = _load(root, "captures.har")
    out: set[str] = set()
    for entry in har["log"]["entries"]:
        canon = json.dumps({"request": entry.get("request"), "response": entry.get("response")}, sort_keys=True)
        out.add(sha256_bytes(canon.encode()))
    return out


def check_independence(a: Path, b: Path, name_a: str, name_b: str) -> list[Issue]:
    """Supposedly independent sets must not share origins, scenario IDs or identical exchanges."""
    pair = f"{name_a}~{name_b}"
    gta, gtb = _load(a, "ground_truth.json"), _load(b, "ground_truth.json")
    issues: list[Issue] = []
    if gta.get("origin") == gtb.get("origin"):
        issues.append(Issue("shared_origin", pair, str(gta.get("origin"))))
    shared_ids = {s["id"] for s in gta["scenarios"]} & {s["id"] for s in gtb["scenarios"]}
    if shared_ids:
        issues.append(Issue("shared_scenario_ids", pair, ",".join(sorted(shared_ids))))
    shared = _request_fingerprints(a) & _request_fingerprints(b)
    if shared:
        issues.append(Issue("shared_exchanges", pair, str(len(shared))))
    return issues


def audit(
    specs: Iterable[CorpusSpec],
    *,
    pins: Mapping[str, str] | None = None,
    independent_pairs: Iterable[tuple[str, str]] = (),
) -> list[Issue]:
    """Full read-only audit. Returns an empty list when every corpus is intact."""
    by_name = {spec.name: spec for spec in specs}
    issues: list[Issue] = []
    for spec in by_name.values():
        issues += verify_manifest(spec.root, spec.name, pinned_manifest_sha256=(pins or {}).get(spec.name))
        issues += validate_ground_truth(spec.root, spec.name)
        issues += compare_regeneration(spec)
    for left, right in independent_pairs:
        issues += check_independence(by_name[left].root, by_name[right].root, left, right)
    return issues
