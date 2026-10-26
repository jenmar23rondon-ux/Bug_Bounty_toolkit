"""Offline human-declared actor provenance, separate from authorization and findings.

Session fingerprints are observations, never account proofs. This sidecar does not
change EvidenceRecord, graph, assessment, approval or finding state.
"""

from __future__ import annotations

from datetime import datetime
import hashlib
import hmac
import json
from pathlib import Path
import re
from typing import Any, Iterable

from .evidence_engine import EvidenceRecord

MANIFEST_SCHEMA = "bbtk.actor-labels/1"
PROVENANCE_SCHEMA = "bbtk.actor-provenance/1"
LABELS = frozenset({"owner", "second_account", "anonymous", "role_a", "role_b", "unknown"})
COLORS = frozenset({"red", "orange", "yellow", "green", "cyan", "blue", "purple", "pink"})
MAX_MANIFEST_BYTES = 1_000_000
MAX_CAPTURES = 4096
_FINGERPRINT = re.compile(r"hmac-sha256:[a-f0-9]{24}")


def _ref(kind: str, value: object, *, program: str, key: bytes) -> str:
    if len(key) < 32 or not program or len(program) > 80:
        raise ValueError("A program and private HMAC key of at least 32 bytes are required.")
    payload = json.dumps([PROVENANCE_SCHEMA, program, kind, value], sort_keys=True, separators=(",", ":"))
    return kind + ":" + hmac.new(key, payload.encode(), hashlib.sha256).hexdigest()[:32]


def account_ref(alias: str, *, program: str, key: bytes) -> str:
    """Opaque program-scoped human alias; does not verify account ownership."""
    return _ref("account", alias, program=program, key=key)


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for name, value in pairs:
        if name in out:
            raise ValueError("Duplicate manifest field.")
        out[name] = value
    return out


def load_manifest(path: Path) -> dict[str, Any]:
    """Read a bounded local manifest; duplicate keys and extra fields fail closed."""
    with path.open("rb") as stream:
        raw = stream.read(MAX_MANIFEST_BYTES + 1)
    if len(raw) > MAX_MANIFEST_BYTES:
        raise ValueError("Manifest exceeds size bound.")
    try:
        document = json.loads(raw, object_pairs_hook=_pairs)
    except (ValueError, UnicodeError, RecursionError):
        raise ValueError("Invalid actor manifest JSON.") from None
    return validate_manifest(document)


def _text(value: object) -> bool:
    return isinstance(value, str) and 0 < len(value) <= 300 and not any(ord(c) < 32 for c in value)


def validate_manifest(document: Any) -> dict[str, Any]:
    """Validate structure without echoing private input in exceptions."""
    if not isinstance(document, dict) or set(document) != {"schema", "program", "labels", "distinct_accounts"}:
        raise ValueError("Invalid actor manifest fields.")
    if document["schema"] != MANIFEST_SCHEMA or (not _text(document["program"]) or len(document["program"]) > 80):
        raise ValueError("Invalid actor manifest schema or program.")
    rows = document["labels"]
    if not isinstance(rows, list) or len(rows) > MAX_CAPTURES:
        raise ValueError("Invalid actor label count.")
    seen = set()
    accounts = set()
    for row in rows:
        required = {"source_path", "locator", "label"}
        optional = {"account", "declared_by_human", "browser", "pwnfox_color"}
        if not isinstance(row, dict) or not required <= set(row) or set(row) - required - optional:
            raise ValueError("Invalid actor label fields.")
        if any(not _text(row[name]) for name in required) or row["label"] not in LABELS:
            raise ValueError("Invalid capture selector or label.")
        selector = (row["source_path"], row["locator"])
        if selector in seen:
            raise ValueError("Duplicate capture selector.")
        seen.add(selector)
        if "pwnfox_color" in row and (not isinstance(row["pwnfox_color"], str) or row["pwnfox_color"] not in COLORS):
            raise ValueError("Unsupported Pwnfox color.")
        if "browser" in row and not _text(row["browser"]):
            raise ValueError("Invalid browser alias.")
        if "account" in row:
            if not _text(row["account"]) or row.get("declared_by_human") is not True:
                raise ValueError("Account aliases require explicit human declaration.")
            if row["label"] in {"anonymous", "unknown"}:
                raise ValueError("Anonymous or unknown labels cannot assert an account.")
            accounts.add(row["account"])
        elif "declared_by_human" in row:
            raise ValueError("Human declaration requires an account alias.")
    pairs = document["distinct_accounts"]
    if not isinstance(pairs, list) or len(pairs) > MAX_CAPTURES:
        raise ValueError("Invalid distinct-account declarations.")
    seen_pairs = set()
    for pair in pairs:
        if (
            not isinstance(pair, list)
            or len(pair) != 2
            or any(not _text(x) for x in pair)
            or pair[0] == pair[1]
            or not set(pair) <= accounts
        ):
            raise ValueError("Distinct accounts require two declared human aliases.")
        marker = tuple(sorted(pair))
        if marker in seen_pairs:
            raise ValueError("Duplicate distinct-account declaration.")
        seen_pairs.add(marker)
    return document


def _time(value: str | None) -> str | None:
    try:
        parsed = datetime.fromisoformat((value or "").replace("Z", "+00:00"))
        return parsed.isoformat() if parsed.tzinfo is not None else None
    except ValueError:
        return None


def associate_actors(
    records: Iterable[EvidenceRecord],
    manifest: dict[str, Any],
    *,
    program: str,
    key: bytes,
) -> dict[str, Any]:
    """Adapt existing capture records into a deterministic, content-free sidecar.

    Selectors must match exactly one record provenance. All selectors must resolve;
    the caller must supply only this program's records and its existing private key.
    Nothing is joined across invocations/programs. No I/O or network is performed.
    """
    validate_manifest(manifest)
    if manifest["program"] != program:
        raise ValueError("Manifest belongs to another program.")
    program_ref = _ref("program", program, program=program, key=key)
    index: dict[tuple[str, str], list[EvidenceRecord]] = {}
    for count, record in enumerate(records):
        if count >= MAX_CAPTURES:
            raise ValueError("Capture count exceeds bound.")
        for provenance in record.provenance:
            index.setdefault((provenance.source_path, provenance.locator), []).append(record)
    declarations = {(row["source_path"], row["locator"]): row for row in manifest["labels"]}
    if any(selector not in index or len(index[selector]) != 1 for selector in declarations):
        raise ValueError("Unresolved or ambiguous capture selector.")
    captures: list[dict[str, Any]] = []
    for selector, matches in sorted(index.items()):
        if len(matches) != 1:
            raise ValueError("Ambiguous capture provenance.")
        record = matches[0]
        row = declarations.get(selector, {})
        session_values = [
            record.request_session_fingerprint,
            record.response_session_fingerprint,
            record.session_fingerprint,
        ]
        if any(value is not None and not _FINGERPRINT.fullmatch(value) for value in session_values):
            raise ValueError("Unsupported session fingerprint format.")
        # Re-scope existing HMACs: even identical imported fingerprints cannot join programs.
        session = record.request_session_fingerprint or record.session_fingerprint
        account = account_ref(row["account"], program=program, key=key) if "account" in row else None
        captures.append(
            {
                "capture_ref": _ref("capture", selector, program=program, key=key),
                "evidence_ref": _ref("evidence", record.evidence_id, program=program, key=key),
                "source_ref": _ref("source", selector[0], program=program, key=key),
                "locator_ref": _ref("locator", selector, program=program, key=key),
                "label": row.get("label", "unknown"),
                "pwnfox_color": row.get("pwnfox_color"),
                "account_ref": account,
                "browser_ref": _ref("browser", row["browser"], program=program, key=key) if "browser" in row else None,
                "session_ref": _ref("session", session, program=program, key=key) if session else None,
                "captured_at": _time(record.captured_at),
                "session_change_observed": bool(
                    record.request_session_fingerprint
                    and record.response_session_fingerprint
                    and record.request_session_fingerprint != record.response_session_fingerprint
                ),
                "identity_basis": "human_declaration" if account else "unknown",
            }
        )
    conflicts: list[dict[str, Any]] = []

    def conflict(code: str, group: list[dict[str, Any]], *, block: bool) -> None:
        conflicts.append(
            {
                "code": code,
                "captures": sorted(row["capture_ref"] for row in group),
                "resolution": "human_review_required",
            }
        )
        if block:
            for row in group:
                row["account_ref"] = None
                row["identity_basis"] = "unknown"

    # Evaluate all groups against the original declarations, before suppressing claims.
    groups: list[tuple[str, list[dict[str, Any]], bool]] = []
    for label in sorted(LABELS - {"unknown", "anonymous"}):
        group = [row for row in captures if row["label"] == label]
        if len({row["account_ref"] for row in group if row["account_ref"]}) > 1:
            groups.append(("label_account_conflict", group, True))
        if len({row["session_ref"] for row in group if row["session_ref"]}) > 1:
            groups.append(("label_multiple_sessions", group, False))
    for session in sorted({row["session_ref"] for row in captures if row["session_ref"]}):
        group = [row for row in captures if row["session_ref"] == session]
        if len({row["account_ref"] for row in group if row["account_ref"]}) > 1:
            groups.append(("session_account_conflict", group, True))
    for row in captures:
        if row["label"] == "anonymous" and row["session_ref"]:
            groups.append(("anonymous_session_material", [row], True))
    for code, group, block in groups:
        conflict(code, group, block=block)
    valid_accounts = {row["account_ref"] for row in captures if row["account_ref"]}
    distinct = sorted(
        sorted(account_ref(alias, program=program, key=key) for alias in pair)
        for pair in manifest["distinct_accounts"]
        if all(account_ref(alias, program=program, key=key) in valid_accounts for alias in pair)
    )
    return {
        "schema": PROVENANCE_SCHEMA,
        "program_ref": program_ref,
        "captures": captures,
        "conflicts": conflicts,
        "distinct_accounts": distinct,
        "different_capture_times": len({row["captured_at"] for row in captures if row["captured_at"]}) > 1,
    }


def pwnfox_color(source: object) -> str | None:
    """Read X-PwnFox-Color from HAR headers or a header mapping; never infer an actor."""
    headers: object = source
    if isinstance(source, dict) and isinstance(source.get("request"), dict):
        headers = source["request"].get("headers")
    if isinstance(headers, dict):
        pairs = list(headers.items())
    elif isinstance(headers, list):
        pairs = [(row.get("name"), row.get("value")) for row in headers if isinstance(row, dict)]
    else:
        return None
    colors = [
        value.lower()
        for name, value in pairs
        if isinstance(name, str) and name.lower() == "x-pwnfox-color" and isinstance(value, str)
    ]
    return colors[0] if len(colors) == 1 and colors[0] in COLORS else None
