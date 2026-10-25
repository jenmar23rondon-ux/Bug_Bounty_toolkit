"""Offline, researcher-reviewed preparation of native access-check cases."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import tempfile
from typing import Any
from urllib.parse import unquote

from .access_control.comparison import account_observations, exact, load_case, lookup, parse_json, pointer_parts
from .analysis.access_assessment import assess_access_control_data
from .burp_import import (
    MAX_EXCHANGE_BYTES,
    CapturedExchange,
    captured_response,
    parse_captured_exchanges,
    read_capture_file,
)
from .case_generator import MARKER, SESSION_HEADER, CaseGenerationOptions, ReadPair, inspect_read_pair, prepare_case
from .core.scope_validator import ScopeValidator
from .core.redaction import SENSITIVE_KEY

MAX_CANDIDATES = 64
MAX_PROPOSAL_BYTES = 2_000_000
SENSITIVE_FIELD = re.compile(SENSITIVE_KEY.pattern + "|" + SESSION_HEADER.pattern + r"|jwt|private.?key", re.I)
REVIEW_ATTESTATIONS = (
    "accounts_authorized",
    "resource_ownership_confirmed",
    "resource_private",
    "read_only_confirmed",
    "controls_success_confirmed",
    "markers_private_confirmed",
    "captured_origin_confirmed",
    "approved",
)
POINTER_FIELDS = ("success_pointer", "resource_pointer", "private_pointer")


@dataclass(frozen=True)
class IdorDiscovery:
    """Contains private messages; expose only discovery_summary to a console/report."""

    proposal: dict[str, Any]
    owner: tuple[CapturedExchange, ...]
    actor: tuple[CapturedExchange, ...]


def _json_document(exchange: CapturedExchange) -> Any:
    response = captured_response(exchange)
    if response is None:
        return None
    content_type = response.headers.get("content-type", "").split(";", 1)[0].strip().lower()
    if content_type != "application/json" and not content_type.endswith("+json"):
        return None
    try:
        return parse_json(response.body_text)
    except ValueError as exc:
        raise ValueError("Captured JSON is malformed or ambiguous; inspect it locally.") from exc


def json_scalar_fields(document: Any, include_sensitive: bool = False) -> dict[str, Any]:
    """Bounded JSON pointers shared by offline case and object discovery."""
    result: dict[str, Any] = {}
    nodes = 0

    def visit(value: Any, path: str, depth: int) -> None:
        nonlocal nodes
        nodes += 1
        if nodes > 4096 or depth > 16:
            raise ValueError("Captured JSON exceeds the discovery structure limit.")
        if isinstance(value, dict):
            for key, child in value.items():
                if len(key) > 128 or (not include_sensitive and SENSITIVE_FIELD.search(key)):
                    continue
                visit(child, path + "/" + key.replace("~", "~0").replace("/", "~1"), depth + 1)
        elif isinstance(value, list):
            for index, child in enumerate(value):
                visit(child, path + "/" + str(index), depth + 1)
        elif path and len(path) <= 256 and type(value) in {str, int, bool}:
            result[path] = value
            if len(result) > 128:
                raise ValueError("Captured JSON exceeds the discovery field limit.")

    visit(document, "", 0)
    return result


_leaves = json_scalar_fields


def _resource_matches(value: Any, identifier: str) -> bool:
    return type(value) in {str, int} and str(value) == identifier


def _credential_values(owner: CapturedExchange, actor: CapturedExchange) -> tuple[str, ...]:
    values: list[str] = []
    for exchange in (owner, actor):
        response = captured_response(exchange)
        if response is not None:
            values.extend(value for name, value in response.headers.items() if SESSION_HEADER.search(name))
            values.extend(response.set_cookies)
        for pointer, value in _leaves(_json_document(exchange), include_sensitive=True).items():
            if isinstance(value, str) and any(SENSITIVE_FIELD.search(part) for part in pointer_parts(pointer)):
                values.append(value)
    return tuple(unquote(value) for value in values)


def _proof_markers(
    left: Any, right: Any, owner: CapturedExchange, actor: CapturedExchange, credentials: tuple[str, ...] | None = None
) -> bool:
    if not isinstance(left, str) or not isinstance(right, str):
        return False
    if not MARKER.fullmatch(left) or not MARKER.fullmatch(right) or left in right or right in left:
        return False
    for exchange in (owner, actor):
        request = exchange.request
        material = [unquote(request.prepared_url()), *[unquote(value) for value in request.headers.values()]]
        if any(marker in value for marker in (left, right) for value in material):
            return False
    credentials = credentials if credentials is not None else _credential_values(owner, actor)
    if any(marker in value for value in credentials for marker in (left, right)):
        return False
    return right not in (owner.raw_response or "") and left not in (actor.raw_response or "")


def _suggestions(owner: CapturedExchange, actor: CapturedExchange, pair: ReadPair) -> dict[str, list[str]]:
    left, right = _leaves(_json_document(owner)), _leaves(_json_document(actor))
    credentials = _credential_values(owner, actor)
    suggestions: dict[str, list[str]] = {field: [] for field in POINTER_FIELDS}
    for pointer in sorted(left.keys() & right.keys()):
        own, act = left[pointer], right[pointer]
        if type(own) is not type(act):
            continue
        name = pointer_parts(pointer)[-1].casefold()
        if name in {"success", "ok", "status", "code"} and exact(own, act):
            suggestions["success_pointer"].append(pointer)
        if _resource_matches(own, pair.owner_resource) and _resource_matches(act, pair.actor_resource):
            suggestions["resource_pointer"].append(pointer)
        if _proof_markers(own, act, owner, actor, credentials):
            suggestions["private_pointer"].append(pointer)
    return suggestions


def _capture_entry(role: str, index: int, exchange: CapturedExchange) -> dict[str, Any]:
    stem = f"captures/{role}-{index + 1:03d}"
    return {
        "request": stem + ".request.http",
        "request_sha256": hashlib.sha256(exchange.raw_request.encode("utf-8")).hexdigest(),
        "response": stem + ".response.http" if exchange.raw_response is not None else None,
        "response_sha256": hashlib.sha256(exchange.raw_response.encode("utf-8")).hexdigest()
        if exchange.raw_response is not None
        else None,
    }


def discover_idor(
    program: str,
    owner: Path,
    actor: Path,
    *,
    base_url: str | None = None,
    owner_response: Path | None = None,
    actor_response: Path | None = None,
    accounts_authorized: bool = False,
) -> IdorDiscovery:
    """Suggest structurally compatible known-resource pairs, never send or authorize a test."""
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,79}", program) or type(accounts_authorized) is not bool:
        raise ValueError("A valid program and boolean authorization declaration are required.")

    def exchanges(path: Path, response_path: Path | None) -> tuple[CapturedExchange, ...]:
        return parse_captured_exchanges(
            read_capture_file(path),
            base_url,
            read_capture_file(response_path, MAX_EXCHANGE_BYTES) if response_path is not None else None,
        )

    owners, actors = exchanges(owner, owner_response), exchanges(actor, actor_response)
    # Validate the bounded JSON structure even for an exchange that will not be paired.
    for exchange in (*owners, *actors):
        _leaves(_json_document(exchange))
    proposal: dict[str, Any] = {
        "type": "idor-case-proposal",
        "version": 1,
        "program": program,
        "state": "needs_review",
        "accounts_authorized": accounts_authorized,
        "confirmed": False,
        "network_requests_sent": 0,
        "owner_count": len(owners),
        "actor_count": len(actors),
        "pairs_reviewed": 0,
        "session_only_pairs": 0,
        "unsupported_pairs": 0,
        "candidates_truncated": False,
        "captures": {
            "owner": [_capture_entry("owner", index, exchange) for index, exchange in enumerate(owners)],
            "actor": [_capture_entry("actor", index, exchange) for index, exchange in enumerate(actors)],
        },
        "candidates": [],
    }
    for oi, own in enumerate(owners):
        for ai, act in enumerate(actors):
            if len(proposal["candidates"]) >= MAX_CANDIDATES:
                proposal["candidates_truncated"] = True
                return IdorDiscovery(proposal, owners, actors)
            proposal["pairs_reviewed"] += 1
            left = {key.lower(): value for key, value in own.request.headers.items()}
            right = {key.lower(): value for key, value in act.request.headers.items()}
            session_changes = sum(
                left.get(name) != right.get(name) for name in left.keys() | right.keys() if SESSION_HEADER.search(name)
            )
            if own.request.prepared_url() == act.request.prepared_url() and session_changes:
                proposal["session_only_pairs"] += 1
                continue
            try:
                pair = inspect_read_pair(own.request, act.request, base_url)
            except ValueError:
                proposal["unsupported_pairs"] += 1
                continue
            review: dict[str, Any] = dict.fromkeys(POINTER_FIELDS)
            review.update(dict.fromkeys(REVIEW_ATTESTATIONS, False))
            review["expected_cross_access"] = None
            proposal["candidates"].append(
                {
                    "id": f"candidate-{len(proposal['candidates']) + 1:03d}",
                    "owner_index": oi,
                    "actor_index": ai,
                    "base_url": pair.origin,
                    "resource": pair.resource,
                    "session_headers": list(pair.session_headers),
                    "differences": {
                        "session_headers": session_changes,
                        "path_segments": int("path_segment" in pair.resource),
                        "query_parameters": int("query_parameter" in pair.resource),
                    },
                    "suggested_checks": _suggestions(own, act, pair),
                    "review": review,
                }
            )
    return IdorDiscovery(proposal, owners, actors)


def discovery_summary(discovery: IdorDiscovery) -> dict[str, Any]:
    """Allowlist a shareable count-only summary: no URLs, names, pointers or values."""
    proposal = discovery.proposal
    return {
        "type": "idor-discovery-summary",
        "state": "needs_review",
        "confirmed": False,
        "network_requests_sent": 0,
        **{
            key: proposal[key]
            for key in (
                "owner_count",
                "actor_count",
                "pairs_reviewed",
                "session_only_pairs",
                "unsupported_pairs",
                "candidates_truncated",
            )
        },
        "candidates": [
            {
                "id": row["id"],
                "differences": row["differences"],
                "suggested_field_counts": {key: len(value) for key, value in row["suggested_checks"].items()},
                "researcher_approval_required": True,
            }
            for row in proposal["candidates"]
        ],
    }


def _write_private(path: Path, data: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    with os.fdopen(os.open(path, flags, 0o600), "wb") as handle:
        handle.write(data)


def save_proposal(discovery: IdorDiscovery, directory: Path) -> Path:
    """Save an exclusive private bundle; never overwrite captures or shared reports."""
    directory = directory.expanduser().absolute()
    if any(path.is_symlink() for path in (directory, *directory.parents)):
        raise ValueError("Private proposal directories must not use symbolic links.")
    rendered = (json.dumps(discovery.proposal, indent=2, ensure_ascii=True) + "\n").encode()
    if len(rendered) > MAX_PROPOSAL_BYTES:
        raise ValueError("Proposal exceeds its size limit; select fewer captures.")
    if directory.exists():
        raise ValueError("Proposal directory already exists; choose a new private directory.")
    directory.parent.mkdir(parents=True, exist_ok=True)
    directory.mkdir(mode=0o700)
    try:
        (directory / "captures").mkdir(mode=0o700)
        for role, exchanges in (("owner", discovery.owner), ("actor", discovery.actor)):
            for index, exchange in enumerate(exchanges):
                entry = _capture_entry(role, index, exchange)
                _write_private(directory / entry["request"], exchange.raw_request.encode("utf-8"))
                if exchange.raw_response is not None:
                    _write_private(directory / entry["response"], exchange.raw_response.encode("utf-8"))
        path = directory / "proposal.json"
        _write_private(path, rendered)
    except BaseException:
        shutil.rmtree(directory)
        raise
    return path


def _snapshot(root: Path, entries: Any, role: str, index: Any, base_url: str) -> CapturedExchange:
    if not isinstance(entries, list) or type(index) is not int or not 0 <= index < len(entries) <= 32:
        raise ValueError("Invalid proposal capture selection.")
    entry = entries[index]
    if not isinstance(entry, dict) or set(entry) != {"request", "request_sha256", "response", "response_sha256"}:
        raise ValueError("Invalid proposal capture manifest.")
    stem = f"captures/{role}-{index + 1:03d}"
    if entry["request"] != stem + ".request.http" or entry["response"] not in (None, stem + ".response.http"):
        raise ValueError("Proposal capture references must use their original private bundle paths.")
    request = read_capture_file(root / entry["request"], MAX_EXCHANGE_BYTES)
    response = read_capture_file(root / entry["response"], MAX_EXCHANGE_BYTES) if entry["response"] else None
    for content, digest in ((request, entry["request_sha256"]), (response, entry["response_sha256"])):
        if content is None or not isinstance(digest, str) or hashlib.sha256(content).hexdigest() != digest:
            raise ValueError("Approval requires unchanged request and response snapshots for both accounts.")
    return parse_captured_exchanges(request, base_url, response)[0]


def approve_idor(
    proposal_path: Path,
    candidate_id: str,
    program: str,
    scope: ScopeValidator,
    *,
    approve: bool = False,
    dry_run: bool = False,
) -> dict[str, Any]:
    """Require explicit review, verify saved controls offline and reuse the native case builder/loader."""
    if approve is not True:
        raise ValueError("Explicit --approve is required; discovery is not execution authorization.")
    if not re.fullmatch(r"candidate-[0-9]{3}", candidate_id):
        raise ValueError("Choose a candidate ID from the private proposal.")
    try:
        proposal = parse_json(read_capture_file(proposal_path, MAX_PROPOSAL_BYTES).decode("utf-8"))
    except (ValueError, UnicodeError) as exc:
        raise ValueError("Proposal must be bounded valid JSON in its original private bundle.") from exc
    if (
        not isinstance(proposal, dict)
        or proposal.get("type") != "idor-case-proposal"
        or proposal.get("version") != 1
        or proposal.get("program") != program
        or proposal.get("state") != "needs_review"
        or proposal.get("confirmed") is not False
        or not isinstance(proposal.get("captures"), dict)
        or not isinstance(proposal.get("candidates"), list)
        or len(proposal["candidates"]) > MAX_CANDIDATES
    ):
        raise ValueError("Proposal type, program or candidate structure is invalid.")
    rows = [row for row in proposal["candidates"] if isinstance(row, dict) and row.get("id") == candidate_id]
    if len(rows) != 1:
        raise ValueError("Candidate is missing or ambiguous.")
    candidate = rows[0]
    review = candidate.get("review")
    if (
        not isinstance(review, dict)
        or set(review) != set(POINTER_FIELDS) | set(REVIEW_ATTESTATIONS) | {"expected_cross_access"}
        or any(review.get(field) is not True for field in REVIEW_ATTESTATIONS)
        or review.get("expected_cross_access") != "deny"
    ):
        raise ValueError(
            "Researcher review must explicitly confirm accounts, ownership, privacy, read semantics, controls, origin and approval."
        )
    for field in POINTER_FIELDS:
        pointer_parts(review[field])
        if any(SENSITIVE_FIELD.search(part) for part in pointer_parts(review[field])):
            raise ValueError("Credentials/session fields cannot be selected as comparison proof.")
    base_url = candidate.get("base_url")
    if not isinstance(base_url, str):
        raise ValueError("The reviewed captured origin is required.")
    root = proposal_path.expanduser().absolute().parent
    owner = _snapshot(root, proposal["captures"].get("owner"), "owner", candidate.get("owner_index"), base_url)
    actor = _snapshot(root, proposal["captures"].get("actor"), "actor", candidate.get("actor_index"), base_url)
    try:
        pair = inspect_read_pair(owner.request, actor.request, base_url)
    except ValueError as exc:
        raise ValueError("Reviewed captures no longer form a supported native read pair.") from exc
    if pair.resource != candidate.get("resource"):
        raise ValueError("The proposed resource selector no longer matches both captures.")
    for exchange in (owner, actor):
        try:
            scope.require(exchange.request.prepared_url())
        except ValueError as exc:
            raise ValueError("A reviewed capture is outside the existing program scope.") from exc
    own, act = _json_document(owner), _json_document(actor)
    values = [(lookup(own, review[field]), lookup(act, review[field])) for field in POINTER_FIELDS]
    success, resource, markers = values
    if not exact(*success) or type(success[0]) not in {bool, str, int}:
        raise ValueError("Both captured controls must agree on the selected application-success value.")
    if (
        type(resource[0]) is not type(resource[1])
        or not _resource_matches(resource[0], pair.owner_resource)
        or not _resource_matches(resource[1], pair.actor_resource)
    ):
        raise ValueError("The selected JSON resource fields must match both captured request identifiers.")
    if not _proof_markers(*markers, owner, actor):
        raise ValueError("Both controls need distinct non-reflected private proof markers.")
    output = root / f"case-{candidate_id}.json"
    if output.exists():
        raise ValueError("An approved case already exists; create a new proposal rather than overwrite it.")
    captures = proposal["captures"]
    case, _ = prepare_case(
        CaseGenerationOptions(
            owner=root / captures["owner"][candidate["owner_index"]]["request"],
            actor=root / captures["actor"][candidate["actor_index"]]["request"],
            output=output,
            base_url=base_url,
            resource_pointer=review["resource_pointer"],
            private_pointer=review["private_pointer"],
            success_pointer=review["success_pointer"],
            success_value=success[0],
            private_marker=markers[0],
            actor_marker=markers[1],
            accounts_authorized=True,
            resource_private=True,
            dry_run=True,
        )
    )
    case["checks"].update(owner_resource=resource[0], actor_resource=resource[1])
    for exchange, value, marker, other in (
        (owner, resource[0], markers[0], markers[1]),
        (actor, resource[1], markers[1], markers[0]),
    ):
        response = captured_response(exchange)
        assert response is not None
        facts = account_observations(response, case["checks"], value, marker)
        if (
            response.status_code != 200
            or not all(facts[key] is True for key in ("application_success", "resource_match", "private_match"))
            or other in response.body_text
        ):
            raise ValueError("Captured own-resource controls do not validate the reviewed checks.")
    if not dry_run:
        # Validate through the same loader that access-check uses before publishing a case.
        temporary: Path | None = None
        try:
            with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=root, delete=False) as handle:
                temporary = Path(handle.name)
                json.dump(case, handle)
            load_case(temporary, scope)
        finally:
            if temporary is not None:
                temporary.unlink(missing_ok=True)
        _write_private(output, (json.dumps(case, indent=2, ensure_ascii=True) + "\n").encode())
    return {
        "type": "idor-case-approval",
        "candidate": candidate_id,
        "case_written": not dry_run,
        "network_requests_sent": 0,
        "confirmed": False,
        "assessment": assess_access_control_data(case, None),
    }
