"""Explicit offline import of private, manually selected Burp evidence. No network API."""

from __future__ import annotations

import argparse
import base64
from dataclasses import dataclass
from datetime import datetime
import hashlib
import json
import os
import stat
from pathlib import Path
import re
import tempfile
from typing import Any, Sequence
from urllib.parse import urlsplit
import xml.etree.ElementTree as ET

from .burp_import import CapturedExchange, parse_captured_exchanges
from .core.private_files import atomic_private_write, local_path, read_private_input

SCHEMA = "bbtk.burp-passive/1"
MAX_ENTRIES = 100
MAX_FILE_BYTES = 16 * 1024 * 1024
MAX_MESSAGE_BYTES = 1_000_000


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def _origin(value: str) -> str:
    parts = urlsplit(value)
    if (
        parts.scheme not in {"http", "https"}
        or not parts.hostname
        or parts.username is not None
        or parts.password is not None
        or parts.path not in {"", "/"}
        or parts.query
        or parts.fragment
    ):
        raise ValueError("Invalid bridge origin.")
    port = parts.port
    host = parts.hostname.lower()
    if ":" in host:
        host = "[" + host + "]"
    suffix = "" if port is None or port == (443 if parts.scheme == "https" else 80) else f":{port}"
    return f"{parts.scheme}://{host}{suffix}"


def _project(value: object) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[a-z0-9][a-z0-9._-]{0,63}", value):
        raise ValueError("Invalid bridge project.")
    return value


def _time(value: object) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or len(value) > 40:
        raise ValueError("Invalid bridge timestamp.")
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("Bridge timestamps require a timezone.")
    return parsed.isoformat()


@dataclass(frozen=True, repr=False)
class Selection:
    """Private mock/adapter input; timestamps are capture times, never invented."""

    origin: str
    request: bytes
    response: bytes | None = None
    timestamp: str | None = None


@dataclass(frozen=True, repr=False)
class ImportedCapture:
    locator: str
    exchange: CapturedExchange
    timestamp: str | None


@dataclass(frozen=True)
class BridgePreview:
    declared: int
    duplicates: int
    rejected: int
    captures: tuple[ImportedCapture, ...]

    def summary(self) -> dict[str, object]:
        # An allowlist, rather than best-effort scrubbing of arbitrary capture content.
        return {
            "schema": SCHEMA,
            "entries": self.declared,
            "accepted": len(self.captures),
            "duplicates": self.duplicates,
            "rejected": self.rejected,
            "network_requests_sent": 0,
            "vulnerabilities_confirmed": 0,
            "human_review_required": True,
        }


def envelope(project: str, selections: Sequence[Selection]) -> bytes:
    """Build a PRIVATE transfer file; callers must obtain manual selection first."""
    _project(project)
    if not 1 <= len(selections) <= MAX_ENTRIES:
        raise ValueError("Bridge selection count exceeds limits.")
    entries: list[dict[str, object]] = []
    for selection in selections:
        if any(len(raw) > MAX_MESSAGE_BYTES for raw in (selection.request, selection.response or b"")):
            raise ValueError("Bridge message exceeds limits.")
        entries.append(
            {
                "origin": _origin(selection.origin),
                "timestamp": _time(selection.timestamp),
                "request": base64.b64encode(selection.request).decode("ascii"),
                "response": None
                if selection.response is None
                else base64.b64encode(selection.response).decode("ascii"),
            }
        )
    payload = {"schema": SCHEMA, "project": project, "entries": entries}
    result = _canonical({"payload": payload, "sha256": hashlib.sha256(_canonical(payload)).hexdigest()})
    if len(result) > MAX_FILE_BYTES:
        raise ValueError("Bridge file exceeds limits.")
    return result


def _unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate bridge JSON key.")
        result[key] = value
    return result


def inspect_bytes(raw: bytes, *, project: str, origins: Sequence[str]) -> BridgePreview:
    """Validate selection again on import; error messages never echo private content."""
    try:
        return _inspect(raw, project=project, origins=origins)
    except (ValueError, TypeError, KeyError, AttributeError, RecursionError, OverflowError):
        raise ValueError("Bridge file refused; inspect the private input locally.") from None


def _inspect(raw: bytes, *, project: str, origins: Sequence[str]) -> BridgePreview:
    if len(raw) > MAX_FILE_BYTES or not origins or len(origins) > MAX_ENTRIES:
        raise ValueError("Bridge limits exceeded.")
    allowed = {_origin(origin) for origin in origins}
    document = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique)
    if set(document) != {"payload", "sha256"}:
        raise ValueError("Invalid envelope.")
    payload = document["payload"]
    if set(payload) != {"schema", "project", "entries"} or payload["schema"] != SCHEMA:
        raise ValueError("Unsupported protocol.")
    if _project(payload["project"]) != _project(project):
        raise ValueError("Project mismatch.")
    digest = hashlib.sha256(_canonical(payload)).hexdigest()
    if document["sha256"] != digest:
        raise ValueError("Incomplete or changed transfer.")
    entries = payload["entries"]
    if not isinstance(entries, list) or not 1 <= len(entries) <= MAX_ENTRIES:
        raise ValueError("Invalid entry count.")
    captures: list[ImportedCapture] = []
    seen: set[bytes] = set()
    duplicates = rejected = 0
    for index, entry in enumerate(entries):
        try:
            if set(entry) != {"origin", "timestamp", "request", "response"}:
                raise ValueError("Invalid entry.")
            origin = _origin(entry["origin"])
            if origin not in allowed:
                raise ValueError("Out of scope.")
            timestamp = _time(entry["timestamp"])
            messages: list[bytes | None] = []
            for name in ("request", "response"):
                encoded = entry[name]
                if encoded is None and name == "response":
                    messages.append(None)
                else:
                    if not isinstance(encoded, str) or len(encoded) > 4 * ((MAX_MESSAGE_BYTES + 2) // 3):
                        raise ValueError("Message limit.")
                    decoded = base64.b64decode(encoded, validate=True)
                    if len(decoded) > MAX_MESSAGE_BYTES:
                        raise ValueError("Message limit.")
                    messages.append(decoded)
            request, response = messages
            if request is None:
                raise ValueError("Missing request.")
            exchange = parse_captured_exchanges(request, base_url=origin, response_data=response)[0]
            # The existing parser checks Host/target consistency; scope is checked on its result.
            parts = urlsplit(exchange.request.prepared_url())
            if _origin(f"{parts.scheme}://{parts.netloc}") != origin:
                raise ValueError("Destination mismatch.")
            key = _canonical(
                [
                    origin,
                    base64.b64encode(request).decode("ascii"),
                    None if response is None else base64.b64encode(response).decode("ascii"),
                ]
            )
            if key in seen:
                duplicates += 1
                continue
            seen.add(key)
            captures.append(ImportedCapture(f"burp-passive:{digest}#/entries/{index}", exchange, timestamp))
        except (ValueError, TypeError, KeyError, AttributeError):
            rejected += 1
    return BridgePreview(len(entries), duplicates, rejected, tuple(captures))


def _private_location(path: Path) -> None:
    """Raw artifacts belong in an existing owned 0700 directory outside checkouts."""
    path = local_path(path)
    try:
        info = path.parent.stat()
        if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
            raise ValueError("Private directory required.")
        if any((parent / ".git").is_file() or (parent / ".git" / "HEAD").is_file() for parent in path.parents):
            raise ValueError("Private captures must stay outside Git checkouts.")
    except OSError:
        raise ValueError("Private directory unavailable.") from None


def export_selected(
    path: Path, project: str, origins: Sequence[str], selections: Sequence[Selection], *, authorized: bool = False
) -> BridgePreview:
    """Mockable passive adapter. Atomic private publication, no overwrite or network."""
    if not authorized:
        raise ValueError("Human authorization attestation required.")
    _private_location(path)
    raw = envelope(project, selections)
    preview = inspect_bytes(raw, project=project, origins=origins)
    if preview.rejected:
        raise ValueError("Selection contains rejected entries; review preview before export.")
    # Only store unique captures, while preserving their original capture timestamps.
    unique = [
        Selection(
            f"{urlsplit(item.exchange.request.url).scheme}://{urlsplit(item.exchange.request.url).netloc}",
            item.exchange.raw_request.encode(),
            None if item.exchange.raw_response is None else item.exchange.raw_response.encode(),
            item.timestamp,
        )
        for item in preview.captures
    ]
    published = envelope(project, unique)
    final = inspect_bytes(published, project=project, origins=origins)
    atomic_private_write(path, published)
    return BridgePreview(preview.declared, preview.duplicates, preview.rejected, final.captures)


def import_private(path: Path, *, project: str, origins: Sequence[str], authorized: bool = False) -> BridgePreview:
    if not authorized:
        raise ValueError("Human authorization attestation required.")
    _private_location(path)
    return inspect_bytes(read_private_input(path, MAX_FILE_BYTES, protected=True), project=project, origins=origins)


def private_xml(preview: BridgePreview) -> bytes:
    """Explicit in-memory adapter for the existing evidence importer; still PRIVATE.

    Do not publish this as a report. The transfer is the single retained raw artifact.
    """
    root = ET.Element("items")
    for capture in preview.captures:
        item = ET.SubElement(root, "item")
        ET.SubElement(item, "url").text = capture.exchange.request.prepared_url()
        if capture.timestamp:
            ET.SubElement(item, "time").text = capture.timestamp
        for name, message in (("request", capture.exchange.raw_request), ("response", capture.exchange.raw_response)):
            if message is not None:
                ET.SubElement(item, name, base64="true").text = base64.b64encode(message.encode()).decode()
    return bytes(ET.tostring(root, encoding="utf-8"))


def evidence_bundle(preview: BridgePreview) -> dict[str, Any]:
    """Normalize with the existing importer; returned bundle remains private.

    Temporary XML is mode 0600 inside a mode 0700 directory and removed on exit.
    Stable transfer locators replace transient filenames. No assessment is performed.
    """
    from .analysis.evidence_engine import import_evidence

    if not preview.captures:
        raise ValueError("No accepted captures to import.")
    with tempfile.TemporaryDirectory(prefix="bbtk-private-") as directory:
        path = Path(directory) / "selected.xml"
        atomic_private_write(path, private_xml(preview))
        bundle = import_evidence([path], format_name="burp-xml")
    rows = bundle["records"]
    if not isinstance(rows, list):
        raise ValueError("Unexpected evidence bundle.")
    locators = {f"/item[{index}]": capture.locator for index, capture in enumerate(preview.captures, 1)}
    for row in rows:
        for provenance in row["provenance"]:
            provenance["source_path"] = "private-burp-transfer"
            provenance["locator"] = locators[provenance["locator"]]
    bundle["bundle_id"] = hashlib.sha256(_canonical(rows)).hexdigest()[:24]
    bundle["inputs"] = [{"format": SCHEMA, "records_parsed": len(preview.captures)}]
    bundle["bridge_review"] = preview.summary()
    return bundle


def main() -> None:
    parser = argparse.ArgumentParser(description="Offline private Burp bridge preview/import; emits counts only.")
    parser.add_argument("input", type=Path)
    parser.add_argument("--project", required=True)
    parser.add_argument("--origin", action="append", required=True)
    parser.add_argument("--attest-authorized-captures", action="store_true")
    parser.add_argument("--private-bundle", type=Path, help="Explicit private normalized evidence output")
    parser.add_argument("--report", type=Path, help="Explicitly save a content-free review summary")
    args = parser.parse_args()
    try:
        preview = import_private(
            args.input, project=args.project, origins=args.origin, authorized=args.attest_authorized_captures
        )
        if args.private_bundle:
            _private_location(args.private_bundle)
            atomic_private_write(args.private_bundle, _canonical(evidence_bundle(preview)))
        report = _canonical(preview.summary())
        if args.report:
            atomic_private_write(args.report, report)
        print(report.decode())
    except ValueError:
        parser.exit(2, "Bridge refused; check authorization, private permissions, protocol and scope locally.\n")


if __name__ == "__main__":
    main()
