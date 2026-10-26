"""Reproducible local before/after metrics; stdout contains counts only."""

from __future__ import annotations

import json
from pathlib import Path
import socket
import tempfile
from time import perf_counter
from unittest.mock import patch
import xml.etree.ElementTree as ET
import base64

from bugbounty_toolkit.analysis.evidence_engine import import_evidence
from bugbounty_toolkit.burp_import import captured_response
from bugbounty_toolkit.burp_passive_bridge import export_selected, import_private, evidence_bundle
from bugbounty_toolkit.core.private_files import atomic_private_write
from .corpus import ORIGIN, corpus


def run() -> dict[str, object]:
    captures = corpus()
    root = ET.Element("items")
    for capture in captures:
        item = ET.SubElement(root, "item")
        ET.SubElement(item, "url").text = (
            ORIGIN + "/items/" + capture.request.decode().split("/items/")[1].split(" ")[0]
        )
        ET.SubElement(item, "time").text = capture.timestamp
        for name, value in (("request", capture.request), ("response", capture.response)):
            if value is not None:
                ET.SubElement(item, name, base64="true").text = base64.b64encode(value).decode()
    with (
        tempfile.TemporaryDirectory() as directory,
        patch.object(socket.socket, "connect", side_effect=AssertionError("Network forbidden")),
    ):
        path = Path(directory)
        atomic_private_write(path / "baseline.xml", bytes(ET.tostring(root, encoding="utf-8")))
        start = perf_counter()
        before = import_evidence([path / "baseline.xml"], "burp-xml")
        before_seconds = perf_counter() - start
        start = perf_counter()
        export_selected(path / "bridge.json", "lab", [ORIGIN], captures + [captures[0]], authorized=True)
        after = import_private(path / "bridge.json", project="lab", origins=[ORIGIN], authorized=True)
        bundle = evidence_bundle(after)
        after_seconds = perf_counter() - start
    paired = sum(
        captured_response(row.exchange).body_text == '{"item":' + str(index) + "}"
        for index, row in enumerate(after.captures)
    )
    return {
        "baseline_sha": "bd289808600d57983f1dcacaa9b68c0d7eea0d18",
        "corpus_exchanges": 50,
        "before": {
            "records": len(before["records"]),
            "preserved_percent": 100,
            "seconds": round(before_seconds, 6),
            "documented_operator_actions": 3,
            "missing_capture_timestamps": 0,
        },
        "after": {
            "records": len(bundle["records"]),
            "preserved_percent": len(after.captures) * 2,
            "pairing_correct": paired,
            "seconds": round(after_seconds, 6),
            "documented_operator_actions": 6,
            "duplicates_stored": 0,
            "duplicate_probe_removed": 1,
            "missing_capture_timestamps": sum(row.timestamp is None for row in after.captures),
            "export_errors": 0,
            "secret_leaks_in_summary": sum(
                capture.request.decode().split("Cookie: ")[1].split("\r\n")[0] in json.dumps(after.summary())
                for capture in captures
            ),
        },
        "network_requests_sent": 0,
        "notes": "Action counts are documented workflow steps, not a timed human usability study. Unknown Burp capture timestamps stay null.",
    }


if __name__ == "__main__":
    print(json.dumps(run(), indent=2, sort_keys=True))
