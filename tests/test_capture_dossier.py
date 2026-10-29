from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from bugbounty_toolkit.reporting.capture_dossier import build_capture_dossier
from labs.batch_capture_eval.fixtures import CANARY, burp, entry, har


class CaptureDossierTests(unittest.TestCase):
    def test_duplicates_keep_source_digests_and_locators_without_secrets(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            first, second = Path(tmp) / "private-name.har", Path(tmp) / "copy.har"
            first.write_bytes(har([entry("/items/1", session="alice")]))
            second.write_bytes(first.read_bytes())
            with patch("socket.socket.connect", side_effect=AssertionError("network attempted")):
                dossier = build_capture_dossier([first, second])
            self.assertEqual(dossier["summary"]["duplicates_merged"], 1)
            self.assertEqual(len(dossier["observations"]), 1)
            self.assertEqual(len(dossier["observations"][0]["provenance"]), 2)
            self.assertFalse(dossier["finding_confirmed"])
            for value in (CANARY, tmp, "private-name", "alice"):
                self.assertNotIn(value, json.dumps(dossier))

    def test_burp_response_is_an_inconclusive_observation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "capture.xml"
            source.write_bytes(
                burp(
                    [
                        (
                            "GET /x HTTP/1.1\r\nHost: burp.example.test\r\n\r\n",
                            "HTTP/1.1 403 Forbidden\r\n\r\ndenied",
                            False,
                        )
                    ]
                )
            )
            dossier = build_capture_dossier([source])
            self.assertEqual(dossier["observations"][0]["status"], "inconclusive")
            self.assertEqual(dossier["observations"][0]["http_status"], 403)

    def test_changed_source_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "capture.har"
            source.write_bytes(har([entry("/items/1", session="alice")]))
            from bugbounty_toolkit.reporting import capture_dossier

            original = capture_dossier.import_evidence

            def mutate(*args, **kwargs):
                result = original(*args, **kwargs)
                source.write_bytes(b"changed")
                return result

            with patch.object(capture_dossier, "import_evidence", side_effect=mutate):
                with self.assertRaisesRegex(ValueError, "changed"):
                    build_capture_dossier([source])
