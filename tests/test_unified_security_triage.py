"""Tests for unified security-research triage (read-only)."""

from __future__ import annotations

from pathlib import Path
import tempfile
import unittest

from bugbounty_toolkit.analysis.unified_security_triage import (
    SECURITY_STATES,
    UNIFIED_FORBIDDEN,
    build_unified_security_triage,
)
from bugbounty_toolkit.core.records import ProgramPaths

try:
    from fastapi.testclient import TestClient

    from bugbounty_toolkit.dashboard import create_app
    from labs.dashboard_triage_lab.run_lab import build_lab
except ImportError:  # pragma: no cover
    TestClient = None  # type: ignore[assignment,misc]
    build_lab = None  # type: ignore[assignment]


@unittest.skipIf(TestClient is None, "Install optional .[dashboard] dependencies.")
class UnifiedSecurityTriageTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        assert build_lab is not None
        build_lab(self.root)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_unified_view_read_only_and_unconfirmed(self) -> None:
        view = build_unified_security_triage(ProgramPaths(self.root, "multi-candidates"))
        self.assertEqual(view["type"], "unified-security-research-triage")
        self.assertTrue(view["read_only"])
        self.assertFalse(view["ai_may_confirm_findings"])
        self.assertFalse(view["finding_confirmed"])
        self.assertEqual(view["network_requests_sent"], 0)
        self.assertIn("exploit", view["forbidden_actions"])
        self.assertIn("ai_approve_finding", view["forbidden_actions"])
        for row in view["candidates"]:
            self.assertIn(row["security_state"], SECURITY_STATES)
            self.assertFalse(row["ai_may_confirm"])
            self.assertFalse(row["finding_confirmed"])
            self.assertFalse(row["session_data_included"])
            self.assertFalse(row["executable_html"])
            self.assertTrue(row["classification_reasons"])

    def test_family_filter_and_states(self) -> None:
        paths = ProgramPaths(self.root, "multi-candidates")
        xss = build_unified_security_triage(paths, family="xss")
        self.assertTrue(all(r["family"] == "xss" for r in xss["candidates"]))
        idor = build_unified_security_triage(paths, family="idor")
        self.assertTrue(all(r["family"] == "idor" for r in idor["candidates"]))
        with self.assertRaises(ValueError):
            build_unified_security_triage(paths, family="nope")

    def test_rejected_and_broken_map_to_controls_or_integrity(self) -> None:
        rejected = build_unified_security_triage(ProgramPaths(self.root, "rejected"))
        self.assertTrue(any(r["security_state"] == "negative_control" for r in rejected["candidates"]))
        broken = build_unified_security_triage(ProgramPaths(self.root, "invalid-references"))
        self.assertTrue(
            any(
                r["security_state"] in {"integrity_blocked", "gap_blocked", "inconclusive"}
                for r in broken["candidates"]
            )
        )

    def test_api_endpoint(self) -> None:
        client = TestClient(
            create_app(self.root, "multi-candidates"),
            base_url="http://127.0.0.1:8765",
            client=("127.0.0.1", 50000),
        )
        response = client.get("/api/triage/security-research")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertFalse(data["ai_may_confirm_findings"])
        self.assertEqual(sorted(UNIFIED_FORBIDDEN), sorted(data["forbidden_actions"]))
        # Ensure HTML shell does not use innerHTML for this panel (textContent pattern).
        html = client.get("/").text
        self.assertIn("security-research", html)
        self.assertNotIn("innerHTML", html)


if __name__ == "__main__":
    unittest.main()
