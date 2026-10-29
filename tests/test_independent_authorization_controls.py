from __future__ import annotations

import unittest
from unittest.mock import patch

from labs.authorization_controls_independent.evaluate import evaluate


class IndependentAuthorizationControlsTests(unittest.TestCase):
    def test_frozen_response_controls_without_network(self) -> None:
        with patch("socket.socket.connect", side_effect=AssertionError("external request")):
            report = evaluate()
        self.assertEqual(report["cases"], 17)
        self.assertEqual(report["correct"], 17, report["rows"])
        self.assertEqual(report["false_positive_access"], 0)
        self.assertEqual(report["false_negative_access"], 0)
