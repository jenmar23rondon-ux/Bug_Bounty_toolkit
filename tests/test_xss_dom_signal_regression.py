from __future__ import annotations

import unittest

from labs.investigator_workflow_efficacy.bbtk_arm import classify
from labs.investigator_workflow_efficacy.capture import Capture, Exchange


class DomSignalRegressionTests(unittest.TestCase):
    def _capture(self, body: str) -> Capture:
        return Capture("xss-regression", "B", [Exchange("request", 200, {}, body, "/")])

    def test_safe_text_sink_is_rejected(self) -> None:
        result = classify(self._capture("<script>o.textContent = location.search</script>"))
        self.assertEqual(result[:2], ("reject", "safe_text_sink_only"))

    def test_dangerous_sink_is_reviewable_not_confirmed(self) -> None:
        result = classify(self._capture("<script>o.insertAdjacentHTML('beforeend', location.search)</script>"))
        self.assertEqual(result[:2], ("review", "sink_reached"))
        self.assertFalse(result[2])

    def test_unrelated_sink_abstains(self) -> None:
        result = classify(self._capture("<script>o.innerHTML = '<b>fixed</b>'</script>"))
        self.assertEqual(result[:2], ("abstain", "inconclusive"))


if __name__ == "__main__":
    unittest.main()
