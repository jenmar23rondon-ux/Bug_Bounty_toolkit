"""Offline unit tests for the business-logic candidate test planner."""

from __future__ import annotations

import json
import unittest
from pathlib import Path

from bugbounty_toolkit.analysis.business_logic_planner import (
    PLAN_SCHEMA,
    analyze_business_logic,
    detect_checkout_flow,
    extract_parameters,
)


FIXTURE = Path(__file__).resolve().parent / "fixtures" / "business_logic_cart_checkout.har"


class BusinessLogicPlannerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.har_text = FIXTURE.read_text(encoding="utf-8")
        self.plan = analyze_business_logic(self.har_text, source_label="fixture")

    def test_schema_and_never_confirm(self) -> None:
        self.assertEqual(self.plan["schema"], PLAN_SCHEMA)
        self.assertIs(self.plan["finding_confirmed"], False)
        self.assertIs(self.plan["requests_sent"], False)
        self.assertIn("CANDIDATES", self.plan["disclaimer"])
        for test in self.plan["tests"]:
            self.assertIs(test["finding_confirmed"], False)

    def test_detects_core_parameters(self) -> None:
        categories = {p["category"] for p in self.plan["parameters"]}
        for expected in (
            "price",
            "quantity",
            "coupon",
            "currency",
            "shipping",
            "tax",
            "cart_order_id",
            "plan_tier_role",
        ):
            self.assertIn(expected, categories, msg=f"missing {expected}")
        self.assertGreaterEqual(self.plan["parameter_count"], 8)
        self.assertGreaterEqual(self.plan["test_count"], 10)

    def test_checkout_flow_and_step_skip(self) -> None:
        flow = self.plan["checkout_flow"]
        self.assertEqual(flow["steps_observed"], ["cart", "checkout", "pay"])
        self.assertTrue(flow["multi_step_detected"])
        self.assertTrue(flow["complete_cart_checkout_pay"])
        ideas = {t["idea"] for t in self.plan["tests"]}
        self.assertIn("skip_checkout_step", ideas)
        self.assertIn("coupon_race", ideas)
        self.assertIn("cross_account_object_reuse", ideas)
        race = next(t for t in self.plan["tests"] if t["idea"] == "coupon_race")
        self.assertTrue(race["manual_only"])

    def test_redacts_secrets_from_outputs(self) -> None:
        blob = json.dumps(self.plan)
        self.assertNotIn("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9", blob)
        self.assertNotIn("Bearer eyJ", blob)
        for param in self.plan["parameters"]:
            self.assertNotIn("password", str(param.get("sample_value_redacted", "")).lower())

    def test_markdown_summary(self) -> None:
        md = self.plan["markdown"]
        self.assertIn("Business-logic test plan", md)
        self.assertIn("finding_confirmed stays false", md)
        self.assertIn("quantity", md)

    def test_json_records_input(self) -> None:
        records = {
            "records": [
                {
                    "method": "POST",
                    "url": "https://shop.test/api/cart",
                    "content_type": "application/json",
                    "body": '{"qty":1,"price":9.99}',
                }
            ]
        }
        plan = analyze_business_logic(json.dumps(records))
        cats = {p["category"] for p in plan["parameters"]}
        self.assertIn("quantity", cats)
        self.assertIn("price", cats)

    def test_extract_and_flow_helpers(self) -> None:
        entries = json.loads(self.har_text)["log"]["entries"]
        params = extract_parameters(entries)
        self.assertTrue(any(p["name"] == "coupon" for p in params))
        flow = detect_checkout_flow(entries)
        self.assertIn("cart", flow["steps_observed"])


if __name__ == "__main__":
    unittest.main()
