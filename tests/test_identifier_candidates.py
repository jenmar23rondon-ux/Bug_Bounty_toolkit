"""Unit and adversarial tests for structured identifier-candidate extraction."""

from __future__ import annotations

import unittest

from bugbounty_toolkit.analysis.identifier_candidates import (
    ExtractionError,
    extract_candidates,
    object_discovery_candidates,
)
from labs.identifier_extraction_eval.evaluate import compare, evaluate
from labs.identifier_extraction_eval.fixtures import cases


class IdentifierCandidateTests(unittest.TestCase):
    def test_uuid_preserves_type_and_locator(self) -> None:
        result = extract_candidates(json_body='{"user_id": "550e8400-e29b-41d4-a716-446655440000"}')
        self.assertEqual(len(result.candidates), 1)
        candidate = result.candidates[0]
        self.assertEqual(candidate.value_type, "str")
        self.assertEqual(candidate.id_format, "uuid")
        self.assertEqual(candidate.locator, "/user_id")

    def test_integer_type_preserved(self) -> None:
        result = extract_candidates(json_body='{"account_id": 7}')
        self.assertEqual(result.candidates[0].value, 7)
        self.assertEqual(result.candidates[0].value_type, "int")

    def test_page_number_excluded(self) -> None:
        result = extract_candidates(url="https://lab.example/items?page=3&per_page=50")
        self.assertEqual(result.candidates, [])

    def test_jwt_and_csrf_excluded(self) -> None:
        result = extract_candidates(
            json_body='{"access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIn0.x"}',
            form_body="csrf_token=abcXYZ999&resource_id=44",
        )
        values = [candidate.value for candidate in result.candidates]
        self.assertEqual(values, ["44"])
        self.assertTrue(any(item["reason"] in {"secret_or_signature_name", "jwt_token"} for item in result.rejected))

    def test_id_password_not_reference(self) -> None:
        result = extract_candidates(json_body='{"id_password": "hunter2", "user_id": 55}')
        self.assertEqual([c.value for c in result.candidates], [55])

    def test_matrix_parameter(self) -> None:
        result = extract_candidates(url="https://lab.example/api/books;isbn=9780143127550/chapters")
        locators = [c.locator for c in result.candidates]
        self.assertIn("/path/1;isbn", locators)

    def test_xml_and_attribute(self) -> None:
        result = extract_candidates(xml_body='<ticket id="T-9001"><owner_id>42</owner_id></ticket>')
        values = {(c.locator, c.value) for c in result.candidates}
        self.assertIn(("/ticket/@id", "T-9001"), values)
        self.assertIn(("/ticket/owner_id", "42"), values)

    def test_xml_doctype_blocked(self) -> None:
        result = extract_candidates(
            xml_body='<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root><id>1</id></root>'
        )
        self.assertEqual(result.candidates, [])
        self.assertTrue(any(item["reason"] == "xml_doctype_or_entity_blocked" for item in result.rejected))

    def test_malformed_json_rejected(self) -> None:
        result = extract_candidates(json_body='{"user_id": 1,')
        self.assertEqual(result.candidates, [])
        self.assertTrue(result.rejected)

    def test_duplicate_json_key_rejected(self) -> None:
        result = extract_candidates(json_body='{"id": 1, "id": 2}')
        self.assertEqual(result.candidates, [])
        self.assertTrue(any("duplicate_json_key" in item["reason"] for item in result.rejected))

    def test_invalid_encoding_rejected(self) -> None:
        result = extract_candidates(json_body=b'{"user_id": "\xff"}')
        self.assertEqual(result.candidates, [])
        self.assertTrue(any(item["reason"] == "invalid_encoding" for item in result.rejected))

    def test_numeric_noise_ignored(self) -> None:
        result = extract_candidates(json_body='{"price": 19, "quantity": 2}')
        self.assertEqual(result.candidates, [])

    def test_declared_reference(self) -> None:
        result = extract_candidates(declared_references={"linked_object": "Z9Y8X7"})
        self.assertEqual(result.candidates[0].source, "declared")
        self.assertEqual(result.candidates[0].value, "Z9Y8X7")

    def test_array_ids(self) -> None:
        result = extract_candidates(json_body='{"order_ids": [101, 202]}')
        self.assertEqual([c.value for c in result.candidates], [101, 202])
        self.assertTrue(all(c.source == "json_array" for c in result.candidates))
        self.assertTrue(all(c.value_type == "int" for c in result.candidates))

    def test_opt_in_adapter_does_not_raise(self) -> None:
        payload = object_discovery_candidates(json_body='{"user_id": 1}')
        self.assertEqual(payload[0]["value"], 1)
        self.assertEqual(payload[0]["value_type"], "int")

    def test_oversized_input_raises(self) -> None:
        from bugbounty_toolkit.analysis import identifier_candidates as mod

        original = mod.MAX_INPUT_BYTES
        try:
            mod.MAX_INPUT_BYTES = 16
            with self.assertRaises(ExtractionError):
                extract_candidates(json_body='{"user_id": "0123456789abcdef"}')
        finally:
            mod.MAX_INPUT_BYTES = original


class IdentifierLabTests(unittest.TestCase):
    def test_corpus_covers_required_scenarios(self) -> None:
        ids = {case["id"] for case in cases()}
        required = {
            "uuid_valid",
            "page_number",
            "id_in_array",
            "id_in_xml",
            "matrix_param",
            "two_ids_different_types",
            "jwt_excluded",
            "url_signature_excluded",
            "malformed_json",
            "xml_external_blocked",
            "duplicate_field",
            "numeric_noise",
            "unconventional_names",
            "form_url_encoded",
            "id_password_not_reference",
        }
        self.assertTrue(required.issubset(ids))

    def test_after_improves_or_matches_before(self) -> None:
        report = compare()
        self.assertEqual(report["after"]["secret_leaks"], 0)
        self.assertTrue(report["after"]["types_preserved"])
        self.assertTrue(report["after"]["locators_valid"])
        self.assertTrue(report["after"]["rejected_ok"])
        self.assertGreaterEqual(report["after"]["overall"]["recall"], report["before"]["overall"]["recall"])
        self.assertGreaterEqual(report["after"]["overall"]["f1"], report["before"]["overall"]["f1"] - 0.05)

    def test_evaluate_after_has_high_precision(self) -> None:
        after = evaluate()
        self.assertGreaterEqual(after["overall"]["precision"], 0.9)
        self.assertGreaterEqual(after["overall"]["recall"], 0.85)


if __name__ == "__main__":
    unittest.main()
