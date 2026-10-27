"""Ground-truth fixtures covering every supported encoding and adversarial case.

Each case is a fully offline, synthetic capture. No third-party HTTP is involved.
Labels are the only source of truth for precision/recall measurement.
"""

from __future__ import annotations

from typing import Any

Case = dict[str, Any]


def cases() -> list[Case]:
    """Return the full adversarial ground-truth corpus."""
    return [
        {
            "id": "uuid_valid",
            "description": "Valid UUID in a typed field",
            "url": "https://lab.example/api/users",
            "json_body": '{"user_id": "550e8400-e29b-41d4-a716-446655440000"}',
            "expected": [
                {
                    "value": "550e8400-e29b-41d4-a716-446655440000",
                    "value_type": "str",
                    "id_format": "uuid",
                    "source": "json",
                    "locator": "/user_id",
                }
            ],
            "must_reject_secrets": True,
        },
        {
            "id": "page_number",
            "description": "Pagination page number must be excluded",
            "url": "https://lab.example/api/items?page=3&per_page=50",
            "expected": [],
            "must_not_include": ["3", "50"],
        },
        {
            "id": "id_in_array",
            "description": "Integer IDs inside a JSON array under an id-named key",
            "json_body": '{"order_ids": [101, 202, 303]}',
            "expected": [
                {
                    "value": 101,
                    "value_type": "int",
                    "id_format": "numeric",
                    "source": "json_array",
                    "locator": "/order_ids/0",
                },
                {
                    "value": 202,
                    "value_type": "int",
                    "id_format": "numeric",
                    "source": "json_array",
                    "locator": "/order_ids/1",
                },
                {
                    "value": 303,
                    "value_type": "int",
                    "id_format": "numeric",
                    "source": "json_array",
                    "locator": "/order_ids/2",
                },
            ],
        },
        {
            "id": "id_in_xml",
            "description": "Object id as an XML element and attribute",
            "xml_body": '<ticket id="T-9001"><owner_id>42</owner_id></ticket>',
            "expected": [
                {
                    "value": "T-9001",
                    "value_type": "str",
                    "id_format": "opaque",
                    "source": "xml_attr",
                    "locator": "/ticket/@id",
                },
                {
                    "value": "42",
                    "value_type": "str",
                    "id_format": "numeric",
                    "source": "xml",
                    "locator": "/ticket/owner_id",
                },
            ],
        },
        {
            "id": "matrix_param",
            "description": "URL matrix parameter carries an object id",
            "url": "https://lab.example/api/books;isbn=9780143127550/chapters",
            "expected": [
                {
                    "value": "9780143127550",
                    "value_type": "str",
                    "id_format": "numeric",
                    "source": "matrix",
                    "locator": "/path/1;isbn",
                }
            ],
        },
        {
            "id": "two_ids_different_types",
            "description": "Two identifiers of different scalar types must preserve type",
            "json_body": '{"account_id": 7, "device_ref": "a1b2c3d4e5f6"}',
            "expected": [
                {"value": 7, "value_type": "int", "id_format": "numeric", "source": "json", "locator": "/account_id"},
                {
                    "value": "a1b2c3d4e5f6",
                    "value_type": "str",
                    "id_format": "opaque",
                    "source": "json",
                    "locator": "/device_ref",
                },
            ],
        },
        {
            "id": "jwt_excluded",
            "description": "JWT tokens must never become candidates",
            "json_body": ('{"access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc"}'),
            "expected": [],
            "must_not_include_values_matching": "eyJ",
        },
        {
            "id": "url_signature_excluded",
            "description": "URL signatures and HMAC digests are not object refs",
            "url": "https://lab.example/dl?file_id=99&signature=abc123def456",
            "expected": [
                {
                    "value": "99",
                    "value_type": "str",
                    "id_format": "numeric",
                    "source": "query",
                    "locator": "/query/file_id/0",
                }
            ],
            "must_not_include": ["abc123def456"],
        },
        {
            "id": "malformed_json",
            "description": "Malformed JSON is rejected (no crash, no candidates)",
            "json_body": '{"user_id": 1,',
            "expected": [],
            "expect_rejected": True,
        },
        {
            "id": "xml_external_blocked",
            "description": "XML with DOCTYPE/ENTITY must be blocked (no XXE)",
            "xml_body": (
                '<?xml version="1.0"?>'
                '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
                "<root><id>&xxe;</id></root>"
            ),
            "expected": [],
            "expect_rejected": True,
        },
        {
            "id": "duplicate_field",
            "description": "Duplicate JSON keys are treated as uncertainty/rejection",
            "json_body": '{"id": 1, "id": 2}',
            "expected": [],
            "expect_rejected": True,
        },
        {
            "id": "numeric_noise",
            "description": "Numbers that are not named like IDs must not be candidates",
            "json_body": '{"price": 19, "quantity": 2, "tax_rate": 8}',
            "expected": [],
            "must_not_include": [19, 2, 8],
        },
        {
            "id": "unconventional_names",
            "description": "Objects without conventional id names still yield UUID candidates",
            "json_body": '{"widget": "550e8400-e29b-41d4-a716-446655440099"}',
            "expected": [
                {
                    "value": "550e8400-e29b-41d4-a716-446655440099",
                    "value_type": "str",
                    "id_format": "uuid",
                    "source": "json",
                    "locator": "/widget",
                }
            ],
        },
        {
            "id": "path_numeric_id",
            "description": "Numeric path segment after a collection noun",
            "url": "https://lab.example/api/v1/orders/88421/items",
            "expected": [
                {"value": "88421", "value_type": "str", "id_format": "numeric", "source": "path", "locator": "/path/3"}
            ],
        },
        {
            "id": "form_url_encoded",
            "description": "application/x-www-form-urlencoded body with typed id",
            "form_body": "ticket_id=AB12CD&note=hello",
            "expected": [
                {
                    "value": "AB12CD",
                    "value_type": "str",
                    "id_format": "opaque",
                    "source": "form",
                    "locator": "/form/ticket_id/0",
                }
            ],
            "must_not_include": ["hello"],
        },
        {
            "id": "id_password_not_reference",
            "description": "Field names like id_password must never be treated as object refs",
            "json_body": '{"id_password": "hunter2", "user_id": 55}',
            "expected": [
                {"value": 55, "value_type": "int", "id_format": "numeric", "source": "json", "locator": "/user_id"}
            ],
            "must_not_include": ["hunter2"],
        },
        {
            "id": "csrf_and_cookie_excluded",
            "description": "CSRF tokens and cookies are secrets, never candidates",
            "form_body": "csrf_token=abcXYZ999&resource_id=44",
            "expected": [
                {
                    "value": "44",
                    "value_type": "str",
                    "id_format": "numeric",
                    "source": "form",
                    "locator": "/form/resource_id/0",
                }
            ],
            "must_not_include": ["abcXYZ999"],
        },
        {
            "id": "declared_reference",
            "description": "Explicitly declared reference fields are always candidates",
            "declared_references": {"linked_object": "Z9Y8X7"},
            "expected": [
                {
                    "value": "Z9Y8X7",
                    "value_type": "str",
                    "id_format": "opaque",
                    "source": "declared",
                    "locator": "/declared/linked_object",
                }
            ],
        },
        {
            "id": "nested_json",
            "description": "Nested JSON object carries a typed identifier",
            "json_body": '{"lease": {"tenant_id": 9001, "unit": {"code": "B-12"}}}',
            "expected": [
                {
                    "value": 9001,
                    "value_type": "int",
                    "id_format": "numeric",
                    "source": "json",
                    "locator": "/lease/tenant_id",
                }
            ],
        },
        {
            "id": "invalid_encoding",
            "description": "Invalid UTF-8 bytes are rejected, never guessed",
            "json_body": b'{"user_id": "\xff\xfe"}',
            "expected": [],
            "expect_rejected": True,
        },
    ]


def legacy_baseline_cases() -> list[Case]:
    """Subset used for the before/after comparison against legacy object_relationships rules."""
    return [
        case
        for case in cases()
        if case["id"]
        in {
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
            "path_numeric_id",
            "form_url_encoded",
            "id_password_not_reference",
            "csrf_and_cookie_excluded",
            "nested_json",
        }
    ]
