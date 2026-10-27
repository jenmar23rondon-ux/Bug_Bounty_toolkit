"""Versioned synthetic HTTP response pairs. No captured credentials or canaries."""

from __future__ import annotations

from typing import Any

CORPUS_VERSION = "semantic-response-diff-eval/1"


def _resp(
    status: int,
    body: str,
    *,
    content_type: str = "application/json",
    headers: dict[str, str] | None = None,
    origin: str | None = None,
) -> dict[str, Any]:
    merged = {"content-type": content_type}
    if headers:
        merged.update(headers)
    return {
        "status_code": status,
        "headers": merged,
        "body": body,
        "origin_ref": origin,
    }


def corpus() -> list[dict[str, Any]]:
    """Ground-truth scenarios for precision/recall of relevant differences."""
    rows: list[dict[str, Any]] = []

    def add(
        name: str,
        left: dict[str, Any],
        right: dict[str, Any],
        *,
        relevant_kinds: list[str],
        expect_structural_equal: bool = False,
        expect_behavioral: bool | None = None,
        ignore_volatile: list[str] | None = None,
        must_preserve_authz: bool = False,
        baseline_false_equivalence: bool = False,
        notes: str = "",
    ) -> None:
        rows.append(
            {
                "name": name,
                "left": left,
                "right": right,
                "relevant_kinds": relevant_kinds,
                "expect_structural_equal": expect_structural_equal,
                "expect_behavioral": expect_behavioral,
                "ignore_volatile": ignore_volatile or [],
                "must_preserve_authz": must_preserve_authz,
                "baseline_false_equivalence": baseline_false_equivalence,
                "notes": notes,
            }
        )

    # 1. Equivalent JSON with different timestamps (volatile under explicit rule).
    add(
        "equivalent_json_timestamps",
        _resp(200, '{"id":101,"owner":"alice","timestamp":"2024-01-01T00:00:00Z"}', origin="eq-ts-a"),
        _resp(200, '{"id":101,"owner":"alice","timestamp":"2024-06-01T12:00:00Z"}', origin="eq-ts-b"),
        relevant_kinds=[],
        expect_structural_equal=True,
        expect_behavioral=True,
        ignore_volatile=["timestamp"],
        notes="timestamp ignored only via explicit rule; owner/id untouched",
    )

    # 2. Different keys (added/removed).
    add(
        "different_keys",
        _resp(200, '{"id":1,"owner":"alice"}', origin="keys-a"),
        _resp(200, '{"id":1,"owner":"alice","role":"admin"}', origin="keys-b"),
        relevant_kinds=["key_added"],
        must_preserve_authz=True,
        expect_behavioral=False,
    )

    # 3. Different types.
    add(
        "different_types",
        _resp(200, '{"id":1,"owner":"alice"}', origin="types-a"),
        _resp(200, '{"id":"1","owner":"alice"}', origin="types-b"),
        relevant_kinds=["type_changed"],
        must_preserve_authz=True,
        expect_behavioral=False,
    )

    # 4. Array reordered (same multiset).
    add(
        "array_reordered",
        _resp(200, '{"items":[1,2,3]}', origin="arr-a"),
        _resp(200, '{"items":[3,1,2]}', origin="arr-b"),
        relevant_kinds=["array_reordered"],
        expect_behavioral=True,
    )

    # 5. HTML denial body vs another HTML denial (structure).
    add(
        "html_denial_bodies",
        _resp(
            403,
            "<html><body><h1>Forbidden</h1><p>Access denied</p></body></html>",
            content_type="text/html",
            origin="html-den-a",
        ),
        _resp(
            403,
            "<html><body><h1>Forbidden</h1><p>Access denied</p></body></html>",
            content_type="text/html",
            origin="html-den-b",
        ),
        relevant_kinds=[],
        expect_structural_equal=True,
        expect_behavioral=True,
    )

    # 6. Valid access vs HTML denial (authz-relevant).
    add(
        "access_vs_html_denial",
        _resp(200, '{"id":42,"owner":"alice","email":"a@lab.test"}', origin="access-a"),
        _resp(
            403,
            "<html><body><h1>Forbidden</h1></body></html>",
            content_type="text/html",
            origin="access-b",
        ),
        relevant_kinds=["status_changed", "content_type_changed", "body_kind_changed"],
        must_preserve_authz=True,
        expect_behavioral=False,
    )

    # 7. HTTP 200 with JSON error vs success.
    add(
        "http200_json_error_vs_success",
        _resp(200, '{"success":true,"owner":"alice","id":7}', origin="err-a"),
        _resp(200, '{"success":false,"error":"forbidden"}', origin="err-b"),
        relevant_kinds=["key_added", "key_removed", "value_changed"],
        must_preserve_authz=True,
        expect_behavioral=False,
    )

    # 8. Login redirect.
    add(
        "login_redirect",
        _resp(200, '{"id":1}', origin="redir-a"),
        _resp(
            302,
            "",
            content_type="text/html",
            headers={"location": "https://lab.test/login"},
            origin="redir-b",
        ),
        relevant_kinds=["status_changed", "location_changed", "content_type_changed"],
        must_preserve_authz=True,
        expect_behavioral=False,
    )

    # 9. Sensitive fields change — must surface as sensitive+authz-adjacent.
    add(
        "sensitive_fields",
        _resp(200, '{"id":1,"token":"tok_canary_alpha_9f3a","password":"pwd_canary_alpha_9f3a"}', origin="sens-a"),
        _resp(200, '{"id":1,"token":"tok_canary_bravo_9f3a","password":"pwd_canary_bravo_9f3a"}', origin="sens-b"),
        relevant_kinds=["value_changed"],
        must_preserve_authz=True,
        # Trying to ignore token/password must fail (protected/sensitive).
        ignore_volatile=["token", "password"],
    )

    # 10. Large response truncated safely.
    big = '{"id":1,"blob":"' + ("A" * 50_000) + '"}'
    big2 = '{"id":1,"blob":"' + ("B" * 50_000) + '"}'
    add(
        "large_responses",
        _resp(200, big, origin="big-a"),
        _resp(200, big2, origin="big-b"),
        relevant_kinds=["value_changed"],
        expect_behavioral=True,
    )

    # 11. Encoding / charset in content-type (family equal).
    add(
        "encoding_content_type",
        _resp(
            200,
            '{"id":1}',
            content_type="application/json; charset=utf-8",
            origin="enc-a",
        ),
        _resp(
            200,
            '{"id":1}',
            content_type="application/json; charset=UTF-8",
            origin="enc-b",
        ),
        relevant_kinds=[],
        expect_structural_equal=True,
        expect_behavioral=True,
    )

    # 12. Declared Content-Length mismatch.
    body = '{"ok":true}'
    add(
        "content_length_mismatch",
        _resp(200, body, headers={"content-length": "9999"}, origin="cl-a"),
        _resp(200, body, headers={"content-length": str(len(body.encode()))}, origin="cl-b"),
        relevant_kinds=["content_length_mismatch"],
        expect_behavioral=True,
    )

    # 13. Malformed JSON.
    add(
        "malformed_json",
        _resp(200, '{"id":1}', origin="mal-a"),
        _resp(200, '{"id":1,}', origin="mal-b"),
        relevant_kinds=["body_kind_changed"],
        expect_behavioral=False,
    )

    # 14. Deceptive volatile: claim "id" is volatile — must NOT hide it.
    add(
        "deceptive_volatile_id",
        _resp(200, '{"id":101,"timestamp":"t1"}', origin="dec-a"),
        _resp(200, '{"id":202,"timestamp":"t2"}', origin="dec-b"),
        relevant_kinds=["value_changed"],
        ignore_volatile=["id", "timestamp"],
        must_preserve_authz=True,
        expect_behavioral=False,
        notes="id is protected; timestamp may be ignored",
    )

    # 15. Baseline false equivalence trap: bodies differ only in whitespace that
    # naive equality flags, while semantic (JSON) sees equal structure.
    # Actually use same JSON different key order — naive string unequal, semantic equal.
    add(
        "json_key_order_only",
        _resp(200, '{"a":1,"b":2}', origin="order-a"),
        _resp(200, '{"b":2,"a":1}', origin="order-b"),
        relevant_kinds=[],
        expect_structural_equal=True,
        expect_behavioral=True,
        baseline_false_equivalence=False,  # baseline reports difference (false positive diff)
        notes="naive baseline sees body inequality; semantic sees equality",
    )

    # 16. Owner change must never be normalized away.
    add(
        "owner_change_preserved",
        _resp(200, '{"id":1,"owner":"alice","timestamp":"t1"}', origin="own-a"),
        _resp(200, '{"id":1,"owner":"bob","timestamp":"t2"}', origin="own-b"),
        relevant_kinds=["value_changed"],
        ignore_volatile=["timestamp", "owner"],
        must_preserve_authz=True,
        expect_behavioral=False,
    )

    return rows
