"""Offline business-logic test-plan generator (candidates only; never executes).

Reads a local HAR or JSON capture records and emits a minimized JSON (+ optional
Markdown) plan of manipulation *ideas*. Every item is a CANDIDATE:
``finding_confirmed`` stays false. No HTTP requests are sent.
"""

from __future__ import annotations

import json
import re
from typing import Any, Mapping
from urllib.parse import parse_qsl, urlsplit

from ..core.redaction import RedactionDestination, redact_text, redact_url
from .har_import import HarImportError, load_har_entries

PLAN_SCHEMA = "bbtk-business-logic-plan/1"
MAX_INPUT_BYTES = 1_000_000
MAX_PARAMS = 64
MAX_TESTS = 128

# name-pattern -> (category, base confidence)
_PARAM_RULES: tuple[tuple[re.Pattern[str], str, float], ...] = (
    (re.compile(r"(?i)^(unit[_-]?price|price|amount|total|cost|subtotal|discount)$"), "price", 0.9),
    (re.compile(r"(?i)(price|amount|total|cost|subtotal|discount)"), "price", 0.7),
    (re.compile(r"(?i)^(quantity|qty|count|items)$"), "quantity", 0.9),
    (re.compile(r"(?i)(quantity|qty|count|items)"), "quantity", 0.65),
    (re.compile(r"(?i)^(coupon|promo|voucher|gift[_-]?code|discount[_-]?code|code)$"), "coupon", 0.9),
    (re.compile(r"(?i)(coupon|promo|voucher|gift)"), "coupon", 0.7),
    (re.compile(r"(?i)^(currency|curr|ccy)$"), "currency", 0.9),
    (re.compile(r"(?i)currency"), "currency", 0.65),
    (re.compile(r"(?i)^(shipping|freight|delivery[_-]?fee)$"), "shipping", 0.85),
    (re.compile(r"(?i)(shipping|freight)"), "shipping", 0.6),
    (re.compile(r"(?i)^(tax|vat|gst)$"), "tax", 0.85),
    (re.compile(r"(?i)(^|[_-])(tax|vat|gst)([_-]|$)"), "tax", 0.6),
    (re.compile(r"(?i)^(cart|order|checkout)[_-]?(id|uuid|token)?$"), "cart_order_id", 0.9),
    (re.compile(r"(?i)(cart|order|checkout).*(id|uuid|token)|(id|uuid).*(cart|order)"), "cart_order_id", 0.7),
    (re.compile(r"(?i)^(plan|tier|role|subscription)$"), "plan_tier_role", 0.85),
    (re.compile(r"(?i)(plan|tier|role|subscription)"), "plan_tier_role", 0.6),
)

_SENSITIVE_NAME = re.compile(
    r"(?i)password|passwd|secret|token|api.?key|authorization|cookie|session|csrf|credential|bearer"
)

_CHECKOUT_HINT = re.compile(r"(?i)/(cart|basket|bag|checkout|payment|pay|order)(/|$|\?)")
_FLOW_STEPS = (
    ("cart", re.compile(r"(?i)/(cart|basket|bag)(/|$|\?)")),
    ("checkout", re.compile(r"(?i)/checkout(/|$|\?)")),
    ("pay", re.compile(r"(?i)/(payment|pay|charge|billing)(/|$|\?)")),
)

_DISCLAIMER = (
    "All items are CANDIDATES only. finding_confirmed stays false. "
    "Confirmation requires manual testing on the user's own accounts within program scope."
)


def _classify_name(name: str) -> tuple[str, float] | None:
    for pattern, category, confidence in _PARAM_RULES:
        if pattern.search(name):
            return category, confidence
    return None


def _value_hint(value: Any, category: str) -> float:
    """Small confidence bump from value type (never raise confidence above 0.95)."""
    bump = 0.0
    if category == "quantity":
        if isinstance(value, (int, float)) or (isinstance(value, str) and re.fullmatch(r"-?\d+(\.\d+)?", value)):
            bump = 0.05
    elif category in {"price", "shipping", "tax"}:
        if isinstance(value, (int, float)) or (isinstance(value, str) and re.fullmatch(r"-?\d+(\.\d{1,4})?", value)):
            bump = 0.05
    elif category == "currency":
        if isinstance(value, str) and re.fullmatch(r"[A-Za-z]{3}", value):
            bump = 0.05
    elif category == "coupon":
        if isinstance(value, str) and 3 <= len(value) <= 64:
            bump = 0.03
    return bump


def _walk_json(obj: Any, prefix: str = "") -> list[tuple[str, Any]]:
    found: list[tuple[str, Any]] = []
    if isinstance(obj, dict):
        for key, value in obj.items():
            if not isinstance(key, str):
                continue
            path = f"{prefix}.{key}" if prefix else key
            found.append((path, value))
            found.extend(_walk_json(value, path))
    elif isinstance(obj, list):
        for index, value in enumerate(obj[:32]):
            path = f"{prefix}[{index}]"
            found.extend(_walk_json(value, path))
    return found


def _parse_body(body: str | None, content_type: str) -> list[tuple[str, Any, str]]:
    """Return (name, value, location) from a request body."""
    if not body:
        return []
    ct = content_type.lower()
    out: list[tuple[str, Any, str]] = []
    if "json" in ct or (body[:1] in "{["):
        try:
            parsed = json.loads(body)
        except ValueError:
            parsed = None
        if parsed is not None:
            for name, value in _walk_json(parsed):
                out.append((name, value, "json_body"))
            return out
    if "x-www-form-urlencoded" in ct or "=" in body:
        for key, value in parse_qsl(body, keep_blank_values=True):
            out.append((key, value, "form"))
    return out


def _redact_value(name: str, value: Any) -> str:
    if _SENSITIVE_NAME.search(name):
        return "[redacted]"
    text = value if isinstance(value, str) else json.dumps(value, default=str)
    redacted = redact_text(text, destination=RedactionDestination.MINIMIZED_ARTIFACT)
    if redacted is None:
        return "[redacted]"
    if len(redacted) > 64:
        return redacted[:61] + "..."
    return redacted


def _test_ideas(category: str, name: str) -> list[dict[str, Any]]:
    ideas: list[dict[str, Any]] = []
    if category == "quantity":
        for idea, detail in (
            ("negative_quantity", "Set quantity to a negative number"),
            ("zero_quantity", "Set quantity to 0"),
            ("fractional_quantity", "Set quantity to a fractional value (e.g. 0.5)"),
            ("huge_quantity", "Set quantity to an extremely large value"),
        ):
            ideas.append({"idea": idea, "detail": detail, "manual_only": False})
    elif category == "price":
        for idea, detail in (
            ("price_lower", f"Lower {name} below the server-side expected amount"),
            ("price_zero", f"Set {name} to 0"),
            ("price_negative", f"Set {name} to a negative value"),
        ):
            ideas.append({"idea": idea, "detail": detail, "manual_only": False})
    elif category == "currency":
        ideas.append(
            {
                "idea": "currency_swap",
                "detail": "Swap currency to a lower-value code while keeping the numeric amount",
                "manual_only": False,
            }
        )
    elif category == "coupon":
        for idea, detail, manual in (
            ("coupon_reuse", "Reuse the same coupon across multiple orders", False),
            ("coupon_stacking", "Apply multiple coupons / stack discounts", False),
            ("coupon_after_total", "Apply coupon after the order total was already computed", False),
            ("coupon_race", "Parallel coupon redemption race (two concurrent checkouts)", True),
        ):
            ideas.append({"idea": idea, "detail": detail, "manual_only": manual})
    elif category == "shipping":
        ideas.append(
            {
                "idea": "shipping_tamper",
                "detail": "Set shipping fee to 0 or a negative value",
                "manual_only": False,
            }
        )
    elif category == "tax":
        ideas.append(
            {
                "idea": "tax_tamper",
                "detail": "Set tax to 0 or omit the tax field",
                "manual_only": False,
            }
        )
    elif category == "cart_order_id":
        ideas.append(
            {
                "idea": "cross_account_object_reuse",
                "detail": "Reuse cart/order id from account A while authenticated as account B",
                "manual_only": True,
            }
        )
    elif category == "plan_tier_role":
        ideas.append(
            {
                "idea": "plan_tier_escalation",
                "detail": "Change plan/tier/role to a higher entitlement value in the request",
                "manual_only": False,
            }
        )
    return ideas


def _entry_request(entry: Mapping[str, Any]) -> dict[str, Any] | None:
    request = entry.get("request")
    return request if isinstance(request, dict) else None


def _content_type(headers: Any) -> str:
    if not isinstance(headers, list):
        return ""
    for header in headers:
        if not isinstance(header, dict):
            continue
        name = header.get("name")
        if isinstance(name, str) and name.lower() == "content-type":
            value = header.get("value")
            return value if isinstance(value, str) else ""
    return ""


def _post_data_text(request: Mapping[str, Any]) -> str:
    post = request.get("postData")
    if isinstance(post, dict):
        text = post.get("text")
        if isinstance(text, str):
            return text
        params = post.get("params")
        if isinstance(params, list):
            pairs: list[str] = []
            for item in params:
                if isinstance(item, dict) and isinstance(item.get("name"), str):
                    pairs.append(f"{item['name']}={item.get('value', '')}")
            return "&".join(pairs)
    return ""


def extract_parameters(entries: list[Any]) -> list[dict[str, Any]]:
    """Detect business-logic-relevant parameters across HAR entries."""
    seen: dict[tuple[str, str, str], dict[str, Any]] = {}
    for index, entry in enumerate(entries):
        if not isinstance(entry, Mapping):
            continue
        request = _entry_request(entry)
        if request is None:
            continue
        raw_url = request.get("url")
        url = raw_url if isinstance(raw_url, str) else ""
        method = request.get("method") if isinstance(request.get("method"), str) else "GET"
        parsed = urlsplit(url)
        candidates: list[tuple[str, Any, str]] = []
        for key, value in parse_qsl(parsed.query, keep_blank_values=True):
            candidates.append((key, value, "query"))
        body = _post_data_text(request)
        ct = _content_type(request.get("headers"))
        if not ct and isinstance(request.get("postData"), dict):
            mime = request["postData"].get("mimeType")
            ct = mime if isinstance(mime, str) else ""
        candidates.extend(_parse_body(body, ct))
        for name, value, location in candidates:
            if _SENSITIVE_NAME.search(name):
                continue
            classified = _classify_name(name.rsplit(".", 1)[-1].rsplit("[", 1)[0])
            if classified is None:
                classified = _classify_name(name)
            if classified is None:
                continue
            category, confidence = classified
            confidence = min(0.95, confidence + _value_hint(value, category))
            dedupe = (name, location, category)
            if dedupe in seen:
                continue
            seen[dedupe] = {
                "name": name,
                "location": location,
                "category": category,
                "confidence": round(confidence, 2),
                "sample_value_redacted": _redact_value(name, value),
                "request_index": index,
                "method": method,
                "url_redacted": redact_url(url, destination=RedactionDestination.MINIMIZED_ARTIFACT),
            }
            if len(seen) >= MAX_PARAMS:
                return list(seen.values())
    return list(seen.values())


def detect_checkout_flow(entries: list[Any]) -> dict[str, Any]:
    """Detect multi-step cart -> checkout -> pay sequences from HAR order."""
    observed: list[str] = []
    for entry in entries:
        if not isinstance(entry, Mapping):
            continue
        request = _entry_request(entry)
        if request is None:
            continue
        raw_url = request.get("url")
        url = raw_url if isinstance(raw_url, str) else ""
        for label, pattern in _FLOW_STEPS:
            if pattern.search(url) and label not in observed:
                observed.append(label)
                break
    complete = observed == ["cart", "checkout", "pay"] or (
        "cart" in observed and "checkout" in observed and "pay" in observed
    )
    return {
        "steps_observed": observed,
        "multi_step_detected": len(observed) >= 2,
        "complete_cart_checkout_pay": complete,
        "step_skip_candidates": (
            [
                {
                    "idea": "skip_checkout_step",
                    "detail": "Jump from cart directly to payment, skipping intermediate checkout steps",
                    "manual_only": True,
                    "finding_confirmed": False,
                },
                {
                    "idea": "replay_later_step",
                    "detail": "Replay a later checkout/pay request without completing earlier steps",
                    "manual_only": True,
                    "finding_confirmed": False,
                },
            ]
            if len(observed) >= 2
            else []
        ),
    }


def build_test_plan(parameters: list[dict[str, Any]], flow: dict[str, Any]) -> list[dict[str, Any]]:
    tests: list[dict[str, Any]] = []
    for param in parameters:
        for idea in _test_ideas(str(param["category"]), str(param["name"])):
            tests.append(
                {
                    "parameter": param["name"],
                    "category": param["category"],
                    "location": param["location"],
                    "confidence": param["confidence"],
                    "idea": idea["idea"],
                    "detail": idea["detail"],
                    "manual_only": idea["manual_only"],
                    "finding_confirmed": False,
                    "url_redacted": param["url_redacted"],
                    "request_index": param["request_index"],
                }
            )
            if len(tests) >= MAX_TESTS:
                break
        if len(tests) >= MAX_TESTS:
            break
    for skip in flow.get("step_skip_candidates", []):
        if len(tests) >= MAX_TESTS:
            break
        tests.append(
            {
                "parameter": None,
                "category": "checkout_flow",
                "location": "sequence",
                "confidence": 0.8,
                "idea": skip["idea"],
                "detail": skip["detail"],
                "manual_only": True,
                "finding_confirmed": False,
                "url_redacted": None,
                "request_index": None,
            }
        )
    return tests


def plan_to_markdown(plan: Mapping[str, Any]) -> str:
    lines = [
        "# Business-logic test plan (candidates only)",
        "",
        _DISCLAIMER,
        "",
        f"- Schema: `{plan.get('schema')}`",
        f"- Parameters detected: {plan.get('parameter_count', 0)}",
        f"- Candidate tests: {plan.get('test_count', 0)}",
        f"- Checkout flow steps: {', '.join(plan.get('checkout_flow', {}).get('steps_observed', [])) or '(none)'}",
        "",
        "## Parameters",
        "",
    ]
    for param in plan.get("parameters", []):
        lines.append(
            f"- `{param['name']}` ({param['location']}, {param['category']}, "
            f"confidence={param['confidence']}) sample={param['sample_value_redacted']}"
        )
    lines.extend(["", "## Candidate tests", ""])
    for index, test in enumerate(plan.get("tests", []), start=1):
        manual = " [manual-only]" if test.get("manual_only") else ""
        target = test.get("parameter") or "checkout sequence"
        lines.append(f"{index}. **{test['idea']}** on `{target}`{manual}: {test['detail']}")
    lines.extend(["", "## Confirmation", "", _DISCLAIMER, ""])
    return "\n".join(lines)


def _load_json_records(text: str) -> list[Any]:
    data = json.loads(text)
    if isinstance(data, dict):
        if isinstance(data.get("log"), dict) and isinstance(data["log"].get("entries"), list):
            return list(data["log"]["entries"])
        for key in ("entries", "records", "requests", "captures"):
            if isinstance(data.get(key), list):
                return list(data[key])
        # Single synthetic request record
        if "request" in data or "url" in data:
            return [data]
    if isinstance(data, list):
        return data
    raise ValueError("Input must be HAR JSON or a list/object of captured request records.")


def _normalize_record(record: Any) -> Any:
    """Accept toolkit-style records with top-level url/method/body as HAR-like entries."""
    if not isinstance(record, dict):
        return record
    if "request" in record:
        return record
    url = record.get("url")
    if not isinstance(url, str):
        return record
    method = record.get("method") if isinstance(record.get("method"), str) else "GET"
    headers = record.get("headers") if isinstance(record.get("headers"), list) else []
    body = record.get("body") if isinstance(record.get("body"), str) else ""
    post: dict[str, Any] | None = None
    if body:
        mime = record.get("content_type") if isinstance(record.get("content_type"), str) else "application/json"
        post = {"mimeType": mime, "text": body}
    request: dict[str, Any] = {"method": method, "url": url, "headers": headers}
    if post is not None:
        request["postData"] = post
    return {"request": request}


def analyze_business_logic(text: str, *, source_label: str = "local-input") -> dict[str, Any]:
    """Build an offline business-logic candidate test plan from HAR/JSON text."""
    if len(text.encode("utf-8")) > MAX_INPUT_BYTES:
        raise ValueError("Input exceeds the analysis size limit.")
    try:
        raw_entries = _load_json_records(text)
    except ValueError:
        # Fall back to strict HAR loader for clearer errors on malformed HAR.
        try:
            raw_entries = load_har_entries(text.encode("utf-8"), max_bytes=MAX_INPUT_BYTES)
        except HarImportError as exc:
            raise ValueError(f"Invalid capture input: {exc}") from exc
    entries = [_normalize_record(entry) for entry in raw_entries]
    parameters = extract_parameters(entries)
    flow = detect_checkout_flow(entries)
    tests = build_test_plan(parameters, flow)
    plan: dict[str, Any] = {
        "schema": PLAN_SCHEMA,
        "source": source_label,
        "finding_confirmed": False,
        "requests_sent": False,
        "disclaimer": _DISCLAIMER,
        "parameter_count": len(parameters),
        "test_count": len(tests),
        "parameters": parameters,
        "checkout_flow": flow,
        "tests": tests,
        "markdown": "",
    }
    plan["markdown"] = plan_to_markdown(plan)
    return plan


def analyze_business_logic_file(path_text: str, *, label: str | None = None) -> dict[str, Any]:
    """Convenience wrapper used by the CLI (text already bounded-read)."""
    return analyze_business_logic(path_text, source_label=label or "local-input")
