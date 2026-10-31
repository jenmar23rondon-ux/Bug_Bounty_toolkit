# Offline business-logic test planner

`analysis/business_logic_planner.py` and `bbtk analyze business-logic` build a
**candidate-only** manipulation test plan from a local HAR file or JSON capture
records. No HTTP requests are sent. Every item has `finding_confirmed: false`.
Confirmation requires manual testing on the user's own accounts within program
scope. Version stays 0.2.2.

## Usage

```bash
bbtk analyze business-logic \
  --input path/to/capture.har \
  --output reports/business-logic-plan.json \
  --markdown reports/business-logic-plan.md
```

Input may be:

- a HAR document (`log.entries`), or
- JSON with `entries` / `records` / `requests` / `captures`, or a single record
  with top-level `url` / `method` / `body`.

## What it detects

Parameter name heuristics (plus light value-type hints) for:

| Category | Example names |
| --- | --- |
| price | price, amount, total, cost, subtotal, discount |
| quantity | quantity, qty, count, items |
| coupon | coupon, promo, voucher, gift code |
| currency | currency, curr, ccy |
| shipping / tax | shipping, freight, tax, vat, gst |
| cart/order ids | cart_id, order_id, checkout token |
| plan/tier/role | plan, tier, role, subscription |

## Candidate ideas (not executed)

- Quantity: negative, zero, fractional, huge
- Price / shipping / tax tamper (lower, zero, negative)
- Currency swap
- Coupon reuse, stacking, apply-after-total; parallel redemption flagged **manual-only**
- Checkout step skipping when cart → checkout → pay appears in HAR order
- Cross-account cart/order id reuse (manual-only)

Sensitive values are redacted with `core/redaction.py`. Authorization headers and
tokens never appear in the plan.

## Safety contract

- Offline only: `requests_sent` is always false
- `finding_confirmed` stays false on the plan and every candidate
- No third-party HTTP clients, no network in tests
- Synthetic fixtures only under `tests/fixtures/`
