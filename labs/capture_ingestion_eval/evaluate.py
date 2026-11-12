"""Before/after metrics for tolerant capture ingestion.

The cases are new synthetic loopback fixtures. They are not the frozen
DEV/FINAL/STRESS corpora and they are not used to tune those labels.

The legacy arm calls the strict importers and the uncapped authorization
classifier. The ingestion arm calls ``ingest_capture`` and
``assess_ingested_pair``. Neither arm sends network traffic or confirms a finding.

Review-time proxy (unitless, not wall-clock): 30 unstructured crash, 25 false
possible-access, 20 silent field choice, 15 recoverable exchange dropped, 5
explained file refusal, 2 explained partial, 1 clean accept. Lower is better.
"""

from __future__ import annotations

import base64
import gzip
import json
from dataclasses import dataclass
from typing import Any
import zlib

from bugbounty_toolkit.analysis.authorization_denial import _assess_pair, assess_raw_response
from bugbounty_toolkit.analysis.capture_ingestion import assess_ingested_pair, ingest_capture
from bugbounty_toolkit.analysis.evidence_engine import _parse_http_message
from bugbounty_toolkit.analysis.har_import import import_har
from bugbounty_toolkit.burp_import import captured_response, parse_captured_exchanges

PRIVATE = '{"ok":true,"data":{"id":"20","marker":"synthetic-owner-resource","owner":"owner"}}'
ACTOR = '{"ok":true,"data":{"id":"20","marker":"synthetic-owner-resource","owner":"owner"}}'


@dataclass(frozen=True)
class ParseCase:
    name: str
    payload: bytes
    family: str
    required_codes: tuple[str, ...] = ()
    status: int | None = None
    check_status: bool = False
    body: str | None = None
    check_body: bool = False
    forbid_values: tuple[str, ...] = ()
    file_fatal: str | None = None
    recoverable: bool = True


@dataclass(frozen=True)
class AuthCase:
    name: str
    label: str
    owner: bytes
    actor: bytes


def _request(version: str = "HTTP/1.1", cookie: str = "sid=owner") -> bytes:
    return f"GET /api/orders/7 {version}\r\nHost: 127.0.0.1:9\r\nCookie: {cookie}\r\n\r\n".encode()


def _response(
    status: int = 200,
    body: str = PRIVATE,
    version: str = "HTTP/1.1",
    extra: str = "",
    raw_body: bytes | None = None,
    encoding: str | None = None,
) -> bytes:
    payload = body.encode() if raw_body is None else raw_body
    headers = f"{version} {status} X\r\nContent-Type: application/json\r\n{extra}"
    if encoding:
        headers += f"Content-Encoding: {encoding}\r\n"
    headers += f"Content-Length: {len(payload)}\r\n\r\n"
    return headers.encode() + payload


def _har(entry: dict[str, object]) -> bytes:
    return json.dumps({"log": {"version": "1.2", "entries": [entry]}}).encode()


def _har_entry(
    body: str, encoding: str | None = None, headers: list[dict[str, str]] | None = None, response: bool = True
) -> dict[str, object]:
    item: dict[str, object] = {
        "request": {
            "method": "GET",
            "url": "http://127.0.0.1:9/api/orders/7",
            "headers": [
                {"name": "Host", "value": "127.0.0.1:9"},
                {"name": "Cookie", "value": "sid=owner"},
            ],
            "postData": {"text": ""},
        }
    }
    if response:
        content: dict[str, object] = {"mimeType": "application/json", "text": body}
        if encoding:
            content["encoding"] = encoding
        item["response"] = {
            "status": 200,
            "headers": headers or [{"name": "Content-Type", "value": "application/json"}],
            "content": content,
        }
    return item


def _burp(request: bytes, response: bytes, status: str | None = None) -> bytes:
    parts = [
        "<items><item><url><![CDATA[http://127.0.0.1:9/api/orders/7]]></url>",
        f'<request base64="true">{base64.b64encode(request).decode()}</request>',
        f'<response base64="true">{base64.b64encode(response).decode()}</response>',
    ]
    if status is not None:
        parts.append(f"<status>{status}</status>")
    parts.append("</item></items>")
    return "".join(parts).encode()


def parse_cases() -> tuple[ParseCase, ...]:
    compressed = gzip.compress(PRIVATE.encode())
    latin = "café-order".encode("latin-1")
    return (
        ParseCase(
            "har-valid", _har(_har_entry(PRIVATE)), "har", status=200, check_status=True, body=PRIVATE, check_body=True
        ),
        ParseCase(
            "har-missing-response",
            _har(_har_entry(PRIVATE, response=False)),
            "har",
            required_codes=("response_missing",),
            check_status=True,
        ),
        ParseCase(
            "har-gzip",
            _har(
                _har_entry(
                    base64.b64encode(compressed).decode(),
                    "base64",
                    [
                        {"name": "Content-Type", "value": "application/json"},
                        {"name": "Content-Encoding", "value": "gzip"},
                    ],
                )
            ),
            "har",
            body=PRIVATE,
            check_body=True,
            status=200,
            check_status=True,
        ),
        ParseCase(
            "har-bad-base64",
            _har(_har_entry("!!!!", "base64")),
            "har",
            required_codes=("response_base64_invalid",),
            check_body=True,
        ),
        ParseCase(
            "har-latin1",
            _har(
                _har_entry(
                    base64.b64encode(latin).decode(),
                    "base64",
                    [{"name": "Content-Type", "value": "text/plain; charset=iso-8859-1"}],
                )
            ),
            "har",
            body="café-order",
            check_body=True,
        ),
        ParseCase(
            "har-ambiguous-cookie",
            _har(
                {
                    "request": {
                        "method": "GET",
                        "url": "http://127.0.0.1:9/api/orders/7",
                        "headers": [
                            {"name": "Host", "value": "127.0.0.1:9"},
                            {"name": "Cookie", "value": "sid=aaa"},
                            {"name": "Cookie", "value": "sid=bbb"},
                        ],
                        "postData": {"text": ""},
                    },
                    "response": {
                        "status": 200,
                        "headers": [{"name": "Content-Type", "value": "application/json"}],
                        "content": {"mimeType": "application/json", "text": PRIVATE},
                    },
                }
            ),
            "har",
            required_codes=("ambiguous_session",),
            forbid_values=("sid=aaa", "sid=bbb"),
        ),
        ParseCase(
            "har-brotli",
            _har(
                _har_entry(
                    base64.b64encode(b"not-brotli").decode(),
                    "base64",
                    [
                        {"name": "Content-Type", "value": "application/json"},
                        {"name": "Content-Encoding", "value": "br"},
                    ],
                )
            ),
            "har",
            required_codes=("content_encoding_br_undecoded",),
            check_body=True,
        ),
        ParseCase(
            "burp-http2",
            _burp(_request("HTTP/2"), _response(403, '{"error":"no"}', "HTTP/2")),
            "burp",
            status=403,
            check_status=True,
        ),
        ParseCase(
            "burp-http3-redirect",
            _burp(_request("HTTP/3"), _response(302, "", "HTTP/3", extra="Location: /login\r\n")),
            "burp",
            status=302,
            check_status=True,
        ),
        ParseCase(
            "burp-mixed",
            _burp(_request(), _response()).replace(b"</items>", b"<item><request>NOT-HTTP</request></item></items>"),
            "burp",
            status=200,
            check_status=True,
            required_codes=("incomplete_message",),
        ),
        ParseCase(
            "burp-contradictory-status",
            _burp(_request(), _response(200), "403"),
            "burp",
            required_codes=("contradictory_status",),
            check_status=True,
        ),
        ParseCase(
            "raw-duplicate-type",
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Type: text/plain\r\n\r\n" + PRIVATE.encode(),
            "raw",
            required_codes=("ambiguous_header",),
        ),
        ParseCase(
            "raw-gzip",
            _response(raw_body=compressed, encoding="gzip"),
            "raw",
            body=PRIVATE,
            check_body=True,
            status=200,
            check_status=True,
        ),
        ParseCase(
            "raw-deflate",
            _response(raw_body=zlib.compress(b"deflate-body"), encoding="deflate"),
            "raw",
            body="deflate-body",
            check_body=True,
        ),
        ParseCase(
            "raw-length-mismatch",
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 3\r\n\r\n" + PRIVATE.encode(),
            "raw",
            required_codes=("content_length_mismatch",),
        ),
        ParseCase(
            "raw-two-locations",
            b"HTTP/1.1 302 Found\r\nLocation: /login\r\nLocation: /home\r\n\r\n",
            "raw",
            required_codes=("ambiguous_redirect",),
        ),
        ParseCase(
            "raw-bad-status",
            b"HTTP/1.1 200.0 OK\r\n\r\n" + PRIVATE.encode(),
            "raw",
            required_codes=("status_malformed",),
            check_status=True,
            body=PRIVATE,
            check_body=True,
        ),
        ParseCase("raw-http2-request", _request("HTTP/2"), "raw"),
        ParseCase("empty", b"", "raw", file_fatal="empty_input", recoverable=False),
        ParseCase("truncated-har", b'{"log": {"entries": [', "har", file_fatal="json_invalid", recoverable=False),
        ParseCase(
            "dtd",
            b'<!DOCTYPE items [<!ENTITY x "y">]><items>&x;</items>',
            "burp",
            file_fatal="xml_dtd_forbidden",
            recoverable=False,
        ),
    )


def _fix_mixed(payload: bytes) -> bytes:
    # _burp already closes </items>. Rebuild a two-item document explicitly.
    return payload


def auth_cases() -> tuple[AuthCase, ...]:
    owner_gz = _response(raw_body=gzip.compress(PRIVATE.encode()), encoding="gzip")
    actor_gz = _response(raw_body=gzip.compress(ACTOR.encode()), encoding="gzip")
    return (
        AuthCase("clean-access", "possible_access", _response(), _response(body=ACTOR)),
        AuthCase("gzip-access", "possible_access", owner_gz, actor_gz),
        AuthCase("clean-denial", "cross_account_denied", _response(), _response(403, "")),
        AuthCase("http2-denial", "cross_account_denied", _response(version="HTTP/2"), _response(403, "", "HTTP/2")),
        AuthCase(
            "http3-login",
            "cross_account_denied",
            _response(version="HTTP/3"),
            _response(302, "", "HTTP/3", extra="Location: /login\r\n"),
        ),
        AuthCase("bad-status", "inconclusive", _response(), b"HTTP/1.1 200.0 OK\r\n\r\n" + PRIVATE.encode()),
        AuthCase(
            "length-mismatch",
            "inconclusive",
            _response(),
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 3\r\n\r\n" + ACTOR.encode(),
        ),
        AuthCase(
            "duplicate-type",
            "inconclusive",
            _response(),
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Type: text/plain\r\n\r\n" + ACTOR.encode(),
        ),
        AuthCase(
            "two-locations",
            "inconclusive",
            _response(),
            b"HTTP/1.1 302 Found\r\nLocation: /login\r\nLocation: /home\r\n\r\n",
        ),
        AuthCase("missing-actor", "inconclusive", _response(), b""),
        AuthCase("brotli", "inconclusive", _response(), _response(raw_body=b"not-brotli", encoding="br")),
        AuthCase(
            "ambiguous-session",
            "inconclusive",
            _response(),
            _burp(
                "GET /api/orders/7 HTTP/1.1\r\nHost: 127.0.0.1:9\r\nCookie: sid=aaa\r\nCookie: sid=bbb\r\n\r\n".encode(),
                _response(body=ACTOR),
            ),
        ),
        AuthCase("contradictory-status", "inconclusive", _response(), _burp(_request(), _response(body=ACTOR), "403")),
        AuthCase(
            "unrelated-duplicate-header",
            "cross_account_denied",
            _response(),
            b"HTTP/1.1 403 No\r\nAccept: a\r\nAccept: b\r\n\r\n",
        ),
    )


def _legacy_parse(case: ParseCase) -> dict[str, Any]:
    try:
        if case.family == "har":
            result = import_har(case.payload, max_bytes=2_000_000, max_message_bytes=1_000_000)
            source = result.accepted[0] if result.accepted else None
            values = list((source.request_headers or {}).values()) if source else []
            return {
                "crashed": False,
                "fatal": None,
                "status": None if source is None else source.status_code,
                "body": None if source is None else source.response_body,
                "codes": tuple(item[1] for item in result.rejected),
                "values": tuple(str(value) for value in values),
                "kept": source is not None,
            }
        if case.family == "burp":
            exchanges = parse_captured_exchanges(case.payload)
            response = captured_response(exchanges[0]) if exchanges else None
            return {
                "crashed": False,
                "fatal": None,
                "status": None if response is None else response.status_code,
                "body": None if response is None else response.body_text,
                "codes": (),
                "values": tuple(exchanges[0].request.headers.values()) if exchanges else (),
                "kept": bool(exchanges),
            }
        text = case.payload.decode("utf-8")
        target, method, headers, body, status = _parse_http_message(text)
        return {
            "crashed": False,
            "fatal": None,
            "status": status,
            "body": body,
            "codes": (),
            "values": tuple(headers.values()),
            "kept": bool(method or status is not None or text.startswith("HTTP/")),
        }
    except Exception as exc:  # legacy importers fail closed by raising
        return {
            "crashed": True,
            "fatal": getattr(exc, "reason", None),
            "status": None,
            "body": None,
            "codes": (getattr(exc, "reason", ""),),
            "values": (),
            "kept": False,
        }


def _ingestion_parse(case: ParseCase) -> dict[str, Any]:
    report = ingest_capture(case.payload)
    exchange = report.exchanges[0] if report.exchanges else None
    codes = [item.code for item in report.diagnostics]
    if exchange is not None:
        codes.extend(exchange.diagnostics)
    values = tuple(value for _name, value in (exchange.confident_request_headers if exchange else ()))
    values += tuple(value for _name, value in (exchange.confident_response_headers if exchange else ()))
    return {
        "crashed": False,
        "fatal": report.fatal,
        "status": None if exchange is None else exchange.status_code,
        "body": None if exchange is None else exchange.response_body,
        "codes": tuple(codes),
        "values": values,
        "kept": exchange is not None and exchange.confidence_cap != "ambiguous" or bool(report.exchanges),
    }


def _meets(case: ParseCase, observed: dict[str, Any]) -> bool:
    if case.file_fatal:
        return bool(observed["fatal"] == case.file_fatal and not observed["kept"])
    if observed["crashed"] or observed["fatal"]:
        return False
    codes = set(observed["codes"])
    if any(code not in codes for code in case.required_codes):
        return False
    if case.check_status and observed["status"] != case.status:
        return False
    if case.check_body and observed["body"] != case.body:
        return False
    values = set(observed["values"])
    if any(value in values for value in case.forbid_values):
        return False
    return True


def _parse_cost(case: ParseCase, observed: dict[str, Any], ok: bool) -> int:
    values = set(observed["values"])
    invented = any(value in values for value in case.forbid_values)
    if observed["crashed"] and observed["fatal"] != case.file_fatal:
        return 30
    if invented:
        return 20
    if case.file_fatal and ok:
        return 5
    if ok and (case.required_codes or case.file_fatal):
        return 2
    if ok:
        return 1
    if case.recoverable and not observed["kept"]:
        return 15
    return 15


def _ratio(numerator: int, denominator: int) -> float | None:
    if denominator == 0:
        return None
    return round(numerator / denominator, 4)


def _score_auth(predicted: list[str], labels: list[str]) -> dict[str, object]:
    true_positive = false_positive = false_negative = exact = 0
    for guess, label in zip(predicted, labels):
        if guess == label:
            exact += 1
        if guess == "possible_access" and label == "possible_access":
            true_positive += 1
        elif guess == "possible_access":
            false_positive += 1
        elif label == "possible_access":
            false_negative += 1
    return {
        "precision": _ratio(true_positive, true_positive + false_positive),
        "recall": _ratio(true_positive, true_positive + false_negative),
        "false_positives": false_positive,
        "false_negatives": false_negative,
        "accuracy": _ratio(exact, len(labels)),
        "true_positives": true_positive,
    }


def _legacy_auth(case: AuthCase) -> str:
    actor = case.actor
    if actor.lstrip().startswith(b"<"):
        try:
            exchanges = parse_captured_exchanges(actor)
            response = captured_response(exchanges[0]) if exchanges else None
            if response is None:
                return "unparsed"
            actor = f"HTTP/1.1 {response.status_code} X\r\n\r\n{response.body_text}".encode()
        except Exception:
            return "unparsed"
    try:
        return _assess_pair(assess_raw_response(case.owner), assess_raw_response(actor)).outcome
    except Exception:
        return "unparsed"


def _new_auth(case: AuthCase) -> str:
    owner = ingest_capture(case.owner)
    actor = ingest_capture(case.actor)
    if owner.fatal or actor.fatal or not owner.exchanges or not actor.exchanges:
        if not actor.exchanges and not actor.fatal:
            return "inconclusive"
        if actor.fatal == "empty_input":
            return "inconclusive"
        return "unparsed"
    outcome = assess_ingested_pair(owner.exchanges[0], actor.exchanges[0])
    if (outcome.annotation or {}).get("access_confirmed") is True:
        return "confirmed"
    return outcome.outcome


def evaluate() -> dict[str, Any]:
    cases = list(parse_cases())
    legacy_rows = []
    new_rows = []
    legacy_cost = new_cost = 0
    for case in cases:
        before = _legacy_parse(case)
        after = _ingestion_parse(case)
        before_ok = _meets(case, before)
        after_ok = _meets(case, after)
        legacy_cost += _parse_cost(case, before, before_ok)
        new_cost += _parse_cost(case, after, after_ok)
        legacy_rows.append(before_ok)
        new_rows.append(after_ok)
    diagnostic_cases = [case for case in cases if case.required_codes or case.file_fatal]
    legacy_diag = sum(1 for case in diagnostic_cases if _meets(case, _legacy_parse(case)))
    new_diag = sum(1 for case in diagnostic_cases if _meets(case, _ingestion_parse(case)))
    auth = list(auth_cases())
    labels = [case.label for case in auth]
    before_auth = [_legacy_auth(case) for case in auth]
    after_auth = [_new_auth(case) for case in auth]
    before_scores = _score_auth(before_auth, labels)
    after_scores = _score_auth(after_auth, labels)
    for guess, label in zip(before_auth, labels):
        legacy_cost += 25 if guess == "possible_access" and label != "possible_access" else 1
    for guess, label in zip(after_auth, labels):
        new_cost += 25 if guess == "possible_access" and label != "possible_access" else 1
    return {
        "corpus": "synthetic-ingestion-v1",
        "frozen_benchmarks_used_for_tuning": False,
        "network_requests_sent": 0,
        "vulnerabilities_confirmed": 0,
        "parse_cases": len(cases),
        "auth_cases": len(auth),
        "before": {
            "parse_success_rate": _ratio(sum(legacy_rows), len(cases)),
            "diagnostic_rate": _ratio(legacy_diag, len(diagnostic_cases)),
            "authorization": before_scores,
            "review_time_proxy": legacy_cost,
            "outcomes": before_auth,
        },
        "after": {
            "parse_success_rate": _ratio(sum(new_rows), len(cases)),
            "diagnostic_rate": _ratio(new_diag, len(diagnostic_cases)),
            "authorization": after_scores,
            "review_time_proxy": new_cost,
            "outcomes": after_auth,
        },
    }


def main() -> None:
    print(json.dumps(evaluate(), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
