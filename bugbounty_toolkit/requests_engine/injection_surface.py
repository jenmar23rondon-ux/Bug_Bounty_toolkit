"""Where an XSS or SQLi probe value is placed.

Query placement stays the default. POST requires ``json`` or ``form``. Header
placement accepts only a short allowlist. A result with no recorded location
is inconclusive and is not confirmed.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from urllib.parse import urlencode

from ..access_control.body import BodyDocument
from ..access_control.comparison import MISSING, lookup, replace_pointer
from ..core.http_client import RequestSpec
from .parameters import with_parameter

HEADER_ALLOWLIST: tuple[str, ...] = ("Referer", "User-Agent", "X-Forwarded-Host", "Origin")
LOCATIONS: frozenset[str] = frozenset({"query", "body_form", "body_json", "header"})
_CANONICAL = {name.lower(): name for name in HEADER_ALLOWLIST}


@dataclass(frozen=True)
class InjectionSurface:
    method: str = "GET"
    content_type: str | None = None
    header_inject: tuple[str, ...] = ()
    body_template: str | None = None

    @property
    def location(self) -> str:
        if self.header_inject:
            return "header"
        if self.method == "POST" and self.content_type == "json":
            return "body_json"
        if self.method == "POST" and self.content_type == "form":
            return "body_form"
        return "query"


def canonical_header(name: str) -> str:
    found = _CANONICAL.get(name.strip().lower())
    if found is None:
        raise ValueError("Header injection only allows Referer, User-Agent, X-Forwarded-Host, and Origin.")
    return found


def validate_surface(
    method: str,
    content_type: str | None,
    header_inject: tuple[str, ...] | list[str],
    body_template: str | None,
) -> InjectionSurface:
    """Reject ambiguous or disallowed placements before any request is built."""
    verb = method.upper()
    if verb not in {"GET", "POST"}:
        raise ValueError("Method must be GET or POST.")
    if verb == "POST" and content_type is None:
        raise ValueError("POST requires --content-type json or form.")
    if verb == "GET" and content_type is not None:
        raise ValueError("Content type is only valid with POST.")
    if content_type not in {None, "json", "form"}:
        raise ValueError("Content type must be json or form.")
    headers = tuple(canonical_header(name) for name in header_inject)
    if headers and verb != "GET":
        raise ValueError("Header injection cannot be combined with POST.")
    if headers and content_type is not None:
        raise ValueError("Header injection cannot be combined with a request body.")
    if content_type == "json" and not body_template:
        raise ValueError("JSON injection requires a --body template.")
    if content_type == "json":
        BodyDocument.parse(body_template, "application/json")
    if content_type == "form" and body_template:
        BodyDocument.parse(body_template, "application/x-www-form-urlencoded")
    return InjectionSurface(verb, content_type, headers, body_template)


def bind_parameters(surface: InjectionSurface, parameters: list[str]) -> None:
    if surface.location == "header":
        names = [canonical_header(name) for name in parameters]
        if set(names) != set(surface.header_inject):
            raise ValueError("Parameters must match the allowlisted --header-inject headers.")
        return
    if surface.location == "body_json":
        for name in parameters:
            if not name.startswith("/"):
                raise ValueError("JSON parameters must be JSON pointers such as /q.")
            json_body(surface.body_template or "", name, "")
        return
    if surface.location == "body_form" and surface.body_template:
        for name in parameters:
            form_body(surface.body_template, name, "")


def baseline_value(route: str, parameter: str, surface: InjectionSurface) -> str:
    if surface.location == "query":
        from urllib.parse import parse_qsl, urlsplit

        return dict(parse_qsl(urlsplit(route).query, keep_blank_values=True)).get(parameter, "")
    if surface.location == "body_json":
        document = BodyDocument.parse(surface.body_template, "application/json")
        value = lookup(document.value, parameter)
        if value is MISSING:
            raise ValueError("The declared JSON pointer does not exist.")
        if isinstance(value, str):
            return value
        return json.dumps(value, ensure_ascii=True, separators=(",", ":"))
    if surface.location == "body_form":
        if not surface.body_template:
            return ""
        document = BodyDocument.parse(surface.body_template, "application/x-www-form-urlencoded")
        pairs = document.value
        if isinstance(pairs, list):
            for item in pairs:
                if isinstance(item, tuple) and len(item) == 2 and item[0] == parameter:
                    return str(item[1])
        raise ValueError("The declared form field is not in the body template.")
    return ""


def json_body(template: str, pointer: str, value: str) -> str:
    """Replace one declared pointer. Sibling keys, arrays, and value types stay."""
    document = BodyDocument.parse(template, "application/json")
    updated = replace_pointer(document.value, pointer, value)
    return json.dumps(updated, ensure_ascii=True, allow_nan=False, separators=(",", ":"))


def form_body(template: str | None, name: str, value: str) -> str:
    if not template:
        return urlencode([(name, value)])
    document = BodyDocument.parse(template, "application/x-www-form-urlencoded")
    pairs = document.value
    if not isinstance(pairs, list):
        raise ValueError("Form template must be urlencoded fields.")
    found = False
    fields: list[tuple[str, str]] = []
    for item in pairs:
        if not isinstance(item, tuple) or len(item) != 2:
            continue
        key, current = str(item[0]), str(item[1])
        if key == name:
            fields.append((key, value))
            found = True
        else:
            fields.append((key, current))
    if not found:
        raise ValueError("The declared form field is not in the body template.")
    return urlencode(fields)


def build_injection_request(
    route: str,
    parameter: str,
    payload: str,
    headers: dict[str, str],
    surface: InjectionSurface,
) -> RequestSpec:
    location = surface.location
    request_headers = dict(headers)
    if location == "query":
        return RequestSpec(method="GET", url=with_parameter(route, parameter, payload), headers=request_headers)
    if location == "header":
        header_name = canonical_header(parameter)
        if any(char in payload for char in "\r\n"):
            raise ValueError("Header probe values cannot contain CR or LF.")
        request_headers[header_name] = payload
        return RequestSpec(method="GET", url=route, headers=request_headers)
    if location == "body_form":
        request_headers["Content-Type"] = "application/x-www-form-urlencoded"
        return RequestSpec(
            method="POST",
            url=route,
            headers=request_headers,
            body=form_body(surface.body_template, parameter, payload),
        )
    if location == "body_json":
        request_headers["Content-Type"] = "application/json"
        return RequestSpec(
            method="POST",
            url=route,
            headers=request_headers,
            body=json_body(surface.body_template or "", parameter, payload),
        )
    raise ValueError("Parameter location is missing.")


def seal_parameter_location(result: dict[str, object], location: str | None) -> None:
    """Record location. A missing location is inconclusive and is not confirmed."""
    if location in LOCATIONS:
        result["parameter_location"] = location
        return
    result["parameter_location"] = None
    result["classification"] = "inconclusive"
    result["finding_state"] = "inconclusive"
    result["confirmed"] = False
    result["confirmation_gap"] = "no_second_proof"
    result["rejection_reason"] = "no_second_proof"
