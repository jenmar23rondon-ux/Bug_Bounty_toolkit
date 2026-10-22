from __future__ import annotations

from dataclasses import dataclass, field
from http.cookies import CookieError, SimpleCookie
import re
from pathlib import Path
from urllib.parse import urlsplit

from .analysis.html_context import parse_html_document
from .core.http_client import HttpClient, RequestSpec, ResponseRecord
from .core.redaction import redact_url
from .core.scope_validator import ScopeValidator
from .reporting.evidence import write_evidence_json
from .utils.exceptions import ToolkitError


TOKEN_FIELD = re.compile(r"csrf|xsrf|authenticity|request.?verification|anti.?forgery|token", re.IGNORECASE)
HTML_TYPES = {"text/html", "application/xhtml+xml"}
SAMESITE_VALUES = {"strict", "lax", "none"}
REDIRECT_STATUSES = {301, 302, 303, 307, 308}


@dataclass(frozen=True)
class CsrfOptions:
    url: str
    headers: dict[str, str] = field(default_factory=dict)


def _response_cookies(response: ResponseRecord) -> list[dict[str, object]]:
    raw_cookies = list(response.set_cookies)
    if not raw_cookies and response.headers.get("set-cookie"):
        raw_cookies.append(response.headers["set-cookie"])

    observations: list[dict[str, object]] = []
    for raw_cookie in raw_cookies:
        parsed = SimpleCookie()
        try:
            parsed.load(raw_cookie)
        except CookieError:
            observations.append({"samesite": "unknown", "secure": False, "httponly": False})
            continue
        morsels = list(parsed.values())
        if not morsels:
            observations.append({"samesite": "unknown", "secure": False, "httponly": False})
            continue
        for morsel in morsels:
            same_site = morsel["samesite"].strip().lower()
            observations.append(
                {
                    "samesite": same_site if same_site in SAMESITE_VALUES else "missing",
                    "secure": bool(morsel["secure"]),
                    "httponly": bool(morsel["httponly"]),
                }
            )
    return observations


def _form_observations(document: str) -> tuple[list[dict[str, object]], int]:
    soup = parse_html_document(document)
    forms: list[dict[str, object]] = []
    for form in soup.find_all("form"):
        method = str(form.get("method") or "get").strip().lower()
        if method not in {"get", "post", "dialog"}:
            method = "get"
        has_hidden_token = any(
            str(field.get("type") or "text").strip().lower() == "hidden"
            and TOKEN_FIELD.search(f"{field.get('name', '')} {field.get('id', '')}") is not None
            for field in form.find_all("input")
        )
        forms.append({"method": method, "hidden_token_present": has_hidden_token})
    post_forms = [form for form in forms if form["method"] == "post"]
    post_forms_with_token = sum(form["hidden_token_present"] is True for form in post_forms)
    return forms, post_forms_with_token


def _classify(forms: list[dict[str, object]], cookies: list[dict[str, object]]) -> str:
    post_forms = [form for form in forms if form["method"] == "post"]
    post_forms_with_token = sum(form["hidden_token_present"] is True for form in post_forms)
    if (
        post_forms
        and post_forms_with_token
        and cookies
        and all(cookie["samesite"] in SAMESITE_VALUES for cookie in cookies)
    ):
        return "protected"
    if post_forms and not post_forms_with_token and any(cookie["samesite"] in {"lax", "none"} for cookie in cookies):
        return "possible_csrf"
    return "weak"


class CsrfAuditor:
    """Collect conservative, non-exploitative CSRF indicators from one HTML response."""

    def __init__(self, scope: ScopeValidator, client: HttpClient):
        self.scope = scope
        self.client = client

    def validate(self, options: CsrfOptions) -> None:
        parsed = urlsplit(options.url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ValueError("CSRF audits require an absolute HTTP(S) URL.")
        self.scope.require(options.url)

    def run(self, options: CsrfOptions, evidence_dir: Path) -> tuple[Path, dict[str, object]]:
        self.validate(options)
        stop_reason: str | None = None
        response: ResponseRecord | None = None
        try:
            response = self.client.send(RequestSpec("GET", options.url, options.headers))
        except (ToolkitError, ValueError) as exc:
            stop_reason = "transport_error"
            result: dict[str, object] = {
                "type": "csrf-audit",
                "url": redact_url(options.url),
                "classification": "inconclusive",
                "reason": type(exc).__name__,
                "stop_reason": stop_reason,
                "heuristic": True,
                "confirmed": False,
                "note": "Heuristic only; no request was successfully analyzed.",
            }
        else:
            content_type = response.headers.get("content-type", "").split(";", 1)[0].strip().lower()
            result = {
                "type": "csrf-audit",
                "url": redact_url(options.url),
                "status_code": response.status_code,
                "content_type": content_type or None,
                "body_truncated": response.body_truncated,
                "heuristic": True,
                "confirmed": False,
            }
            if response.status_code in {401, 403, 429}:
                result.update(classification="inconclusive", stop_reason="access_or_rate_limit")
                stop_reason = "access_or_rate_limit"
            elif response.status_code in REDIRECT_STATUSES:
                result.update(classification="inconclusive", stop_reason="redirect_not_followed")
                stop_reason = "redirect_not_followed"
            elif not 200 <= response.status_code < 300:
                result.update(classification="inconclusive", stop_reason="unexpected_status")
                stop_reason = "unexpected_status"
            elif response.body_truncated:
                result.update(classification="inconclusive", stop_reason="truncated_response")
                stop_reason = "truncated_response"
            elif content_type not in HTML_TYPES:
                result.update(classification="inconclusive", stop_reason="not_html")
                stop_reason = "not_html"
            else:
                forms, post_forms_with_token = _form_observations(response.body_text)
                cookies = _response_cookies(response)
                classification = _classify(forms, cookies)
                none_without_secure = sum(
                    cookie["samesite"] == "none" and cookie["secure"] is False for cookie in cookies
                )
                result.update(
                    classification=classification,
                    form_count=len(forms),
                    form_methods=[form["method"] for form in forms],
                    post_form_count=sum(form["method"] == "post" for form in forms),
                    post_forms_with_hidden_token=post_forms_with_token,
                    cookies_observed=len(cookies),
                    cookie_samesite=[cookie["samesite"] for cookie in cookies],
                    samesite_none_without_secure=none_without_secure,
                    forms=forms,
                    cookies=cookies,
                    stop_reason=None,
                )
            result["note"] = (
                "Heuristic only: this single GET inspects forms and response cookie attributes; it does not submit forms, "
                "simulate a cross-site browser request, or confirm CSRF exploitability."
            )

        result["stop_reason"] = stop_reason
        result["requests_attempted"] = 1
        path = write_evidence_json(evidence_dir, result, prefix="csrf-audit")
        return path, result
