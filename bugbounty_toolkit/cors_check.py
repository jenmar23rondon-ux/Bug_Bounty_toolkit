from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit

from .core.http_client import HttpClient, RequestSpec
from .core.redaction import redact_url
from .core.scope_validator import ScopeValidator
from .reporting.evidence import write_evidence_json
from .utils.exceptions import ToolkitError

# Confirmation-bar rejection reasons (CORS only). Distinct from ledger REJECTION_REASONS.
CORS_REJECTION_REASONS = frozenset({"false_positive", "out_of_scope", "no_second_proof"})
CORS_FINDING_STATES = frozenset({"candidate", "confirmed", "not_observed", "inconclusive", "rejected"})

_CREDENTIAL_HEADER_NAMES = frozenset({"cookie", "authorization"})


def origins_for_target(url: str) -> list[str]:
    host = urlsplit(url).hostname
    if not host:
        raise ValueError("URL must include a hostname.")
    return list(
        dict.fromkeys(
            (
                "https://evil.com",
                "null",
                f"https://evil.{host}",
                f"https://{host}.evil.com",
            )
        )
    )


def classify_cors(origin: str, allow_origin: str | None, allow_credentials: str | None) -> str:
    """Header-policy verdict only. Reflection + ACAC is a candidate signal, not confirmation."""
    if allow_origin is None or allow_origin.strip() == "*":
        return "SEGURO"
    if allow_origin.strip() != origin:
        return "SEGURO"
    return "VULNERABLE" if acac_allows_credentials(allow_credentials) else "DÉBIL"


def request_sends_credentials(headers: dict[str, str]) -> bool:
    """True when the request carries Cookie or Authorization (credentialed CORS probe)."""
    for key, value in headers.items():
        if key.lower() in _CREDENTIAL_HEADER_NAMES and (value or "").strip():
            return True
    return False


def attacker_origin_reflected(origin: str, allow_origin: str | None) -> bool:
    return allow_origin is not None and allow_origin.strip() == origin and allow_origin.strip() != "*"


def acac_allows_credentials(allow_credentials: str | None) -> bool:
    return (allow_credentials or "").strip() == "true"


def body_readable_cross_origin(status_code: int | None, body_text: str, body_size: int) -> bool:
    """
    Legacy body-presence helper, not proof of browser readability or privacy.
    A successful non-empty response can be public and the cookie can be analytics.
    """
    if status_code is None or status_code < 200 or status_code >= 300:
        return False
    if body_size <= 0:
        return False
    return bool((body_text or "").strip())


def assess_cors_finding(
    *,
    origin: str,
    allow_origin: str | None,
    allow_credentials: str | None,
    request_headers: dict[str, str],
    status_code: int | None = None,
    body_text: str = "",
    body_size: int = 0,
    rejection_reason: str | None = None,
    transport_error: bool = False,
    body_truncated: bool = False,
) -> dict[str, object]:
    """
    Assess header-policy indicators without inferring private data or browser access.

    Native HTTP cannot prove credential delivery, private-resource policy or a
    successful attacker-origin browser read. Explicit rejection requires a reason.
    """
    classification = "error" if transport_error else classify_cors(origin, allow_origin, allow_credentials)
    reflected = attacker_origin_reflected(origin, allow_origin)
    acac = acac_allows_credentials(allow_credentials)
    credentialed = request_sends_credentials(request_headers)
    private_readable = False

    if rejection_reason is not None:
        if rejection_reason not in CORS_REJECTION_REASONS:
            raise ValueError(f"Unsupported CORS rejection reason: {rejection_reason}")
        return {
            "classification": classification,
            "finding_state": "rejected",
            "confirmed": False,
            "origin_reflected": reflected,
            "acac_true": acac,
            "credentialed_request": credentialed,
            "private_body_readable": private_readable,
            "confirmation_gap": None,
            "rejection_reason": rejection_reason,
        }

    if (
        transport_error
        or body_truncated
        or status_code in {401, 403, 429}
        or (status_code is not None and status_code >= 500)
    ):
        return {
            "classification": classification,
            "finding_state": "inconclusive",
            "confirmed": False,
            "origin_reflected": reflected,
            "acac_true": acac,
            "credentialed_request": credentialed,
            "private_body_readable": private_readable,
            "confirmation_gap": None,
            "rejection_reason": None,
        }

    if reflected and acac:
        # Single header signal — candidate, not reportable confirmation.
        gap = "no_second_proof"
        return {
            "classification": classification,
            "finding_state": "candidate",
            "confirmed": False,
            "origin_reflected": True,
            "acac_true": True,
            "credentialed_request": credentialed,
            "private_body_readable": private_readable,
            "confirmation_gap": gap,
            "rejection_reason": None,
        }

    if reflected:
        # Reflection without ACAC: weak single signal → candidate, not confirmed.
        return {
            "classification": classification,
            "finding_state": "candidate",
            "confirmed": False,
            "origin_reflected": True,
            "acac_true": False,
            "credentialed_request": credentialed,
            "private_body_readable": private_readable,
            "confirmation_gap": "no_second_proof",
            "rejection_reason": None,
        }

    return {
        "classification": classification,
        "finding_state": "not_observed",
        "confirmed": False,
        "origin_reflected": False,
        "acac_true": acac,
        "credentialed_request": credentialed,
        "private_body_readable": private_readable,
        "confirmation_gap": None,
        "rejection_reason": None,
    }


def aggregate_cors_classification(results: list[dict[str, object]], stop_reason: str | None) -> str:
    """Overall evidence classification: confirmed > candidate > inconclusive > not_observed."""
    states = {str(row.get("finding_state") or "") for row in results}
    if "confirmed" in states:
        return "confirmed"
    if "candidate" in states:
        return "candidate"
    if stop_reason or "inconclusive" in states or "error" in {str(row.get("classification") or "") for row in results}:
        return "inconclusive"
    return "not_observed"


@dataclass(frozen=True)
class CorsOptions:
    url: str
    headers: dict[str, str] = field(default_factory=dict)


class CorsChecker:
    def __init__(self, scope: ScopeValidator, client: HttpClient):
        self.scope = scope
        self.client = client

    def validate(self, options: CorsOptions) -> list[str]:
        parsed = urlsplit(options.url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ValueError("CORS checks require an absolute HTTP(S) URL.")
        self.scope.require(options.url)
        return origins_for_target(options.url)

    def run(self, options: CorsOptions, evidence_dir: Path) -> tuple[Path, list[dict[str, object]]]:
        origins = self.validate(options)
        results: list[dict[str, object]] = []
        stop_reason = None
        for origin in origins:
            headers = {key: value for key, value in options.headers.items() if key.lower() != "origin"}
            headers["Origin"] = origin
            try:
                response = self.client.send(RequestSpec("GET", options.url, headers))
            except (ToolkitError, ValueError) as exc:
                assessment = assess_cors_finding(
                    origin=origin,
                    allow_origin=None,
                    allow_credentials=None,
                    request_headers=headers,
                    transport_error=True,
                )
                results.append(
                    {
                        "origin": origin,
                        "classification": "error",
                        "reason": type(exc).__name__,
                        "finding_state": assessment["finding_state"],
                        "confirmed": False,
                        "origin_reflected": assessment["origin_reflected"],
                        "acac_true": assessment["acac_true"],
                        "credentialed_request": assessment["credentialed_request"],
                        "private_body_readable": False,
                        "body_size": 0,
                        "confirmation_gap": assessment["confirmation_gap"],
                        "rejection_reason": assessment["rejection_reason"],
                    }
                )
                stop_reason = "transport_error"
                break
            allow_origin = response.headers.get("access-control-allow-origin")
            allow_credentials = response.headers.get("access-control-allow-credentials")
            assessment = assess_cors_finding(
                origin=origin,
                allow_origin=allow_origin,
                allow_credentials=allow_credentials,
                request_headers=headers,
                status_code=response.status_code,
                body_text=response.body_text,
                body_size=response.body_size,
                body_truncated=response.body_truncated,
            )
            results.append(
                {
                    "origin": origin,
                    "status_code": response.status_code,
                    "access_control_allow_origin": allow_origin,
                    "access_control_allow_credentials": allow_credentials,
                    "classification": assessment["classification"],
                    "finding_state": assessment["finding_state"],
                    "confirmed": assessment["confirmed"],
                    "origin_reflected": assessment["origin_reflected"],
                    "acac_true": assessment["acac_true"],
                    "credentialed_request": assessment["credentialed_request"],
                    "private_body_readable": assessment["private_body_readable"],
                    "body_size": response.body_size,
                    "confirmation_gap": assessment["confirmation_gap"],
                    "rejection_reason": assessment["rejection_reason"],
                    "duration_ms": response.duration_ms,
                }
            )
            if response.status_code in {401, 403, 429}:
                stop_reason = "access_or_rate_limit"
                break
        overall = aggregate_cors_classification(results, stop_reason)
        evidence = {
            "type": "cors",
            "url": redact_url(options.url),
            "requests_attempted": len(results),
            "stop_reason": stop_reason,
            "results": results,
            "classification": overall,
            "confirmed": overall == "confirmed",
            "note": (
                "Header reflection + ACAC alone is a candidate. Independent browser and privacy proof requires a credentialed "
                "response body readable by the attacker Origin (second proof). Request credentials "
                "and response bodies are omitted from evidence; only body_size and boolean signals "
                "are recorded. Rejection reasons: false_positive / out_of_scope / no_second_proof."
            ),
        }
        path = write_evidence_json(evidence_dir, evidence, prefix="cors")
        return path, results
